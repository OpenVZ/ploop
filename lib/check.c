/*
 *  Copyright (C) 2008-2012, Parallels, Inc. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <linux/types.h>
#include <string.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#include "ploop.h"

enum {
	ZEROFIX = 0,
	IGNORE
};

enum {
	NONFATAL = 0,
	FATAL
};

enum {
	SOFT_FIX = 0,
	HARD_FIX
};

struct ploop_check_desc {
	int    fd;
	int    ro;
	int    hard_force;
	int    check;
	off_t  bd_size;
	off_t  size;
	__u32 *bmap;
	int   *clean;
	int   *fatality;
	__u32 *alloc_head;
};

int read_safe(int fd, void * buf, unsigned int size, off_t pos, char *msg)
{
	ssize_t res;

	res = pread(fd, buf, size, pos);
	if (res == size)
		return 0;

	if (res < 0) {
		ploop_err(errno, "%s", msg);
		return SYSEXIT_READ;
	}

	ploop_log(0, "Short %s", msg);
	return SYSEXIT_READ;
}

int write_safe(int fd, void * buf, unsigned int size, off_t pos, char *msg)
{
	ssize_t res;

	res = pwrite(fd, buf, size, pos);
	if (res == size)
		return 0;

	if (res < 0) {
		ploop_err(errno, "%s", msg);
		return SYSEXIT_WRITE;
	}
	ploop_log(0,  "Short %s", msg);
	return SYSEXIT_WRITE;
}

static int fsync_safe(int fd)
{
	if (fsync(fd)) {
		ploop_err(errno, "fsync");
		return SYSEXIT_FSYNC;
	}
	return 0;
}

static int close_safe(int fd)
{
	if (close(fd)) {
		ploop_err(errno, "close");
		return SYSEXIT_WRITE;
	}
	return 0;
}

static int zero_index(int fd, __u32 clu)
{
	__u32 zero = 0;

	return write_safe(fd, &zero, sizeof(zero),
		     clu * sizeof(clu) + sizeof(struct ploop_pvd_header),
		     "write zero index");
}

static int zero_index_fix(struct ploop_check_desc *d, __u32 clu,
			   int hard_fix, int ignore, int fatal)
{
	char *msg;
	int   skip = d->ro;
	int   ret = 0;

	if (hard_fix && !d->hard_force)
		skip = 1;

	if (skip) {
		msg = fatal ? "FATAL" : "Skipped";
		*d->clean = 0;
		if (fatal)
			*d->fatality = 1;
	} else {
		msg = ignore ? "Ignored" : "Fixed";
		if (!ignore)
			ret = zero_index(d->fd, clu);
	}

	ploop_log(0,  "%s", msg);
	return ret;
}

static int check_one_slot(struct ploop_check_desc *d, __u32 clu, off_t isec,
		__u32 blocksize, int version)
{
	__u64 cluster = S2B(blocksize);
	__u32 cluster_log = ffs(blocksize) - 1;
	__u32 iblk = isec >> cluster_log;

	if ((clu << cluster_log) > d->bd_size) {
		ploop_log(0, "Data cluster (%u) beyond block device size... ",
				clu);
		return zero_index_fix(d, clu, SOFT_FIX, ZEROFIX, NONFATAL);
	}

	if (version == PLOOP_FMT_V1 && (isec % (1 << cluster_log) != 0)) {
		ploop_log(0, "L2 slot (%u) corrupted... ",
				clu);
		return zero_index_fix(d, clu, HARD_FIX, ZEROFIX, FATAL);
	}

	if ((off_t)iblk * cluster + cluster > d->size) {
		ploop_log(0, "Data cluster %u beyond EOF, vsec=%u... ",
			iblk, clu);
		return zero_index_fix(d, clu, HARD_FIX, ZEROFIX, FATAL);
	}

	if (d->check) {
		if (d->bmap[iblk / 32] & (1 << (iblk % 32))) {
			ploop_log(0, "Block %u is used more than once, vsec=%u... ",
				iblk, clu);
			zero_index_fix(d, clu, HARD_FIX, IGNORE, FATAL);
		}
		d->bmap[iblk / 32] |= (1 << (iblk % 32));
	}

	if (iblk > *d->alloc_head)
		*d->alloc_head = iblk;

	return 0;
}

/* Check if *fd is already opened r/w; reopen image if not */
static int reopen_rw(const char *image, int *fd)
{
	int flags, newfd, ret;

	flags = fcntl(*fd, F_GETFL);
	if (flags & O_RDWR)
		return 0;

	ploop_log(3, "Reopen rw %s", image);
	newfd = open(image, O_RDWR);
	if (newfd < 0) {
		ploop_err(errno, "Can't reopen %s", image);
		return SYSEXIT_OPEN;
	}

	ret = close_safe(*fd);
	if (ret) {
		close(newfd);
		return ret;
	}

	*fd = newfd;

	return 0;
}

static int fill_hole(const char *image, int *fd, off_t start, off_t end, int *log, int repair)
{
	static const char buf[0x100000];
	off_t offset;

	if (!*log) {
		int ret;

		ploop_err(0, "%s: ploop image '%s' is sparse",
				repair ? "Warning" : "Error", image);
		if (!repair)
			return SYSEXIT_PLOOPFMT;
		*log = 1;
		print_output(0, "filefrag -vs", image);
		ploop_log(0, "Reallocating sparse blocks back");
		ret = reopen_rw(image, fd);
		if (ret)
			return ret;
	}

	ploop_log(1, "Filling hole at start=%lu len=%lu",
			(long unsigned)start,
			(long unsigned)(end - start));

	for (offset = start; offset < end; offset += sizeof(buf)) {
		ssize_t n, len;

		len = end - offset;
		if (len > sizeof(buf))
			len = sizeof(buf);

		n = pwrite(*fd, buf, len, offset);
		if (n != len) {
			if (n >= 0)
				errno = EIO;
			ploop_err(errno, "Failed to write");
			return SYSEXIT_WRITE;
		}
	}

	return fsync_safe(*fd);
}

static int check_and_repair_sparse(const char *image, int *fd, uint64_t cluster, int flags)
{
	int last;
	int i, ret;
	struct statfs sfs;
	struct stat st;
	uint64_t prev_end;
	char buf[40960] = "";
	struct fiemap *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];
	int log = 0;
	int count = (sizeof(buf) - sizeof(*fiemap)) /
		    sizeof(struct fiemap_extent);
	int repair = flags & CHECK_REPAIR_SPARSE;

	ret = fstatfs(*fd, &sfs);
	if (ret < 0) {
		ploop_err(errno, "Unable to statfs delta file %s", image);
		return SYSEXIT_FSTAT;
	}

	if (sfs.f_type != EXT4_SUPER_MAGIC)
		return 0;

	ret = fstat(*fd, &st);
	if (ret < 0) {
		ploop_err(errno, "Unable to stat delta file %s", image);
		return SYSEXIT_FSTAT;
	}

	prev_end = 0;
	last = 0;

	while (!last && prev_end < st.st_size) {
		fiemap->fm_start	= prev_end;
		fiemap->fm_length	= st.st_size;
		fiemap->fm_flags	= FIEMAP_FLAG_SYNC;
		fiemap->fm_extent_count = count;

		ret = ioctl_device(*fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
		if (ret)
			return ret;

		if (fiemap->fm_mapped_extents == 0)
			break;

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;

			if (fm_ext[i].fe_logical >= st.st_size) {
				last = 1;
				break;
			}

			if ((fm_ext[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) &&
			    (fm_ext[i].fe_logical % cluster ||
					fm_ext[i].fe_length % cluster)) {
				ploop_err(0, "Delta file %s contains uninitialized blocks"
						" (offset=%" PRIu64 "len=%" PRIu64 ")"
						" which are not aligned to cluster size",
						image, (uint64_t)fm_ext[i].fe_logical, (uint64_t)fm_ext[i].fe_length);

				ret = fill_hole(image, fd, fm_ext[i].fe_logical,
						fm_ext[i].fe_logical + fm_ext[i].fe_length, &log, repair);
				if (ret)
					goto out;
			}

			if (fm_ext[i].fe_flags & ~(FIEMAP_EXTENT_LAST |
						   FIEMAP_EXTENT_UNWRITTEN))
				ploop_log(1, "Warning: extent with unexpected flags 0x%x",
									fm_ext[i].fe_flags);
			if (prev_end != fm_ext[i].fe_logical &&
					(ret = fill_hole(image, fd, prev_end, fm_ext[i].fe_logical, &log, repair)))
				goto out;

			prev_end = fm_ext[i].fe_logical + fm_ext[i].fe_length;
		}
	}

	if (prev_end < st.st_size &&
			(ret = fill_hole(image, fd, prev_end, st.st_size, &log, repair)))
		goto out;

	if (log)
		print_output(0, "filefrag -vs", image);

	ret = 0;

out:

	return ret;
}

int ploop_check(char *img, int flags, __u32 *blocksize_p)
{
	struct ploop_check_desc d;
	int i, j;
	int fd;
	int ret = 0;
	int ret2;
	const int ro = (flags & CHECK_READONLY);
	const int verbose = (flags & CHECK_TALKATIVE);
	off_t bd_size;
	struct stat stb;
	void *buf = NULL;
	__u32 *l2_ptr = NULL;

	struct ploop_pvd_header vh_buf;
	struct ploop_pvd_header *vh = &vh_buf;

	__u32 alloc_head;
	__u32 l1_slots;
	__u32 l2_slot = 0;
	__u32 m_Flags;

	__u32 *bmap = NULL;
	unsigned int bmap_size = 0;

	int fatality = 0;   /* fatal errors detected */
	int clean = 1;	    /* image is clean */
	__u64 cluster;

	int force = (flags & CHECK_FORCE);
	int hard_force = (flags & CHECK_HARDFORCE);
	int check = (flags & CHECK_DETAILED);
	int version;

	fd = open(img, O_RDONLY);
	if (fd < 0) {
		ploop_err(errno, "ploop_check: can't open %s", img);
		return SYSEXIT_OPEN;
	}

	if (flags & CHECK_RAW) {
		if (!blocksize_p || !*blocksize_p) {
			ploop_err(0, "Cluster blocksize required for raw image");
			ret = SYSEXIT_PARAM;
			goto done;
		}
		cluster = S2B(*blocksize_p);
		ret = 0;
		goto done;
	}

	if (fstat(fd, &stb)) {
		ploop_err(errno, "ploop_check: can't fstat %s",
				img);
		ret = SYSEXIT_OPEN;
		goto done;
	}

	ret = read_safe(fd, vh, sizeof(*vh), 0, "read PVD header");
	if (ret)
		goto done;

	ret = SYSEXIT_PLOOPFMT;
	version = ploop1_version(vh);
	if (version == PLOOP_FMT_ERROR) {
		ploop_err(0, "Wrong signature in image %s", img);
		goto done;
	}
	if (vh->m_Type != PRL_IMAGE_COMPRESSED) {
		ploop_err(0, "Wrong type in image %s", img);
		goto done;
	}
	if (!is_valid_blocksize(vh->m_Sectors)) {
		ploop_err(0, "Wrong cluster size %d in image %s",
				vh->m_Sectors, img);
		goto done;
	}

	l1_slots = vh->m_FirstBlockOffset >> (ffs(vh->m_Sectors) - 1);
	if (vh->m_FirstBlockOffset % vh->m_Sectors != 0 || l1_slots == 0) {
		ploop_err(0, "Wrong first block offset in image %s", img);
		goto done;
	}
	if (blocksize_p != NULL)
		*blocksize_p = vh->m_Sectors;
	cluster = S2B(vh->m_Sectors);
	if (p_memalign(&buf, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto done;
	}
	l2_ptr = (__u32*)buf;

	ret = 0;
	bd_size = get_SizeInSectors(vh);
	alloc_head = l1_slots - 1;

	if (!vh->m_DiskInUse && !force) {
		if (verbose)
			ploop_log(0, "Image is clean, check is skipped");
		goto done;
	}

	if (vh->m_DiskInUse && (vh->m_Flags & CIF_FmtVersionConvert)) {
		ploop_err(0, "Image %s is in the changing version state",
				img);
		ret = SYSEXIT_EBUSY;
		goto done;
	}

	if (check) {
		bmap_size = (stb.st_size + cluster - 1)/(cluster);
		bmap_size = (bmap_size + 31)/8;
		bmap = malloc(bmap_size);
		if (bmap == NULL) {
			ploop_err(ENOMEM, "ploop_check: malloc");
			if (verbose) {
				check = 0;
			} else {
				ret = SYSEXIT_MALLOC;
				goto done;
			}
		}
		if (check) {
			memset(bmap, 0, bmap_size);
			for (i = 0; i < l1_slots; i++)
				bmap[i / 32] |= 1 << (i % 32);
		}
	}

	if (!ro) {
		ret = reopen_rw(img, &fd);
		if (ret)
			goto done;
	}

	/* in */
	d.fd	     = fd;
	d.ro	     = ro;
	d.hard_force = hard_force;
	d.check	     = check;
	d.bd_size    = bd_size;
	d.size	     = stb.st_size;
	/* out */
	d.bmap	     = bmap;
	d.clean	     = &clean;
	d.fatality   = &fatality;
	d.alloc_head = &alloc_head;

	for (i = 0; i < l1_slots; i++) {
		int skip = (i == 0) ? sizeof(*vh) / sizeof(__u32) : 0;

		ret = read_safe(fd, buf, cluster, i * cluster,
			   "read index table");
		if (ret)
			goto done;

		if (!ro && vh->m_DiskInUse) {
			ret = write_safe(fd, buf, cluster, i * cluster,
				    "re-write index table");
			if (ret)
				goto done;
		}

		for (j = skip; j < cluster/4; j++, l2_slot++) {
			if (l2_ptr[j] == 0)
				continue;

			ret = check_one_slot(&d, l2_slot,
					ploop_ioff_to_sec(l2_ptr[j], vh->m_Sectors, version),
					vh->m_Sectors, version);
			if (ret)
				goto done;
		}
	}

	alloc_head++;

	if (check) {
		for (i = 0; i < bmap_size/4; i++) {
			int k;

			if (bmap[i] == 0xFFFFFFFF)
				continue;

			if (i * 32 >= alloc_head)
				break;

			for (k = 0; k < 32 && k < alloc_head - i * 32; k++) {
				if (!(bmap[i] & (1 << k))) {
					ploop_log(0, "Hole at block %u", i*32 + k);
				}
			}
		}
	}

	if (fatality) {
		ploop_err(0, "Fatal errors were found, image %s is not repaired", img);
		ret = SYSEXIT_PLOOPFMT;
		goto done;
	}

	if ((off_t)alloc_head * cluster < stb.st_size) {
		if (!ro) {
			ploop_log(0, "Trimming tail");
			if (ftruncate(fd, (off_t)alloc_head * cluster)) {
				ploop_err(errno, "ftruncate");
				ret = SYSEXIT_FTRUNCATE;
				goto done;
			}
		} else {
			ploop_err(0, "Want to trim tail");
			alloc_head = (stb.st_size + cluster - 1)/(cluster);
		}
	}

	if (alloc_head > l1_slots)
		m_Flags = vh->m_Flags & ~CIF_Empty;
	else
		m_Flags = vh->m_Flags | CIF_Empty;

	if (vh->m_DiskInUse != 0) {
		ploop_err(0, "Dirty flag is set");
		if (!(flags & CHECK_DROPINUSE)) {
			ret = SYSEXIT_PLOOPINUSE;
			goto done;
		}
	}
	if (vh->m_Flags != m_Flags)
		ploop_err(0, "CIF_Empty flag is incorrect");

	/* useless to repair header if content was not fixed */
	if (!clean) {
		ret = SYSEXIT_PLOOPFMT;
		goto done;
	}

	/* the content is clean, only header checks remained */
	if (vh->m_DiskInUse == 0 && vh->m_Flags == m_Flags)
		goto done;

	/* header needs fix but we can't */
	if (ro) {
		ploop_err(0, "Image is clean but unable to fix the header on ro image");
		ret = SYSEXIT_WRITE;
		goto done;
	}

	vh->m_DiskInUse = 0;
	vh->m_Flags = m_Flags;

	ret = write_safe(fd, vh, sizeof(*vh), 0, "write PVD header");
	if (!ret)
		ret = fsync_safe(fd);
done:
	if (ret == 0)
		ret = check_and_repair_sparse(img, &fd, cluster, flags);

	ret2 = close_safe(fd);
	if (ret2 && !ret)
		ret = ret2;

	free(bmap);
	free(buf);

	return ret;
}

int check_deltas(struct ploop_disk_images_data *di, char **images,
		int raw, __u32 *blocksize)
{
	int i;
	int ret = 0;

	for (i = 0; images[i] != NULL; i++) {
		int raw_delta = (raw && i == 0);
		int ro = (images[i+1] != NULL);
		int flags = CHECK_DETAILED |
			(di ? (CHECK_DROPINUSE | CHECK_REPAIR_SPARSE) : 0) |
			(ro ? CHECK_READONLY : 0) |
			(raw_delta ? CHECK_RAW : 0);
		__u32 cur_blocksize = raw_delta ? *blocksize : 0;

		ret = ploop_check(images[i], flags, &cur_blocksize);
		if (ret) {
			ploop_err(0, "%s : irrecoverable errors (%s)",
					images[i], ro ? "ro" : "rw");
			break;
		}
		if (*blocksize == 0)
			*blocksize = cur_blocksize;
		if (cur_blocksize != *blocksize) {
			ploop_err(0, "Incorrect blocksize %s bs=%d [current bs=%d]",
					images[i], *blocksize, cur_blocksize);
			ret = SYSEXIT_PARAM;
			break;
		}
	}

	return ret;
}

int check_dd(struct ploop_disk_images_data *di, const char *uuid)
{
	char **images;
	__u32 blocksize;
	int raw;
	int ret;
	char **devices;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = ploop_get_devs(di, &devices);
	if (ret == 0) {
		ploop_err(0, "Can't check, in use by device: %s", devices[0]);
		ploop_free_array(devices);
		return SYSEXIT_PLOOPINUSE;
	}
	else if (ret == -1)
		/* Some system error */
		return SYSEXIT_SYS;

	images = make_images_list(di, (uuid) ? uuid : di->top_guid, 0);
	if (!images) {
		/* this might fail for a number of reasons, so
		 * let's return something more or less generic.
		 */
		ret = SYSEXIT_DISKDESCR;
		goto out;
	}

	blocksize = di->blocksize;
	raw = (di->mode == PLOOP_RAW_MODE);

	ret = check_deltas(di, images, raw, &blocksize);

	ploop_free_array(images);
out:
	ploop_unlock_dd(di);

	return ret;
}

int check_deltas_same(const char *img1, const char *img2) {
	int i, ret;
	int fd[2] = { -1, -1 };
	struct ploop_pvd_header vh[2];
	struct stat st[2];
	const char *img[2] = { img1, img2 };

	for (i = 0; i < 2; i++) {
		fd[i] = open(img[i], O_RDONLY);
		if (fd[i] < 0) {
			ploop_err(errno, "Can't open %s", img[i]);
			ret = SYSEXIT_OPEN;
			goto done;
		}

		if (fstat(fd[i], &st[i]) < 0) {
			ploop_err(errno, "Can't fstat %s", img[i]);
			ret = SYSEXIT_FSTAT;
			goto done;
		}

		ret = read_safe(fd[i], &vh[i], sizeof(vh[i]), 0,
				"read PVD header");
		if (ret)
			goto done;
		/* clear "in use" flag since it might be different */
		vh[i].m_DiskInUse = 0;
	}

	ret = SYSEXIT_PLOOPFMT;

	if (st[0].st_size != st[1].st_size) {
		ploop_err(0, "Images %s and %s are of different size",
				img[0], img[1]);
		goto done;
	}

	if (memcmp(&vh[0], &vh[1], sizeof(vh[0])) != 0) {
		ploop_err(0, "Images %s and %s are not identical",
				img[0], img[1]);
		goto done;
	}

	ret = 0;
done:
	for (i = 0; i < 2; i++)
		if (fd[i] >= 0)
			close(fd[i]);

	return ret;
}
