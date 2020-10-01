/*
 *  Copyright (c) 2008-2017 Parallels International GmbH.
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
#include <sys/param.h>
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

int fsync_safe(int fd)
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

static int fill_hole(const char *image, int *fd, off_t start, off_t end,
		struct delta *delta, __u32 *rmap, __u32 rmap_size, int *log, int repair)
{
	int ret;
	static const char buf[0x100000];
	off_t offset, len, n;
	__u32 cluster = delta ? S2B(delta->blocksize) : sizeof(buf);
	off_t data_offset = delta ? delta->l1_size * cluster : 0;

	for (len = 0, offset = start; offset < end; offset += len) {
		ssize_t e = (offset + cluster) / cluster * cluster;
		__u32 id = offset / cluster ;

		len = MIN(e - offset, end - offset);
		if (rmap) {
			if (id >= rmap_size)
				continue;
			if (offset > data_offset && rmap[id] == PLOOP_ZERO_INDEX)
				continue;
		}

		if (!*log) {
			ploop_err(0, "%s: ploop image '%s' is sparse",
					repair ? "Warning" : "Error", image);
			*log = 1;
			print_output(0, "filefrag -vs", image);
			ploop_log(0, "Reallocating sparse blocks back");
			ret = reopen_rw(image, fd);
			if (ret)
				return ret;
		}

		if (rmap)
			ploop_log(0, "Filling hole at start=%lu len=%lu rmap[%u]=%u",
				(long unsigned)offset, (long unsigned)len, id, rmap[id]);
		else
			ploop_log(0, "Filling hole at start=%lu len=%lu",
				(long unsigned)offset, (long unsigned)len);

		if (!repair)
			return SYSEXIT_PLOOPFMT;

		n = pwrite(*fd, buf, len, offset);
		if (n != len) {
			if (n >= 0)
				errno = EIO;
			ploop_err(errno, "Failed to write offset=%lu len=%lu",
					offset, len);
			return SYSEXIT_WRITE;
		}
	}

	return 0;
}

static int restore_hole(const char *image, int *fd, off_t start,
		off_t end, struct delta *delta,
		__u32 *rmap, __u32 rmap_size,
		 int *log, int repair)
{
	int ret;
	off_t offset, len;
	uint64_t cluster = S2B(delta->blocksize);
	off_t data_offset = delta->l1_size * cluster;

	for (len = 0, offset = start; offset < end; offset += len) {
		ssize_t e = (offset + cluster) / cluster * cluster;

		len = MIN(e - offset, end - offset);
		__u32 id = offset / cluster ;
		if (id >= rmap_size)
			continue;
		if (offset > data_offset && rmap[id] == PLOOP_ZERO_INDEX) {
			ploop_log(0, "Restore the hole at offset=%lu len=%lu ID=%d",
					offset, len, id);
			if (*log == 0) {
				*log = 1;
				print_output(0, "filefrag -vs", image);
				ret = reopen_rw(image, fd);
				if (ret)
					return ret;
			}
			if (!repair)
				return SYSEXIT_PLOOPFMT;

			if (fallocate(*fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, offset, len) == -1 ) {
				ploop_err(errno, "Failed to fallocate offset=%lu len=%lu",
						offset, len);
				return SYSEXIT_WRITE;
			}
		}
	}

	return 0;
}

static int check_and_repair(const char *image, int *fd, __u64 cluster, int flags)
{
	int last;
	int i, ret;
	struct statfs sfs;
	uint64_t prev_end;
	off_t end = 0;
	char buf[40960] = "";
	struct fiemap *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];
	int log = 0;
	int count = (sizeof(buf) - sizeof(*fiemap)) /
		    sizeof(struct fiemap_extent);
	int repair = flags & CHECK_REPAIR_SPARSE;
	struct delta delta = {.fd = -1};
	struct delta *delta_p = NULL;
	__u32 *rmap = NULL, rmap_size = 0;

	return 0;

	ret = fstatfs(*fd, &sfs);
	if (ret < 0) {
		ploop_err(errno, "Unable to statfs delta file %s", image);
		return SYSEXIT_FSTAT;
	}

	if (sfs.f_type != EXT4_SUPER_MAGIC)
		return 0;

	if (!(flags & CHECK_RAW)) {
		__u32 max = 0;

		if (open_delta(&delta, image, O_RDWR, OD_ALLOW_DIRTY))
			return SYSEXIT_OPEN;

		if (flags & CHECK_DEFRAG) {
			ret = image_defrag(&delta);
			goto out;
		}

		rmap_size = delta.l2_size + delta.l1_size;
		if (delta.alloc_head > rmap_size) {
			if (delta.alloc_head > rmap_size * 2) {
				ploop_err(0, "Image %s size %d blocks exceeds device size %d blocks",
					image, delta.alloc_head, rmap_size);
				ret = SYSEXIT_PARAM;
				goto out;
			}
			rmap_size = delta.alloc_head;
		}
		rmap = alloc_reverse_map(rmap_size);
		if (rmap == NULL) {
			ret = SYSEXIT_MALLOC;
			goto out;
		}

		ret = range_build_rmap(1, rmap_size,
				rmap, rmap_size, &delta, NULL, &max);
		if (ret)
			goto out;
		rmap_size = max + 1;
		cluster = S2B(delta.blocksize);
		delta_p = &delta;
		end = cluster * (max + 1);
	} else {
		struct stat st;

		if (fstat(*fd, &st)) {
			ploop_err(errno, "Can not stat %s", image);
			return SYSEXIT_FSTAT;
		}
		end = st.st_size;
	}

	if (!repair)
		goto out;

	prev_end = 0;
	last = 0;
	while (!last && prev_end < end) {
		fiemap->fm_start	= prev_end;
		fiemap->fm_length	= end;
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

			if (fm_ext[i].fe_logical >= end) {
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
						fm_ext[i].fe_logical + fm_ext[i].fe_length,
						delta_p, rmap, rmap_size, &log, repair);
				if (ret)
					goto out;
			}

			if (fm_ext[i].fe_flags & ~(FIEMAP_EXTENT_LAST |
						   FIEMAP_EXTENT_UNWRITTEN))
				ploop_log(1, "Warning: extent with unexpected flags 0x%x",
									fm_ext[i].fe_flags);
			if (prev_end != fm_ext[i].fe_logical &&
					(ret = fill_hole(image, fd, prev_end, fm_ext[i].fe_logical,
							 delta_p, rmap, rmap_size, &log, repair)))
				goto out;

			if (!(flags & CHECK_READONLY) && rmap != NULL) {
				ret = restore_hole(image, fd, fm_ext[i].fe_logical, fm_ext[i].fe_logical + fm_ext[i].fe_length,
					delta_p, rmap, rmap_size, &log, repair);
				if (ret)
					goto out;
			}
		
			prev_end = fm_ext[i].fe_logical + fm_ext[i].fe_length;
		}
	}

	if (prev_end < end &&
			(ret = fill_hole(image, fd, prev_end, end, delta_p, rmap, rmap_size,  &log, repair)))
		goto out;

	if (log)
		print_output(0, "filefrag -vs", image);

	ret = 0;

out:
	close_delta(&delta);
	free(rmap);

	return ret;
}

int ploop_check(const char *img, int flags, __u32 *blocksize_p, int *cbt_allowed)
{
	struct ploop_check_desc d;
	int i, j;
	int fd;
	int ret = 0;
	int ret2;
	const int ro = flags & (CHECK_READONLY|CHECK_LIVE);
	const int verbose = (flags & CHECK_TALKATIVE);
	off_t bd_size;
	struct stat stb;
	void *buf = NULL;
	__u32 *l2_ptr = NULL;
	struct ploop_pvd_header *vh = NULL;

	__u32 alloc_head;
	__u32 l1_slots;
	__u32 l2_slot = 0;

	__u32 *bmap = NULL;
	unsigned int bmap_size = 0;

	int fatality = 0;   /* fatal errors detected */
	int clean = 1;	    /* image is clean */
	__u64 cluster;

	int force = flags & (CHECK_FORCE|CHECK_LIVE);
	int hard_force = (flags & CHECK_HARDFORCE);
	int check = flags & (CHECK_DETAILED|CHECK_LIVE);
	int live = (flags & CHECK_LIVE);
	int version;
	int disk_in_use;

	fd = open(img, O_RDONLY|O_DIRECT|O_CLOEXEC);
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

	if (p_memalign((void *)&vh, 4096, 4096)) {
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	ret = read_safe(fd, vh, 4096, 0, "read PVD header");
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

	/* 0 for old format */
	disk_in_use = vh->m_DiskInUse == SIGNATURE_DISK_IN_USE;
	if (cbt_allowed != NULL)
		*cbt_allowed = !disk_in_use;

	if (!disk_in_use && !force) {
		if (verbose)
			ploop_log(0, "Image is clean, check is skipped");
		goto done;
	}

	if (disk_in_use && (vh->m_Flags & CIF_FmtVersionConvert)) {
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

	if (fatality) {
		ploop_err(0, "Fatal errors were found, image %s is not repaired", img);
		ret = SYSEXIT_PLOOPFMT;
		goto done;
	}

	if (live)
		goto done;

	if (disk_in_use && (off_t)alloc_head * cluster < stb.st_size) {
		if (!ro) {
			ploop_log(0, "Max cluster: %d (image size %lu) trimming tail",
					alloc_head, stb.st_size);
			if (ftruncate(fd, (off_t)alloc_head * cluster)) {
				ploop_err(errno, "ftruncate");
				ret = SYSEXIT_FTRUNCATE;
				goto done;
			}
		} else {
			ploop_err(0, "Want to trim tail");
		}
	}

	if (disk_in_use != 0) {
		ploop_err(0, "Dirty flag is set");
		if (!(flags & CHECK_DROPINUSE)) {
			ret = SYSEXIT_PLOOPINUSE;
			goto done;
		}
	}

	/* useless to repair header if content was not fixed */
	if (!clean) {
		ret = SYSEXIT_PLOOPFMT;
		goto done;
	}

	/* the content is clean, only header checks remained */
	if (disk_in_use == 0)
		goto done;

	/* header needs fix but we can't */
	if (ro) {
		if (!(flags & CHECK_DROPINUSE)) {
			ploop_err(0, "Image is clean but unable to fix the header on ro image");
			ret = SYSEXIT_WRITE;
			goto done;
		}
		ret = reopen_rw(img, &fd);
		if (ret)
			goto done;
	}

	vh->m_DiskInUse = 0;
	vh->m_Flags = 0;
	vh->m_FormatExtensionOffset = 0;

	ret = write_safe(fd, vh, sizeof(*vh), 0, "write PVD header");
	if (!ret)
		ret = fsync_safe(fd);
done:
	if (ret == 0)
		ret = check_and_repair(img, &fd, cluster, flags);

	ret2 = close_safe(fd);
	if (ret2 && !ret)
		ret = ret2;

	free(bmap);
	free(buf);
	free(vh);

	return ret;
}

int check_deltas(struct ploop_disk_images_data *di, char **images,
		int raw, __u32 *blocksize, int *cbt_allowed, int flags)
{
	int i, f;
	int ret = 0;

	if (cbt_allowed != NULL)
		*cbt_allowed = 1;

	f = flags | CHECK_DETAILED | CHECK_REPAIR_SPARSE |
		(di ? CHECK_DROPINUSE : 0);

	for (i = 0; images[i] != NULL; i++) {
		int raw_delta = (raw && i == 0);
		int ro = (images[i+1] != NULL);
		int delta_cbt_allowed;
		__u32 cur_blocksize = raw_delta ? *blocksize : 0;

		if (!(flags & CHECK_READONLY)) {
			if (ro)
				f |= CHECK_READONLY;
			else
				f &= ~CHECK_READONLY;
		}
		if (raw_delta)
			f |= CHECK_RAW;
		else
			f &= ~CHECK_RAW;

		ret = ploop_check(images[i], f, &cur_blocksize,
				&delta_cbt_allowed);
		if (ret) {
			ploop_err(0, "%s : irrecoverable errors (%s)",
					images[i], ro ? "ro" : "rw");
			break;
		}

		if (cbt_allowed != NULL && !delta_cbt_allowed)
			*cbt_allowed = 0;

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

int check_deltas_live(struct ploop_disk_images_data *di)
{
	char **images;
	__u32 blocksize;
	int raw, ret;

	if (di == NULL)
		return 0;

	images = make_images_list(di, di->top_guid, 0);
	if (!images)
		return SYSEXIT_DISKDESCR;

	blocksize = di->blocksize;
	raw = (di->mode == PLOOP_RAW_MODE);

	ret = check_deltas(di, images, raw, &blocksize, NULL, CHECK_LIVE);

	ploop_free_array(images);

	return ret;
}

int check_dd(struct ploop_disk_images_data *di, const char *uuid,
		int flags)
{
	char **images;
	__u32 blocksize;
	int raw;
	int ret;
	char **devices = NULL;

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

	ret = check_deltas(di, images, raw, &blocksize, NULL, flags);

	ploop_free_array(images);
out:
	ploop_unlock_dd(di);

	return ret;
}
