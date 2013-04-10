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
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>

#include "ploop.h"

int init_delta_array(struct delta_array * p)
{
	p->delta_max = 0;
	p->delta_arr = NULL;
	p->data_cache_cluster = -1;
	p->raw_fd = -1;
	p->bd_size = 0;
	return 0;
}

void deinit_delta_array(struct delta_array * p)
{
	int i;

	for (i = 0; i < p->delta_max; i++)
		close_delta(&p->delta_arr[i]);
	if (p->raw_fd != -1)
		close(p->raw_fd);
	free(p->delta_arr);
}

int extend_delta_array(struct delta_array * p, char * path, int rw, int od_flags)
{
	struct delta * da;

	da = realloc(p->delta_arr, (p->delta_max + 1)*sizeof(struct delta));
	if (da == NULL) {
		ploop_err(errno, "realloc");
		return SYSEXIT_NOMEM;
	}
	p->delta_arr = da;

	if (open_delta(&da[p->delta_max], path, rw, od_flags))
		return SYSEXIT_OPEN;
	p->delta_max++;

	return 0;
}

static int local_delta_open(char *pathname, int flags, mode_t mode)
{
	return open(pathname, flags, mode);
}
static int local_delta_close(int fd)
{
	return close(fd);
}
static int local_delta_pread(int fd, void *buf, size_t count, off_t offset)
{
	return pread(fd, buf, count, offset);
}
static int local_delta_pwrite(int fd, void *buf, size_t count, off_t offset)
{
	return pwrite(fd, buf, count, offset);
}
static int local_delta_fstat(int fd, struct stat *buf)
{
	return fstat(fd, buf);
}
static int local_delta_fsync(int fd)
{
	return fsync(fd);
}
static struct delta_fops local_delta_fops = {
	.open = local_delta_open,
	.close = local_delta_close,
	.pread = local_delta_pread,
	.pwrite = local_delta_pwrite,
	.fstat = local_delta_fstat,
	.fsync = local_delta_fsync,
};

void close_delta(struct delta *delta)
{
	int err = errno;

	free(delta->hdr0);
	delta->hdr0 = NULL;
	free(delta->l2);
	delta->l2 = NULL;
	if (delta->fops != NULL)
		delta->fops->close(delta->fd);
	delta->fops = NULL;
	delta->fd = -1;
	errno = err;
}

int open_delta_simple(struct delta * delta, const char * path, int rw, int od_flags)
{
	delta->fops = &local_delta_fops;

	delta->hdr0 = NULL;
	delta->l2 = NULL;

	ploop_log(0, "Opening delta %s", path);
	delta->fd = delta->fops->open((char *)path, rw, 0600);
	if (delta->fd < 0) {
		ploop_err(errno, "open %s", path);
		return -1;
	}

	return 0;
}

int open_delta(struct delta * delta, const char * path, int rw, int od_flags)
{
	struct ploop_pvd_header *vh;
	void *p;
	ssize_t res;
	struct stat stat;
	int rc;
	__u64 cluster;
	int err;

	rc = open_delta_simple(delta, path, rw, od_flags);
	if (rc != 0)
		return -1;

	rc = delta->fops->fstat(delta->fd, &stat);
	if (rc != 0) {
		ploop_err(errno, "stat %s", path);
		close_delta(delta);
		return -1;
	}

	delta->l1_dirty = 0;
	delta->l2_dirty = 0;
	delta->l2_cache = -1;
	delta->dirtied = 0;

	if (p_memalign(&p, 4096, SECTOR_SIZE)) {
		close_delta(delta);
		return -1;
	}
	vh = p;

	res = delta->fops->pread(delta->fd, vh, SECTOR_SIZE, 0);
	if (res != SECTOR_SIZE) {
		err = (res >= 0) ? EIO : errno;
		ploop_err(errno, "read 1st sector of %s", path);
		goto open_delta_failed;
	}
	delta->blocksize = vh->m_Sectors;
	cluster = S2B(vh->m_Sectors);

	if ((err = p_memalign(&p, 4096, cluster)))
		goto open_delta_failed;
	delta->hdr0 = p;

	if ((err = p_memalign(&p, 4096, cluster)))
		goto open_delta_failed;
	delta->l2 = p;

	res = delta->fops->pread(delta->fd, delta->hdr0, cluster, 0);
	if (res != cluster) {
		err = (res >= 0) ? EIO : errno;
		ploop_err(errno, "read %s", path);
		goto open_delta_failed;
	}

	if (memcmp(vh->m_Sig, SIGNATURE_STRUCTURED_DISK, sizeof(vh->m_Sig)) ||
	    vh->m_Type != PRL_IMAGE_COMPRESSED ||
	    !is_valid_blocksize(vh->m_Sectors)) {
		ploop_err(errno, "Invalid image header %s", path);
		err = EINVAL;
		goto open_delta_failed;
	}
	delta->alloc_head = stat.st_size / (vh->m_Sectors * SECTOR_SIZE);

	delta->l1_size = vh->m_FirstBlockOffset / vh->m_Sectors;
	delta->l2_size = vh->m_SizeInSectors / vh->m_Sectors;

	if (vh->m_DiskInUse && !(od_flags & OD_ALLOW_DIRTY)) {
		ploop_err(0, "Image is in use %s", path);
		err = EBUSY;
		goto open_delta_failed;
	}

	free(vh);
	return 0;

open_delta_failed:
	close_delta(delta);
	free(vh);
	errno = err;
	return -1;
}

static int change_delta_state(struct delta * delta, __u32 m_DiskInUse)
{
	ssize_t res;

	res = delta->fops->pwrite(delta->fd, &m_DiskInUse, sizeof(m_DiskInUse),
				  offsetof(struct ploop_pvd_header, m_DiskInUse));
	if (res != sizeof(m_DiskInUse)) {
		if (res >= 0)
			errno = EIO;
		return -1;
	}
	if (delta->fops->fsync(delta->fd))
		return -1;
	return 0;
}

int dirty_delta(struct delta * delta)
{
	int rc = change_delta_state(delta, SIGNATURE_DISK_IN_USE);

	if (!rc)
		delta->dirtied = 2;

	return rc;
}

int clear_delta(struct delta * delta)
{
	int rc = change_delta_state(delta, 0);

	if (!rc)
		delta->dirtied = 0;

	return rc;
}

static int READ(struct delta * delta, void * buf, unsigned int size, off_t pos)
{
	ssize_t res;

	res = delta->fops->pread(delta->fd, buf, size, pos);
	if (res != size) {
		if (res >= 0)
			errno = EIO;
		return -1;
	}
	return 0;
}

static int WRITE(struct delta * delta, void * buf, unsigned int size, off_t pos)
{
	ssize_t res;

	res = delta->fops->pwrite(delta->fd, buf, size, pos);
	if (res != size) {
		if (res >= 0)
			errno = EIO;
		return -1;
	}
	return 0;
}

int read_size_from_image(const char *img_name, int raw, off_t * res)
{
	struct delta delta = {};

	if (!raw) {
		if (open_delta(&delta, img_name, O_RDONLY, OD_NOFLAGS))
			return SYSEXIT_OPEN;

		*res = delta.l2_size * delta.blocksize;
	} else {
		struct stat stat;

		if (open_delta_simple(&delta, img_name, O_RDONLY, OD_NOFLAGS))
			return SYSEXIT_OPEN;

		if(delta.fops->fstat(delta.fd, &stat)) {
			ploop_err(errno, "fstat");
			close_delta(&delta);
			return SYSEXIT_READ;
		}

		*res = (stat.st_size + 512 - 1) / 512;
	}

	close_delta(&delta);
	return 0;
}

/*
 * delta: output delta
 * iblk: iblock number of block to relocate
 * buf: a buffer of S2B(blocksize) bytes
 * map: if not NULL, will be filled with <req_cluster, iblk> of
 *	relocated block
 *
 * Returns 0 if requested block not found in L2 table, otherwise 1.
 *	   -1 on error
 */
static int relocate_block(struct delta *delta, __u32 iblk, void *buf,
			  struct reloc_map *map)
{
	int   l2_cluster = 0;
	__u32 l2_slot = 0;
	__u32 clu = 0;
	__u64 cluster = S2B(delta->blocksize);

	assert(cluster);

	for (clu = 0; clu < delta->l2_size; clu++) {
		int n = cluster / sizeof(__u32);

		l2_cluster = (clu + PLOOP_MAP_OFFSET) / n;
		l2_slot	   = (clu + PLOOP_MAP_OFFSET) % n;

		if (l2_cluster >= delta->l1_size) {
			ploop_err(0, "abort: relocate_block l2_cluster >= delta->l1_size");
			return -1;
		}

		if (delta->l2_cache != l2_cluster) {
			if (READ(delta, delta->l2, cluster,
				 (off_t)l2_cluster * cluster)) {
				ploop_err(errno, "Can't read L2 table");
				return -1;
			}
			delta->l2_cache = l2_cluster;
		}

		if (delta->l2[l2_slot] == iblk * B2S(cluster))
			break;
	}

	if (clu >= delta->l2_size)
		return 0; /* found nothing */

	if (READ(delta, buf, cluster,
				S2B(delta->l2[l2_slot]))) {
		ploop_err(errno, "Can't read block to relocate");
		return -1;
	}

	delta->l2[l2_slot] = delta->alloc_head++ * B2S(cluster);
	if (delta->l2[l2_slot] == 0) {
		ploop_err(0, "relocate_block: delta->l2[l2_slot] == 0");
		return -1;
	}

	if (WRITE(delta, buf, cluster,
				S2B(delta->l2[l2_slot]))) {
		ploop_err(errno, "Can't write relocate block");
		return -1;
	}

	if (delta->fops->fsync(delta->fd)) {
		ploop_err(errno, "fsync");
		return -1;
	}

	if (WRITE(delta, &delta->l2[l2_slot], sizeof(__u32),
		  (off_t)l2_cluster * cluster + l2_slot * sizeof(__u32))) {
		ploop_err(errno, "Can't update L2 table");
		return -1;
	}

	if (map) {
		map->req_cluster = l2_slot - PLOOP_MAP_OFFSET;
		map->iblk = delta->alloc_head - 1;
	}

	return 1;
}

/*
 * odelta: output delta
 * bdsize: requested new block-device size
 * buf: a buffer of blocksize bytes
 * gm: if not NULL, gm->ctl and gm->zblks will be allocated and filled
 */
int grow_delta(struct delta *odelta, off_t bdsize, void *buf,
	       struct grow_maps *gm)
{
	int i, rc;
	struct ploop_pvd_header vh;
	struct ploop_pvd_header *ivh = &vh;
	int i_l1_size, i_l2_size;
	int i_l1_size_sync_alloc = 0;
	int map_idx = 0;
	__u64 cluster = S2B(odelta->blocksize);

	assert(cluster);

	memset(ivh, 0, sizeof(*ivh));
	generate_pvd_header(ivh, bdsize, odelta->blocksize);
	ivh->m_DiskInUse = SIGNATURE_DISK_IN_USE;
	i_l1_size = ivh->m_FirstBlockOffset / ivh->m_Sectors;
	i_l2_size = ivh->m_SizeInSectors / ivh->m_Sectors;

	if (odelta->alloc_head < odelta->l1_size) {
		ploop_err(0, "grow_delta: odelta->alloc_head < odelta->l1_size");
		return -1;
	}

	/* assume that we're called early enough */
	if (odelta->l2_cache >= 0) {
		ploop_err(0, "odelta->l2_cache >= 0");
		return -1;
	}

	if (odelta->alloc_head < i_l1_size) {
		i_l1_size_sync_alloc = i_l1_size - odelta->alloc_head;
		memset(buf, 0, cluster);
		for (i = odelta->alloc_head; i < i_l1_size; i++)
			if (WRITE(odelta, buf, cluster,
				  (off_t)i * cluster)) {
				ploop_err(errno, "Can't append zero block");
				return SYSEXIT_WRITE;
			}

		odelta->alloc_head += i_l1_size_sync_alloc;
	}

	if (gm) {
		int n = i_l1_size - i_l1_size_sync_alloc - odelta->l1_size;
		gm->ctl = malloc(offsetof(struct ploop_index_update_ctl,
					  rmap[n]));
		gm->zblks = malloc(sizeof(__u32) * n);
		if (!gm->ctl || !gm->zblks) {
			ploop_err(errno, "Can't malloc gm");
			return SYSEXIT_MALLOC;
		}
	}

	for (i = odelta->l1_size; i < i_l1_size - i_l1_size_sync_alloc; i++) {
		rc = relocate_block(odelta, i, buf,
				    gm ? &gm->ctl->rmap[map_idx] : NULL);
		if (rc == -1)
			return SYSEXIT_RELOC;

		if (rc && gm) {
			gm->zblks[map_idx] = i;
			map_idx++;
		} else {
			memset(buf, 0, cluster);

			if (odelta->fops->fsync(odelta->fd)) {
				ploop_err(errno, "fsync");
				return SYSEXIT_FSYNC;
			}

			if (WRITE(odelta, buf, cluster,
				  (off_t)i * cluster)) {
				ploop_err(errno, "Can't nullify L2 table");
				return SYSEXIT_WRITE;
			}
		}
	}

	/* all requested blocks are relocated; time to update header */
	if (!gm) {
		struct stat stat;

		if (odelta->fops->fsync(odelta->fd)) {
			ploop_err(errno, "fsync");
			return SYSEXIT_FSYNC;
		}

		if (odelta->fops->fstat(odelta->fd, &stat)) {
			ploop_err(errno, "fstat");
			return SYSEXIT_FSTAT;
		}

		if (stat.st_size / ivh->m_Sectors <= ivh->m_FirstBlockOffset)
			ivh->m_Flags = CIF_Empty;

		if (WRITE(odelta, ivh, sizeof(*ivh), 0)) {
			ploop_err(errno, "Can't write PVD header");
			return SYSEXIT_WRITE;
		}
	} else {
		gm->ctl->n_maps = map_idx;
	}

	odelta->l1_size = i_l1_size;
	odelta->l2_size = i_l2_size;

	return 0;
}

int grow_raw_delta(const char *image, off_t append_size)
{
	struct delta delta = {};
	struct stat stat;
	off_t pos;
	int ret;
	void *buf;
	unsigned long i = 0;

	if (p_memalign(&buf, 4096, DEF_CLUSTER))
		return SYSEXIT_MALLOC;

	memset(buf, 0, DEF_CLUSTER);

	if (open_delta_simple(&delta, image, O_WRONLY, OD_NOFLAGS))
		return SYSEXIT_OPEN;

	if(delta.fops->fstat(delta.fd, &stat)) {
		ploop_err(errno, "fstat");
		close_delta(&delta);
		return SYSEXIT_READ;
	}

	pos = stat.st_size;

	ret = SYSEXIT_WRITE;
	while (append_size > 0) {
		size_t size = (append_size > DEF_CLUSTER) ? DEF_CLUSTER : append_size;

		if (PWRITE(&delta, buf, size, pos))
			goto err;

		append_size -= size;
		pos         += size;

		if ((++i & 0xffUL) == 0)
			usleep(1000);
	}

	if (delta.fops->fsync(delta.fd)) {
		ploop_err(errno, "fsync");
		goto err;
	}
	ret = 0;

	if (pos != stat.st_size && delta.fops->update_size)
		ret = delta.fops->update_size(delta.fd, image);

err:
	close_delta(&delta);
	return ret;
}
