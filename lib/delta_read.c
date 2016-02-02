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
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>

#include "ploop.h"

void init_delta_array(struct delta_array * p)
{
	p->delta_max = 0;
	p->delta_arr = NULL;
	p->data_cache_cluster = -1;
	p->raw_fd = -1;
	p->bd_size = 0;
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
		return SYSEXIT_MALLOC;
	}
	p->delta_arr = da;

	if (open_delta(&da[p->delta_max], path, rw, od_flags))
		return SYSEXIT_OPEN;
	p->delta_max++;

	return 0;
}

void close_delta(struct delta *delta)
{
	int err = errno;

	free(delta->hdr0);
	delta->hdr0 = NULL;
	free(delta->l2);
	delta->l2 = NULL;
	close(delta->fd);
	delta->fd = -1;
	errno = err;
}

int open_delta_simple(struct delta * delta, const char * path, int rw, int od_flags)
{
	delta->hdr0 = NULL;
	delta->l2 = NULL;

	ploop_log(0, "Opening delta %s", path);
	delta->fd = open(path, rw, 0600);
	if (delta->fd < 0) {
		ploop_err(errno, "open %s", path);
		return -1;
	}

	return 0;
}

int open_delta(struct delta * delta, const char * path, int rw, int od_flags)
{
	struct ploop_pvd_header *vh = NULL;
	void *p;
	ssize_t res;
	struct stat stat;
	int rc;
	__u64 cluster;
	int err;

	rc = open_delta_simple(delta, path, rw, od_flags);
	if (rc != 0)
		return -1;

	rc = fstat(delta->fd, &stat);
	if (rc != 0) {
		err = errno;
		ploop_err(errno, "stat %s", path);
		goto error;
	}

	delta->l1_dirty = 0;
	delta->l2_dirty = 0;
	delta->l2_cache = -1;
	delta->dirtied = 0;

	if ((err = p_memalign(&p, 4096, 4096)))
		goto error;
	vh = p;
	delta->hdr0 = p;
	/* read header */
	res = pread(delta->fd, delta->hdr0, 4096, 0);
	if (res != 4096) {
		err = (res >= 0) ? EIO : errno;
		ploop_err(errno, "read 1st sector of %s", path);
		goto error;
	}

	delta->version = ploop1_version(vh);
	if (delta->version == PLOOP_FMT_ERROR) {
		ploop_err(errno, "Unknown ploop image version in the header %s",
				path);
		err = EINVAL;
		goto error;
	}

	if (vh->m_Type != PRL_IMAGE_COMPRESSED ||
			!is_valid_blocksize(vh->m_Sectors))
	{
		ploop_err(errno, "Invalid image header %s", path);
		err = EINVAL;
		goto error;
	}

	delta->blocksize = vh->m_Sectors;
	delta->alloc_head = stat.st_size / (vh->m_Sectors * SECTOR_SIZE);
	delta->l1_size = vh->m_FirstBlockOffset / vh->m_Sectors;
	delta->l2_size = get_SizeInSectors(vh) / vh->m_Sectors;

	cluster = S2B(vh->m_Sectors);
	if (p_memalign(&p, 4096, cluster)) {
		err = errno;
		goto error;
	}
	delta->l2 = p;

	if (vh->m_DiskInUse && !(od_flags & OD_ALLOW_DIRTY)) {
		ploop_err(0, "Image is in use %s", path);
		err = EBUSY;
		goto error;
	}

	return 0;

error:
	close_delta(delta);
	errno = err;
	return -1;
}

int change_delta_version(struct delta *delta, int version)
{
	if (PWRITE(delta, ploop1_signature(version),
			sizeof(((struct ploop_pvd_header*) 0)->m_Sig),
			offsetof(struct ploop_pvd_header, m_Sig)))
		return SYSEXIT_WRITE;

	if (fsync(delta->fd)) {
		ploop_err(errno, "fsync");
		return SYSEXIT_FSYNC;
	}
	return 0;
}

int change_delta_flags(struct delta * delta, __u32 flags)
{
	if (PWRITE(delta, &flags, sizeof(flags),
			offsetof(struct ploop_pvd_header, m_Flags)))
		return SYSEXIT_WRITE;

	if (fsync(delta->fd)) {
		ploop_err(errno, "Failed to change delta flags");
		return SYSEXIT_FSYNC;
	}
	return 0;
}

static int change_delta_state(struct delta * delta, __u32 m_DiskInUse)
{
	ssize_t res;

	res = pwrite(delta->fd, &m_DiskInUse, sizeof(m_DiskInUse),
				  offsetof(struct ploop_pvd_header, m_DiskInUse));
	if (res != sizeof(m_DiskInUse)) {
		if (res >= 0)
			errno = EIO;
		return -1;
	}
	if (fsync(delta->fd))
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

	res = pread(delta->fd, buf, size, pos);
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

	res = pwrite(delta->fd, buf, size, pos);
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

		if (fstat(delta.fd, &stat)) {
			ploop_err(errno, "fstat");
			close_delta(&delta);
			return SYSEXIT_READ;
		}

		*res = (stat.st_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
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

		if (delta->l2[l2_slot] == ploop_sec_to_ioff((off_t)iblk * delta->blocksize,
					delta->blocksize, delta->version))
			break;
	}

	if (clu >= delta->l2_size)
		return 0; /* found nothing */

	if (READ(delta, buf, cluster, S2B(ploop_ioff_to_sec(delta->l2[l2_slot],
						delta->blocksize, delta->version)))) {
		ploop_err(errno, "Can't read block to relocate");
		return -1;
	}

	delta->l2[l2_slot] = ploop_sec_to_ioff((off_t)delta->alloc_head++ * delta->blocksize,
			delta->blocksize, delta->version);
	if (delta->l2[l2_slot] == 0) {
		ploop_err(0, "relocate_block: delta->l2[l2_slot] == 0");
		return -1;
	}

	if (WRITE(delta, buf, cluster, S2B(ploop_ioff_to_sec(delta->l2[l2_slot],
						delta->blocksize, delta->version)))) {
		ploop_err(errno, "Can't write relocate block");
		return -1;
	}

	if (fsync(delta->fd)) {
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
	int i_l1_size;
	int i_l1_size_sync_alloc = 0;
	off_t i_l2_size;
	int map_idx = 0;
	__u64 cluster = S2B(odelta->blocksize);

	assert(cluster);

	memset(ivh, 0, sizeof(*ivh));
	generate_pvd_header(ivh, bdsize, odelta->blocksize, odelta->version);
	ivh->m_DiskInUse = SIGNATURE_DISK_IN_USE;
	i_l1_size = ivh->m_FirstBlockOffset / ivh->m_Sectors;
	i_l2_size = get_SizeInSectors(ivh) / ivh->m_Sectors;

	if (odelta->alloc_head < odelta->l1_size) {
		ploop_err(0, "grow_delta: odelta->alloc_head < odelta->l1_size");
		return SYSEXIT_PARAM;
	}

	/* assume that we're called early enough */
	if (odelta->l2_cache >= 0) {
		ploop_err(0, "odelta->l2_cache >= 0");
		return SYSEXIT_PARAM;
	}

	/* Total number of image-blocks in the image file is lesser
	 * than number of image-blocks for new index table. So,
	 * we can simply nullify this gap, no relocation needed for this
	 */
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

			if (fsync(odelta->fd)) {
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

		if (fsync(odelta->fd)) {
			ploop_err(errno, "fsync");
			return SYSEXIT_FSYNC;
		}

		if (fstat(odelta->fd, &stat)) {
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

	if (open_delta_simple(&delta, image, O_WRONLY, OD_NOFLAGS)) {
		ret = SYSEXIT_OPEN;
		goto err1;
	}

	if(fstat(delta.fd, &stat)) {
		ploop_err(errno, "fstat");
		ret = SYSEXIT_READ;
		goto err;
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

	if (fsync(delta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
		goto err;
	}
	ret = 0;

err:
	close_delta(&delta);
err1:
	free(buf);

	return ret;
}

int ploop_grow_raw_delta_offline(const char *image, off_t new_size)
{
	int ret;
	off_t old_size;

	ret = read_size_from_image(image, 1, &old_size);
	if (ret)
		return ret;

	new_size = (new_size + (4096 >> PLOOP1_SECTOR_LOG) - 1) &
				~((4096 >> PLOOP1_SECTOR_LOG) - 1);

	if (new_size == old_size)
		return 0;

	if (new_size < old_size) {
		/* Use truncate(1) for offline truncate of raw delta */
		ploop_err(0, "Error: new size %llu is less than "
				"the old size %llu",
				(unsigned long long)new_size,
				(unsigned long long)old_size);
		return SYSEXIT_PARAM;
	}

	return grow_raw_delta(image, (new_size - old_size) << PLOOP1_SECTOR_LOG);
}

int ploop_grow_delta_offline(const char *image, off_t new_size)
{
	off_t old_size;
	struct ploop_pvd_header *vh;
	struct ploop_pvd_header new_vh = {};
	struct delta delta = {};
	void *buf = NULL;
	int ret = 0;

	if (open_delta(&delta, image, new_size ? O_RDWR : O_RDONLY, OD_OFFLINE))
		return SYSEXIT_OPEN;

	vh = (struct ploop_pvd_header *)delta.hdr0;

	if (check_blockdev_size(new_size, delta.blocksize, delta.version)) {
		ret = SYSEXIT_PARAM;
		goto out;
	}

	old_size = get_SizeInSectors(vh);

	generate_pvd_header(&new_vh, new_size, delta.blocksize, delta.version);
	if (get_SizeInSectors(&new_vh) == old_size)
		goto out;

	if (get_SizeInSectors(&new_vh) < old_size) {
		ploop_err(0, "Error: new size %llu is less than "
				"the old size %llu",
				(unsigned long long)new_size,
				(unsigned long long)old_size);
		ret = SYSEXIT_PARAM;
		goto out;
	}

	if (dirty_delta(&delta)) {
		ploop_err(errno, "Failed to set dirty flag");
		ret = SYSEXIT_WRITE;
		goto out;
	}

	if (p_memalign(&buf, 4096, S2B(delta.blocksize))) {
		ret = SYSEXIT_MALLOC;
		goto out;
	}

	ret = grow_delta(&delta, get_SizeInSectors(&new_vh), buf, NULL);
	if (ret)
		goto out;

	if (clear_delta(&delta)) {
		ploop_err(errno, "Failed to clear dirty flag");
		ret = SYSEXIT_WRITE;
		goto out;
	}

	if (fsync(delta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
		goto out;
	}
	ret = 0;

out:
	close_delta(&delta);
	free(buf);

	return ret;
}
