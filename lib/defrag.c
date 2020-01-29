/*
 *  Copyright (c) 2019 Virtuozzo International GmbH. All rights reserved.
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
#include <sys/syscall.h>
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

#include "bit_ops.h"
#include "ploop.h"

static ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
		loff_t *off_out, size_t len, unsigned int flags)
{
	return syscall(__NR_copy_file_range, fd_in, off_in, fd_out,
			off_out, len, flags);
}

static int update_bat(struct delta *delta, __u32 clu, __u32 old, __u32 new)
{
	off_t off = sizeof(struct ploop_pvd_header) + (clu * sizeof(__u32));

	ploop_log(0, "Update BAT cluster: %d off: %lu %d->%d",
			clu, off, old, new);
	new <<= ploop_fmt_log(delta->version);
	return write_safe(delta->fd, &new, sizeof(new), off,
			"Cannot update BAT");
}

static int reallocate_cluster(struct delta *delta, __u32 clu,
		 __u32 src, __u32 dst)
{
	int rc;
	off_t s, d;
	__u32 cluster = S2B(delta->blocksize);
	int len = cluster;

	s = src * cluster;
	d = dst * cluster;

	ploop_log(0, "Reallocate cluster #%d data from %u/off: %lu to %u/off: %lu",
			clu, src, s, dst, d);
	while (len) {
		int r = copy_file_range(delta->fd, &s, delta->fd, &d, len, 0);
		if (r <= 0) {
			ploop_err(errno, "copy_file_range");
			return -1;
		}
		len -= r;
		s += r;
		d += r;
	}

	rc = update_bat(delta, clu, src, dst);
	if (rc)
		return rc;

	return fsync_safe(delta->fd);
}

static int do_defrag(struct delta *delta,__u64 *hole_bitmap,
		int hole_bitmap_size, int nr_clusters)

{
	unsigned int i, rc, dst = 0, n = 0, log;
	__u32 cluster, off;
	struct ploop_pvd_header *hdr = (struct ploop_pvd_header *) delta->hdr0;

	log = ploop_fmt_log(delta->version);
	cluster = S2B(delta->blocksize);

	for (i = 0; i < hdr->m_Size; i++) {
		int l2_cluster = (i + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (i + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		if (delta->l2_cache != l2_cluster) {
			if (PREAD(delta, delta->l2, cluster, (off_t)l2_cluster * cluster))
				return -1;
			delta->l2_cache = l2_cluster;
		}

		off = delta->l2[l2_slot] >> log;
		if (off == 0)
			continue;
		if (off < hole_bitmap_size)
			continue;
		if (off < nr_clusters)
			continue;
		dst = BitFindNextSet64(hole_bitmap, hole_bitmap_size, dst);
		if (dst == -1) {
			ploop_log(0, "No free clusters found");
			break;
		}
		if (dst > off) 
			continue;
		rc = reallocate_cluster(delta, i, off, dst);
		if (rc)
			return rc;
		
		dst++;
		n++;
	}

	if (n)
		ploop_log(0, "cluster defragmentation: total: %d allocated: %d reallocated: %d",
				hdr->m_Size, nr_clusters, n);

	return 0;
}

int build_hole_bitmap(struct delta *delta, __u64 **hole_bitmap,
		__u32 *hole_bitmap_size, int *nr_clusters)
{
	int log, nr_clu_in_bat;
	__u32 clu, cluster, off;
	__u64 size;
	struct ploop_pvd_header *hdr = (struct ploop_pvd_header *) delta->hdr0;

	nr_clu_in_bat = hdr->m_FirstBlockOffset / hdr->m_Sectors;
	*hole_bitmap_size = hdr->m_Size + nr_clu_in_bat;
	size = (*hole_bitmap_size + 7) / 8; /* round up byte */
	size = (size + sizeof(unsigned long)-1) & ~(sizeof(unsigned long)-1);
	if (p_memalign((void *)hole_bitmap, sizeof(__u64), size))
		return SYSEXIT_MALLOC;
	memset(*hole_bitmap, 0xff, size);

	log = ploop_fmt_log(delta->version);
	cluster = S2B(delta->blocksize);

	for (clu = 0; clu < nr_clu_in_bat; clu++)
		BMAP_CLR(*hole_bitmap, clu);

	for (clu = 0; clu < hdr->m_Size; clu++) {
		int l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		if (delta->l2_cache != l2_cluster) {
			if (PREAD(delta, delta->l2, cluster, (off_t)l2_cluster * cluster))
				return SYSEXIT_READ;
			delta->l2_cache = l2_cluster;
		}

		if (delta->l2[l2_slot] == 0)
			continue;

		off = delta->l2[l2_slot] >> log; 
		if (off < *hole_bitmap_size) {
			ploop_log(0, "BAT %d -> %d", clu, off);
			BMAP_CLR(*hole_bitmap, off);
			*nr_clusters += 1;
		} else
			ploop_err(0, "Cluster %d[%d] allocated outside devce %d",
					clu, off, *hole_bitmap_size);
	}
	delta->l2_cache = -1;

	return 0;
}

int image_defrag(struct delta *delta)
{
	int rc = 0, nr_clusters;
	__u32 hole_bitmap_size;
	__u64 *hole_bitmap;

	rc = build_hole_bitmap(delta, &hole_bitmap,
			&hole_bitmap_size, &nr_clusters);
	if (rc || nr_clusters == 0)
		goto err;
	rc = do_defrag(delta, hole_bitmap, hole_bitmap_size, nr_clusters);
err:
	free(hole_bitmap);

	return rc;
}

int ploop_image_defrag(const char *image, int flags)
{
	int rc;
	struct delta d = {};

	rc = open_delta(&d, image, O_RDWR, OD_ALLOW_DIRTY);
	if (rc)
		return rc;

	rc = image_defrag(&d);
	close_delta(&d);

	return rc;
}

int ploop_image_shuffle(const char *image, int nr, int flags)
{
	int rc, nr_clusters, i, n = 0, log;
	__u32 hole_bitmap_size, dst, cluster, off;
	__u64 *hole_bitmap;
	struct delta d = {};
	struct ploop_pvd_header *hdr;
	rc = open_delta(&d, image, O_RDWR, OD_ALLOW_DIRTY);
	if (rc)
		return rc;

	rc = build_hole_bitmap(&d, &hole_bitmap, &hole_bitmap_size, &nr_clusters);
	if (rc || nr_clusters == 0)
		goto err;

	hdr = (struct ploop_pvd_header *) d.hdr0;
	ploop_log(0, "Image %s clusters: %d total: %d",
			image, nr_clusters, hdr->m_Size);
	dst = d.l2_size;
	log = ploop_fmt_log(d.version);
	cluster = S2B(d.blocksize);
	for (i = 0; i < hdr->m_Size; i++) {
		int l2_cluster = (i + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (i + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		if (d.l2_cache != l2_cluster) {
			if (PREAD(&d, d.l2, cluster, (off_t)l2_cluster * cluster))
				return -1;
			d.l2_cache = l2_cluster;
		}

		off = d.l2[l2_slot] >> log;
		if (off == 0)
			continue;
		rc = reallocate_cluster(&d, i, off, ++dst);
		if (rc)
			return rc;
		if (n++ >= nr)
			break;
	}

err:
	free(hole_bitmap);
	close_delta(&d);

	return rc;
}
