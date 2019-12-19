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

	ploop_log(0, "Reallocate cluster %d data from %u/off: %lu to %u/off: %lu",
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

static int do_defrag(struct delta *delta,
		__u32 *idx_map, int idx_map_size, 
		__u64 *hole_bitmap, int hole_bitmap_size,
		int nr_clusters)

{
	unsigned int i, rc, dst = 0, n = 0;

	ploop_log(3, "cluster defragmentation: total: %d allocated: %d",
			idx_map_size, nr_clusters);
	for (i = 0; i < idx_map_size; i++) {
		if (idx_map[i] == 0)
			continue;
		if (idx_map[i] < hole_bitmap_size)
			continue;
		if (idx_map[i] < nr_clusters)
			continue;
		dst = BitFindNextSet64(hole_bitmap, hole_bitmap_size, dst);
		if (dst == -1)
			break;
		if (dst > idx_map[i]) 
			continue;
		rc = reallocate_cluster(delta, i, idx_map[i], dst);
		if (rc)
			return rc;
		
		dst++;
		n++;
	}

	ploop_log(n ? 0 : 3, "%d cluster reallocated", n);

	return 0;
}

static int build_idx_map(struct delta *delta,
		__u32 *idx_map, __u32 idx_map_size, 
		__u64 *hole_bitmap, __u32 hole_bitmap_size)
{
	int log, nr_clu_in_bat, nr_clusters = 0;
	__u32 clu, cluster;
	struct ploop_pvd_header *hdr = (struct ploop_pvd_header *) delta->hdr0;

	nr_clu_in_bat = hdr->m_FirstBlockOffset / hdr->m_Sectors;
	log = ploop_fmt_log(delta->version);
	cluster = S2B(delta->blocksize);

	for (clu = 0; clu < nr_clu_in_bat; clu++)
		BMAP_CLR(hole_bitmap, clu);

	for (clu = 0; clu < hdr->m_Size; clu++) {
		int l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		if (delta->l2_cache != l2_cluster) {
			if (PREAD(delta, delta->l2, cluster, (off_t)l2_cluster * cluster))
				return -1;
			delta->l2_cache = l2_cluster;
		}

		idx_map[clu] = delta->l2[l2_slot] >> log; 
		if (idx_map[clu]) {
			if (idx_map[clu] < hole_bitmap_size)
				BMAP_CLR(hole_bitmap, idx_map[clu]);
			else
				ploop_log(0, "Cluster %d[%d] allocated outside devce %d",
					clu, idx_map[clu], hole_bitmap_size);

			nr_clusters++;
		}
	}

	return nr_clusters;
}

int image_defrag(struct delta *delta)
{
	int rc = 0, nr_clusters;
	__u32 nr_clu_in_bat, hole_bitmap_size, *idx_map;
	__u64 *hole_bitmap, size;
	struct ploop_pvd_header *hdr = (struct ploop_pvd_header *) delta->hdr0;

	if (delta->version == PLOOP_FMT_V1)
		return 0;

	idx_map = calloc(hdr->m_Size, sizeof(__u32));
	if (idx_map == NULL)
		return SYSEXIT_MALLOC;

	nr_clu_in_bat = hdr->m_FirstBlockOffset / hdr->m_Sectors;
	hole_bitmap_size = hdr->m_Size + nr_clu_in_bat;
	size = (hole_bitmap_size + 7) / 8; /* round up byte */
	size = (size + sizeof(unsigned long)-1) & ~(sizeof(unsigned long)-1);
	if (p_memalign((void *)&hole_bitmap, sizeof(__u64), size)) {
		free(idx_map);
		return SYSEXIT_MALLOC;
	}
	memset(hole_bitmap, 0xff, size);

	nr_clusters = build_idx_map(delta, idx_map, hdr->m_Size,
			hole_bitmap, hole_bitmap_size);
	if (nr_clusters == -1) {
		rc = SYSEXIT_READ;
		goto err;
	} else if (nr_clusters == 0)
		goto err;
	

	rc = do_defrag(delta, idx_map, hdr->m_Size,
                        hole_bitmap, hole_bitmap_size, nr_clusters);

err:
	free(idx_map);
	free(hole_bitmap);

	return rc;
}
