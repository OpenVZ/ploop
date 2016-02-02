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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#include "ploop.h"

#define MIN(a, b) (a < b ? a : b)

static void range_fix_gaps(struct freemap *freemap, __u32 iblk_start, __u32 iblk_end,
		__u32 n_to_fix, __u32 *rmap);
static int range_split(struct freemap *rangemap, struct freemap *freemap,
		struct relocmap **relocmap_pp);

struct pfiemap *fiemap_alloc(int n)
{
	int len = offsetof(struct pfiemap, extents[n]);
	struct pfiemap *pfiemap = malloc(len);

	if (!pfiemap) {
		ploop_err(errno, "Can't alloc pfiemap");
		return NULL;
	}

	memset(pfiemap, 0, len);
	pfiemap->n_entries_alloced = n;
	return pfiemap;
}

static int fiemap_add_extent(struct pfiemap **pfiemap_pp, __u64 pos, __u64 len)
{
	int i;
	struct pfiemap *pfiemap = *pfiemap_pp;

	// XXX: not optimal - O(N**2) !!!
	for (i = 0; i < pfiemap->n_entries_used; i++)
		if (pfiemap->extents[i].pos + pfiemap->extents[i].len == pos) {
			pfiemap->extents[i].len += len;
			return 0;
		} else if (pos + len == pfiemap->extents[i].pos) {
			pfiemap->extents[i].pos = pos;
			pfiemap->extents[i].len += len;
			return 0;
		}

	if (pfiemap->n_entries_used == pfiemap->n_entries_alloced) {
		i = pfiemap->n_entries_alloced * 2;

		*pfiemap_pp = realloc(*pfiemap_pp, offsetof(struct pfiemap,
							    extents[i]));
		if (!*pfiemap_pp) {
			ploop_err(errno, "Can't realloc pfiemap");
			return(SYSEXIT_MALLOC);
		}

		pfiemap = *pfiemap_pp;
		pfiemap->n_entries_alloced = i;
	}

	i = pfiemap->n_entries_used++;
	pfiemap->extents[i].pos = pos;
	pfiemap->extents[i].len = len;

	return 0;
}

static char fieflags[256];
static char *fl(__u32 fe_flags)
{
	fieflags[0] = 0;

	if (fe_flags & FIEMAP_EXTENT_UNKNOWN)
		strcat(fieflags, "unknown,");
	if (fe_flags & FIEMAP_EXTENT_DELALLOC)
		strcat(fieflags, "delalloc,");
	if (fe_flags & FIEMAP_EXTENT_DATA_ENCRYPTED)
		strcat(fieflags, "encrypted,");
	if (fe_flags & FIEMAP_EXTENT_NOT_ALIGNED)
		strcat(fieflags, "not_aligned,");
	if (fe_flags & FIEMAP_EXTENT_DATA_INLINE)
		strcat(fieflags, "inline,");
	if (fe_flags & FIEMAP_EXTENT_DATA_TAIL)
		strcat(fieflags, "tail_packed,");
	if (fe_flags & FIEMAP_EXTENT_UNWRITTEN)
		strcat(fieflags, "unwritten,");
	if (fe_flags & FIEMAP_EXTENT_MERGED)
		strcat(fieflags, "merged,");
	if (fe_flags & FIEMAP_EXTENT_LAST)
		strcat(fieflags, "last");

	return fieflags;
}

int fiemap_get(int fd, __u64 off, __u64 start, off_t size, struct pfiemap **pfiemap_pp)
{
	int  i;
	int  rc;
	int  n		= 0;
	int  last	= 0;
	char buf[40960] = "";

	struct fiemap	     *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];

	int count = (sizeof(buf) - sizeof(*fiemap)) /
		    sizeof(struct fiemap_extent);

	memset(fiemap, 0, sizeof(struct fiemap));
	fiemap->fm_start = start;

	do {
		fiemap->fm_length	= ~0ULL;
		fiemap->fm_flags	= FIEMAP_FLAG_SYNC;
		fiemap->fm_extent_count = count;

		rc = ioctl_device(fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
		if (rc)
			return rc;

		if (fiemap->fm_mapped_extents == 0)
			break;

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			n++;

			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;

			if (!(fm_ext[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) ||
			    fm_ext[i].fe_flags & ~FIEMAP_EXTENT_UNWRITTEN &
			    ~FIEMAP_EXTENT_LAST) {
				ploop_err(0, "Skipping extent (%llu/%llu"
					"/%llu) with unexpected flags=%s",
					(long long unsigned)fm_ext[i].fe_length,
					(long long unsigned)fm_ext[i].fe_logical,
					(long long unsigned)fm_ext[i].fe_physical,
					fl(fm_ext[i].fe_flags));
				continue;
			}

			if (n == 1 && fm_ext[i].fe_logical < start) {
				fm_ext[i].fe_physical += start - fm_ext[i].fe_logical;
				fm_ext[i].fe_length   -= start - fm_ext[i].fe_logical;
				fm_ext[i].fe_logical   = start;
			}
			if (i < fiemap->fm_mapped_extents - 1 &&
			    fm_ext[i+1].fe_physical == fm_ext[i].fe_physical +
						       fm_ext[i].fe_length) {
				fm_ext[i+1].fe_physical -= fm_ext[i].fe_length;
				fm_ext[i+1].fe_logical	-= fm_ext[i].fe_length;
				fm_ext[i+1].fe_length	+= fm_ext[i].fe_length;
				continue;
			}

			if (fm_ext[i].fe_logical >= size)
				return 0;

			if (fm_ext[i].fe_logical + fm_ext[i].fe_length > size) {
				rc = fiemap_add_extent(pfiemap_pp, fm_ext[i].fe_physical + off,
						  size - fm_ext[i].fe_logical);
				if (rc)
					return rc;
				return 0;
			}

			rc = fiemap_add_extent(pfiemap_pp, fm_ext[i].fe_physical + off,
					  fm_ext[i].fe_length);
			if (rc)
				return rc;
		}

		fiemap->fm_start = (fm_ext[i-1].fe_logical +
				    fm_ext[i-1].fe_length);

	} while (last == 0 && fiemap->fm_start < size);

	return 0;
}

void fiemap_adjust(struct pfiemap *pfiemap, __u32 blocksize)
{
	int i;
	__u64 cluster = S2B(blocksize);

	assert(cluster);

	for(i = 0; i < pfiemap->n_entries_used; i++) {
		__u64 pos;

		pos = (pfiemap->extents[i].pos + cluster - 1) & ~(cluster - 1);
		if (pos >= pfiemap->extents[i].pos + pfiemap->extents[i].len) {
			pfiemap->extents[i].pos = pfiemap->extents[i].len = 0;
			continue;
		}

		pfiemap->extents[i].len -= (pos - pfiemap->extents[i].pos);
		pfiemap->extents[i].pos = pos;

		pfiemap->extents[i].len &= ~(cluster - 1);
		if (pfiemap->extents[i].len == 0) {
			pfiemap->extents[i].pos = 0;
			continue;
		}
	}
}

static int fiemap_extent_process(__u32 clu, __u32 len, __u32 *rmap, __u32 rlen,
				  struct delta *delta)
{
	__u64 cluster = S2B(delta->blocksize);

	assert(cluster);

	while (len > 0) {
		int   l2_cluster;
		__u32 l2_slot;
		__u32 j;
		__u32 last;

		l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		l2_slot	   = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		last	   = MIN(l2_slot + len, cluster / sizeof(__u32));

		if (l2_cluster >= delta->l1_size) {
			ploop_err(0, "abort fiemap_extent_process: l2_cluster >= delta->l1_size");
			return SYSEXIT_ABORT;
		}

		if (delta->l2_cache != l2_cluster) {
			if (PREAD(delta, delta->l2, cluster,
						(off_t)l2_cluster * cluster))
				return SYSEXIT_READ;
			delta->l2_cache = l2_cluster;
		}

		for (j = l2_slot; j < last; j++) {
			__u32 ridx;

			if (!delta->l2[j])
				continue;

			ridx = delta->l2[j] / ploop_sec_to_ioff(delta->blocksize,
							delta->blocksize, delta->version);
			if (ridx >= rlen) {
				ploop_err(0,
					"Image corrupted: L2[%u] == %u (max=%" PRIu64 ")",
					clu + j - l2_slot, delta->l2[j],
					(uint64_t)((rlen - 1) * B2S(cluster)));
				return(SYSEXIT_PLOOPFMT);
			}
			if (ridx < delta->l1_size) {
				ploop_err(0,
					"Image corrupted: L2[%u] == %u (min=%" PRIu64 ")",
					clu + j - l2_slot, delta->l2[j],
					(uint64_t)(delta->l1_size * B2S(cluster)));
				return(SYSEXIT_PLOOPFMT);
			}

			rmap[ridx] = l2_cluster * (cluster / sizeof(__u32)) +
				     j - PLOOP_MAP_OFFSET;
		}

		clu += (last - l2_slot);
		len -= (last - l2_slot);
	}
	return 0;
}

int fiemap_build_rmap(struct pfiemap *pfiemap, __u32 *rmap, __u32 rlen,
		       struct delta *delta)
{
	int i, rc;
	__u64 cluster = S2B(delta->blocksize);

	assert(cluster);

	memset(rmap, 0xff, rlen * sizeof(__u32));
	delta->l2_cache = -1;

	for(i = 0; i < pfiemap->n_entries_used; i++) {
		__u64 clu = pfiemap->extents[i].pos / cluster;
		__u64 len = pfiemap->extents[i].len / cluster;

		if (clu * cluster != pfiemap->extents[i].pos ||
		    len * cluster != pfiemap->extents[i].len ||
		    clu >= (__u32)-1 || len >= (__u32)-1)
		{
			ploop_err(0, "abort");
			return SYSEXIT_ABORT;
		}

		rc = fiemap_extent_process(clu, len, rmap, rlen, delta);
		if (rc)
			return rc;
	}
	return 0;
}

struct freemap *freemap_alloc(int n)
{
	int len = offsetof(struct freemap, extents[n]);
	struct freemap *freemap = malloc(len);

	if (!freemap) {
		ploop_err(errno, "Can't alloc freemap");
		return NULL;
	}

	memset(freemap, 0, len);
	freemap->n_entries_alloced = n;
	return freemap;
}

static int freemap_add_extent(struct freemap **freemap_pp,
			       __u32 clu, __u32 iblk, __u32 len)
{
	int i;
	struct freemap *freemap = *freemap_pp;

	if (freemap->n_entries_used == freemap->n_entries_alloced) {
		i = freemap->n_entries_alloced * 2;

		*freemap_pp = realloc(*freemap_pp, offsetof(struct freemap,
							    extents[i]));
		if (!*freemap_pp) {
			ploop_err(errno, "Can't realloc freemap");
			return SYSEXIT_MALLOC;
		}

		freemap = *freemap_pp;
		freemap->n_entries_alloced = i;
	}

	i = freemap->n_entries_used++;
	freemap->extents[i].clu = clu;
	freemap->extents[i].iblk = iblk;
	freemap->extents[i].len = len;

	return 0;
}

int rmap2freemap(__u32 *rmap, __u32 iblk_start, __u32 iblk_end,
		 struct freemap **freemap_pp, int *entries_used)
{
	__u32 iblk, clu;
	__u32 e_clu  = 0;
	__u32 e_iblk = 0;
	__u32 e_len  = 0;
	int   state  = 0;
	int   ret;

	for (iblk = iblk_start; iblk < iblk_end; iblk++) {
		clu = rmap[iblk];

		if ((clu == PLOOP_ZERO_INDEX && state) ||
		    (clu != PLOOP_ZERO_INDEX && state &&
		     !(iblk == e_iblk + e_len && clu == e_clu + e_len)))
		{
			ret = freemap_add_extent(freemap_pp, e_clu, e_iblk, e_len);
			if (ret)
				return ret;
			e_clu = e_iblk = 0;
			state = 0;
		}

		if (clu == PLOOP_ZERO_INDEX)
			continue;

		if (iblk == e_iblk + e_len && clu == e_clu + e_len) {
			e_len++;
		} else {
			/* new extent */
			e_clu = clu;
			e_iblk = iblk;
			e_len = 1;
			state = 1;
		}
	}

	if (state) {
		ret = freemap_add_extent(freemap_pp, e_clu, e_iblk, e_len);
		if (ret)
			return ret;
	}

	*entries_used = (*freemap_pp)->n_entries_used;
	return 0;
}

int freeblks_alloc(struct ploop_freeblks_ctl **freeblks_pp, int n)
{
	int clear = (*freeblks_pp == NULL) ? 1 : 0;

	*freeblks_pp = realloc(*freeblks_pp,
			       offsetof(struct ploop_freeblks_ctl, extents[n]));
	if (!*freeblks_pp) {
		ploop_err(errno, "Can't alloc freeblks ioc struct");
		return SYSEXIT_MALLOC;
	}

	if (clear)
		memset(*freeblks_pp, 0,
		       offsetof(struct ploop_freeblks_ctl, extents[n]));

	return 0;
}

int freemap2freeblks(struct freemap *freemap,
		int lvl, struct ploop_freeblks_ctl **freeblks_pp, __u32 *total)
{
	struct ploop_freeblks_ctl *freeblks;
	int   i, ret;
	int   n	    = freemap->n_entries_used;

	*total = 0;
	*freeblks_pp = NULL;
	ret = freeblks_alloc(freeblks_pp, n);
	if (ret)
		return ret;
	freeblks = *freeblks_pp;

	for(i = 0; i < n; i++) {
		if (!freemap->extents[i].len) {
			ploop_err(0, "abort: freemap2freeblks !freemap->extents[i].len");
			return SYSEXIT_ABORT;
		}
		freeblks->extents[i].clu = freemap->extents[i].clu;
		freeblks->extents[i].iblk = freemap->extents[i].iblk;
		freeblks->extents[i].len = freemap->extents[i].len;
		*total += freeblks->extents[i].len;
	}

	freeblks->n_extents = n;
	freeblks->level	    = lvl;

	*freeblks_pp = freeblks;
	return 0 ;
}

int freeblks2freemap(struct ploop_freeblks_ctl *freeblks,
		       struct freemap **freemap_pp, __u32 *total)
{
	int   i, ret;
	int   n	    = freeblks->n_extents;

	*total = 0;
	for(i = 0; i < n; i++) {
		if (!freeblks->extents[i].len) {
			ploop_err(0, "abort: freeblks2freemap !freeblks->extents[i].len");
			return SYSEXIT_ABORT;
		}
		ret = freemap_add_extent(freemap_pp,
				   freeblks->extents[i].clu,
				   freeblks->extents[i].iblk,
				   freeblks->extents[i].len);
		if (ret)
			return ret;
		*total += freeblks->extents[i].len;
	}

	return 0;
}

static int range_build_rmap(__u32 iblk_start, __u32 iblk_end,
		       __u32 *rmap, __u32 rlen, struct delta *delta, __u32 *out)
{
	__u32 clu;
	__u32 n_found = 0;
	__u32 n_requested = iblk_end - iblk_start;
	__u64 cluster = S2B(delta->blocksize);

	assert(cluster);

	if (iblk_start >= iblk_end) {
		ploop_err(0, "range_build_rmap: iblk_start >= iblk_end");
		return SYSEXIT_ABORT;
	}

	if (delta->l2_size >= PLOOP_ZERO_INDEX) {
		ploop_err(0, "range_build_rmap: delta->l2_size >= PLOOP_ZERO_INDEX");
		return SYSEXIT_ABORT;
	}

	memset(rmap, 0xff, rlen * sizeof(__u32));
	delta->l2_cache = -1;

	for (clu = 0; clu < delta->l2_size; clu++) {
		int   l2_cluster;
		__u32 l2_slot;
		__u32 ridx;

		l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		l2_slot	   = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));

		if (l2_cluster >= delta->l1_size) {
			ploop_err(0, "range_build_rmap: l2_cluster >= delta->l1_size");
			return SYSEXIT_ABORT;
		}


		if (delta->l2_cache != l2_cluster) {
			if (PREAD(delta, delta->l2, cluster,
			      (off_t)l2_cluster * cluster))
				return SYSEXIT_READ;
			delta->l2_cache = l2_cluster;
		}
		ridx = delta->l2[l2_slot] / ploop_sec_to_ioff(delta->blocksize,
				delta->blocksize, delta->version);
		if (ridx >= rlen) {
			ploop_err(0,
				"Image corrupted: L2[%u] == %u (max=%" PRIu64 ") (2)",
				clu, delta->l2[l2_slot],
				(uint64_t)((rlen - 1) * B2S(cluster)));
			return SYSEXIT_PLOOPFMT;
		}
		if (ridx && ridx < delta->l1_size) {
			ploop_err(0,
				"Image corrupted: L2[%u] == %u (min=%" PRIu64 ") (2)",
				clu, delta->l2[l2_slot],
				(uint64_t)(delta->l1_size * B2S(cluster)));
			return SYSEXIT_PLOOPFMT;
		}

		if (iblk_start <= ridx && ridx < iblk_end) {
			rmap[ridx] = l2_cluster * (cluster / sizeof(__u32)) +
				     l2_slot - PLOOP_MAP_OFFSET;
			n_found++;
			if (n_found >= n_requested)
				break;
		}
	}

	*out = n_found;
	return 0;
}

int range_build(__u32 a_h, __u32 n_free_blocks,
		__u32 *rmap, __u32 rlen,
		struct delta     *delta,
		struct freemap   *freemap,
		struct freemap  **rangemap_pp,
		struct relocmap **relocmap_pp)
{
	int ret;
	__u32 s = a_h - n_free_blocks;
	__u32 n;
	int entries_used;

	ret = range_build_rmap(s, a_h, rmap, rlen, delta, &n);
	if (ret)
		return ret;

	if (n != n_free_blocks)
		range_fix_gaps(freemap, s, a_h, n_free_blocks - n, rmap);

	ret = rmap2freemap(rmap, s, a_h, rangemap_pp, &entries_used);
	if (ret)
		return ret;
	ret = range_split(*rangemap_pp, freemap, relocmap_pp);
	if (ret)
		return ret;

	return 0;
}

static void range_fix_gaps(struct freemap *freemap, __u32 iblk_start, __u32 iblk_end,
		    __u32 n_to_fix, __u32 *rmap)
{
	__u32 ridx;
	int   n = freemap->n_entries_used;
	struct ploop_free_cluster_extent *fext	   = &freemap->extents[0];
	struct ploop_free_cluster_extent *fext_end = &freemap->extents[n];

	for (ridx = iblk_start; ridx < iblk_end; ridx++) {
		if (rmap[ridx] != PLOOP_ZERO_INDEX)
			continue;

		while (fext < fext_end && fext->iblk + fext->len <= ridx)
			fext++;
		if (fext == fext_end)
			return;

		if (fext->iblk <= ridx) {
			rmap[ridx] = fext->clu + (ridx - fext->iblk);
			if(--n_to_fix == 0)
				return;
		}
	}
}

struct relocmap *relocmap_alloc(int n)
{
	int len = offsetof(struct relocmap, extents[n]);
	struct relocmap *relocmap = malloc(len);

	if (!relocmap) {
		ploop_err(errno, "Can't alloc relocmap");
		return NULL;
	}

	memset(relocmap, 0, len);
	relocmap->n_entries_alloced = n;
	return relocmap;
}

static int relocmap_add_extent(struct relocmap **relocmap_pp,
			 __u32 clu, __u32 iblk, __u32 len, __u32 free)
{
	int i;
	struct relocmap *relocmap = *relocmap_pp;

	if (!len)
		return 0;

	if (relocmap->n_entries_used == relocmap->n_entries_alloced) {
		i = relocmap->n_entries_alloced * 2;

		*relocmap_pp = realloc(*relocmap_pp, offsetof(struct relocmap,
							    extents[i]));
		if (!*relocmap_pp) {
			ploop_err(errno, "Can't realloc relocmap");
			return SYSEXIT_MALLOC;
		}

		relocmap = *relocmap_pp;
		relocmap->n_entries_alloced = i;
	}


	i = relocmap->n_entries_used++;
	relocmap->extents[i].clu = clu;
	relocmap->extents[i].iblk = iblk;
	relocmap->extents[i].len = len;
	relocmap->extents[i].free = free;

	return 0;
}

static int range_split(struct freemap *rangemap, struct freemap *freemap,
		 struct relocmap **relocmap_pp)
{
	int i, ret;
	int j = 0; /* index in freemap->extents[] */
	__u32 fi, fl, ri, rl, rc, l;

	for (i = 0; i < rangemap->n_entries_used; i++) {

		ri = rangemap->extents[i].iblk;
		rc = rangemap->extents[i].clu;
		rl = rangemap->extents[i].len;

		while (rl > 0) {
			/* find first free extent intersecting with us */
			while (j < freemap->n_entries_used &&
			       freemap->extents[j].iblk + freemap->extents[j].len <= ri)
				j++;

			if (j >= freemap->n_entries_used) {
				ret = relocmap_add_extent(relocmap_pp, rc, ri, rl, 0);
				if (ret)
					return ret;
				break; /* next iter of main loop */
			}

			/* freemap->extents[j] is valid */
			fi = freemap->extents[j].iblk;
			fl = freemap->extents[j].len;

			if (fi <= ri ) { /* free extent precedes range extent */
				l = MIN(ri + rl, fi + fl) - ri;
				ret = relocmap_add_extent(relocmap_pp, rc, ri, l, 1);
				if (ret)
					return ret;
			} else { /* free extent follows range extent */
				l = MIN(ri + rl, fi) - ri;
				ret = relocmap_add_extent(relocmap_pp, rc, ri, l, 0);
				if (ret)
					return ret;
			}

			ri += l;
			rc  += l;
			rl  -= l;
		}
	}

	if ((*relocmap_pp)->n_entries_used < rangemap->n_entries_used) {
		ploop_err(0, "abort: range_split (*relocmap_pp)->n_entries_used < rangemap->n_entries_used");
		return SYSEXIT_ABORT;
	}

	return 0;
}

int relocmap2relocblks(struct relocmap *relocmap, int lvl, __u32 a_h, __u32 n_scanned,
			struct ploop_relocblks_ctl **relocblks_pp)
{
	struct ploop_relocblks_ctl *relocblks;
	int i;
	int n = (relocmap == NULL) ? 0 : relocmap->n_entries_used;

	relocblks = malloc(offsetof(struct ploop_relocblks_ctl, extents[n]));
	if (!relocblks) {
		ploop_err(0, "Can't alloc relocblks ioc struct");
		return (SYSEXIT_MALLOC);
	}
	memset(relocblks, 0, offsetof(struct ploop_relocblks_ctl, extents[n]));

	relocblks->level      = lvl;
	relocblks->alloc_head = a_h;
	relocblks->n_scanned  = n_scanned;

	for(i = 0; i < n; i++) {
		if (!relocmap->extents[i].len) {
			free(relocblks);
			ploop_err(0, "abort: relocmap2relocblks !relocmap->extents[i].len");
			return SYSEXIT_ABORT;
		}
		relocblks->extents[i].clu = relocmap->extents[i].clu;
		relocblks->extents[i].iblk = relocmap->extents[i].iblk;
		relocblks->extents[i].len = relocmap->extents[i].len;
		relocblks->extents[i].free = relocmap->extents[i].free;
	}

	relocblks->n_extents = n;
	*relocblks_pp = relocblks;

	return 0;
}
