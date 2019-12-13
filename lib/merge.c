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
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>
#include <assert.h>

#include "ploop.h"
#include "cbt.h"

static int sync_cache(struct delta * delta)
{
	int skip = 0;

	if (!delta->l2_dirty)
		return 0;

	/* Sync data before we write out new index table. */
	if (fsync(delta->fd)) {
		ploop_err(errno, "fsync");
		return -1;
	}

	if (delta->l2_cache < 0) {
		ploop_err(0, "abort: delta->l2_cache < 0");
		return -1;
	}
	if (delta->l2_cache >= delta->l1_size) {
		ploop_err(0, "abort: delta->l2_cache >= delta->l1_size");
		return -1;
	}

	if (delta->l2_cache == 0)
		skip = sizeof(struct ploop_pvd_header);

	ploop_log(3, "Sync cache %d", delta->l2_cache);
	/* Write index table */
	if (PWRITE(delta, (__u8 *)delta->l2 + skip,
				S2B(delta->blocksize) - skip,
				(off_t)delta->l2_cache * S2B(delta->blocksize) + skip))
		return SYSEXIT_WRITE;

	/* Sync index table. We can delay this, but this does not
	 * improve performance
	 */
	if (fsync(delta->fd)) {
		ploop_err(errno, "fsync");
		return -1;
	}
	delta->l2_dirty = 0;
	return 0;
}

static int locate_l2_entry(struct delta_array *p, int level, int i, __u32 k, int *out)
{
	__u64 cluster;
	for (level++; level < p->delta_max; level++) {
		if (p->delta_arr[level].l2_cache == -1) {
			if (i >= p->delta_arr[level].l1_size)
				break; /* grow is monotonic! */
			cluster = S2B(p->delta_arr[level].blocksize);
			if (PREAD(&p->delta_arr[level], p->delta_arr[level].l2,
						cluster, (off_t)i * cluster))
				return SYSEXIT_READ;
			p->delta_arr[level].l2_cache = i;
		}
		if (p->delta_arr[level].l2[k]) {
			*out = level;
			return 0;
		}
	}
	*out = -1;
	return 0;
}

static int grow_lower_delta(const char *device, int top,
		const char *src_image, const char *dst_image,
		int end_level)
{
	off_t src_size = 0; /* bdsize of source delta to merge */
	off_t dst_size = 0; /* bdsize of destination delta for merge */
	int i;
	struct ploop_pvd_header *vh;
	struct grow_maps grow_maps;
	const char *fmt;
	int dst_is_raw = 0;
	void *buf = NULL;
	struct delta odelta = {.fd = -1};
	int ret, blocksize;
	__u64 cluster;
	char **names = NULL;

	if (top)
		ret = ploop_get_size(device, &src_size);
	else
		ret = read_size_from_image(src_image, 0, &src_size);
	if (ret)
		return ret;

	if (ploop_get_names(device, &names, &fmt, &blocksize)) {
		ploop_err(errno, "find_delta_names");
		ret = SYSEXIT_SYSFS;
		goto done;
	}
	ploop_free_array(names);

	if (strcmp(fmt, "raw") == 0)
		dst_is_raw = 1;

	if ((ret = read_size_from_image(dst_image, dst_is_raw, &dst_size)))
		goto done;

	if (src_size <= dst_size) {
		ret = 0;
		goto done;
	}

	if (dst_is_raw) {
		ret = grow_raw_delta(dst_image, S2B(src_size - dst_size), 0);
		goto done;
	}

	/* Here we know for sure that destination delta is in ploop1 format */
	if (open_delta(&odelta, dst_image, O_RDWR, OD_NOFLAGS)) {
		ploop_err(errno, "open_delta");
		ret = SYSEXIT_OPEN;
		goto done;
	}

	cluster = S2B(odelta.blocksize);
	if (p_memalign(&buf, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	if (dirty_delta(&odelta)) {
		ploop_err(errno, "dirty_delta");
		ret = SYSEXIT_WRITE;
		goto done;
	}

	if (grow_loop_image(dst_image, NULL, odelta.blocksize, src_size)) {
		ret = SYSEXIT_WRITE;
		goto done;
	}

	/* relocate blocks w/o nullifying them and changing on-disk header */
	ret = grow_delta(&odelta, src_size, buf, &grow_maps);
	if (clear_delta(&odelta)) {
		ploop_err(errno, "clear_delta");
		ret = SYSEXIT_WRITE;
	}
	if (ret)
		goto done;

	if (grow_maps.ctl->n_maps) {
		ret = update_delta_index(device, end_level, &grow_maps);
		if (ret)
			goto done;

		/* nullify relocated blocks on disk */
		memset(buf, 0, cluster);
		for (i = 0; i < grow_maps.ctl->n_maps; i++) {
			if (PWRITE(&odelta, buf, cluster,
						(off_t)(grow_maps.zblks[i]) * cluster)) {
				ret = SYSEXIT_WRITE;
				goto done;
			}
		}
	}

	/* save new image header of destination delta on disk */
	vh = (struct ploop_pvd_header *)buf;
	generate_pvd_header(vh, src_size, odelta.blocksize, odelta.version);
	if (PREAD(&odelta, &vh->m_Flags, sizeof(vh->m_Flags),
		  offsetof(struct ploop_pvd_header, m_Flags))) {
		ret = SYSEXIT_READ;
		goto done;
	}
	if (PWRITE(&odelta, vh, sizeof(*vh), 0)) {
		ret = SYSEXIT_WRITE;
		goto done;
	}

	if (fsync(odelta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
	}

done:
	free(buf);
	close_delta(&odelta);
	return ret;
}

int merge_image(const char *device, int start_level, int end_level, int raw,
		int merge_top, char **images, const char *new_image)
{
	int last_delta = 0;
	char **names = NULL;
	struct delta_array da = {};
	struct delta odelta = {};
	int i, i_end, ret = 0;
	__u32 k;
	__u32 allocated = 0;
	__u64 cluster;
	void *data_cache = NULL;
	__u32 blocksize;
	int version = PLOOP_FMT_UNDEFINED;
	const char *merged_image;

	if (new_image && access(new_image, F_OK) == 0) {
		ploop_err(EEXIST, "Can't merge to new image %s", new_image);
		return SYSEXIT_PARAM;
	}

	if (device) {
		if (start_level <= end_level || start_level < 0) {
			ploop_err(0, "Invalid parameters: start_level %d end_level %d",
					start_level, end_level);
			return SYSEXIT_PARAM;
		}

		if (!new_image && !merge_top)
			if ((ret = grow_lower_delta(device,
						merge_top,
						images[start_level],
						images[end_level],
						end_level)))
				return ret;

		if (merge_top) {
			/* top delta is in running state */
			start_level--;
			names = ++images;
			if (start_level <= end_level)
				start_level = end_level;
		}
		names = images;

		if (merge_top) {
			if (new_image) {
				/* Special case: only one delta below top one:
				 * copy it to new_image and do ploop_replace()
				 */
				ret = copy_delta(names[0], new_image);
				if (ret)
					return ret;

				ret = replace_delta(device, start_level, new_image, 0, PLOOP_FMT_RDONLY);
				if (ret)
					goto rm_delta;
			}
			ret = merge_top_delta(device);
rm_delta:
			if (ret && new_image)
				unlink(new_image);

			return ret;
		}
	}
	last_delta = start_level - end_level;
	names = images;

	if (new_image) {
		last_delta++;
		merged_image = new_image;
	} else
		merged_image = names[end_level];

	if (!raw) {
		if (open_delta(&odelta, merged_image, O_RDWR,
			       device ? OD_NOFLAGS : OD_OFFLINE)) {
			ploop_err(errno, "open_delta");
			ret = SYSEXIT_OPEN;
			goto merge_done2;
		}
		if (dirty_delta(&odelta)) {
			ploop_err(errno, "dirty_delta");
			ret = SYSEXIT_WRITE;
			goto merge_done2;
		}
	} else {
		if (open_delta_simple(&odelta, merged_image, O_RDWR,
				      device ? 0 : OD_OFFLINE)) {
			ret = SYSEXIT_WRITE;
			goto merge_done2;
		}
	}

	blocksize = odelta.blocksize;
	version = odelta.version;
	init_delta_array(&da);
	for (i = 0; i < last_delta; i++) {
		ret = extend_delta_array(&da, names[start_level - i],
					device ? O_RDONLY|O_DIRECT : O_RDONLY,
					device ? OD_NOFLAGS : OD_OFFLINE);
		if (ret)
			goto merge_done2;

		if (blocksize != da.delta_arr[i].blocksize) {
			ploop_err(errno, "Wrong blocksize %s bs=%d [prev bs=%d]",
					names[i], da.delta_arr[i].blocksize, blocksize);
			ret = SYSEXIT_PLOOPFMT;
			goto merge_done2;
		}

		if (version != da.delta_arr[i].version) {
			ploop_err(errno, "Wrong version %s %d [prev %d]",
					names[i], da.delta_arr[i].version, version);
			ret = SYSEXIT_PLOOPFMT;
			goto merge_done2;
		}
	}
	cluster = S2B(blocksize);

	if (new_image) { /* Create it */
		struct ploop_pvd_header *vh;
		off_t size;
		int mode = (raw) ? PLOOP_RAW_MODE : PLOOP_EXPANDED_MODE;

		vh = (struct ploop_pvd_header *)da.delta_arr[0].hdr0;
		size = get_SizeInSectors(vh);

		ret = create_image(new_image, blocksize, size, mode, version, 0);
		if (ret)
			goto merge_done2;
	}

	if (p_memalign(&data_cache, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto merge_done2;
	}

	if (!device && !new_image) {
		struct ploop_pvd_header *vh;
		vh = (struct ploop_pvd_header *)da.delta_arr[0].hdr0;

		if (!raw) {
			if ((ret = grow_delta(&odelta, get_SizeInSectors(vh),
				   data_cache, NULL)))
				goto merge_done;
		} else {
			off_t src_size = get_SizeInSectors(vh);
			off_t dst_size;

			ret = read_size_from_image(merged_image, 1, &dst_size);
			if (ret)
				goto merge_done;

			if (src_size > dst_size) {
				ret = grow_raw_delta(merged_image,
					       S2B(src_size - dst_size), 0);
				if (ret)
					goto merge_done;
			}
		}
	}

	i_end = (da.delta_arr[0].l2_size + PLOOP_MAP_OFFSET + cluster/4 - 1) /
		(cluster/4);
	for (i = 0; i < i_end; i++) {
		int k_start = 0;
		int k_end   = cluster/4;

		/* Load L2 table */
		if (PREAD(&da.delta_arr[0], da.delta_arr[0].l2,
			  cluster, (off_t)i * cluster)) {
			ret = SYSEXIT_READ;
			goto merge_done;
		}

		/* Announce L2 cache valid. This information is not used. */
		da.delta_arr[0].l2_cache = i;

		/* And invalidate L2 cache for lower delta, they will
		 * be fetched on demand.
		 */
		for (k = 1; k < last_delta; k++)
			da.delta_arr[k].l2_cache = -1;

		/* Iterate over all L2 entries */
		if (i == 0)
			k_start = PLOOP_MAP_OFFSET;
		if (i == i_end - 1)
			k_end   = da.delta_arr[0].l2_size + PLOOP_MAP_OFFSET -
				  i * cluster/4;

		for (k = k_start; k < k_end; k++) {
			int level2 = 0;

			/* If entry is not present in base level,
			 * lookup lower deltas.
			 */
			if (da.delta_arr[0].l2[k] == 0) {
				ret = locate_l2_entry(&da, 0, i, k, &level2);
				if (ret)
					goto merge_done;
				if (level2 < 0)
					continue;
			}

			if (PREAD(&da.delta_arr[level2], data_cache, cluster,
						S2B(ploop_ioff_to_sec(da.delta_arr[level2].l2[k],
								blocksize, version)))) {
				ret = SYSEXIT_READ;
				goto merge_done;
			}

			if (raw) {
				off_t opos;
				opos = i * (cluster/4) + k - PLOOP_MAP_OFFSET;
				if (PWRITE(&odelta, data_cache, cluster,
					   opos*cluster)) {
					ret = SYSEXIT_WRITE;
					goto merge_done;
				}
				continue;
			}

			if (i != odelta.l2_cache) {
				if (odelta.l2_cache >= 0)
					if ((ret = sync_cache(&odelta)))
						goto merge_done;

				odelta.l2_cache = i;
				if (PREAD(&odelta, odelta.l2, cluster,
					  (off_t)(i * cluster))) {
					ret = SYSEXIT_READ;
					goto merge_done;
				}
				odelta.l2_dirty = 0;
			}

			if (odelta.l2[k] == 0) {
				odelta.l2[k] = ploop_sec_to_ioff((off_t)odelta.alloc_head++ * B2S(cluster),
							blocksize, version);
				if (odelta.l2[k] == 0) {
					ploop_err(0, "abort: odelta.l2[k] == 0");
					ret = SYSEXIT_ABORT;
					goto merge_done;
				}
				odelta.l2_dirty = 1;
				allocated++;
			}
			if (PWRITE(&odelta, data_cache, cluster,
						S2B(ploop_ioff_to_sec(odelta.l2[k],
								blocksize, version)))) {
				ret = SYSEXIT_WRITE;
				goto merge_done;
			}
		}
	}

	if (fsync(odelta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
		goto merge_done;
	}

	if (odelta.l2_dirty) {
		int skip = 0;

		if (odelta.l2_cache < 0) {
			ploop_err(0, "abort: odelta.l2_cache < 0");
			ret = SYSEXIT_ABORT;
			goto merge_done;
		}
		if (odelta.l2_cache >= odelta.l1_size) {
			ploop_err(0, "abort: odelta.l2_cache >= odelta.l1_size");
			ret = SYSEXIT_ABORT;
			goto merge_done;
		}

		if (odelta.l2_cache == 0)
			skip = sizeof(struct ploop_pvd_header);

		if (PWRITE(&odelta, (__u8 *)odelta.l2 + skip,
					cluster - skip,
					(off_t)odelta.l2_cache * cluster + skip)) {
			ret = SYSEXIT_WRITE;
			goto merge_done;
		}
		if (fsync(odelta.fd)) {
			ploop_err(errno, "fsync");
			ret = SYSEXIT_FSYNC;
			goto merge_done;
		}
	}

	if (!raw && clear_delta(&odelta)) {
		ploop_err(errno, "clear_delta");
		ret = SYSEXIT_WRITE;
	} else {
		if (fsync(odelta.fd)) {
			ploop_err(errno, "fsync");
			ret = SYSEXIT_FSYNC;
		}
	}

merge_done:
	close_delta(&odelta);

	if (device && !ret) {
		if (new_image) {
#if 0 //FIXME
			ret = do_replace_delta(lfd, start_level, fd, blocksize, new_image, 0, PLOOP_FMT_RDONLY);
			if (ret)
				goto close_lfd;
#endif
		}


		for (i = end_level + 1; i <= start_level; i++) {
			ret = notify_merged_backward(device, i);
			if (ret) 
				goto merge_done2;
		}

		if (merge_top)
			ret = merge_top_delta(device);
	}

merge_done2:
	if (!device && !raw && ret == 0)
		ploop_move_cbt(images[0], images[1]);

	free(data_cache);
	deinit_delta_array(&da);
	return ret;
}

/* Logs a line showing deltas to merge and the merge destination,
 * that looks something like these:
 *
 *	Merging image: delta_file -> parent_delta_file
 *
 *	Merging images: delta_file_1 file_2 file_3 -> (new) new_delta
 */
static void log_merge_images_info(struct ploop_disk_images_data *di,
		char **names, int start_level, int end_level, const char *new_delta)
{
	char basedir[PATH_MAX];
	char imglist[LOG_BUF_SIZE];
	char merged_image[PATH_MAX];
	int i, pos = 0;

	get_basedir(di->runtime->xml_fname, basedir, sizeof(basedir));
	normalize_image_name(basedir, new_delta ? new_delta : names[0],
				merged_image, sizeof(merged_image));

	for (i = start_level; i > end_level; i--) {
		int n;
		char img[PATH_MAX];

		normalize_image_name(basedir, names[i], img, sizeof(img));
		n = snprintf(imglist + pos, sizeof(imglist) - pos, "%s ", img);
		if (n <= 0)
			// error?
			break;
		pos += n;
		if (pos >= sizeof(imglist))
			// output truncated!
			break;
	}

	ploop_log(0, "Merging image%s: %s-> %s%s",
			start_level - end_level - 1  > 1 ? "s" : "",
			imglist,
			new_delta ? "(new) " : "", merged_image);
}

void print_BAT(__u32 *l2, int cluster, int clu, int start, int end)
{
	int i;

	for (i = start; i < end; i++) {
		ploop_log(0, "%d-%d", (clu * cluster/4) + i - (clu ? 0 : 16), l2[i]);
	}
}

static int zero_base_delta(const char *base, const char *top)
{
	int rc, i, k, i_end;
	struct delta_array da = {};
	struct delta *odelta;
	__u64 cluster;

	ploop_log(0, "Zero BAT in base %s", base);
	init_delta_array(&da);
	rc = extend_delta_array(&da, base, O_RDWR, OD_NOFLAGS);
	if (rc)
		return rc;
	rc = extend_delta_array(&da, top, O_RDONLY|O_DIRECT, OD_OFFLINE|OD_ALLOW_DIRTY);
	if (rc)
		goto err;

	odelta = &da.delta_arr[0];
	cluster = S2B(odelta->blocksize);
	i_end = odelta->l1_size;
	for (i = 0; i < i_end; i++) {
		int k_start = 0;
		int k_end = cluster/4;

		/* Load L2 table */
		if (PREAD(odelta, odelta->l2, cluster, (off_t)i * cluster)) {
			rc = SYSEXIT_READ;
			goto err;
		}
		odelta->l2_cache = i;
		
                /* And invalidate L2 cache for lower delta, they will
		 * be fetched on demand.
		 */
		da.delta_arr[1].l2_cache = -1;
		/* Iterate over all L2 entries */
		if (i == 0)
			k_start = PLOOP_MAP_OFFSET;
		if (i == i_end - 1)
			k_end = da.delta_arr[0].l2_size + PLOOP_MAP_OFFSET -
				i * cluster/sizeof(__u32);

		for (k = k_start; k < k_end; k++) {
			int level2 = 0;

			if (da.delta_arr[0].l2[k] == 0)
				continue;
			rc = locate_l2_entry(&da, 0, i, k, &level2);
			if (rc)
				goto err;
			if (level2 < 0)
				continue;
			ploop_log(0, "zero cluster=%d idx=%d", i, k);
			odelta->l2[k] = 0;
			odelta->l2_dirty = 1;
		}

		rc = sync_cache(odelta);
		if (rc)
			goto err;
	}
	
err:
	deinit_delta_array(&da);

	return rc;	
}

static int reverse_merge_online(struct ploop_disk_images_data *di,
		const char *guid, const char *top_guid, int sid,
		const char *devname, const char *base, const char *top,
		int start_level, int end_level)
{
	char ldev[64];
	char cfg[PATH_MAX];
	char *t, *cfg1, *rm_fname;
	int rc, lfd =  -1;
	int top_idx, base_idx;

	ploop_log(0, "Online reverse merge %s -> %s [%d]", base, top,
			di->snapshots[sid]->temporary);
	top_idx = find_image_idx_by_guid(di, top_guid);
	if (top_idx == -1) {
		ploop_err(0, "Can't find image by uuid %s", top_guid);
		return SYSEXIT_PARAM;
	}
	base_idx = find_image_idx_by_guid(di, guid);
	if (base_idx == -1) {
		ploop_err(0, "Can't find image by uuid %s", guid);
		return SYSEXIT_PARAM;
	}

	// Validate
	rc = ploop_di_delete_snapshot(di, guid, 1, NULL);
	if (rc)
		return rc;
	// prepare config
	get_disk_descriptor_fname(di, cfg, sizeof(cfg));
	cfg1 = alloca(strlen(cfg) + 6);
	sprintf(cfg1, "%s.tmp", cfg);

	/* Process transition state */
	switch (di->snapshots[sid]->temporary) {
	case snap_temporary_zero_swap:
		if (end_level > start_level)
			goto swap;
		goto merge_top;
	default:
		break;
	}
	rc = grow_lower_delta(devname, 1, top, base, end_level);
	if (rc)
		return rc;
	// Mark base delta in transition state
	di->snapshots[sid]->temporary = snap_temporary_zero;
	rc = ploop_store_diskdescriptor(cfg1, di);
	if (rc)
		return rc;
	// 1) get new loop device
	lfd = loop_create(base, ldev, sizeof(ldev));
        if (rc)
		goto err1;
	// 4) deny to resume
	rc = dm_setnoresume(devname, 1);
	if (rc && errno != EBUSY)
		goto err1;
	// 3) suspend
	rc = ploop_suspend_device(devname);
	if (rc)
		goto err1;
	// 5) Mark base delta as in transition state
	if (rename(cfg1, cfg)) {
		ploop_err(errno, "Can not rename %s ->%s", cfg1, cfg);
		rc = SYSEXIT_RENAME;
		goto err;
	}
	// 6) Zero BAT in base delta which present in top delta
	rc = zero_base_delta(base, top);
	if (rc)
		goto err;

	// 7) swap deltas
	t = di->images[base_idx]->file;
	di->images[base_idx]->file = di->images[top_idx]->file;
	di->images[top_idx]->file = t;
	di->snapshots[sid]->temporary = snap_temporary_zero_swap;
	rc = ploop_store_diskdescriptor(cfg, di);
	if (rc)
		goto err;
swap:
	// 8) swap deltas
	ploop_log(0, "Swap top '%s' delta with lower '%s'", top, base);
	rc = dm_flip_upper_deltas(devname, ldev, top);
	if (rc)
		goto err;
	rc = dm_setnoresume(devname, 0);
	if (rc)
		goto err;
	rc = ploop_resume_device(devname);
	if (rc)
		goto err;
	rc = update_delta_inuse(top, 0);
	if (rc)
		goto err;

merge_top:
	rc = ploop_di_delete_snapshot(di, guid, 1, &rm_fname);
	if (rc)
		goto err1;
	rc = ploop_store_diskdescriptor(cfg1, di);
	if (rc)
		goto err1;
	rc = merge_top_delta(devname);
	if (rc)
		goto err1;
	if (rename(cfg1, cfg)) {
		ploop_err(errno, "Can not rename %s ->%s", cfg1, cfg);

		rc = SYSEXIT_RENAME;
		goto err1;
	}

	if (unlink(rm_fname))
		ploop_err(errno, "Can not to unlink %s", rm_fname);

err:
	if (rc) {
		dm_setnoresume(devname, 0);
		ploop_resume_device(devname);
	}
err1:
	unlink(cfg1);
	close(lfd);

	return rc;
}

int ploop_delete_snapshot_by_guid(struct ploop_disk_images_data *di,
		const char *guid, const char *new_delta)
{
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	char dev[64];
	char *device = NULL;
	char *parent_fname = NULL;
	char *child_fname = NULL;
	char *delete_fname = NULL;
	const char *child_guid;
	char **names = NULL;
	int ret;
	int start_level = -1;
	int end_level = -1;
	int merge_top_online = 0;
	int raw = 0;
	int online = 0;
	int sid, child_idx; /* parent and child snapshot ids */
	int i, nelem;
	const char *fmt;
	int blocksize;

	ret = SYSEXIT_PARAM;
	sid = find_snapshot_by_guid(di, guid);
	if (sid == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s", guid);
		return ret;
	}

	parent_fname = find_image_by_guid(di, guid);
	if (parent_fname == NULL) {
		ploop_err(0, "Can't find image by uuid %s", guid);
		return ret;
	}

	child_guid = ploop_get_child_by_uuid(di, guid);
	if (child_guid == NULL) {
		ploop_err(0, "Can't find child snapshot by uuid %s", guid);
		return ret;
	}

	child_idx = find_snapshot_by_guid(di,
			ploop_get_child_by_uuid(di, guid));
	if (child_idx == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				child_guid);
		return ret;
	}

	child_fname = find_image_by_guid(di, child_guid);
	if (child_fname == NULL) {
		ploop_err(0, "Can't find image by uuid %s",
				child_guid);
		return ret;
	}

	nelem = ploop_get_child_count_by_uuid(di, guid);
	if (nelem > 1) {
		ploop_err(0, "Can't merge to snapshot %s: it has %d children",
				guid, nelem);
		return ret;
	}

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1) {
		return SYSEXIT_SYS;
	}
	else if (ret == 0)
		online = 1;

	if (online) {
		struct stat c_st, p_st;

		if (stat(child_fname, &c_st)) {
			ploop_err(errno, "Can't stat %s", child_fname);
			return SYSEXIT_FSTAT;
		}

		if (stat(parent_fname, &p_st)) {
			ploop_err(errno, "Can't stat %s", parent_fname);
			return SYSEXIT_FSTAT;
		}

		ret = complete_running_operation(di, dev);
		if (ret)
			return ret;
		if ((ret = ploop_get_names(dev, &names, &fmt, &blocksize)))
			return ret;
		nelem = get_list_size(names);
		for (i = 0; names[i] != NULL; i++) {
			ret = fname_cmp(names[i], &c_st);
			if (ret == -1) {
				goto err;
			} else if (ret == 0) {
				start_level = i;
				continue;
			}

			ret = fname_cmp(names[i], &p_st);
			if (ret == -1)
				goto err;
			else if (ret == 0)
				end_level = i;
		}

		if (end_level != -1 && start_level != -1) {
			/* reverse merge in progress */
			if (di->snapshots[sid]->temporary ==
						snap_temporary_zero_swap &&
					end_level == start_level + 1)
				return reverse_merge_online(di, guid,
						child_guid, sid, device,
						parent_fname, child_fname,
						start_level, end_level);

				
			if (end_level + 1 != start_level) {
				ploop_err(0, "Inconsistency detected %s [%d] %s [%d]",
						parent_fname, end_level, child_fname, start_level);
				ret = SYSEXIT_PARAM;
				goto err;
			}
			device = dev;
#if 0 //FIXME RAW
			if (start_level == 0)
				raw = info.raw;
#endif
			merge_top_online = (start_level == nelem -1);
			if (merge_top_online && end_level == 0)
				return reverse_merge_online(di, guid,
						child_guid, sid, device,
						parent_fname, child_fname,
						start_level, end_level);
		} else if (end_level == -1 && start_level == -1) {
			online = 0;
		} else {
			ploop_err(0, "Inconsistency detected %s [%d] %s [%d]",
					parent_fname, end_level, child_fname, start_level);
			ret = SYSEXIT_PARAM;
			goto err;
		}
	}

	if (!online) {
		start_level = 1;
		end_level = 0;
		/* Only base image could be in RAW format */
		if (di->mode == PLOOP_RAW_MODE &&
				!guidcmp(di->snapshots[sid]->parent_guid, NONE_UUID))
			raw = 1;

		names = malloc(3 * sizeof(char *));
		if (names == NULL) {
			ret = SYSEXIT_MALLOC;
			goto err;
		}
		names[1] = strdup(child_fname);
		names[0] = strdup(parent_fname);
		if (names[0] == NULL || names[1] == NULL) {
			ret = SYSEXIT_MALLOC;
			goto err;
		}
		names[2] = NULL;
	}

	ret = check_snapshot_mount(di, guid, parent_fname,
			di->snapshots[sid]->temporary);
	if (ret)
		goto err;
	if (!merge_top_online) {
		ret = check_snapshot_mount(di, guid, child_fname,
			di->snapshots[child_idx]->temporary);
		if (ret)
			goto err;
	}

	ploop_log(0, "%sline %s merge %s -> %s%s",
			merge_top_online ? "On": "Off",
			get_snap_str(di->snapshots[sid]->temporary),
			child_guid, guid,
			raw ? " (raw)" : "");
	log_merge_images_info(di, names, start_level, end_level, new_delta);

	/* To automerge in case crash */
	di->snapshots[parent_idx]->temporary = 1;
	get_disk_descriptor_fname(di, conf, sizeof(conf));
	ret = ploop_store_diskdescriptor(conf, di);
	if (ret)
		goto err;
	
	/* make validation before real merge */
	ret = ploop_di_delete_snapshot(di, guid, merge_top_online, &delete_fname);
	if (ret)
		goto err;

	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err;

	ret = merge_image(device, start_level, end_level, raw, merge_top_online,
			names, new_delta);
	if (ret)
		goto err;

	if (new_delta) {
		/* Write new delta name to dd.xml, and remove the old file.
		 * Note we can only write new delta now after merge_image()
		 * as the file is created and we can use realpath() on it.
		 */
		int idx;
		char *oldimg, *newimg;

		newimg = realpath(new_delta, NULL);
		if (!newimg) {
			ploop_err(errno, "Error in realpath(%s)", new_delta);
			ret = SYSEXIT_PARAM;
			goto err;
		}

		idx = find_image_idx_by_guid(di, guid);
		if (idx == -1) {
			ploop_err(0, "Unable to find image by uuid %s",
					guid);
			ret = SYSEXIT_PARAM;
			goto err;
		}

		oldimg = di->images[idx]->file;
		di->images[idx]->file = newimg;

		ret = ploop_store_diskdescriptor(conf_tmp, di);
		if (ret)
			goto err;

		ploop_log(0, "Removing %s", oldimg);
		ret = unlink(oldimg);
		if (ret) {
			ploop_err(errno, "unlink %s", oldimg);
			ret = SYSEXIT_UNLINK;
		}

		free(oldimg);
	}

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
		goto err;
	}

	ploop_log(0, "Removing %s", delete_fname);
	if (unlink(delete_fname)) {
		ploop_err(errno, "unlink %s", delete_fname);
		ret = SYSEXIT_UNLINK;
	}

	if (ret == 0)
		ploop_log(0, "ploop snapshot merged");
	else
		ploop_log(0, "failed to merge ploop snapshot");

err:
	free(delete_fname);
	ploop_free_array(names);

	return ret;
}

int ploop_merge_snapshot(struct ploop_disk_images_data *di, struct ploop_merge_param *param)
{
	return 0;
}

