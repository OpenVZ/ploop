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
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>
#include <assert.h>

#include "ploop.h"

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

static int grow_lower_delta(const char *device, int top, int start_level, int end_level)
{
	off_t src_size = 0; /* bdsize of source delta to merge */
	off_t dst_size = 0; /* bdsize of destination delta for merge */
	char *src_image = NULL;
	char *dst_image = NULL;
	int i, devfd;
	struct ploop_pvd_header *vh;
	struct grow_maps grow_maps;
	char *fmt;
	int dst_is_raw = 0;
	void *buf;
	struct delta odelta = {};
	int ret;
	__u64 cluster;

	if (top) {
		if ((ret = ploop_get_size(device, &src_size)))
			return ret;
	} else {
		if (find_delta_names(device, end_level, end_level,
				     &src_image, &fmt)) {
			ploop_err(errno, "find_delta_names");
			return(SYSEXIT_SYSFS);
		}

		if ((ret = read_size_from_image(src_image, 0, &src_size)))
			return ret;
	}

	if (find_delta_names(device, start_level, start_level,
			     &dst_image, &fmt)) {
		ploop_err(errno, "find_delta_names");
		return(SYSEXIT_SYSFS);
	}

	if (strcmp(fmt, "raw") == 0)
		dst_is_raw = 1;

	if ((ret = read_size_from_image(dst_image, dst_is_raw, &dst_size)))
		return ret;

	if (src_size <= dst_size)
		return 0;

	if (dst_is_raw) {
		return grow_raw_delta(dst_image, S2B(src_size - dst_size));
	}

	/* Here we know for sure that destination delta is in ploop1 format */

	if (open_delta(&odelta, dst_image, O_RDWR, OD_NOFLAGS)) {
		ploop_err(errno, "open_delta");
		return(SYSEXIT_OPEN);
	}

	if (dirty_delta(&odelta)) {
		ploop_err(errno, "dirty_delta");
		ret = SYSEXIT_WRITE;
		goto done;
	}
	cluster = S2B(odelta.blocksize);
	if (p_memalign(&buf, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	/* relocate blocks w/o nullifying them and changing on-disk header */
	if ((ret = grow_delta(&odelta, src_size, buf, &grow_maps)))
		goto done;

	if (grow_maps.ctl->n_maps &&
	    odelta.fops->update_size &&
	    (ret = odelta.fops->update_size(odelta.fd, dst_image)))
		goto done;

	if (clear_delta(&odelta)) {
		ploop_err(errno, "clear_delta");
		ret = SYSEXIT_WRITE;
		goto done;
	}

	devfd = open(device, O_RDONLY);
	if (devfd < 0) {
		ploop_err(errno, "open dev");
		ret = SYSEXIT_DEVICE;
		goto done;
	}

	/* update in-core map_node mappings for relocated blocks */
	grow_maps.ctl->level = start_level;
	ret = ioctl_device(devfd, PLOOP_IOC_UPDATE_INDEX, grow_maps.ctl);
	close(devfd);
	if (ret)
		goto done;

	/* nullify relocated blocks on disk */
	memset(buf, 0, cluster);
	for (i = 0; i < grow_maps.ctl->n_maps; i++)
		if (PWRITE(&odelta, buf, cluster,
			   (off_t)(grow_maps.zblks[i]) * cluster)) {
			ret = SYSEXIT_WRITE;
			goto done;
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

	if (odelta.fops->fsync(odelta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
	}

done:
	close_delta(&odelta);
	return ret;
}

int get_delta_info(const char *device, struct merge_info *info)
{
	char *fmt;

	if (ploop_get_attr(device, "top", &info->top_level)) {
		ploop_err(0, "Can't find top delta");
		return SYSEXIT_SYSFS;
	}

	if (info->top_level == 0) {
		ploop_err(0, "Single delta, nothing to merge");
		return SYSEXIT_PARAM;
	}

	if (info->end_level == 0)
		info->end_level = info->top_level;

	if (info->end_level > info->top_level ||
	    info->start_level > info->end_level)
	{
		ploop_err(0, "Illegal top level");
		return SYSEXIT_SYSFS;
	}

	if (info->end_level == info->top_level) {
		int running;

		if (ploop_get_attr(device, "running", &running)) {
			ploop_err(0, "Can't get running attr");
			return SYSEXIT_SYSFS;
		}

		if (running) {
			int ro;

			if (ploop_get_delta_attr(device, info->top_level, "ro", &ro)) {
				ploop_err(0, "Can't get ro attr");
				return SYSEXIT_SYSFS;
			}
			if (!ro)
				info->merge_top = 1;
		}
	}
	info->names = calloc(1, (info->end_level - info->start_level + 2) * sizeof(char*));
	if (info->names == NULL) {
		ploop_err(errno, "malloc");
		return SYSEXIT_MALLOC;
	}
	if (find_delta_names(device, info->start_level, info->end_level, info->names, &fmt))
		return SYSEXIT_SYSFS;
	if (strcmp(fmt, "raw") == 0)
		info->raw = 1;

	return 0;
}

int merge_image(const char *device, int start_level, int end_level, int raw, int merge_top,
		      char **images)
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
	__u32 blocksize = 0;
	__u32 prev_blocksize = 0;
	int version = PLOOP_FMT_UNDEFINED;

	if (start_level >= end_level || start_level < 0) {
		ploop_err(0, "Invalid parameters: start_level %d end_level %d",
			start_level, end_level);
		return -1;
	}
	if (device) {
		ret = ploop_complete_running_operation(device);
		if (ret)
			return ret;

		if (merge_top) {
			/* top delta is in running state merged
			by means of PLOOP_IOC_MERGE */
			end_level--;
			names = ++images;
			if (end_level <= start_level)
				end_level = 0;
		} else
			names = images;

		if ((ret = grow_lower_delta(device, merge_top, start_level, end_level)))
			return ret;

		if (end_level == 0) {
			int lfd;

			ploop_log(0, "Merging top delta");
			lfd = open(device, O_RDONLY);
			if (lfd < 0) {
				ploop_err(errno, "open dev %s", device);
				return SYSEXIT_DEVICE;
			}

			ret = ioctl_device(lfd, PLOOP_IOC_MERGE, 0);
			close(lfd);

			return ret;
		}
		last_delta = end_level - start_level;
	} else {
		last_delta = get_list_size(images) - 1;
		names = images;
	}

	init_delta_array(&da);

	for (i = 0; i < last_delta; i++) {
		// FIXME: add check for blocksize
		ret = extend_delta_array(&da, names[i],
					device ? O_RDONLY|O_DIRECT : O_RDONLY,
					device ? OD_NOFLAGS : OD_OFFLINE);
		if (ret)
			goto merge_done2;

		blocksize = da.delta_arr[i].blocksize;
		if (i != 0 && blocksize != prev_blocksize) {
			ploop_err(errno, "Wrong blocksize %s bs=%d [prev bs=%d]",
					names[i], blocksize, prev_blocksize);
			goto merge_done2;
		}
		prev_blocksize = blocksize;

		if (i != 0 && version != da.delta_arr[i].version) {
			ploop_err(errno, "Wrong version %s %d [prev %d]",
					names[i], da.delta_arr[i].version, version);
			goto merge_done2;
		}
		version = da.delta_arr[i].version;
	}
	if (blocksize == 0) {
		ploop_err(errno, "Wrong blocksize 0");
		goto merge_done2;

	}
	cluster = S2B(blocksize);
	if (!raw) {
		if (open_delta(&odelta, names[last_delta], O_RDWR,
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
		if (open_delta_simple(&odelta, names[last_delta], O_RDWR,
				      device ? 0 : OD_OFFLINE)) {
			ret = SYSEXIT_WRITE;
			goto merge_done2;
		}
	}
	if (p_memalign(&data_cache, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto merge_done2;
	}

	if (!device) {
		struct ploop_pvd_header *vh;
		vh = (struct ploop_pvd_header *)da.delta_arr[0].hdr0;

		if (!raw) {
			if ((ret = grow_delta(&odelta, get_SizeInSectors(vh),
				   data_cache, NULL)))
				goto merge_done;
		} else {
			off_t src_size = get_SizeInSectors(vh);
			off_t dst_size;

			ret = read_size_from_image(names[last_delta], 1, &dst_size);
			if (ret)
				goto merge_done;

			if (src_size > dst_size) {
				ret = grow_raw_delta(names[last_delta],
					       S2B(src_size - dst_size));
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
				if (locate_l2_entry(&da, 0, i, k, &level2)) {
					ret = -1;
					goto merge_done;
				}
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
					ret = -1;
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

	if (device && allocated &&
	    odelta.fops->update_size &&
	    (ret = odelta.fops->update_size(odelta.fd, names[last_delta]))) {
		ploop_err(errno, "update_size");
		goto merge_done;
	}

	if (odelta.fops->fsync(odelta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
		goto merge_done;
	}

	if (odelta.l2_dirty) {
		int skip = 0;

		if (odelta.l2_cache < 0) {
			ploop_err(0, "abort: odelta.l2_cache < 0");
			ret = -1;
			goto merge_done;
		}
		if (odelta.l2_cache >= odelta.l1_size) {
			ploop_err(0, "abort: odelta.l2_cache >= odelta.l1_size");
			ret = -1;
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
		if (odelta.fops->fsync(odelta.fd)) {
			ploop_err(errno, "fsync");
			ret = SYSEXIT_FSYNC;
			goto merge_done;
		}
	}

	if (!raw && clear_delta(&odelta)) {
		ploop_err(errno, "clear_delta");
		ret = SYSEXIT_WRITE;
	} else {
		if (odelta.fops->fsync(odelta.fd)) {
			ploop_err(errno, "fsync");
			ret = SYSEXIT_FSYNC;
		}
	}

merge_done:
	close_delta(&odelta);

	if (device && !ret) {
		int lfd;
		__u32 level;

		lfd = open(device, O_RDONLY);
		if (lfd < 0) {
			ploop_err(errno, "open dev");
			ret = SYSEXIT_DEVICE;
			goto merge_done2;
		}

		level = start_level + 1;

		for (i = start_level + 1; i <= end_level; i++) {
			ret = ioctl_device(lfd, PLOOP_IOC_DEL_DELTA, &level);
			if (ret) {
				close(lfd);
				goto merge_done2;
			}
		}

		if (merge_top) {
			ploop_log(0, "Merging top delta");
			ret = ioctl_device(lfd, PLOOP_IOC_MERGE, 0);
		}

		close(lfd);
	}
merge_done2:
	free(data_cache);
	deinit_delta_array(&da);
	return ret;
}

int ploop_merge_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid, int merge_mode)
{
	char conf[PATH_MAX];
	char dev[64];
	char *device = NULL;
	char *fname = NULL;
	char *parent_fname = NULL;
	char *child_fname = NULL;
	char *delete_fname = NULL;
	char *child_guid = NULL;
	char *parent_guid = NULL;
	char *names[3] = {};
	int ret;
	int start_level = -1;
	int end_level = -1;
	int merge_top = 0;
	int raw = (di->mode == PLOOP_RAW_MODE);
	int online = 0;
	int snap_idx;
	struct merge_info info = {};
	int i, nelem;

	ret = SYSEXIT_PARAM;
	snap_idx = find_snapshot_by_guid(di, guid);
	if (snap_idx == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		return ret;
	}
	fname = find_image_by_guid(di, guid);
	if (fname == NULL) {
		ploop_err(0, "Can't find image by uuid %s",
				guid);
		return ret;
	}
	if (merge_mode == PLOOP_MERGE_WITH_CHILD) {
		parent_guid = (char *)guid;
		parent_fname = fname;
		ret = ploop_get_child_by_uuid(di, guid, &child_guid);
		if (ret) {
			ploop_err(0, "Can't find child by uuid %s",
					child_guid);
			goto err;
		}
		child_fname = find_image_by_guid(di, child_guid);
		if (child_fname == NULL) {
			ploop_err(0, "Can't find image by uuid %s",
					child_guid);
			goto err;
		}
	} else if (merge_mode == PLOOP_MERGE_WITH_PARENT) {
		parent_guid = di->snapshots[snap_idx]->parent_guid;
		child_guid = (char *)guid;
		if (strcmp(parent_guid, NONE_UUID) == 0) {
			ploop_err(0, "Unable to merge base image");
			goto err;
		}
		child_fname = fname;
		parent_fname = find_image_by_guid(di, parent_guid);
		if (parent_fname == NULL) {
			ploop_err(0, "Can't find image by uuid %s",
					 parent_guid);
			goto err;
		}
	} else
		assert(0);

	nelem = ploop_get_child_count_by_uuid(di, parent_guid);
	if (nelem > 1) {
		ploop_err(0, "Unable to merge snapshot %s: it has %d children",
				parent_guid, nelem);
		return SYSEXIT_PARAM;
	}

	ret = ploop_find_dev_by_uuid(di, 1, dev, sizeof(dev));
	if (ret == -1)
		goto err;
	else if (ret == 0)
		online = 1;

	if (online) {
		if ((ret = get_delta_info(dev, &info)))
			goto err;
		nelem = get_list_size(info.names);
		for (i = 0; info.names[i] != NULL; i++) {
			ret = ploop_fname_cmp(info.names[i], child_fname);
			if (ret == -1) {
				goto err;
			} else if (ret == 0) {
				child_fname = info.names[i];
				end_level = nelem - i - 1;
				continue;
			}
			ret = ploop_fname_cmp(info.names[i], parent_fname);
			if (ret == -1)
				goto err;
			else if (ret == 0) {
				parent_fname = info.names[i];
				start_level = nelem - i - 1;
			}
		}

		if (end_level != -1 && start_level != -1) {
			if (end_level != start_level + 1) {
				ploop_err(0, "Inconsistensy detected %s [%d] %s [%d]",
						parent_fname, end_level, child_fname, start_level);
				ret = SYSEXIT_PARAM;
				goto err;
			}
			device = dev;
			raw = info.raw;
			merge_top = (info.top_level == end_level);
		} else if (end_level == -1 && start_level == -1) {
			online = 0;
		} else {
			ploop_err(0, "Inconsistensy detected %s [%d] %s [%d]",
					parent_fname, end_level, child_fname, start_level);
			ret = SYSEXIT_PARAM;
			goto err;
		}
	}
	if (!online) {
		start_level = 0;
		end_level = 1;
	}

	names[0] = strdup(child_fname);
	if (names[0] == NULL) {
		ret = SYSEXIT_MALLOC;
		goto err;
	}
	names[1] = strdup(parent_fname);
	if (names[1] == NULL) {
		ret = SYSEXIT_MALLOC;
		goto err;
	}
	names[2] = NULL;

	/* make validation before real merge */
	ret = ploop_di_merge_image(di, child_guid, &delete_fname);
	if (ret)
		goto err;

	ret = merge_image(device, start_level, end_level, raw, merge_top, names);
	if (ret)
		goto err;

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	ret = ploop_store_diskdescriptor(conf, di);
	if (ret)
		goto err;
	ploop_log(0, "Removing %s", delete_fname);
	if (unlink(delete_fname)) {
		ploop_err(errno, "unlink %s", delete_fname);
		ret = SYSEXIT_UNLINK;
	}
	if (ret == 0)
		ploop_log(0, "ploop snapshot %s has been successfully merged",
				guid);

err:
	for (i = 0; names[i] != NULL; i++)
		free(names[i]);

	free(delete_fname);
	free_images_list(info.names);

	return ret;
}

int ploop_merge_snapshot(struct ploop_disk_images_data *di, struct ploop_merge_param *param)
{
	int ret = SYSEXIT_PARAM;
	const char *guid = NULL;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	if (param->guid != NULL)
		guid = param->guid;
	else if (!param->merge_all)
		guid = di->top_guid;

	if (guid != NULL) {
		ret = ploop_merge_snapshot_by_guid(di, guid, PLOOP_MERGE_WITH_PARENT);
	} else {
		while (di->nsnapshots != 1) {
			ret = ploop_merge_snapshot_by_guid(di, di->top_guid, PLOOP_MERGE_WITH_PARENT);
			if (ret)
				break;
		}
	}
	ploop_unlock_dd(di);

	return ret;
}
