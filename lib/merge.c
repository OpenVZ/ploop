/*
 *  Copyright (c) 2008-2017 Parallels International GmbH.
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
		int start_level)
{
	off_t src_size = 0; /* bdsize of source delta to merge */
	off_t dst_size = 0; /* bdsize of destination delta for merge */
	int i, devfd;
	struct ploop_pvd_header *vh;
	struct grow_maps grow_maps;
	char *fmt;
	int dst_is_raw = 0;
	void *buf = NULL;
	struct delta odelta = {.fd = -1};
	int ret;
	__u64 cluster;

	if (top) {
		if ((ret = ploop_get_size(device, &src_size)))
			return ret;
	} else if ((ret = read_size_from_image(src_image, 0, &src_size)))
		goto done;

	if (find_delta_names(device, start_level, start_level, NULL, &fmt)) {
		ploop_err(errno, "find_delta_names");
		ret = SYSEXIT_SYSFS;
		goto done;
	}

	if (strcmp(fmt, "raw") == 0)
		dst_is_raw = 1;

	if ((ret = read_size_from_image(dst_image, dst_is_raw, &dst_size)))
		goto done;

	if (src_size <= dst_size) {
		ret = 0;
		goto done;
	}

	if (dst_is_raw) {
		ret = grow_raw_delta(dst_image, S2B(src_size - dst_size));
		goto done;
	}

	/* Here we know for sure that destination delta is in ploop1 format */
	if (open_delta(&odelta, dst_image, O_RDWR, OD_NOFLAGS)) {
		ploop_err(errno, "open_delta");
		ret = SYSEXIT_OPEN;
		goto done;
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

	if (clear_delta(&odelta)) {
		ploop_err(errno, "clear_delta");
		ret = SYSEXIT_WRITE;
		goto done;
	}

	devfd = open(device, O_RDONLY|O_CLOEXEC);
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

	if (fsync(odelta.fd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_FSYNC;
	}

done:
	free(buf);
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

	int n = info->end_level - info->start_level + 1;
	info->names = calloc(1, (n + 1) * sizeof(char *));
	info->info = calloc(1, n * sizeof(struct image_info));
	if (info->names == NULL || info->info == NULL) {
		ploop_err(errno, "malloc");
		return SYSEXIT_MALLOC;
	}

	if (find_delta_info(device, info->start_level, info->end_level,
			info->names, info->info, &fmt))
		return SYSEXIT_SYSFS;

	if (strcmp(fmt, "raw") == 0)
		info->raw = 1;

	return 0;
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
	__u32 blocksize = 0;
	__u32 prev_blocksize = 0;
	int version = PLOOP_FMT_UNDEFINED;
	const char *merged_image;

	if (new_image && access(new_image, F_OK) == 0) {
		ploop_err(EEXIST, "Can't merge to new image %s", new_image);
		return SYSEXIT_PARAM;
	}

	if (device) {
		if (start_level >= end_level || start_level < 0) {
			ploop_err(0, "Invalid parameters: start_level %d end_level %d",
					start_level, end_level);
			return SYSEXIT_PARAM;
		}

		if (!new_image)
			if ((ret = grow_lower_delta(device, merge_top,
						images[0],
						images[end_level - start_level],
						start_level)))
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


		if (end_level == 0) {
			int lfd;

			if (new_image) {
				/* Special case: only one delta below top one:
				 * copy it to new_image and do ploop_replace()
				 */
				ret = copy_delta(names[0], new_image);
				if (ret)
					return ret;

				ret = replace_delta(device, start_level, new_image);
				if (ret)
					goto rm_delta;
			}
			ploop_log(0, "Merging top delta");
			lfd = open(device, O_RDONLY|O_CLOEXEC);
			if (lfd < 0) {
				ploop_err(errno, "open dev %s", device);
				ret = SYSEXIT_DEVICE;
				goto rm_delta;
			}

			ret = ioctl_device(lfd, PLOOP_IOC_MERGE, 0);
			close(lfd);

rm_delta:
			if (ret && new_image)
				unlink(new_image);

			return ret;
		}
		last_delta = end_level - start_level;
	} else {
		last_delta = get_list_size(images) - 1;
		names = images;
	}

	if (new_image) {
		last_delta++;
		merged_image = new_image;
	}
	else {
		merged_image = names[last_delta];
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
			ret = SYSEXIT_PLOOPFMT;
			goto merge_done2;
		}
		prev_blocksize = blocksize;

		if (i != 0 && version != da.delta_arr[i].version) {
			ploop_err(errno, "Wrong version %s %d [prev %d]",
					names[i], da.delta_arr[i].version, version);
			ret = SYSEXIT_PLOOPFMT;
			goto merge_done2;
		}
		version = da.delta_arr[i].version;
	}
	if (blocksize == 0) {
		ploop_err(errno, "Wrong blocksize 0");
		ret = SYSEXIT_PLOOPFMT;
		goto merge_done2;

	}
	cluster = S2B(blocksize);

	if (new_image) { /* Create it */
		struct ploop_pvd_header *vh;
		off_t size;
		int mode = (raw) ? PLOOP_RAW_MODE : PLOOP_EXPANDED_MODE;

		vh = (struct ploop_pvd_header *)da.delta_arr[0].hdr0;
		size = get_SizeInSectors(vh);

		ret = create_image(new_image, blocksize, size, mode, version);
		if (ret)
			goto merge_done2;
	}

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
		int lfd;
		__u32 level;

		lfd = open(device, O_RDONLY|O_CLOEXEC);
		if (lfd < 0) {
			ploop_err(errno, "open dev");
			ret = SYSEXIT_DEVICE;
			goto merge_done2;
		}

		if (new_image) {
			int fd;

			fd = open(new_image, O_DIRECT|O_RDONLY|O_CLOEXEC);
			if (fd < 0) {
				ploop_err(errno, "Can't open %s", new_image);
				ret = SYSEXIT_OPEN;
				goto close_lfd;
			}
			ret = do_replace_delta(lfd, start_level, fd, blocksize, new_image);
			close(fd);
			if (ret)
				goto close_lfd;
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
close_lfd:
		close(lfd);
	}

merge_done2:
	if (!device && !raw && ret == 0)
		ploop_move_cbt(images[1], images[0]);

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
		char **names, const char *new_delta)
{
	char basedir[PATH_MAX];
	char imglist[LOG_BUF_SIZE];
	char merged_image[PATH_MAX];
	int i, pos = 0, nimg;

	get_basedir(di->runtime->xml_fname, basedir, sizeof(basedir));

	nimg = get_list_size(names) - 1;
	if (new_delta) {
		nimg++;
		// merged_image is new_delta;
		normalize_image_name(basedir, new_delta,
				merged_image, sizeof(merged_image));
	}
	else {
		// merged_image is names[nimg];
		normalize_image_name(basedir, names[nimg],
				merged_image, sizeof(merged_image));
	}

	for (i = 0; i < nimg; i++) {
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
			nimg > 1 ? "s" : "",
			imglist,
			new_delta ? "(new) " : "", merged_image);
}

int ploop_merge_snapshot_by_guid(struct ploop_disk_images_data *di,
		const char *guid, const char *new_delta)
{
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	char dev[64];
	char *device = NULL;
	char *fname = NULL;
	char *parent_fname = NULL;
	char *child_fname = NULL;
	char *delete_fname = NULL;
	const char *child_guid = NULL;
	const char *parent_guid = NULL;
	char *names[3] = {};
	int ret;
	int start_level = -1;
	int end_level = -1;
	int merge_top = 0;
	int raw = 0;
	int online = 0;
	int parent_idx, child_idx; /* parent and child snapshot ids */
	struct merge_info info = {};
	int i, nelem;

	ret = SYSEXIT_PARAM;
	child_idx = find_snapshot_by_guid(di, guid);
	if (child_idx == -1) {
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

	parent_guid = di->snapshots[child_idx]->parent_guid;
	child_guid = guid;
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
	parent_idx = find_snapshot_by_guid(di, parent_guid);
	if (parent_idx == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				parent_guid);

		goto err;
	}

	nelem = ploop_get_child_count_by_uuid(di, parent_guid);
	if (nelem > 1) {
		ploop_err(0, "Can't merge to snapshot %s: it has %d children",
				parent_guid, nelem);
		goto err;
	}

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	}
	else if (ret == 0)
		online = 1;

	if (online) {
		struct stat st_child, st_parent;

		if (stat(child_fname, &st_child)) {
			ploop_err(errno, "Can't stat %s", child_fname);
			ret = SYSEXIT_FSTAT;
			goto err;
		}

		if (stat(parent_fname, &st_parent)) {
			ploop_err(errno, "Can't stat %s", parent_fname);
			ret = SYSEXIT_FSTAT;
			goto err;
		}

		ret = complete_running_operation(di, dev);
		if (ret)
			goto err;
		if ((ret = get_delta_info(dev, &info)))
			goto err;
		nelem = get_list_size(info.names);
		for (i = 0; info.names[i] != NULL; i++) {
			if (info.info[i].ino) {
				ret = (st_child.st_dev != info.info[i].dev ||
					st_child.st_ino != info.info[i].ino);
			} else
				ret = fname_cmp(info.names[i], &st_child);
			if (ret == -1) {
				goto err;
			} else if (ret == 0) {
				end_level = nelem - i - 1;
				continue;
			}

			if (info.info[i].ino) {
				ret = (st_parent.st_dev != info.info[i].dev ||
					st_parent.st_ino != info.info[i].ino);
			} else
				ret = fname_cmp(info.names[i], &st_parent);
			if (ret == -1)
				goto err;
			else if (ret == 0)
				start_level = nelem - i - 1;
		}

		if (end_level != -1 && start_level != -1) {
			if (end_level != start_level + 1) {
				ploop_err(0, "Inconsistency detected %s [%d] %s [%d]",
						parent_fname, end_level, child_fname, start_level);
				ret = SYSEXIT_PARAM;
				goto err;
			}
			device = dev;
			if (start_level == 0)
				raw = info.raw;
			merge_top = (info.top_level == end_level);
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
		start_level = 0;
		end_level = 1;
		/* Only base image could be in RAW format */
		if (di->mode == PLOOP_RAW_MODE &&
				!guidcmp(di->snapshots[parent_idx]->parent_guid, NONE_UUID))
			raw = 1;
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

	ret = check_snapshot_mount(di, parent_guid, parent_fname,
			di->snapshots[parent_idx]->temporary);
	if (ret)
		goto err;
	ret = check_snapshot_mount(di, child_guid, child_fname,
			di->snapshots[child_idx]->temporary);
	if (ret)
		goto err;

	ploop_log(0, "%sline %s merge %s -> %s%s",
			online ? "On": "Off",
			get_snap_str(di->snapshots[parent_idx]->temporary),
			child_guid, parent_guid,
			raw ? " (raw)" : "");
	log_merge_images_info(di, names, new_delta);

	/* make validation before real merge */
	ret = ploop_di_merge_image(di, child_guid, &delete_fname);
	if (ret)
		goto err;
	/* The parent_guid string was free'd by ploop_di_merge_image().
	 * Hint the compiler/static analyser to error out if it is used.
	 */
	parent_guid = NULL;

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err;

	ret = merge_image(device, start_level, end_level, raw, merge_top, names, new_delta);
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

		idx = find_image_idx_by_guid(di, child_guid);
		if (idx == -1) {
			ploop_err(0, "Unable to find image by uuid %s",
					child_guid);
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
	for (i = 0; names[i] != NULL; i++)
		free(names[i]);

	free(delete_fname);
	ploop_free_array(info.names);
	free(info.info);

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
		ret = ploop_merge_snapshot_by_guid(di, guid, param->new_delta);
	} else {
		while (di->nsnapshots != 1) {
			ret = ploop_merge_snapshot_by_guid(di, di->top_guid, param->new_delta);
			if (ret)
				break;
		}
	}
	ploop_unlock_dd(di);

	return ret;
}
