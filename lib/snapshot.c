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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>

#include "ploop.h"

/* lock temporary snapshot by mount */
#define TSNAPSHOT_MOUNT_LOCK_MARK	"~"

static int is_old_snapshot_format(struct ploop_disk_images_data *di)
{
	if (di->top_guid != NULL && !guidcmp(di->top_guid, TOPDELTA_UUID))
		return 0;

	ploop_err(0, "Snapshot is in old format");
	return 1;
}

/* delete snapshot by guid
 * 1) if guid is not active and last -> delete guid
 * 2) if guid is not last merge with child -> delete child
 */
static int do_delete_snapshot(struct ploop_disk_images_data *di, const char *guid)
{
	int ret;
	char conf[PATH_MAX];
	char *fname = NULL;
	int nelem = 0;
	char dev[64];
	int snap_id;

	if (is_old_snapshot_format(di))
		return SYSEXIT_PARAM;

	snap_id = find_snapshot_by_guid(di, guid);
	if (snap_id == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1)
		return SYSEXIT_SYS;
	else if (ret == 0 && strcmp(di->top_guid, guid) == 0) {
		ret = SYSEXIT_PARAM;
		ploop_err(0, "Unable to delete active snapshot %s",
				guid);
		return SYSEXIT_PARAM;
	}

	nelem = ploop_get_child_count_by_uuid(di, guid);
	if (nelem == 0) {
		if (strcmp(di->snapshots[snap_id]->parent_guid, NONE_UUID) == 0) {
			ploop_err(0, "Unable to delete base image");
			return SYSEXIT_PARAM;
		}
		/* snapshot is not active and last -> delete */
		ret = ploop_di_remove_image(di, guid, 1, &fname);
		if (ret)
			return ret;
		get_disk_descriptor_fname(di, conf, sizeof(conf));
		ret = ploop_store_diskdescriptor(conf, di);
		if (ret) {
			free(fname);
			return ret;
		}
		ploop_log(0, "Removing %s", fname);
		if (fname != NULL && unlink(fname)) {
			ploop_err(errno, "unlink %s", fname);
			free(fname);
			return SYSEXIT_UNLINK;
		}

		free(fname);
		if (ret == 0)
			ploop_log(0, "ploop snapshot %s has been successfully deleted",
				guid);
	} else if (nelem == 1) {
		ret = ploop_merge_snapshot_by_guid(di, guid, PLOOP_MERGE_WITH_CHILD);
	} else {
		/* There no functionality to merge snapshot with >1 child */
		ret = SYSEXIT_PARAM;
		ploop_err(0, "There are %d references on %s snapshot: operation not supported",
				nelem, guid);
	}


	return ret;
}

int ploop_delete_snapshot(struct ploop_disk_images_data *di, const char *guid)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = do_delete_snapshot(di, guid);

	ploop_unlock_dd(di);

	return ret;
}

static int create_snapshot_ioctl(int lfd, int fd, struct ploop_ctl_delta *req)
{
	req->f.pctl_fd = fd;

	if (ioctl(lfd, PLOOP_IOC_SNAPSHOT, req) < 0) {
		ploop_err(errno, "PLOOP_IOC_SNAPSHOT");
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

int create_snapshot(const char *device, const char *delta, int syncfs)
{
	int ret;
	int lfd = -1;
	int fd = -1;
	off_t bdsize;
	struct ploop_ctl_delta req;
	__u32 blocksize;
	int version;

	ret = ploop_complete_running_operation(device);
	if (ret)
		return ret;

	ret = get_image_param_online(device, &bdsize,
			&blocksize, &version);
	if (ret)
		return ret;

	lfd = open(device, O_RDONLY);
	if (lfd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		return SYSEXIT_DEVICE;
	}

	fd = create_snapshot_delta(delta, blocksize, bdsize, version);
	if (fd < 0) {
		ret = SYSEXIT_OPEN;
		goto err;
	}

	memset(&req, 0, sizeof(req));

	req.c.pctl_format = PLOOP_FMT_PLOOP1;
	req.c.pctl_flags = syncfs ? PLOOP_FLAG_FS_SYNC : 0;
	req.c.pctl_cluster_log = ffs(blocksize) - 1;
	req.c.pctl_size = 0;
	req.c.pctl_chunks = 1;
	req.f.pctl_type = PLOOP_IO_AUTO;

	ploop_log(0, "Creating snapshot dev=%s img=%s", device, delta);
	ret = create_snapshot_ioctl(lfd, fd, &req);
	if (ret)
		unlink(delta);
err:
	if (lfd >= 0)
		close(lfd);
	if (fd >= 0)
		close(fd);

	return ret;
}

static int get_snapshot_count(struct ploop_disk_images_data *di)
{
	int n;
	char **images;

	images = make_images_list(di, di->top_guid, 1);
	if (images == NULL)
		return -1;
	n = get_list_size(images);
	free_images_list(images);

	return n;
}

static int do_create_snapshot(struct ploop_disk_images_data *di,
		struct ploop_snapshot_param *param, int temporary)
{
	int ret;
	int fd;
	char dev[64];
	char snap_guid[61];
	char file_guid[61];
	char fname[PATH_MAX];
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	int online = 0;
	int n;
	off_t size;
	__u32 blocksize;
	int version;

	if (param->guid != NULL && !is_valid_guid(param->guid)) {
		ploop_err(0, "Incorrect guid %s", param->guid);
		return SYSEXIT_PARAM;
	}

	if (is_old_snapshot_format(di))
		return SYSEXIT_PARAM;

	ret = merge_temporary_snapshots(di);
	if (ret)
		return ret;

	ret = gen_uuid_pair(snap_guid, sizeof(snap_guid),
			file_guid, sizeof(file_guid));
	if (ret) {
		ploop_err(errno, "Can't generate uuid");
		return ret;
	}

	if (param->guid != NULL) {
		if (find_snapshot_by_guid(di, param->guid) != -1) {
			ploop_err(0, "The snapshot %s already exist",
				param->guid);
			return SYSEXIT_PARAM;
		}
		strcpy(snap_guid, param->guid);
	}
	n = get_snapshot_count(di);
	if (n == -1) {
		return SYSEXIT_PARAM;
	} else if (n > 128-2) {
		/* The number of images limited by 128
		   so the snapshot limit 128 - base_image - one_reserverd
		 */
		ploop_err(errno, "Unable to create a snapshot."
			" The maximum number of snapshots (%d) has been reached",
			n-1);
		return SYSEXIT_PARAM;
	}

	snprintf(fname, sizeof(fname), "%s.%s",
			di->images[0]->file, file_guid);
	ploop_di_change_guid(di, di->top_guid, snap_guid);
	if (temporary)
		ploop_di_set_temporary(di, snap_guid);

	ret = ploop_di_add_image(di, fname, TOPDELTA_UUID, snap_guid);
	if (ret)
		return ret;

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1)
		return SYSEXIT_SYS;
	else if (ret == 0)
		online = 1;

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		return ret;

	if (!online) {
		// offline snapshot
		ret = get_image_param_offline(di, snap_guid, &size, &blocksize, &version);
		if (ret)
			goto err;

		fd = create_snapshot_delta(fname, blocksize, size, version);
		if (fd < 0) {
			ret = SYSEXIT_CREAT;
			goto err;
		}
		close(fd);
	} else {
		// Always sync fs
		ret = create_snapshot(dev, fname, 1);
		if (ret)
			goto err;
	}

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
	}

	if (ret && !online && unlink(fname))
		ploop_err(errno, "Can't unlink %s",
				fname);

	ploop_log(0, "ploop %s %s has been successfully created",
			get_snap_str(temporary), snap_guid);
err:
	if (ret && unlink(conf_tmp))
		ploop_err(errno, "Can't unlink %s", conf_tmp);

	return ret;
}


int ploop_create_snapshot(struct ploop_disk_images_data *di,
		struct ploop_snapshot_param *param)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = do_create_snapshot(di, param, 0);

	ploop_unlock_dd(di);

	return ret;
}

static int open_snap_holder(const char *device, int *holder_fd)
{
	*holder_fd = open(device, O_RDONLY);
	if (*holder_fd == -1) {
		ploop_err(errno, "failed to open %s", device);
		return SYSEXIT_OPEN;
	}

	return 0;
}

int ploop_create_temporary_snapshot(struct ploop_disk_images_data *di,
		struct ploop_tsnapshot_param *param, int *holder_fd)
{
	int ret;
	struct ploop_snapshot_param snap_param = {
		.guid = param->guid
	};
	struct ploop_mount_param mount_param = {
		.ro = 1,
		.guid = param->guid,
		.target = param->target
	};
	char component_name[PLOOP_COOKIE_SIZE];

	if (di == NULL || param == NULL)
		return SYSEXIT_PARAM;

	if (param->guid == NULL) {
		ploop_err(0, "Snapshot guid is not specified");
		return SYSEXIT_PARAM;
	}

	if (param->component_name == NULL) {
		ploop_err(0, "Component name is not specified");
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = do_create_snapshot(di, &snap_param, 1);
	if (ret)
		goto err_unlock;

	/* FIXME: should be processed from 'struct ploop_mount_param' only ?? */
	char *t = di->runtime->component_name;
	snprintf(component_name, sizeof(component_name), "%s%s",
			holder_fd == NULL ? TSNAPSHOT_MOUNT_LOCK_MARK : "",
			param->component_name);
	di->runtime->component_name = component_name;

	ret = mount_image(di, &mount_param, 0);
	di->runtime->component_name = t;

	if (ret)
		goto err_merge;

	strncpy(param->device, mount_param.device, sizeof(param->device));
	param->device[sizeof(param->device) - 1] = '\0';

	if (holder_fd != NULL) {
		ret = open_snap_holder(param->device, holder_fd);
		if (ret)
			goto err;
	}

	ploop_unlock_dd(di);

	return 0;

err:
	ploop_umount(mount_param.device, di);

err_merge:
	ploop_merge_snapshot_by_guid(di, param->guid, PLOOP_MERGE_WITH_CHILD);

err_unlock:
	ploop_unlock_dd(di);

	return ret;
}

static int is_device_inuse(const char *dev)
{
	int count;
	char fname[PATH_MAX];
	char cookie[PLOOP_COOKIE_SIZE] = "";

	if (ploop_get_attr(dev, "open_count", &count))
		return 1;

	/* detect if snapshot locked by ploop mount */
	snprintf(fname, sizeof(fname), "/sys/block/%s/pstate/cookie",
			memcmp(dev, "/dev/", 5) == 0 ? dev + 5 : dev);
	if (read_line_quiet(fname, cookie, sizeof(cookie)))
		return 1;

	if (!strncmp(cookie, TSNAPSHOT_MOUNT_LOCK_MARK,
				sizeof(TSNAPSHOT_MOUNT_LOCK_MARK)-1))
		return 1;

	/* snap holder + mount */
	if (count >= 2)
		return 1;

	/* if there single reference we should detect is holder is alive */
	if (count == 1 && ploop_get_mnt_by_dev(dev, fname, sizeof(fname)) != 0)
		return 1;

	return 0;
}

static int is_snapshot_in_use(struct ploop_disk_images_data *di,
		const char *guid)
{
	char *fname;
	char **devs, **dev;
	int ret, inuse;

	fname = find_image_by_guid(di, guid);
	if (fname == NULL)
		return 1;

	ret = ploop_get_dev_by_delta(di->images[0]->file,
			fname, NULL, &devs);
	if (ret == -1)  /* return inuse on error */
		return 1;
	else if (ret == 1) /* no device found */
		return 0;

	inuse = 0;
	for (dev = devs; *dev != NULL; dev++)
		if (is_device_inuse(*dev)) {
			inuse = 1;
			break;
		}

	ploop_free_array(devs);

	return inuse;
}

int merge_temporary_snapshots(struct ploop_disk_images_data *di)
{
	int i, ret;

	for (i = 0; i < di->nsnapshots; ) {
		const char *guid = di->snapshots[i]->guid;

		if (di->snapshots[i]->temporary &&
				!is_snapshot_in_use(di, guid)) {

			ret = do_delete_snapshot(di, guid);
			if (ret)
				return ret;

			/* di has modified, start from beginning */
			i = 0;
			continue;
		}
		i++;
	}

	return 0;
}

int ploop_switch_snapshot_ex(struct ploop_disk_images_data *di,
		struct ploop_snapshot_switch_param *param)
{
	int ret;
	int fd;
	char dev[64];
	char uuid[61];
	char file_uuid[61];
	char new_top_delta_fname[PATH_MAX] = "";
	char *old_top_delta_fname = NULL;
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	off_t size;
	const char *guid = param->guid;
	int flags = param->flags;
	__u32 blocksize;
	int version;
	int snap_id;

	if (!is_valid_guid(guid)) {
		ploop_err(0, "Incorrect guid %s", guid);
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	if (is_old_snapshot_format(di)) {
		ret = SYSEXIT_PARAM;
		goto err_cleanup1;

	}

	ret = SYSEXIT_PARAM;
	if (strcmp(di->top_guid, guid) == 0) {
		ploop_err(errno, "Nothing to do, already on %s snapshot",
				guid);
		goto err_cleanup1;
	}

	snap_id = find_snapshot_by_guid(di, guid);
	if (snap_id== -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		goto err_cleanup1;
	}

	if (di->snapshots[snap_id]->temporary) {
		ploop_err(0, "Snapshot %s is temporary", guid);
		goto err_cleanup1;
	}

	// Read image param from snapshot we going to switch on
	ret = get_image_param(di, guid, &size, &blocksize, &version);
	if (ret)
		goto err_cleanup1;

	ret = gen_uuid_pair(uuid, sizeof(uuid), file_uuid, sizeof(file_uuid));
	if (ret) {
		ploop_err(errno, "Can't generate uuid");
		goto err_cleanup1;
	}

	if (!(flags & PLOOP_SNAP_SKIP_TOPDELTA_DESTROY)) {
		// device should be stopped
		ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
		if (ret == -1) {
			ret = SYSEXIT_SYS;
			goto err_cleanup1;
		} else if (ret == 0) {
			ret = SYSEXIT_PARAM;
			ploop_err(0, "Unable to perform switch to snapshot operation"
					" on running device (%s)",
					dev);
			goto err_cleanup1;
		}
		ret = ploop_di_remove_image(di, di->top_guid, 0, &old_top_delta_fname);
		if (ret)
			goto err_cleanup1;
	} else if (param->guid_old != NULL) {
		if (!is_valid_guid(param->guid_old)) {
			ploop_err(0, "Incorrect guid %s", param->guid_old);
			goto err_cleanup1;
		}

		if (find_snapshot_by_guid(di, param->guid_old) != -1) {
			ploop_err(0, "Incorrect guid_old %s: already exists",
					param->guid_old);
			goto err_cleanup1;
		}

		ploop_di_change_guid(di, di->top_guid, param->guid_old);
	}

	if (flags & PLOOP_SNAP_SKIP_TOPDELTA_CREATE) {
		ploop_di_change_guid(di, guid, TOPDELTA_UUID);
	} else {
		snprintf(new_top_delta_fname, sizeof(new_top_delta_fname), "%s.%s",
			di->images[0]->file, file_uuid);
		ret = ploop_di_add_image(di, new_top_delta_fname, TOPDELTA_UUID, guid);
		if (ret)
			goto err_cleanup1;
	}

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err_cleanup1;

	// offline snapshot
	if (!(flags & PLOOP_SNAP_SKIP_TOPDELTA_CREATE)) {
		fd = create_snapshot_delta(new_top_delta_fname, blocksize, size, version);
		if (fd == -1) {
			ret = SYSEXIT_CREAT;
			goto err_cleanup2;
		}
		close(fd);
	}

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
		goto err_cleanup3;
	}

	/* destroy precached info */
	drop_statfs_info(di->images[0]->file);

	if (old_top_delta_fname != NULL) {
		ploop_log(0, "Removing %s", old_top_delta_fname);
		if (unlink(old_top_delta_fname))
			ploop_err(errno, "Can't unlink %s",
					old_top_delta_fname);
	}

	ploop_log(0, "ploop snapshot has been successfully switched");
err_cleanup3:
	if (ret && unlink(new_top_delta_fname))
		ploop_err(errno, "Can't unlink %s",
				conf_tmp);
err_cleanup2:
	if (ret && unlink(conf_tmp))
		ploop_err(errno, "Can't unlink %s",
				conf_tmp);
err_cleanup1:
	ploop_unlock_dd(di);
	free(old_top_delta_fname);

	return ret;
}

int ploop_switch_snapshot(struct ploop_disk_images_data *di, const char *guid, int flags)
{
	struct ploop_snapshot_switch_param param = {};

	param.guid = (char *) guid;
	param.flags = flags;

	return ploop_switch_snapshot_ex(di, &param);
}

int ploop_delete_top_delta(struct ploop_disk_images_data *di)
{
	int output = SYSEXIT_PLOOPFMT;
	if (NULL != di->top_guid)
	{
		/* NB. ploop_lock_di inside ploop_delete_snapshot
		 * resets the di content thus the second argument
		 * becomes invalid. backup it and pass that backup
		 * value.
		 * */
		output = ploop_delete_snapshot(di, strdupa(di->top_guid));
	}
	return output;
}
