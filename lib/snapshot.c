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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <uuid/uuid.h>

#include "ploop.h"
#include "cbt.h"

/* lock temporary snapshot by mount */
#define TSNAPSHOT_MOUNT_LOCK_MARK	"~"

static int is_old_snapshot_format(struct ploop_disk_images_data *di)
{
	return 0;

	if (di->top_guid != NULL && !guidcmp(di->top_guid, TOPDELTA_UUID))
		return 0;

	ploop_err(0, "Snapshot is in old format");
	return 1;
}

/* delete snapshot by guid
 * 1) if guid is not active and last -> delete guid
 * 2) if guid is not last merge with child -> delete child
 */
int do_delete_snapshot(struct ploop_disk_images_data *di, const char *guid)
{
	int ret;
	char conf[PATH_MAX];
	int nelem = 0;
	char dev[64];
	int snap_id;

	if (di->runtime->image_type == QCOW_TYPE)
		return qcow_delete_snapshot(di, guid);

	if (is_old_snapshot_format(di) || guid == NULL)
		return SYSEXIT_PARAM;

	snap_id = find_snapshot_by_guid(di, guid);
	if (snap_id == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		return SYSEXIT_NOSNAP;
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
		struct ploop_snapshot_data *snap =  di->snapshots[snap_id];

		if (strcmp(snap->parent_guid, NONE_UUID) == 0) {
			ploop_err(0, "Unable to delete base image");
			return SYSEXIT_PARAM;
		}

		if (strcmp(di->top_guid, guid) == 0) {
			int id = find_snapshot_by_guid(di, snap->parent_guid);
			if (id == -1) {
				ploop_err(0, "Can't find snapshot by uuid %s",
						snap->parent_guid);
				return SYSEXIT_PARAM;
			}

			if (di->snapshots[id]->temporary) {
				ploop_err(0, "Unable to delete top delta,"
						" parent snapshot is temporary");
				return SYSEXIT_PARAM;
			}
		}

		char *fname = find_image_by_guid(di, guid);
		if (fname == NULL) {
			ploop_err(0, "Unable to find image by uuid %s",
					guid);
			return SYSEXIT_PARAM;
		}

		ret = check_snapshot_mount(di, guid, fname, snap->temporary);
		if (ret)
			return ret;

		fname = NULL;
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
		ret = ploop_delete_snapshot_by_guid(di, guid, NULL);
	} else if (!di->snapshots[snap_id]->temporary) {
		ploop_log(1, "Warning: Unable to delete snapshot %s as there are %d references"
				" to it; marking it as temporary instead",
				guid, nelem);
		di->snapshots[snap_id]->temporary = 1;
		get_disk_descriptor_fname(di, conf, sizeof(conf));
		ret = ploop_store_diskdescriptor(conf, di);
	}

	return ret;
}

int ploop_delete_snapshot(struct ploop_disk_images_data *di, const char *guid)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = do_delete_snapshot(di, guid);
	if (ret == 0)
		merge_temporary_snapshots(di);

	ploop_unlock_dd(di);

	return ret;
}

static int create_snapshot_online(struct ploop_disk_images_data *di,
		const char *device, const char *new_top)
{
	int rc;
	off_t size;
	char *top;

	ploop_log(0, "Creating snapshot dev=%s img=%s", device, new_top);
	if (new_top == NULL)
		return SYSEXIT_PARAM;

	rc = get_image_param_online(di, device, &top, &size, NULL, NULL, NULL);
	if (rc)
		return rc;

	rc = update_delta_inuse(new_top, SIGNATURE_DISK_IN_USE);
	if (rc)
		goto err;

	rc = ploop_suspend_device(device);
	if (rc)
		goto err_resume;

	rc = update_delta_inuse(top, 0);
	if (rc)
		goto err_resume;

	rc = dm_reload(di, device, size, RELOAD_SKIP_SUSPEND);

err_resume:
	ploop_resume_device(device);
err:
	free(top);

	return rc;
}

static int create_cbt_snapshot(struct ploop_disk_images_data *di, int fd,
		const char *device, const char *delta,
		 const __u8 *cbt_u, const char *prev_delta)
{
	int ret;
	char dev[64], part[64];
	void *or_data = NULL;

	ret = ploop_get_devname(NULL, device, dev, sizeof(dev), part, sizeof(part));
	if (ret)
		return ret;

	ploop_log(1, "freeze %s", device);
	ploop_suspend_device(part);
	if (ret)
		return ret;

	ret = cbt_snapshot_prepare(fd, cbt_u, &or_data);
	if (ret)
		goto err;

	ret = create_snapshot_online(di, device, delta);
	if (ret)
		goto err;

	ret = cbt_snapshot(fd, cbt_u, prev_delta, or_data);

err:
	ploop_log(0, "unfreeze %s", device);
	ploop_resume_device(part);

	free(or_data);

	return ret;
}

int create_snapshot(struct ploop_disk_images_data *di,
		const char *device, const __u8 *cbt_u,
		const char *delta, const char *prev_delta)
{
	int ret, fd;

	fd = open(device, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		return SYSEXIT_DEVICE;
	}

	if (cbt_u == NULL)
		ret = create_snapshot_online(di, device, delta);
	else
		ret = create_cbt_snapshot(di, fd, device, delta, cbt_u, prev_delta);

	if (ret)
		unlink(delta);
	close(fd);

	return ret;
}

static int get_snapshot_count(struct ploop_disk_images_data *di)
{
	int n;
	char **images;

	if (di->top_guid == NULL)
		return 0;
	images = make_images_list(di, di->top_guid, 1);
	if (images == NULL)
		return -1;
	n = get_list_size(images);
	ploop_free_array(images);

	return n;
}

static int get_new_delta_fname(struct ploop_disk_images_data *di,
		const char *guid, const char *snap_dir, char *out,
		int size)
{
	char *p, *dir;
	char *name = strdupa(di->images[0]->file);
	
	p = strrchr(get_basename(name), '.');
	if (p != NULL && p[1] == '{')
		*p = '\0';
	
	if (snap_dir != NULL) {
		dir = realpath(snap_dir, NULL);
		if (dir == NULL) {
			ploop_err(errno, "Error in realpath(%s)", snap_dir);
			return SYSEXIT_CREAT;
		}
		snprintf(out, size, "%s/%s.%s", dir, name, guid);
		free(dir);
	} else
		snprintf(out, size, "%s.%s", name, guid);

	return 0;
}

int do_create_snapshot(struct ploop_disk_images_data *di,
		const char *guid, const char *snap_dir,
		const char *cbt_uuid, int flags)
{
	int ret, rc;
	int fd;
	char dev[64];
	char snap_guid[UUID_SIZE];
	char top_guid[UUID_SIZE];
	char file_guid[UUID_SIZE];
	char fname[PATH_MAX];
	const char *prev_fname = NULL;
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	int online = 0;
	int temporary = flags & SNAP_TYPE_TEMPORARY;
	int n;
	off_t size;
	__u32 blocksize;
	int version;
	uuid_t u;
	const __u8 *cbt_u = NULL;

	if (cbt_uuid != NULL) {
		ploop_log(0, "Create snapshot CBT uuid=%s", cbt_uuid);
		if (uuid_parse(cbt_uuid, u)) {
			ploop_log(-1, "Incorrect cbt uuid is specified %s",
					cbt_uuid);
			return SYSEXIT_PARAM;
		}
		cbt_u = u;
	}

	if (guid != NULL && !is_valid_guid(guid)) {
		ploop_err(0, "Incorrect guid %s", guid);
		return SYSEXIT_PARAM;
	}

	if (is_old_snapshot_format(di))
		return SYSEXIT_PARAM;

	ret = gen_uuid_pair(snap_guid, sizeof(snap_guid),
			file_guid, sizeof(file_guid));
	if (ret)
		return ret;

	if (di->vol && di->vol->parent) {
	        ret = ploop_uuid_generate(top_guid, sizeof(top_guid));
        	if (ret)
                	return ret;
	} else
		strcpy(top_guid, TOPDELTA_UUID);


	if (guid != NULL) {
		if (find_snapshot_by_guid(di, guid) != -1) {
			ploop_err(0, "The snapshot %s already exist",
				guid);
			return SYSEXIT_PARAM;
		}
		strcpy(snap_guid, guid);
	}
	if (di->runtime->image_type == QCOW_TYPE)
		return qcow_create_snapshot(di, snap_guid);

	merge_temporary_snapshots(di);
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

	rc = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (rc == -1)
		return SYSEXIT_SYS;

	if (rc == 0) {
		if (!(flags & SNAP_TYPE_OFFLINE)) {
			online = 1;
			ret = complete_running_operation(di, dev);
			if (ret)
				return ret;
		}
		ret = get_image_param_online(di, dev, NULL, &size,
				&blocksize, &version, NULL);
		if (ret)
			return ret;
	} else {
		ret = get_image_param_offline(di, di->top_guid, &size, &blocksize, &version);
		if (ret == SYSEXIT_OPEN && errno == EBUSY) {
			/* repair top delta */
			char *topdelta[] = {find_image_by_guid(di, di->top_guid), NULL};
			blocksize = di->blocksize;

			ret = check_deltas(di, topdelta, 0, &blocksize,
					NULL, 0);
			if (ret)
				return ret;

			ret = get_image_param_offline(di, di->top_guid, &size, &blocksize, &version);
		}

		if (ret)
			return ret;
	}

	ret = get_new_delta_fname(di, file_guid, snap_dir, fname, sizeof(fname));
	if (ret)
		return ret;

	prev_fname = find_image_by_guid(di, di->top_guid);
	if (prev_fname == NULL) {
		ploop_err(0, "Unable to find image by uuid %s",
				di->top_guid);
		return SYSEXIT_PARAM;
	}

	ploop_di_change_guid(di, di->top_guid, snap_guid);
	if (temporary)
		ploop_di_set_temporary(di, snap_guid);

	ret = ploop_di_add_image(di, fname, top_guid, snap_guid);
	if (ret)
		return ret;

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		return ret;

	fd = create_snapshot_delta(fname, blocksize, size, version);
	if (fd < 0) {
		ret = SYSEXIT_CREAT;
		goto err;
	}
	close(fd);

	if (!online) {
		// offline snapshot
		if (cbt_u != NULL)
			ret = write_empty_cbt_to_image(fname, prev_fname, cbt_u);
		else if (di->mode != PLOOP_RAW_MODE) {
			if (rc == 0)
				ret = cbt_dump(di, dev, fname);
			else
				ret = ploop_move_cbt(fname, prev_fname);
		}
	} else
		ret = create_snapshot(di, dev, cbt_u, fname, prev_fname);
	if (ret)
		goto err;


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

	ret = do_create_snapshot(di, param->guid, param->snap_dir,
			param->cbt_uuid, 0);

	ploop_unlock_dd(di);

	return ret;
}

int ploop_create_snapshot_offline(struct ploop_disk_images_data *di,
		struct ploop_snapshot_param *param)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = do_create_snapshot(di, param->guid, param->snap_dir,
			param->cbt_uuid, SNAP_TYPE_OFFLINE);

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
	struct ploop_mount_param mount_param = { .ro = 1, };
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

	ret = do_create_snapshot(di, param->guid, param->snap_dir,
			param->cbt_uuid, SNAP_TYPE_TEMPORARY);
	if (ret)
		goto err_unlock;

	/* FIXME: should be processed from 'struct ploop_mount_param' only ?? */
	char *t = di->runtime->component_name;
	snprintf(component_name, sizeof(component_name), "%s%s",
			holder_fd == NULL ? TSNAPSHOT_MOUNT_LOCK_MARK : "",
			param->component_name);
	di->runtime->component_name = component_name;

	mount_param.guid = param->guid;
	mount_param.target = param->target;
	ret = ploop_mount(di, NULL, &mount_param, (di->mode == PLOOP_RAW_MODE));
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
	ploop_delete_snapshot_by_guid(di, param->guid, NULL);

err_unlock:
	ploop_unlock_dd(di);

	return ret;
}

int is_device_inuse(const char *dev)
{
	char fname[PATH_MAX];
	char cookie[PLOOP_COOKIE_SIZE] = "";
	struct dm_image_info i;

	if (dm_get_info(dev, &i))
	       return 1;

	if (cn_find_name(dev, cookie, sizeof(cookie), 0))
		return 1;

	if (!strncmp(cookie, TSNAPSHOT_MOUNT_LOCK_MARK,
				sizeof(TSNAPSHOT_MOUNT_LOCK_MARK)-1))
		return 0;

	/* snap holder + mount */
	if (i.open_count >= 2)
		return 1;

	/* if there single reference we should detect is holder is alive */
	if (i.open_count == 1 && ploop_get_mnt_by_dev(dev, fname, sizeof(fname)) != 0)
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

	ret = find_devs_by_delta(di, fname, &devs);
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
				!is_snapshot_in_use(di, guid))
		{
			int nsnapshots = di->nsnapshots;

			ret = do_delete_snapshot(di, guid);
			if (ret)
				return ret;

			/* di has modified, start from beginning */
			if (nsnapshots != di->nsnapshots) {
				i = 0;
				continue;
			}
		}
		i++;
	}

	return 0;
}

static int reset_top_delta(struct ploop_disk_images_data *di,
		struct ploop_snapshot_switch_param *param)
{
	int ret;
	char *old_top_delta_fname = NULL;
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	const char *guid = param->guid;

	ret = ploop_di_remove_image(di, di->top_guid, 0, &old_top_delta_fname);
	if (ret)
		return ret;

	ploop_di_change_guid(di, guid, TOPDELTA_UUID);

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err;

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
		goto err;
	}

	/* destroy precached info */
	drop_statfs_info(di->images[0]->file);

	if (old_top_delta_fname != NULL) {
		ploop_log(0, "Removing %s", old_top_delta_fname);
		if (unlink(old_top_delta_fname))
			ploop_err(errno, "Can't unlink %s",
					old_top_delta_fname);
	}

err:
	if (ret && unlink(conf_tmp))
		ploop_err(errno, "Can't unlink %s", conf_tmp);

	free(old_top_delta_fname);

	return ret;
}

int ploop_switch_snapshot_ex(struct ploop_disk_images_data *di,
		struct ploop_snapshot_switch_param *param)
{
	int ret;
	int fd;
	char dev[64];
	char uuid[UUID_SIZE];
	char file_uuid[UUID_SIZE];
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

	if (flags & PLOOP_SNAP_SKIP_TOPDELTA_CREATE) {
		ret = reset_top_delta(di, param);
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
			ret = SYSEXIT_PARAM;
			ploop_err(0, "Incorrect guid %s", param->guid_old);
			goto err_cleanup1;
		}

		if (find_snapshot_by_guid(di, param->guid_old) != -1) {
			ret = SYSEXIT_PARAM;
			ploop_err(0, "Incorrect guid_old %s: already exists",
					param->guid_old);
			goto err_cleanup1;
		}

		ploop_di_change_guid(di, di->top_guid, param->guid_old);
	}

	snprintf(new_top_delta_fname, sizeof(new_top_delta_fname), "%s.%s",
		di->images[0]->file, file_uuid);
	ret = ploop_di_add_image(di, new_top_delta_fname, TOPDELTA_UUID, guid);
	if (ret)
		goto err_cleanup1;

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err_cleanup1;

	// offline snapshot
	fd = create_snapshot_delta(new_top_delta_fname, blocksize, size, version);
	if (fd == -1) {
		ret = SYSEXIT_CREAT;
		goto err_cleanup2;
	}
	close(fd);

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
		if (unlink(old_top_delta_fname) && errno != ENOENT)
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

	param.guid = guid;
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
