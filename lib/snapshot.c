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

#include "ploop.h"

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
		.guid = param->guid
	};

	if (di == NULL || param == NULL)
		return SYSEXIT_PARAM;

	if (param->guid == NULL) {
		ploop_err(0, "Snapshot guid is not specified");
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = do_create_snapshot(di, &snap_param, 1);
	if (ret)
		goto err_unlock;

	/* FIXME: should be processed from 'struct ploop_mount_param' only ?? */
	char *t = di->runtime->component_name;
	di->runtime->component_name = param->component_name;

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
