/*
 *  Copyright (c) 2020 Virtuozzo International GmbH. All rights reserved.
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

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysmacros.h>

#include <libdevmapper.h>

#include "ploop.h"

int ploop_dm_message(const char *devname, const char *msg, char **out)
{
	struct dm_task *d;
	const char *r;
	int n, rc = -1, eno;

	if (out)
		*out = NULL;
	ploop_log(3, "DM message: %s %s", devname, msg);
	d = dm_task_create(DM_DEVICE_TARGET_MSG);
	if (d == NULL)
		return SYSEXIT_MALLOC;
	if (!dm_task_set_name(d, devname))
		goto err;
	if (!dm_task_set_sector(d, 0))
		goto err;
	if (!dm_task_set_message(d, msg))
		goto err;
	if (!dm_task_run(d))
		goto err;

	r = dm_task_get_message_response(d);
	if (r && out != NULL) {
		*out = strdup(r);
		n = strlen(*out);
		if ((*out)[n-1] == '\n')
			(*out)[n-1] = '\0';
	}
	rc = 0;

err:
	eno = errno;
	dm_task_destroy(d);
	errno = eno;

	return rc;
}


static const char *get_cmd_name(int cmd)
{
	switch(cmd) {
	case DM_DEVICE_SUSPEND:
		return "suspend";
	case DM_DEVICE_RESUME:
		return "resume";
	case DM_DEVICE_REMOVE:
		return "remove";
	default:
		return "unknown command";
	}
}

static int cmd(const char *devname, int cmd)
{
	struct dm_task *d;
	int rc = -1;
	uint32_t cookie = 0;
	int udev_wait_flag = cmd == DM_DEVICE_RESUME ||
		cmd == DM_DEVICE_REMOVE;

	ploop_log(0, "DM command: %s %s", get_cmd_name(cmd), devname);
	d = dm_task_create(cmd);
	if (d == NULL)
		return SYSEXIT_MALLOC;
	if (!dm_task_set_name(d, devname))
		goto err;
	if (!dm_task_set_add_node(d, DM_ADD_NODE_ON_RESUME))
		goto err;
	if (cmd == DM_DEVICE_REMOVE)
		dm_task_retry_remove(d);
	if (udev_wait_flag &&
			!dm_task_set_cookie(d, &cookie, 0))
		goto err;
		
	if (!dm_task_run(d))
		goto err;
	if (udev_wait_flag)
		dm_udev_wait(cookie);

	rc = 0;
err:
	dm_task_destroy(d);
	return rc;
}

int dm_suspend_device(const char *devname)
{
	return cmd(devname, DM_DEVICE_SUSPEND);
}

int dm_resume_device(const char *devname)
{
	return cmd(devname, DM_DEVICE_RESUME);
}

int dm_remove(const char *devname)
{
	return cmd(devname, DM_DEVICE_REMOVE);
}
