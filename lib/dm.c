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

void ploop_free_dm_message(char *msg)
{
	free(msg);
}

int dm_get_delta_name(const char *devname, int idx, char **out)
{
	char m[64];

	snprintf(m, sizeof(m), "get_delta_name %d", idx);
	if (ploop_dm_message(devname, m, out)) {
		ploop_err(errno, "Failed %s %s", devname, m);
		return -1;
	}

	if (**out == '\0') {
		free(*out);
		*out = NULL;
		return 1;
	}

	return 0;
}

int merge_top_delta(const char *devname)
{
	int rc;	

	ploop_log(0, "Merging top delta");
	rc = ploop_dm_message(devname, "merge", NULL);
	if (rc)
		ploop_err(errno, "Failed to online merge");

	return rc;
}

int notify_merged_backward (const char *devname, int id)
{
	char m[64];
	int rc;	

	snprintf(m, sizeof(m), "notify_merged_backward %d", id);
	rc = ploop_dm_message(devname, m, NULL);
	if (rc)
		ploop_err(errno, "Failed %s %s", m, devname);

	return rc;
}

int update_delta_index(const char *devname, int delta_idx, struct grow_maps *gm)
{
	int i, rc;
	char *p, *m;

	m = malloc(gm->ctl->n_maps * 13 * 2 + sizeof("update_delta_index"));
	if (m == NULL)
		return SYSEXIT_MALLOC;

	p = m;
	p += sprintf(m, "update_delta_index %d ", delta_idx);
	for (i = 0; i < gm->ctl->n_maps; i++) {
		p += sprintf(p, "%d:%d;", gm->ctl->rmap[i].req_cluster,
				gm->ctl->rmap[i].iblk);
	}

	rc = ploop_dm_message(devname, m, NULL);
	if (rc)
		ploop_err(errno, "Failed %s %s", m, devname);

	free(m);

	return rc;
}

int dm_create(const char *devname, __u64 start, __u64 size, int ro,
		const char *args)
{
	struct dm_task *d;
	uint32_t cookie = 0;
	int minor, rc = -1;

	d = dm_task_create(DM_DEVICE_CREATE);
	if (d== NULL)
		return SYSEXIT_MALLOC;
	if (!dm_task_set_name(d, get_basename(devname)))
		goto err;
	if (!dm_task_add_target(d, start, size, "ploop", args))
		goto err;
	if (!dm_task_set_add_node(d, DM_ADD_NODE_ON_CREATE))
		goto err;
	if (ro)
		dm_task_set_ro(d);
	sscanf(get_basename(devname), "ploop%d", &minor);
	dm_task_set_minor(d, minor);
	if (!dm_task_set_cookie(d, &cookie, 0))
		goto err;
	if (!dm_task_run(d))
		goto err;
	dm_udev_wait(cookie);

	rc = 0;
err:
	if (rc)
		ploop_err(errno, "Failed to create ploop device %s", devname);
	dm_task_destroy(d);

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

int dm_remove(const char *devname)
{
	return cmd(devname, DM_DEVICE_REMOVE);
}

int dm_resize(const char *devname, off_t size)
{
	int rc;
	char m[64];

	snprintf(m, sizeof(m), "resize %lu", size);
	rc = ploop_dm_message(devname, m, NULL);
	if (rc)
		ploop_err(errno, "Cann not resize %s", devname);

	return rc;
}

int dm_snapshot(const char *devname, const char *top,  const char *ldevname)
{
	int rc, fd;
	char m[64];

        fd = open(top, O_DIRECT|O_RDONLY|O_CLOEXEC);
        if (fd == -1) {
                ploop_err(errno, "Can't open file %s", top);
                return SYSEXIT_OPEN;
        }

	snprintf(m, sizeof(m), "snapshot %d %s", fd, ldevname);
	rc = ploop_dm_message(devname, m, NULL);
	if (rc)
		ploop_err(errno, "Failed %s %s", devname, m);

	close(fd);

	return rc;
}

int dm_tracking_start(const char *devname)
{
	int rc;

	ploop_log(0, "Start tracking on %s", devname);
	rc = ploop_dm_message(devname, "tracking_start", NULL);
	if (rc)
		ploop_err(errno, "Can not start tracking on %s", devname);

	return rc;
}

int dm_tracking_stop(const char *devname)
{
	int rc;

	ploop_log(0, "Stop tracking on %s", devname);
	rc = ploop_dm_message(devname, "tracking_stop", NULL);
	if (rc)
		ploop_err(errno, "Can not stop tracking on %s", devname);

	return rc;
}

int dm_tracking_get_next(const char *devname, __u64 *pos)
{
	char *out = NULL;
	int rc;

	rc = ploop_dm_message(devname, "tracking_get_next", &out);
	if (rc) {
		if (errno != EAGAIN)
			ploop_err(errno, "Can not get next tracking block on %s",
					devname);
		return rc;
	}

	if (sscanf(out, "%llu", pos) != 1) {
		ploop_err(0, "Not valid tracking offset %s", out);
		rc = SYSEXIT_PARAM;
	}
	free(out);

	return rc;
}

int dm_setnoresume(const char *devname, int on)
{
	int rc;

	ploop_log(0, "Set noresume: %d", on);
	rc = ploop_dm_message(devname, on ? "set_noresume 1" :
			"set_noresume 0", NULL);
	if (rc)
		ploop_err(errno, "Can not set noresume %d on %s",
				on, devname);
	return rc;
}


int ploop_suspend_device(const char *devname)
{
	return cmd(devname, DM_DEVICE_SUSPEND);
}

int ploop_resume_device(const char *devname)
{
	return cmd(devname, DM_DEVICE_RESUME);
}

int dm_flip_upper_deltas(const char *devname, const char *ldevname,
		const char *top_delta)
{
	int rc, fd;
	char m[64];


	ploop_log(0, "FLip upper delta %s %s %s",
			devname, ldevname, top_delta);
	fd = open(top_delta, O_RDONLY|O_CLOEXEC);
	if (fd == -1) {
		ploop_err(errno, "Can not open top delta %s",
				top_delta);
		return SYSEXIT_OPEN;
	}
	snprintf(m, sizeof(m), "flip_upper_deltas %s %d",
			ldevname, fd);
	rc = ploop_dm_message(devname, m, NULL);
	if (rc)
		ploop_err(errno, "Failed %s %s", devname, m);

	close(fd);

	return rc;
}

struct table_data {
	dev_t loopdev;
	const char *params;
	char devname[64];
	const char *base;
	const char *top;
};

/* return:
 *	-1 - error
 *	1 - no error stop processing
 *	0 - success
 */
typedef int (*table_fn)(struct dm_task *task, struct table_data *data);

static int cmp_dev(struct dm_task *task, struct table_data *data)
{
	struct dm_info i;
	int major, minor;

	if (!dm_task_get_info(task, &i)) {
		ploop_err(0, "dm_task_get_info()");
		return -1;
	}

	if (sscanf(data->params, "%d:%d ", &major, &minor) != 2) {
		ploop_err(0, "cmp_dev %s", data->params);
		return -1;
	}

	if (makedev(major, minor) == data->loopdev) {
		snprintf(data->devname, sizeof(data->devname), "%s",
				dm_task_get_name(task));
		return 1;
	}

	return 0;
}

static int cmp_delta(struct dm_task *task, struct table_data *data)
{
	int rc;
	struct dm_info i = {};
	int major, minor;
	char ldev[64];
	char top[PATH_MAX];

	if (!dm_task_get_info(task, &i)) {
		ploop_err(0, "dm_task_get_info()");
		return -1;
	}

	if (sscanf(data->params, "%d:%d ", &major, &minor) != 2) {
		ploop_err(0, "cmp_delta: malformed %s", data->params);
		return -1;
	}
	get_loop_name(minor, 0, ldev, sizeof(ldev));
	rc = get_top_delta(ldev, top, sizeof(top));
	if (rc == -1)	
		return -1;
	else if (rc)
		return 0;

	if (strcmp(data->top, top) == 0) {
		snprintf(data->devname, sizeof(data->devname), "%s",
				dm_task_get_name(task));
		return 1;
	}

	return 0;
}

static int display_entry(struct dm_task *task, struct table_data *data)
{
	char *i = NULL;
	const char *devname = dm_task_get_name(task);

	if (dm_get_delta_name(devname, 0, &i))
		get_top_delta_name(devname, &i, NULL, NULL);
	if (i == NULL)	
		i = strdup("-");
	printf("%s %s\n", devname, i);

	free(i);

	return 0;
}

static int dm_table(const char *devname, table_fn f, struct table_data *data)
{
	struct dm_task *d;
	struct dm_info i;
	void *next = NULL;
	uint64_t start, length;
	char *target_type = NULL;
	char *params;
	int rc = -1, eno;

	d = dm_task_create(DM_DEVICE_TABLE);
	if (d == NULL)
		return SYSEXIT_MALLOC;

	if (!dm_task_set_name(d, devname))
		goto err;
	if (!dm_task_run(d))
		goto err;
	if (!dm_task_get_info(d, &i))
		goto err;
	if (!i.exists) {
		errno = ENOENT;
		goto err;
	}
	devname = (const char *)dm_task_get_name(d);

	do {
		next = dm_get_next_target(d, next, &start, &length,
				&target_type, &params);
		if (target_type && strcmp(target_type, "ploop") == 0) {
			if (data)
				data->params = params;
			rc = f(d, data);
			if (rc == -1)
				goto err;
			else if (rc == 1)
				break;
		}
	} while (next);

	rc = 0;

err:
	eno = errno;
	dm_task_destroy(d);
	errno = eno;

	return rc;
}

static int dm_list(table_fn f, struct table_data *data)
{
	struct dm_task *d;
	struct dm_names *names;
	unsigned next = 0;
	int rc = -1, eno;

	d = dm_task_create(DM_DEVICE_LIST);
	if (d == NULL)
		return SYSEXIT_MALLOC;
	if (!dm_task_run(d))
		goto err;
	names = dm_task_get_names(d);
	if (names == NULL)
		goto err;

	if (names->dev) {
		do {
			names = (struct dm_names *)((char *) names + next);
			rc = dm_table(names->name, f, data);
			if (rc)
				break;
			next = names->next;
		} while (next);
	}
	rc = 0;

err:
	eno = errno;
	dm_task_destroy(d);
	errno = eno;

	return rc;
}

int ploop_list(void)
{
	return dm_list(display_entry, NULL);
}

static int dm_find_dev_by_loop(const char *ldevname,
		struct table_data *data)
{
	struct stat st;

	if (stat(ldevname, &st)) {
		ploop_err(errno, "Can not stat %s", ldevname);
		return SYSEXIT_PARAM;
	}
	data->loopdev = st.st_rdev;

	return dm_list(cmp_dev, data);
}

int dm_find_dev_by_delta(const char *base, const char *top)
{
	struct table_data data = {};

	return dm_list(cmp_delta, &data);
}


/* Find device(s) by top delta and return name(s)
* in a NULL-terminated array pointed to by 'out'.
* Note that
*  - if 0 is returned, 'out' should be free'd using
*    ploop_free_array()
* Return:
*  -1 on error
*   0 found
*   1 not found
*/
static int dm_find_devs(struct ploop_disk_images_data *di,
		const char *delta, char ***out)
{
	int lfd, rc;
	int n = 0;
	char **d, **devs = NULL;

	if (delta == NULL) {
		delta = find_image_by_guid(di, get_top_delta_guid(di));
		if (delta == NULL) {
                	ploop_err(0, "No top delta found found in %s",
					di->runtime->xml_fname);
	                return -1;
		}
	}

        lfd = ploop_global_lock();
        if (lfd == -1)
                return -1;

	rc = get_loop_by_delta(delta, &devs);
	if (rc == -1)
		goto err;
	if (devs == NULL) {
		rc = 1;
		goto err;
	}

	for (d = devs; *d != NULL; d++) {
		struct table_data data = {};

		rc = dm_find_dev_by_loop(*d, &data);
		if (rc == -1)
			goto err;

		if (data.devname[0] != '\0') {
			char dev[64];

			snprintf(dev, sizeof(dev), "/dev/mapper/%s",
					data.devname);
			n = append_array_entry(dev, out, n);
			if (n == -1) {
				rc = -1;
				goto err;
			}
		}
	}
err:
	close(lfd);
	ploop_free_array(devs);
	if (rc && n) {
		ploop_free_array(*out);
		*out = NULL;
	}
	if (rc == 0 && n == 0)
		return 1;

	return rc;
}

int find_devs(struct ploop_disk_images_data *di, char ***out)
{
	return dm_find_devs(di, NULL, out);
}

int find_dev(struct ploop_disk_images_data *di, char *out, int len)
{
	int rc;
	char **devs = NULL;

	rc = dm_find_devs(di, NULL,  &devs);
	if (rc == 0) {
		snprintf(out, len, "%s", devs[0]);
		ploop_free_array(devs);
	}

	return rc;
}

int find_devs_by_delta(const char *delta, char ***out)
{
	return dm_find_devs(NULL, delta, out);
}

int find_dev_by_delta(const char *delta, char *out, int len)
{
	int rc;
	char **devs = NULL;

	rc = dm_find_devs(NULL, delta,  &devs);
	if (rc == 0) {
		snprintf(out, len, "%s", devs[0]);
		ploop_free_array(devs);
	}

	return rc;
}

int dm_reload(struct ploop_disk_images_data *di, const char *device,
	 	const char *ldev, off_t new_size, __u32 blocksize)
{
	int rc, *fds, i, n = 0;
	char t[PATH_MAX];
	char *a[7];
	char *p, *e;
	char **images;

	rc = ploop_suspend_device(device);
	if (rc)
		return rc;

	images = make_images_list(di, di->top_guid, 0);
	if (images == NULL) {
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	for (n = 0; images[n] != NULL; ++n);
	fds = alloca(n * sizeof(int));
	p = t;
	e = p + sizeof(t);
	p += snprintf(p, e-p, "0 %lu ploop %d %s",
			new_size, ffs(blocksize)-1, ldev);
	for (i = 0; i < n-1; i++) {
		ploop_log(0, "Add delta %s (ro)", images[i]);
		fds[i] = open(images[i], O_DIRECT | O_RDONLY);
		if (fds[i] < 0) {
			ploop_err(errno, "Can't open file %s", images[i]);
			rc = SYSEXIT_OPEN;
			goto err;
		}
		p += snprintf(p, e-p, " %d", fds[i]);
	}

	a[0] = "dmsetup";
	a[1] = "reload";
	a[2] = (char *) get_basename(device);
	a[3] = "--table";
	a[4] = t;
	a[5] = NULL;
	rc = run_prg(a);
	if (rc)
		goto err;
err:
	for (i = 1; i < n; i++)
		close(fds[i]);
	ploop_free_array(images);

	int rc1 = ploop_resume_device(device);

	return rc ? rc : rc1;
}
