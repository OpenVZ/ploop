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
/* hardcodec in LVM2.2.02.186/libdm/ioctl/libdm-iface.c
#define DM_IOCTL_RETRIES 25
#define DM_RETRY_USLEEP_DELAY 200000
*/
#define DM_RETRY_TIMEOUT	5
int dm_remove(const char *devname)
{
	int i;

	for (i = 0; i < PLOOP_UMOUNT_TIMEOUT / DM_RETRY_TIMEOUT; i++) {
		if (cmd(devname, DM_DEVICE_REMOVE) == 0)
			return 0;
		else if (errno != EBUSY)
			return SYSEXIT_DEVIOC;
	}

	return SYSEXIT_UMOUNT_BUSY;
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

int dm_flip_upper_deltas(const char *devname)
{
	ploop_log(0, "Flip upper delta %s", devname);
	return ploop_dm_message(devname, "flip_upper_deltas", NULL);
}

struct table_data {
	const char *params;
	char devname[64];
	const char *base;
	const char *top;
	__u32 blocksize;
	__u32 ndelta;
	char **devs;
	int ndevs;
	int flags;
	int open_count;
	int ro;
};

/* return:
 *	-1 - error
 *	1 - not found
 *	0 - found
 */
typedef int (*table_fn)(struct dm_task *task, struct table_data *data);

static int cmp_delta(struct dm_task *task, struct table_data *data)
{
	int rc;
	struct dm_info i = {};
	const char *devname;
	char *base = NULL;

	if (!dm_task_get_info(task, &i)) {
		ploop_err(0, "dm_task_get_info()");
		return -1;
	}

	devname = dm_task_get_name(task);
	rc = dm_get_delta_name(devname, 0, &base);
	if (rc == -1)	
		return -1;
	else if (rc)
		return 0;

	if (strcmp(data->base, base) == 0) {
		snprintf(data->devname, sizeof(data->devname), "/dev/mapper/%s", devname);
		data->ndevs = append_array_entry(data->devname, &data->devs, data->ndevs);
		if (data->ndevs == -1)
			return -1;
		return 0;
	}
	return 1;
}

static int display_entry(struct dm_task *task, struct table_data *data)
{
	int i, n = data->flags == 0 ? 1: 0xffff;
	char *img = NULL;

	for (i = 0; i < n; i++) {
		if (dm_get_delta_name(dm_task_get_name(task), i, &img))
			break;
		if (i == 0)
			printf("%s\t%s\n", dm_task_get_name(task), img);
		else
			printf("\t\t%s\n", img);
		free(img);
	}

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

int ploop_list(int flags)
{
	struct table_data d = {.flags = flags};

	return dm_list(display_entry, &d);
}

static int get_params(struct dm_task *task, struct table_data *data)
{
	struct dm_info i = {};

	if (data->params == NULL)
		return 1;

	if (!dm_task_get_info(task, &i)) {
		ploop_err(0, "dm_task_get_info()");
		return -1;
	}
	data->open_count = i.open_count;
	data->ro = i.read_only;

	if (sscanf(data->params, "%d %*s %d", &data->ndelta, &data->blocksize) != 2) {
		ploop_err(0, "malformed params '%s'", data->params);
		return -1;
	}
	return 0;
}

static int dm_get_info(const char *devname, struct dm_image_info *param)
{
	int rc;
	struct table_data d = {};

	rc = dm_table(devname, get_params, &d);
	if (rc)
		return rc;
	param->open_count = d.open_count;
	param->ro = d.ro;

	return 0;
}

int wait_for_open_count(const char *devname)
{
	struct dm_image_info i;
	useconds_t total = 0;
	useconds_t wait = 10000; // initial wait time 0.01s
	useconds_t maxwait = 500000; // max wait time per iteration 0.5s
	useconds_t maxtotal = PLOOP_UMOUNT_TIMEOUT * 1000000; // max total wait

	do {
		if (dm_get_info(devname, &i) == 0 &&
				i.open_count == 0)
			return 0;

		if (total > maxtotal) {
			ploop_err(0, "Wait for %s open_count=0 failed: timeout has expired",
					devname);
			return SYSEXIT_SYS;
		}

		usleep(wait);
		total += wait;
		wait *= 2;
		if (wait > maxwait)
			wait = maxwait;
	} while (1);
}

int get_image_param_online(const char *devname, char **top, off_t *size,
		__u32 *blocksize, int *version)
{
	int rc;
	struct table_data d = {};

	rc = dm_table(devname, get_params, &d);
	if (rc)
		return rc;
	if (blocksize)
		*blocksize = d.blocksize;
	if (version)
		*version = PLOOP_FMT_V2;
	if (size) {
		rc = ploop_get_size(devname, size);
		if (rc)
			return rc;
	}
	if (top && d.ndelta &&  dm_get_delta_name(devname, d.ndelta-1, top)) {
		ploop_err(0, "dm_get_delta_name");
		return SYSEXIT_SYS;
	}

	return 0;
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
static int dm_find_devs(const char *base, const char *top, char ***out)
{
	struct table_data data = {.base = base, .top = top};

	if (dm_list(cmp_delta, &data))
		return -1;
	if (data.devs != NULL) {
		*out = data.devs;
		return 0;
	}
	return 1;
}

int find_devs(struct ploop_disk_images_data *di, char ***out)
{
	const char *base = NULL, *top = NULL;

	base = find_image_by_guid(di, get_base_delta_uuid(di));
	if (di->vol != NULL)
		top = find_image_by_guid(di, get_top_delta_guid(di));

	return dm_find_devs(base, top, out);
}

int find_dev(struct ploop_disk_images_data *di, char *out, int len)
{
	int rc;
	char **devs = NULL;
	const char *base = NULL, *top = NULL;

	base = find_image_by_guid(di, get_base_delta_uuid(di));
	if (di->vol != NULL)
		top = find_image_by_guid(di, get_top_delta_guid(di));

	rc = dm_find_devs(base, top, &devs);
	if (rc == 0) {
		snprintf(out, len, "%s", devs[0]);
		ploop_free_array(devs);
	}

	return rc;
}

int find_devs_by_delta(const char *delta, char ***out)
{
	return dm_find_devs(delta, NULL, out);
}

int find_dev_by_delta(const char *delta, char *out, int len)
{
	int rc;
	char **devs = NULL;

	rc = dm_find_devs(delta, NULL, &devs);
	if (rc == 0) {
		snprintf(out, len, "%s", devs[0]);
		ploop_free_array(devs);
	}

	return rc;
}

static int do_reload(const char *device, char **images, off_t new_size, 
		__u32 blocksize, int rw2)
{
	int rc, *fds, i, j, n = 0;
	char t[PATH_MAX];
	char *a[7];
	char *p, *e;

	for (n = 0; images[n] != NULL; ++n);
	fds = alloca(n * sizeof(int));
	p = t;
	e = p + sizeof(t);
	p += snprintf(p, e-p, "0 %lu ploop %d",
			new_size, ffs(blocksize)-1);
	for (i = 0; i < n; i++) {
		int r = i < n - (rw2?2:1);
		ploop_log(0, "Adding delta dev=%s img=%s (%s)",
				device, images[i], r ? "ro":"rw");
		fds[i] = open(images[i], O_DIRECT | (r?O_RDONLY:O_RDWR));
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
err:
	for (j = 0; j < i; j++)
		close(fds[j]);

	return rc;
}

int dm_reload2(const char *device, off_t new_size, int rw2)
{
	int rc, rc1;
	__u32 blocksize;
	const char *fmt;
	char **images = NULL;

	if (new_size == 0) {
		rc = ploop_get_size(device, &new_size);
		if (rc)
			return rc;
	}

	rc = ploop_suspend_device(device);
	if (rc)
		return rc;
	rc = ploop_get_names(device, &images, &fmt, (int*)&blocksize);
	if (rc)
		goto err;
	rc = do_reload(device, images, new_size, blocksize, rw2);

	ploop_free_array(images);
err:
	rc1 = ploop_resume_device(device);

	return rc ? rc : rc1;
}

int dm_reload(struct ploop_disk_images_data *di, const char *device,
		off_t new_size, __u32 blocksize)
{
	int rc, rc1;
	char **images = NULL;
	       
	images = make_images_list(di, di->top_guid, 0);
	if (images == NULL)
		return SYSEXIT_MALLOC;

	rc = ploop_suspend_device(device);
	if (rc)
		goto err;

	rc = do_reload(device, images, new_size, blocksize, 0);

	rc1 = ploop_resume_device(device);
err:
	ploop_free_array(images);

	return rc ? rc : rc1;
}
