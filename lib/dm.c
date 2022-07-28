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
#include <time.h>
#include <pthread.h>

#include <libdevmapper.h>

#include "ploop.h"

enum {
	PLOOP_TARGET,
	QCOW_TARGET,
	PUSH_BACKUP_TARGET,
};

static pthread_mutex_t _s_dm_mutex;

__attribute__((constructor)) void __init__(void)
{
	pthread_mutex_init(&_s_dm_mutex, NULL);
}

//NB: do not forget free `out` after usage
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
	if (!dm_task_run(d)) {
		ploop_log(errno, "Failed to '%s' on %s", msg, devname);
		goto err;
	}
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

	snprintf(m, sizeof(m), "get_img_name %d", idx);
	if (ploop_dm_message(devname, m, out)) {
		if (errno == ENOENT)
			return 1;
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

int dm_create(const char *devname, int minor, const char *target,
		__u64 start, __u64 size, int ro, const char *args)
{
	struct dm_task *d;
	uint32_t cookie = 0;
	int rc = -1;

	d = dm_task_create(DM_DEVICE_CREATE);
	if (d == NULL)
		return SYSEXIT_MALLOC;
	if (!dm_task_set_name(d, get_basename(devname)))
		goto err;
	if (!dm_task_add_target(d, start, size, target, args))
		goto err;
	if (!dm_task_set_add_node(d, DM_ADD_NODE_ON_CREATE))
		goto err;
	if (ro)
		dm_task_set_ro(d);
	if (minor == 0)
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
	if (udev_wait_flag) {
		if (pthread_mutex_lock(&_s_dm_mutex))
			ploop_err(errno, "pthread_mutex_lock");
		dm_udev_wait(cookie);
		if (pthread_mutex_unlock(&_s_dm_mutex))
			 ploop_err(errno, "pthread_mutex_unlock");
	}

	rc = 0;
err:
	dm_task_destroy(d);
	return rc;
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

int dm_tracking_clear(const char *devname, __u64 clu)
{
	int rc;
	char m[64];

	snprintf(m, sizeof(m), "tracking_clear %llu", clu);
	rc = ploop_dm_message(devname, m, NULL);
	if (rc)
		ploop_err(errno, "Cannot clear tracking on %s clu=%llu",
					devname, clu);

	return rc;
}

int dm_tracking_get_next(const char *devname, __u64 *pos)
{
	char *out = NULL;
	int rc;

	rc = ploop_dm_message(devname, "tracking_get_next", &out);
	if (rc) {
		ploop_err(errno, "Can not get next tracking block on %s",
					devname);
		return rc;
	}
	ploop_log(3, "tracking_get_next out=%s", out);
	if (out == NULL) {
		errno = EAGAIN;
		return SYSEXIT_SYS;
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

int dm_suspend(const char *devname)
{
	return cmd(devname, DM_DEVICE_SUSPEND);
}

int ploop_suspend_device(const char *devname)
{
	char dev[64], part[64];
	int rc;

	rc = get_part_devname_from_sys(devname, dev, sizeof(dev),
				part, sizeof(part));
	if (rc)
		return rc;

	if (strcmp(dev, part)) {
		rc = cmd(part, DM_DEVICE_SUSPEND);
		if (rc)
			return rc;
		rc = cmd(dev, DM_DEVICE_SUSPEND);
		if (rc)
			cmd(part, DM_DEVICE_RESUME);
	} else
		rc = cmd(devname, DM_DEVICE_SUSPEND);

	return rc;
}

int dm_resume(const char *devname)
{
	return cmd(devname, DM_DEVICE_RESUME);
}

int ploop_resume_device(const char *devname)
{
	char dev[64], part[64];
	int rc;

	rc = get_part_devname_from_sys(devname, dev, sizeof(dev),
			part, sizeof(part));
	if (rc)
		return rc;

	if (strcmp(dev, part)) {
		rc = cmd(dev, DM_DEVICE_RESUME);
		if (rc)
			return rc;
		rc = cmd(part, DM_DEVICE_RESUME);
	} else
		rc = cmd(devname, DM_DEVICE_RESUME);

	return rc;
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
	__u32 version;
	__u32 ndelta;
	char **devs;
	int ndevs;
	int flags;
	int open_count;
	int ro;
	int target_type;
	char status[64];
};

/* return:
 *	-1 - error
 *	1 - not found
 *	0 - found
 */
typedef int (*table_fn)(struct dm_task *task, struct table_data *data);

static int cmp_delta(struct dm_task *task, struct table_data *data)
{
	int rc = 0;
	struct dm_info i = {};
	const char *devname;
	char *base = NULL;
	char *top = NULL;

	if (!dm_task_get_info(task, &i)) {
		ploop_err(0, "dm_task_get_info()");
		return -1;
	}

	devname = dm_task_get_name(task);
	rc = dm_get_delta_name(devname, 0, &base);
	if (rc == -1)	
		return rc;
	else if (rc)
		return 0;

	if (strcmp(data->base, base) == 0) {
		if (data->top) {
			int n;

			if (sscanf(data->params, "%d", &n) != 1) {
				ploop_err(0, "malformed params '%s'", data->params);
				rc = -1;
				goto exit_;
			}

			rc = dm_get_delta_name(devname, n - 1, &top);
			if (rc == -1)
				goto exit_;

			if (strcmp(data->top, top)){
				rc = 1;
				goto exit_;
			}
		}

		snprintf(data->devname, sizeof(data->devname), "/dev/mapper/%s", devname);
		data->ndevs = append_array_entry(data->devname, &data->devs, data->ndevs);
		rc = (data->ndevs == -1) ? -1 : 0;
		goto exit_;
	}

	rc = 1;
exit_:
	free(top);
	free(base);
	return rc;
}

static int display_entry(struct dm_task *task, struct table_data *data)
{
	int i, n = data->flags == 0 ? 1: 0xffff;
	char *img = NULL;
	const char *devname = dm_task_get_name(task);
	char c[PATH_MAX];

	for (i = 0; i < n; i++) {
		if (dm_get_delta_name(devname, i, &img))
			break;
		if (i == 0) {
			printf("%s\t%s", devname, img);
			if (cn_find_name(devname, c, sizeof(c), 0) == 0)
				printf("\t%s", c);
			printf("\n");
		} else
			printf("\t\t%s\n", img);
		free(img);
	}

	return 0;
}

static int get_image_fmt(const char *str)
{
	if (str == NULL)
		return -1;
	if (strcmp(str, "ploop") == 0)
		return PLOOP_TARGET;
	if (strcmp(str, "qcow2") == 0)
		return QCOW_TARGET;
	if (strcmp(str, "push_backup") == 0)
		return PUSH_BACKUP_TARGET;
	return -1;
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
		int t = get_image_fmt(target_type);
		if (t != -1) {
			if (data) {
				data->params = params;
				data->target_type = t;
			}
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
	int n;
	char v[64] = "";
	struct dm_info i = {};

	if (data->params == NULL)
		return 1;

	if (!dm_task_get_info(task, &i)) {
		ploop_err(0, "dm_task_get_info()");
		return -1;
	}
	data->open_count = i.open_count;
	data->ro = i.read_only;

	data->version = PLOOP_FMT_UNDEFINED;
	data->blocksize = 0;
	switch (data->target_type) {
	case PLOOP_TARGET:
		n = sscanf(data->params, "%d %2s %d", &data->ndelta, v, &data->blocksize);
		if (n != 3) {
			ploop_err(0, "malformed ploop params '%s'", data->params);
			return -1;
		}
		if (!strcmp(v, "v2"))
			data->version = PLOOP_FMT_V2;
		break;
	case QCOW_TARGET:
//		n = sscanf(data->params, "%d %d", &data->ndelta, &data->blocksize);
		n = sscanf(data->params, "%d", &data->ndelta);
		data->blocksize = 2048;
		if (n != 1) {
			ploop_err(0, "malformed qcow params '%s'", data->params);
			return -1;
		}
		break;
	case PUSH_BACKUP_TARGET:
		// 253:34256 2048 3600 active
		n = sscanf(data->params, "%*d:%*d %*d %*d %63s", data->status);
		if (n != 1) {
			ploop_err(0, "malformed push_backup params '%s'", data->params);
			return -1;
		}
		break;
	default:
		break;
	}

	return 0;
}

int dm_get_info(const char *devname, struct ploop_tg_info *param)
{
	int rc;
	struct table_data d = {};

	rc = dm_table(devname, get_params, &d);
	if (rc)
		return rc;
	param->open_count = d.open_count;
	param->ro = d.ro;
	param->blocksize = d.blocksize;
	strcpy(param->status, d.status);

	return 0;
}

int ploop_tg_info(const char *devname, struct ploop_tg_info *param)
{
	return dm_get_info(devname, param);
}

static int do_wait_for_open_count(const char *devname, int remove, int tm_sec)
{
	struct ploop_tg_info i;
        struct timespec ts;
	useconds_t total = 0;
	useconds_t wait = 10000; // initial wait time 0.01s
	useconds_t maxwait = 500000; // max wait time per iteration 0.5s
	clock_t end;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	end = ts.tv_sec + tm_sec;

	do {
		int rc = dm_get_info(devname, &i);
		if ((rc == 0 && i.open_count == 0) || rc)
		{
			if (remove) {
				if (cmd(devname, DM_DEVICE_REMOVE) == 0)
					return 0;
				else if (errno != EBUSY)
					return SYSEXIT_DEVIOC;
			} else
				return 0;
		}

		usleep(wait);
		total += wait;
		wait *= 2;
		if (wait > maxwait)
			wait = maxwait;
		clock_gettime(CLOCK_MONOTONIC, &ts);
	} while (ts.tv_sec < end);

	if (i.open_count)
		ploop_err(0, "Wait for %s open_count failed: timeout %d has expired",
					devname, tm_sec);
	else
		ploop_err(EBUSY, "Can't remove device %s", devname);

	return SYSEXIT_SYS;
}

int wait_for_open_count(const char *devname, int tm_sec)
{
	return do_wait_for_open_count(devname, 0, tm_sec);
}

int dm_remove(const char *devname, int tm_sec)
{
	return do_wait_for_open_count(devname, 1, tm_sec);
}

int get_image_param_online(struct ploop_disk_images_data *di,
		const char *devname, char **top, off_t *size,
		__u32 *blocksize, int *version, int *image_fmt)
{
	int rc;
	struct table_data d = {};

	rc = dm_table(devname, get_params, &d);
	if (rc)
		return rc;
	if (blocksize)
		*blocksize = d.blocksize == 0 && di ?
				di->blocksize : d.blocksize;
	if (version)
		*version = d.version;
	if (size) {
		rc = ploop_get_size(devname, size);
		if (rc)
			return rc;
	}
	if (image_fmt)
		*image_fmt = d.target_type;
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
	if (base == NULL) {
		ploop_err(0, "Can't find base delta");
		return SYSEXIT_PARAM;
	}
	if (di->vol != NULL)
		top = find_image_by_guid(di, get_top_delta_guid(di));

	rc = dm_find_devs(base, top, &devs);
	if (rc == 0) {
		const char *d = cn_find_dev(devs, di);
		if (d) 
			snprintf(out, len, "%s", d);
		else
			rc = 1;
	}
	ploop_free_array(devs);

	return rc;
}

int find_devs_by_delta(struct ploop_disk_images_data *di,
		const char *delta, char ***out)
{
	const char *base = delta;
	const char *top = NULL;

	if (di) {
		base = find_image_by_guid(di, get_base_delta_uuid(di));
		top = delta;
	}

	return dm_find_devs(base, top, out);
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

int do_reload(const char *device, char **images, __u32 blocksize, off_t new_size,
		int image_fmt, int flags)
{
	int rc, *fds, i, j, n = 0;
	char t[PATH_MAX];
	char *a[7];
	char *p, *e;

	if (new_size == 0) {
		rc = ploop_get_size(device, &new_size);
		if (rc)
			return rc;
	}

	for (n = 0; images[n] != NULL; ++n);
	fds = alloca(n * sizeof(int));
	p = t;
	e = p + sizeof(t);
	if (image_fmt == PLOOP_FMT)
		p += snprintf(p, e-p, "0 %lu ploop %d",
			new_size, ffs(blocksize)-1);
	else
		p += snprintf(p, e-p, "0 %lu qcow2", new_size);

	for (i = 0; i < n; i++) {
		int r = i < n - (flags & RELOAD_RW2 ? 2 : 1);
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

int dm_reload(struct ploop_disk_images_data *di, const char *device,
		off_t new_size, int flags)
{
	int rc, rc1 = 0;
	char **images = NULL;

	if (flags & RELOAD_ONLINE) {
		rc = ploop_get_names(device, &images);
		if (rc)
			return rc;
	} else {
		images = make_images_list(di, di->top_guid, 0);
		if (images == NULL)
			return SYSEXIT_MALLOC;
	}

	if (!(flags & RELOAD_SKIP_SUSPEND)) {
		rc = ploop_suspend_device(device);
		if (rc)
			goto err;
	}

	rc = do_reload(device, images, di->blocksize, new_size,
			di->runtime->image_fmt, flags);

	if (!(flags & RELOAD_SKIP_SUSPEND))
		rc1 = ploop_resume_device(device);
err:
	ploop_free_array(images);

	return rc ? rc : rc1;
}

int dm_reload_other(const char *device, const char *drv, off_t size)
{
	char t[64];
	char *a[] = {"dmsetup", "reload", (char *) get_basename(device), "--table", t, NULL};

	snprintf(t, sizeof(t), "0 %lu %s", size, drv);

	return run_prg(a);
}

static int dm_tg_reload(const char *dev, const char *dev2, 
		const char *tg, off_t size, __u32 blocksize)
{
	char t[PATH_MAX];
	char *a[] = {"dmsetup", "reload", (char *) get_basename(dev), "--table",  t, NULL};

	snprintf(t, sizeof(t), "0 %lu %s %u %s", size, tg, blocksize, dev2);

	return run_prg(a);
}

/*
1 dmsetup reload ploopXXX --table "0 4294967296 error"
2 dmsetup create ploopXXX_underlining 0 sectors ploop ....
3 dmsetup reload ploopXXX --table "0 4294967296 <tg> 2048 /dev/mapper/ploopXXX_underlining"
4 dmsetup resume ploop_XXX
 */
int ploop_tg_init(const char *dev, const char *tg, struct ploop_tg_data *out)
{
	int rc, image_fmt, minor;
	__u32 blocksize;
	off_t size;
	char *p, **images = NULL;
	char devname[64], part[64];
	char devtg[64] = "";
	struct ploop_tg_data d = {.lckfd = -1};

	ploop_log(0, "Start %s target on %s", tg, dev);
	rc = get_part_devname_from_sys(dev, devname, sizeof(devname), part, sizeof(part));
	if (rc)
		return rc;
	rc = get_image_param_online(NULL, dev, NULL, &size, &blocksize, NULL, &image_fmt);
	if (rc)
		return rc;

	rc = ploop_get_names(dev, &images);
	if (rc)
		return rc;

	out->lckfd = lock(images[0], 1, LOCK_TIMEOUT);
	if (out->lckfd == -1)
		return SYSEXIT_LOCK;

	p = strchr(dev, '.');
	if (p) {
		ploop_err(0, "Device %s hungs in the %s state", dev, p);
		rc = ploop_tg_deinit(dev, &d);
		if (rc)
			goto err;
		dev = d.devname;
	}

	rc = dm_suspend(part);
	if (rc)
		goto err;

	rc = dm_suspend(dev);
	if (rc)
		goto err;

	rc = dm_reload_other(dev, "error", size);
	if (rc)
		goto err;

	minor = get_dev_tg_name(tg, devtg, sizeof(devtg));
	if (minor == -1) {
		rc = -1;
		goto err;
	}

	if (image_fmt == QCOW_FMT) {
		struct ploop_mount_param p = {};

		snprintf(p.device, sizeof(p.device), "%s", devtg);
		rc = qcow_add(images, size, minor, &p, NULL);
	} else
		rc = add_delta(images, devtg, minor, blocksize, 0, 0, sizeof(devtg));
	if (rc)
		goto err_reload;

	rc = dm_tg_reload(dev, devtg, tg, size, blocksize);
	if (rc)
		goto err_reload;

	snprintf(out->devname, sizeof(out->devname), "%s", devtg);
	snprintf(out->devtg, sizeof(out->devtg), "%s", dev);
	snprintf(out->part, sizeof(out->part), "%s", part);
	ploop_log(0, "tg-init %s %s %s", out->devname, out->devtg, out->part);

err:
	dm_resume(dev);
	dm_resume(part);
	ploop_free_array(images);
	if (rc) {
		ploop_unlock(&out->lckfd);
		ploop_err(0, "Failed to start %s target on %s", tg, dev);
	} else
		ploop_log(0, "Target %s has been sucessfully started on %s", tg, dev);

	return rc;

err_reload:
	if (do_reload(dev, images, blocksize, size, image_fmt, 0) == 0)
		dm_remove(devtg, PLOOP_UMOUNT_TIMEOUT);
	if(minor != -1)
		remove(devtg);
	goto err;
}

int ploop_tg_deinit(const char *devtg, struct ploop_tg_data *data)
{
	int rc, image_fmt;
	__u32 blocksize;
	off_t size;
	char *p, **images = NULL;
	char dev[64], part[64];

	p = strchr(devtg, '.');
	if (p ==  NULL) {
		ploop_err(0, "ploop_tg_deinit: incorrect devname '%s'", devtg);
		return SYSEXIT_PARAM;
	}

	ploop_log(0, "ploop_tg_deinit %s", devtg);
	rc = get_part_devname_from_sys(devtg, dev, sizeof(dev), part, sizeof(part));
	if (rc)
		return rc;

	rc = get_image_param_online(NULL, devtg, NULL, &size, &blocksize, NULL, &image_fmt);
	if (rc)
		return rc;

	rc = dm_suspend(part);
	if (rc)
		return rc;

	rc = dm_suspend(dev);
	if (rc)
		goto err;

	rc = dm_suspend(devtg);
	if (rc)
		goto err;

	rc = ploop_get_names(devtg, &images);
	if (rc)
		goto err;

	rc = do_reload(dev, images, blocksize, size, image_fmt, 0);
	if (rc)
		goto err;

	rc = dm_resume(dev);
	if (rc)
		goto err;

	dm_remove(devtg, PLOOP_UMOUNT_TIMEOUT);
	ploop_free_array(images);
	if (data) {
		snprintf(data->devname, sizeof(data->devname), "%s", dev);
		ploop_unlock(&data->lckfd);
	}
	dm_resume(part);

	ploop_log(0, "Device %s has been sucessfully deinited", devtg);
	return 0;

err:
	dm_resume(devtg);
	dm_resume(dev);
	dm_resume(part);
	ploop_free_array(images);
	if (data)
		ploop_unlock(&data->lckfd);
	ploop_err(0, "Failed to deinit %s", dev);

	return rc;
}
