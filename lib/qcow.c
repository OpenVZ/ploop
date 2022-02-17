/*
 *  Copyright (c) 2021 Virtuozzo International GmbH. All rights reserved.
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <byteswap.h>
#include <json-c/json.h>

#include "ploop.h"

typedef enum {
	QCOW2_INCOMPAT_DIRTY = 1,
} qcow_hdr_op_t;

struct qcow_hdr {
	uint32_t magic;
	uint32_t version;
	uint64_t backing_file_offset;
	uint32_t backing_file_size;
	uint32_t cluster_bits;
	uint64_t size; /* in bytes */
	uint32_t crypt_method;
	uint32_t l1_size;
	uint64_t l1_table_offset;
	uint64_t refcount_table_offset;
	uint32_t refcount_table_clusters;
	uint32_t nb_snapshots;
	uint64_t snapshots_offset;

	/* The following fields are only valid for version >= 3 */
	uint64_t incompatible_features;
	uint64_t compatible_features;
	uint64_t autoclear_features;

	uint32_t refcount_order;
	uint32_t header_length;
};

struct qcow_info {
	off_t virtual_size;
	int cluster_size;
};


#define QEMU_IMAGE_NAME "driver=qcow2,file.driver=file,file.filename=%s,file.locking=off"

int qcow_create(const char *image, struct ploop_create_param *param)
{
	int rc;
	char o[256];
	char *a[] = {"qemu-img", "create", "-f", "qcow2", "-o", o, (char *)image, NULL};

	snprintf(o, sizeof(o), "size=%ld,cluster_size=%ld,lazy_refcounts=on,compression_type=zlib",
			S2B(param->size), S2B(param->blocksize?:2048));
	rc = run_prg(a);
	if (rc) {
		ploop_err(0, "Failed to create qcow2 image %s", image);
		return SYSEXIT_SYS;
	}

	if (param->fstype != NULL) {
		struct ploop_disk_images_data *di;

		rc = ploop_open_dd(&di, image);
		if (rc)
			return rc;

		rc = ploop_init_image(di, param);
		ploop_close_dd(di);
		if (rc)
			unlink(image);
	}

	return 0;
}

int qcow_resize(const char *image, off_t size_sec)
{
	int rc;
	char s[64];
	char opts[PATH_MAX];
	char *a[] = {"qemu-img", "resize", "--image-opts", opts, s, NULL};

	snprintf(opts, sizeof(opts), QEMU_IMAGE_NAME, image);
	snprintf(s, sizeof(s), "%ld", S2B(size_sec));
	rc = run_prg(a);
	if (rc) {
		ploop_err(0, "Failed to resize qcow2 image %s", image);
		return SYSEXIT_SYS;

	}

	return 0;
}

static int json_parse(struct json_object* obj, struct qcow_info *info)
{
	struct json_object_iterator it,	ie;

	it = json_object_iter_begin(obj);
	ie = json_object_iter_end(obj);
	for (; !json_object_iter_equal(&it, &ie); json_object_iter_next(&it)) {
		const char *name = json_object_iter_peek_name(&it);
		struct json_object *val = json_object_iter_peek_value(&it);

		if (strcmp(name, "virtual-size") == 0)
			info->virtual_size = B2S(json_object_get_int64(val));
		else if (strcmp(name, "cluster-size") == 0)
			info->cluster_size = B2S(json_object_get_int(val));
	} 
	return 0;
}

static int qcow_info(const char *image, struct qcow_info *info)
{
	int rc = 0;
	json_object *obj = NULL;
	enum json_tokener_error jerr;
	struct json_tokener *tok;
	char buf[4096];
	FILE *fp;

	snprintf(buf, sizeof(buf), "LANG=C qemu-img info -f qcow2 --output=json %s", image);
	fp = popen(buf, "r");
	if (fp == NULL) {
		ploop_err(0, "Failed %s", buf);
		return SYSEXIT_SYS;
	}

	tok = json_tokener_new();
	do {
		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;
		obj = json_tokener_parse_ex(tok, buf, strlen(buf));
	} while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);

	if (jerr != json_tokener_success) {
		ploop_err(0, "Cannot parse json: %s\n", json_tokener_error_desc(jerr));
		rc = -1;
	} else
		rc = json_parse(obj, info);

	json_object_put(obj);
	json_tokener_free(tok);
	pclose(fp);

	return rc;
}

int qcow_open(const char *image, struct ploop_disk_images_data *di)
{
	int rc;
	struct qcow_info i;

	rc = qcow_info(image, &i);
	if (rc)
		return rc;
	di->size = i.virtual_size;
	di->blocksize = i.cluster_size;
	di->runtime->image_fmt = QCOW_FMT;
	return ploop_di_add_image(di, image, TOPDELTA_UUID, NONE_UUID);
}

static int do_qcow_check(const char *image)
{
	int rc;
	char opts[PATH_MAX];
	char *a[] = {"qemu-img", "check", "-q", "-r", "leaks", "--image-opts", opts, NULL};

	if (image == NULL)
		return SYSEXIT_PARAM;

	snprintf(opts, sizeof(opts), QEMU_IMAGE_NAME, image);
	/*
	 * 0   Check completed, the image is (now) consistent
	 * 1   Check not completed because of internal errors
	 * 2   Check completed, image is corrupted
	 * 3   Check completed, image has leaked clusters, but is not corrupted
	 * 63  Checks are not supported by the image format
	 */
	rc = run_prg(a);
	if (rc && rc != 3) {
		ploop_err(0, "Failed to check qcow2 image %s", image);
		return SYSEXIT_SYS;
	}
	return 0;
}

int qcow_check(struct ploop_disk_images_data *di)
{
	return do_qcow_check(find_image_by_guid(di, get_top_delta_guid(di)));
}

int qcow_live_check(const char *device)
{
	int rc;
	char *top;

	rc = get_image_param_online(NULL, device, &top, NULL, NULL, NULL, NULL);
	if (rc)
		return rc;

	rc = ploop_suspend_device(device);
	if (rc)
		goto err;

	rc = do_qcow_check(top);
	ploop_resume_device(device);

err:
	free(top);
	return rc;
}

static int qcow_update_hdr(const char *image, qcow_hdr_op_t op, int set)
{
	int fd, rc = 0;
	size_t n;
	struct qcow_hdr hdr;

	fd = open(image, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open file %s", image);
		return SYSEXIT_OPEN;
	}

	n = pread(fd, &hdr, sizeof(hdr), 0);
	if (n != sizeof(hdr)) {
		ploop_err(errno, "Can't read header %s", image);
		rc = SYSEXIT_READ;
		goto err;
	}

	hdr.incompatible_features = bswap_64(hdr.incompatible_features);
	ploop_log(3, "%s dirty %s %lu", set ? "Set" : "Drop",
			image, hdr.incompatible_features);
	if (set)
		hdr.incompatible_features |= op;
	else
		hdr.incompatible_features &= ~op;

	hdr.incompatible_features = bswap_64(hdr.incompatible_features);
	n = pwrite(fd, &hdr, sizeof(hdr), 0);
	if (n != sizeof(hdr)) {
		ploop_err(errno, "Can't update header %s", image);
		rc = SYSEXIT_WRITE;
		goto err;
	}
err:
	if (close(fd)) {
		ploop_err(errno, "Can't close %s", image);
		rc = SYSEXIT_WRITE;
	}
	return rc;
}

static int qcow_add(struct ploop_disk_images_data *di, struct ploop_mount_param *param)
{
	int fd, rc;
	char b[4096];
	off_t size = di->size;
	const char *i = find_image_by_guid(di, get_top_delta_guid(di));

	if (param->device[0] == '\0')
		get_dev_name(param->device, sizeof(param->device));
	ploop_log(0, "Adding delta dev=%s img=%s (%s)",
			param->device, i, param->ro ? "ro":"rw");

	fd = open(i, O_DIRECT | (param->ro ? O_RDONLY : O_RDWR)|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open file %s", i);
		return SYSEXIT_OPEN;
	}

	if (!param->ro) {
		rc = qcow_update_hdr(i, QCOW2_INCOMPAT_DIRTY, 1);
		if (rc)
			goto err;
	}

	snprintf(b, sizeof(b), "%d", fd);
	rc = dm_create(param->device, 0, "qcow2", 0, size, param->ro, b);
	if (rc && !param->ro)
		qcow_update_hdr(i, QCOW2_INCOMPAT_DIRTY, 0);

err:
	close(fd);

	return rc;
}

int qcow_mount(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param)
{
	int rc;

	rc = qcow_check(di);
	if (rc)
		return rc;
	return qcow_add(di, param);
}

int qcow_grow_device(struct ploop_disk_images_data *di,
		const char *image, const char *device, off_t size)
{
	int rc;

	rc = ploop_suspend_device(device);
	if (rc)
		return rc;

	rc = qcow_resize(image, size);
	if (rc)
		goto err;

	rc = dm_reload(di, device, size, RELOAD_ONLINE|RELOAD_SKIP_SUSPEND);
	if (rc)
		return rc;
err:
	ploop_resume_device(device);

	return rc;
}

static int do_snapshot(const char *image, const char *action, const char *guid)
{
	char opts[PATH_MAX];
	char *a[] = {"qemu-img", "snapshot", (char *) action, (char*) guid, "--image-opts", opts, NULL};

	snprintf(opts, sizeof(opts), QEMU_IMAGE_NAME, image);
	if (run_prg(a)) {
		ploop_err(0, "Failed to snapshot %s", guid);
		return SYSEXIT_SYS;
	}
	return 0;
}

int qcow_create_snapshot(struct ploop_disk_images_data *di,
		const char *guid)
{
	int rc;
	char dev[64];
	const char *images[] = {find_image_by_guid(di, get_top_delta_guid(di)), NULL};
	int online = 0;

	rc = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (rc == -1)
		return SYSEXIT_SYS;
	if (rc == 0)
		online = 1;

	if (online) {
		rc = ploop_suspend_device(dev);
		if (rc)
			return rc;
	}

	rc = do_snapshot(images[0], "-c", guid);
	if (rc)
		goto err;

	if (online) {
		rc = dm_reload(di, dev, 0, RELOAD_SKIP_SUSPEND);
		if (rc)
			return rc; // leave in suspended state
	}

err:
	if (rc) {
		 rc = do_snapshot(images[0], "-d", guid);
	} else {
		ploop_log(0, "%s %s has been successfully created",
				get_snap_str(0), guid);
	}

	if (online)
		ploop_resume_device(dev);

	return rc;
}

int qcow_delete_snapshot(struct ploop_disk_images_data *di,
		const char *guid)
{
	int rc;
	char dev[64];
	const char *images[] = {find_image_by_guid(di, get_top_delta_guid(di)), NULL};
	int online = 0;

	rc = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (rc == -1)
		return SYSEXIT_SYS;
	if (rc == 0)
		online = 1;

	if (online) {
		rc = ploop_suspend_device(dev);
		if (rc)
			return rc;
	}

	rc = do_snapshot(images[0], "-d", guid);
	if (rc)
		goto err;

	if (online) {
		rc = dm_reload(di, dev, 0, RELOAD_SKIP_SUSPEND);
		if (rc)
			return rc; // leave in suspended state
	}
	ploop_log(0, "%s %s has been successfully deleted",
			get_snap_str(0), guid);

err:

	if (online)
		ploop_resume_device(dev);

	return rc;
}

int qcow_switch_snapshot(struct ploop_disk_images_data *di,
		const char *guid)
{
	int rc;
	char dev[64];
	const char *images[] = {find_image_by_guid(di, get_top_delta_guid(di)), NULL};

	rc = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (rc == -1)
		return SYSEXIT_SYS;
	if (rc == 0) {
		ploop_err(0, "Unable to perform switch to snapshot operation"
				" on running device (%s)", dev);
		return SYSEXIT_PARAM;
	}

	rc = do_snapshot(images[0], "-a", guid);
	if (rc)
		ploop_log(0, "Can't switch to snapshot %s", guid);
	else
		ploop_log(0, "ploop snapshot has been successfully switched");
	return rc;
}
