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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <fcntl.h>
#include <byteswap.h>
#include <json-c/json.h>
#include <uuid/uuid.h>

#include "bit_ops.h"
#include "ploop.h"
#include "cbt.h"

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

#define L1_CLUSTER_USED			(1ULL << 63)
#define L2_CLUSTER_STANDARD		(1ULL << 63)
#define L2_CLUSTER_COMPRESSED		(1ULL << 62)

#define L1_OFFSET_MASK			0x00fffffffffffe00ULL
#define L2_OFFSET_MASK 			0x00fffffffffffe00ULL
#define L2_COMPRESSED_OFFSET_SIZE_MASK	0x3fffffffffffffffULL

struct qcow_info {
	off_t virtual_size;
	int cluster_size;
	int cbt_enable;
	char cbt_uuid[UUID_SIZE];
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

static struct json_object *json_get_key(json_object *obj, const char *key)
{
	struct json_object_iterator it,	ie;

	it = json_object_iter_begin(obj);
	ie = json_object_iter_end(obj);
	for (; !json_object_iter_equal(&it, &ie); json_object_iter_next(&it)) {
		const char *name = json_object_iter_peek_name(&it);
		if (strcmp(name, key) == 0)
			return json_object_iter_peek_value(&it);
	}

	return NULL;
}

static const char *json_get_key_string(json_object *obj, const char *key)
{
	struct json_object *val;

	val = json_get_key(obj, key);
	if (val == NULL || json_object_get_type(val) != json_type_string)
		return NULL;

	return json_object_get_string(val);
}

static const char *json_get_uuid(json_object *bmps)
{
	int i;

	if (bmps == NULL || json_object_get_type(bmps) != json_type_array ||
	json_object_array_length(bmps) == 0)
		return NULL;

	for (i = 0; i < json_object_array_length(bmps); i++) {
		struct json_object *el = json_object_array_get_idx(bmps, i);
		struct json_object *flags = json_get_key(el, "flags");
		const char *name = json_get_key_string(el, "name");
		if (flags == NULL || name == NULL)
			continue;
		return name;
	}

	return NULL;
}

static int json_parse(struct json_object* obj, struct qcow_info *info)
{
	struct json_object_iterator it,	ie;

	info->cbt_enable = 0;

	it = json_object_iter_begin(obj);
	ie = json_object_iter_end(obj);
	for (; !json_object_iter_equal(&it, &ie); json_object_iter_next(&it)) {
		const char *name = json_object_iter_peek_name(&it);
		struct json_object *val = json_object_iter_peek_value(&it);

		if (strcmp(name, "virtual-size") == 0)
			info->virtual_size = B2S(json_object_get_int64(val));
		else if (strcmp(name, "cluster-size") == 0)
			info->cluster_size = B2S(json_object_get_int(val));
		else if (strcmp(name, "format-specific") == 0) {
			struct json_object *data = json_get_key(val, "data");
			if (data) {
				struct json_object *bmps = json_get_key(data, "bitmaps");
				const char *name = json_get_uuid(bmps);
				if (name) {
					strncpy(info->cbt_uuid, name, sizeof(info->cbt_uuid)-1);
					info->cbt_uuid[sizeof(info->cbt_uuid)-1] = '\0';
					info->cbt_enable = 1;
				}
			}
		}
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
	if (i.cbt_enable)
		di->cbt_uuid = strdup(i.cbt_uuid);
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

static int qmp_check_reply(struct json_object* obj)
{
	struct json_object *err;

	/* There is the capabilities negotiation mode */
	if (json_get_key(obj, "QMP") != NULL)
		return 0;

	if (json_get_key(obj, "return") != NULL)
		return 0;

	/* Try to get QMP error description */
	err = json_get_key(obj, "error");
	if (err == NULL)
		ploop_err(0, "Unknown QMP error");
	else {
		const char *class, *desc;

		class = json_get_key_string(err, "class");
		desc = json_get_key_string(err, "desc");
		ploop_err(0, "QMP %s: %s", class ? class : "error", desc ? desc : "unknown");
	}

	return -1;
}

#define QMP_REPLY_TIMEOUT	10 /* timeout in seconds */

static int qmp_get_reply(FILE *fp, json_object **replay)
{
	int rc = -1;
	int fd, ret;
	json_object *obj = NULL;
	struct json_tokener *tok;
	enum json_tokener_error jerr;
	struct timeval timeout = {QMP_REPLY_TIMEOUT, 0};
	fd_set fds;

	fd = fileno(fp);
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	tok = json_tokener_new();
	do {
		char buf[4096];

	        ret = select(fd + 1, &fds, NULL, NULL, &timeout);
		if (ret <= 0)
			break;

		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;

		obj = json_tokener_parse_ex(tok, buf, strlen(buf));
	} while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);

	if (ret == 0)
		ploop_err(errno, "Socket timeout expired");
	else if (ret == -1)
		ploop_err(errno, "Socket reading error");
	else if (jerr != json_tokener_success)
		ploop_err(0, "Cannot parse json: %s", json_tokener_error_desc(jerr));
	else
		rc = qmp_check_reply(obj);

	if (replay)
		*replay = obj;
	else
		json_object_put(obj);

	json_tokener_free(tok);

	return rc;
}

static int qmp_run_cmd(FILE *fp, const char *cmd, json_object *args, json_object **replay)
{
	int ret;
	struct json_object *obj = NULL;

	obj = json_object_new_object();
	json_object_object_add(obj, "execute", json_object_new_string(cmd));

	if (args)
		json_object_object_add(obj, "arguments", args);

	ret = fputs(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN), fp);
	json_object_put(obj);
	if (ret == EOF) {
		ploop_err(errno, "Can't write command to qmp socket");
		return SYSEXIT_WRITE;
	}

	ret = fputs("\r\n", fp);
	if (ret == EOF) {
		ploop_err(errno, "Can't write end of line to qmp socket");
		return SYSEXIT_WRITE;
	}

	return qmp_get_reply(fp, replay);
}

static int qcow_quit_qemu(FILE *qmp_fp, int qmp_fd, int pid, int dev_fd,
	const char *qmp_dir, int abort)
{
	int rc = 0;

	if (!abort)
		rc = qmp_run_cmd(qmp_fp, "quit", NULL, NULL);

	if (qmp_fp)
		fclose(qmp_fp);
	else if (qmp_fd > 0)
		close(qmp_fd);

	if (pid > 0)
		rc = wait_pid(pid, "qemu-kvm", &abort);

	if (dev_fd > 0)
		close(dev_fd);

	if (access(qmp_dir, F_OK) == 0)
		rmdir(qmp_dir);

	return rc;
}

static int qmp_launch_qemu(const char *dev, int fd, const char *image,
	int *pid, int *dev_fd, char *qmp_dir, int *qmp_fd, FILE **qmp_fp)
{
	int rc = -1;
	int log = 1;
	int i, ret;
	struct sockaddr_un addr;
	char ploop_opts[64+PATH_MAX];
	char qcow2_opts[64+PATH_MAX];
	char qmp_opts[64+PATH_MAX];
	char qmp_file[PATH_MAX];
	char *arg[] = { "/usr/libexec/qemu-kvm", "-S",
		"-nodefaults",
		"-nographic",
		"-add-fd", ploop_opts,
		"-add-fd", qcow2_opts,
		"-blockdev", "{\"node-name\": \"vz-ploop\", \"driver\": \"host_device\", \"filename\": \"/dev/fdset/1\"}",
		"-blockdev", "{\"node-name\": \"vz-protocol-node\", \"driver\": \"file\", \"filename\": \"/dev/fdset/2\", \"locking\": \"off\"}",
		"-blockdev", "{\"node-name\": \"vz-qcow2-node\", \"driver\": \"qcow2\", \"file\": \"vz-protocol-node\", \"__vz_keep-dirty\": true}",
		"-qmp", qmp_opts,
		NULL
	};

	*dev_fd = open(dev, O_RDWR);
	if (*dev_fd < 0) {
		ploop_err(errno, "Can't open ploop device %s", dev);
		rc = SYSEXIT_DEVICE;
		goto err;
	}

	strcpy(qmp_dir, "/tmp/ploop-qmp-XXXXXX");
	if (mkdtemp(qmp_dir) == NULL) {
		ploop_err(errno, "Can't create unique directory with "
			"template '%s' for communicating with qemu-kvm", qmp_dir);
		rc = SYSEXIT_WRITE;
		goto err;
	}

	snprintf(qmp_file, sizeof(qmp_file), "%s/%s", qmp_dir, "qmp.monitor");
	snprintf(ploop_opts, sizeof(ploop_opts), "fd=%d,set=1,opaque=\"ro:%s\"", *dev_fd, dev);
	snprintf(qcow2_opts, sizeof(qcow2_opts), "fd=%d,set=2,opaque=\"rw:%s\"", fd, image);
	snprintf(qmp_opts, sizeof(qmp_opts), "unix:%s,server,nowait", qmp_file);

	if (log) {
		char b[4096];

		for (i = 0; arg[i] != NULL; i++) {
			strcat(b, arg[i]);
			if (arg[i + 1] != NULL)
				strcat(b, " ");
		}

		ploop_log(0, "Prepared cmd: %s", b);
	}

	*pid = fork();
	if (*pid < 0) {
		ploop_err(errno, "Can't fork");
		goto err;
	} else if (*pid == 0) {
		execv(arg[0], arg);
		ploop_err(errno, "Can't exec %s", arg[0]);
		_exit(1);
	}

	if ((*qmp_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		ploop_err(errno, "Can't create unix socket for qmp");
		goto err;
	}

	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, qmp_file);

	for (i = 0; i < 300; i++) {
		ret = connect(*qmp_fd, (struct sockaddr *)&addr, sizeof(addr));
		if (ret == 0)
			break;

		/* ENOENT       : Socket may not have shown up yet
		 * ECONNREFUSED : Leftover socket hasn't been removed yet */
		if (errno == ENOENT || errno == ECONNREFUSED) {
			usleep(10000); /* Wait time 0.01s */
			continue;
		}

		ploop_err(errno, "Can't connect to socket %s", qmp_file);
		goto err;
	}

	if (ret) {
		ploop_err(errno, "Socket %s did not show up", qmp_file);
		goto err;
	}

	*qmp_fp = fdopen(*qmp_fd, "a+");
	if (*qmp_fp == NULL) {
		ploop_err(errno, "Can't create file stream for qmp");
		rc = SYSEXIT_SYS;
		goto err;
	}

	setvbuf(*qmp_fp, NULL, _IONBF, 0);

	/* Get first QMP greeting message */
	rc = qmp_get_reply(*qmp_fp, NULL);
	if (rc)
		goto err;

	rc = qmp_run_cmd(*qmp_fp, "qmp_capabilities", NULL, NULL);
	if (rc)
		goto err;

	return 0;

err:
	qcow_quit_qemu(*qmp_fp, *qmp_fd, *pid, *dev_fd, qmp_dir, 1);

	return rc;
}

static struct json_object *qmp_bitmap_merge_args(const char *name)
{
	struct json_object *args;
	struct json_object *bmps;
	struct json_object *el;

	args = json_object_new_object();
	json_object_object_add(args, "node", json_object_new_string("vz-ploop"));
	json_object_object_add(args, "target", json_object_new_string(name));
	json_object_object_add(args, "__vz_push", json_object_new_boolean(1));

	el = json_object_new_object();
	json_object_object_add(el, "node", json_object_new_string("vz-qcow2-node"));
	json_object_object_add(el, "name", json_object_new_string(name));

	bmps = json_object_new_array();
	json_object_array_add(bmps, el);
	json_object_object_add(args, "bitmaps", bmps);

	return args;
}

static struct json_object *qmp_bitmap_remove_args(const char *name)
{
	struct json_object *args;

	args = json_object_new_object();
	json_object_object_add(args, "node", json_object_new_string("vz-qcow2-node"));
	json_object_object_add(args, "name", json_object_new_string(name));

	return args;
}

static int qcow_load_cbt(const char *dev, int fd, const char *image, const char *uuid)
{
	int pid = 0;
	int dev_fd = 0;
	int qmp_fd = 0;
	int ret, rc;
	struct json_object *args = NULL;
	FILE *qmp_fp = NULL;
	char qmp_dir[PATH_MAX];

	rc = qmp_launch_qemu(dev, fd, image, &pid, &dev_fd, qmp_dir,
		&qmp_fd, &qmp_fp);
	if (rc)
		return rc;

	args = qmp_bitmap_merge_args(uuid);
	rc = qmp_run_cmd(qmp_fp, "block-dirty-bitmap-merge", args, NULL);
	if (rc)
		goto err;

	args = qmp_bitmap_remove_args(uuid);
	rc = qmp_run_cmd(qmp_fp, "block-dirty-bitmap-remove", args, NULL);
	if (rc)
		goto err;

	rc = 0;

err:
	ret = qcow_quit_qemu(qmp_fp, qmp_fd, pid, dev_fd, qmp_dir, rc);
	if (!rc && ret)
		rc = ret;

	return rc;
}

static struct json_object *qmp_bitmap_move_args(const char *name)
{
	struct json_object *args;
	struct json_object *actions;
	struct json_object *add;
	struct json_object *merge;
	struct json_object *data;
	struct json_object *bmps;
	struct json_object *el;

	data = json_object_new_object();
	json_object_object_add(data, "node", json_object_new_string("vz-qcow2-node"));
	json_object_object_add(data, "name", json_object_new_string(name));
	json_object_object_add(data, "persistent", json_object_new_boolean(1));

	add = json_object_new_object();
	json_object_object_add(add, "type", json_object_new_string("block-dirty-bitmap-add"));
	json_object_object_add(add, "data", data);

	data = json_object_new_object();
	json_object_object_add(data, "node", json_object_new_string("vz-qcow2-node"));
	json_object_object_add(data, "target", json_object_new_string(name));

	el = json_object_new_object();
	json_object_object_add(el, "node", json_object_new_string("vz-ploop"));
	json_object_object_add(el, "name", json_object_new_string(name));
	json_object_object_add(el, "__vz_pull", json_object_new_boolean(1));

	bmps = json_object_new_array();
	json_object_array_add(bmps, el);
	json_object_object_add(data, "bitmaps", bmps);

	merge = json_object_new_object();
	json_object_object_add(merge, "type", json_object_new_string("block-dirty-bitmap-merge"));
	json_object_object_add(merge, "data", data);

	actions = json_object_new_array();
	json_object_array_add(actions, add);
	json_object_array_add(actions, merge);

	args = json_object_new_object();
	json_object_object_add(args, "actions", actions);

	return args;
}

static int qcow_save_cbt(const char *uuid, const char *dev,
		 int fd, const char *image)
{
	int pid = 0;
	int dev_fd = 0;
	int qmp_fd = 0;
	int ret, rc;
	struct json_object *args = NULL;
	FILE *qmp_fp = NULL;
	char qmp_dir[PATH_MAX];

	rc = qmp_launch_qemu(dev, fd, image, &pid, &dev_fd, qmp_dir,
		&qmp_fd, &qmp_fp);
	if (rc)
		return rc;

	args = qmp_bitmap_move_args(uuid);
	rc = qmp_run_cmd(qmp_fp, "transaction", args, NULL);
	if (rc)
		ploop_err(0, "Can't move CBT from device to qcow2 image");

	ret = qcow_quit_qemu(qmp_fp, qmp_fd, pid, dev_fd, qmp_dir, rc);
	if (!rc && ret)
		rc = ret;

	return rc;
}

int qcow_add(char **images, off_t size, int minor,
	 struct ploop_mount_param *param, struct ploop_disk_images_data *di)
{
	int fd, rc;
	char b[4096];
	const char *i = images[0];

	if (param->device[0] == '\0')
		get_dev_name(param->device, sizeof(param->device));
	ploop_log(0, "Adding qcow delta dev=%s img=%s size=%lu (%s)",
			param->device, i, size, param->ro ? "ro":"rw");

	fd = open(i, O_DIRECT | (param->ro ? O_RDONLY : O_RDWR));
	if (fd < 0) {
		ploop_err(errno, "Can't open file %s", i);
		return SYSEXIT_OPEN;
	}

	if (!param->ro) {
		rc = qcow_update_hdr(i, QCOW2_INCOMPAT_DIRTY, 1);
		if (rc)
			goto err;
	}

	if ((di && di->cbt_uuid) && !param->ro) {
		rc = dm_create(param->device, minor, "zero-rq", 0, size, 0, "");
		if (rc)
			goto err;

		rc = qcow_load_cbt(param->device, fd, i, di->cbt_uuid);
		if (rc)
			goto err;

		rc = dm_reload(di, param->device, size, 0);
	} else {
		snprintf(b, sizeof(b), "%d", fd);
		rc = dm_create(param->device, minor, "qcow2", 0, size, param->ro, b);
	}

err:
	if (rc && !param->ro)
		qcow_update_hdr(i, QCOW2_INCOMPAT_DIRTY, 0);

	close(fd);

	return rc;
}

static int add_image(struct ploop_disk_images_data *di, struct ploop_mount_param *param)
{
	char *images[] = {find_image_by_guid(di, get_top_delta_guid(di)), NULL};

	return qcow_add(images, di->size, 0, param, di);
}

int qcow_mount(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param)
{
	int rc;

	rc = qcow_check(di);
	if (rc)
		return rc;
	return add_image(di, param);
}

int qcow_umount(struct ploop_disk_images_data *di,
		const char *device, const char *image)
{
	int rc, fd, image_fmt;
	off_t size;
	char buf[64];
	__u8 uuid[16];

	if (di && di->vol && di->vol->ro)
		return 0;

	rc = get_image_param_online(NULL, device, NULL, &size, NULL, NULL, &image_fmt);
	if (rc)
		return rc;

	if (image_fmt != QCOW_FMT)
		return 0;

	rc = wait_for_open_count(device, di ?
		di->runtime->umount_timeout : PLOOP_UMOUNT_TIMEOUT);
	if (rc)
		return rc;

	rc = ploop_suspend_device(device);
	if (rc)
		return rc;

	fd = open(device, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		rc = SYSEXIT_DEVICE;
		goto err;
	}

	rc = cbt_get_dirty_bitmap_metadata(fd, uuid, NULL);
	close(fd);
	if (rc) {
		if (rc == SYSEXIT_NOCBT)
			rc = 0;
		goto err;
	}

	uuid_unparse(uuid, buf);
	ploop_log(0, "Found dirty bitmap %s for %s, move it to qcow2 image %s",
		buf, device, image);

	fd = open(image, O_RDWR);
	if (fd < 0) {
		ploop_err(errno, "Can't open qcow2 image %s", image);
		rc = SYSEXIT_DEVICE;
		goto err;
	}

	rc = dm_reload_other(device, "zero-rq", size);
	if (rc)
		goto err;

	ploop_resume_device(device);

	rc = qcow_save_cbt(buf, device, fd, image);
	close(fd);
	if (!rc)
		rc = qcow_update_hdr(image, QCOW2_INCOMPAT_DIRTY, 0);

	return rc;

err:
	ploop_resume_device(device);

	return rc;
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

int qcow_alloc_active_bitmap(int fd, __u64 **bitmap, __u32 *bitmap_size,
		int *nr_clusters)
{
	int rc = 0;
	size_t i, j, size, cluster_size;
	size_t l1_size, l1_entries, l2_entries;
	struct qcow_hdr hdr;
	uint32_t version;
	uint64_t disk_size;
	uint64_t *l1 = NULL;
	uint64_t *l2 = NULL;

	size = pread(fd, &hdr, sizeof(hdr), 0);
	if (size != sizeof(hdr)) {
		ploop_err(errno, "Can't read header of qcow2");
		rc = SYSEXIT_READ;
		goto err;
	}

	/* All numbers in qcow2 are stored in Big Endian byte order */
	version = bswap_32(hdr.version);
	if (version != 2 && version != 3) {
		ploop_err(0, "Unknown version of qcow2 %u", version);
		rc = SYSEXIT_PLOOPFMT;
		goto err;
	}

	cluster_size = 1ull << bswap_32(hdr.cluster_bits);
	disk_size = bswap_64(hdr.size);
	l1_entries = bswap_32(hdr.l1_size);

	ploop_log(0, "qcow2 version: %u", version);
	ploop_log(0, "qcow2 cluster size: %lu", cluster_size);
	ploop_log(0, "qcow2 disk size: %lu", disk_size);
	if (version == 3)
		ploop_log(0, "qcow2 incompatible features: %016llx",
			bswap_64(hdr.incompatible_features));

	l1_size = l1_entries * sizeof(uint64_t);
	if (p_memalign((void *)&l1, sizeof(uint64_t), l1_size)) {
		ploop_err(errno, "Can't allocate buffer for L1 table");
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	size = pread(fd, l1, l1_size, bswap_64(hdr.l1_table_offset));
	if (size != l1_size) {
		ploop_err(errno, "Can't read L1 table from qcow2");
		rc = SYSEXIT_READ;
		goto err;
	}

	l2_entries = cluster_size / sizeof(uint64_t);
	if (p_memalign((void *)&l2, sizeof(uint64_t), cluster_size)) {
		ploop_err(errno, "Can't allocate buffer for L2 table");
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	*bitmap_size = (disk_size + cluster_size - 1) / cluster_size;
	size = (*bitmap_size + 7) / 8;
	size = (size + sizeof(unsigned long) - 1) & ~(sizeof(unsigned long) - 1);
	if (p_memalign((void *)bitmap, sizeof(uint64_t), size)) {
		ploop_err(errno, "Can't allocate bitmap for used clusters");
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	bzero(*bitmap, size);
	*nr_clusters = 0;

	for (i = 0; i < l1_entries; i++) {
		uint64_t l1_entry = bswap_64(l1[i]);
		if (l1_entry & L1_CLUSTER_USED && l1_entry & L1_OFFSET_MASK) {
			uint64_t offset = l1_entry & L1_OFFSET_MASK;
			size = pread(fd, l2, cluster_size, offset);
			if (size != cluster_size) {
				ploop_err(errno, "Can't read L2 table from qcow2");
				rc = SYSEXIT_READ;
				goto err;
			}

			for (j = 0; j < l2_entries && (i * l2_entries + j) < *bitmap_size; j++) {
				uint64_t l2_entry = bswap_64(l2[j]);
				if ((l2_entry & L2_CLUSTER_STANDARD ||
				l2_entry & L2_CLUSTER_COMPRESSED) && l2_entry & L2_OFFSET_MASK) {
					if (l2_entry & L2_CLUSTER_STANDARD)
						ploop_log(3, "[%lu]->%llu", i * l2_entries + j,
							(l2_entry & L2_OFFSET_MASK) / cluster_size);
					else
						ploop_log(3, "[%lu]->%016llx", i * l2_entries + j,
							l2_entry & L2_COMPRESSED_OFFSET_SIZE_MASK);

					BMAP_SET(*bitmap, i * l2_entries + j);
					(*nr_clusters)++;
				}
			}
		}
	}

	ploop_log(0, "found %d/%u active used clusters", *nr_clusters, *bitmap_size);

err:
	free(l2);
	free(l1);

	if (rc) {
		free(*bitmap);
		*bitmap = NULL;
	}

	return rc;
}

int qcow_alloc_bitmap(int fd, __u64 **bitmap, __u32 *bitmap_size,
		int *nr_clusters)
{
	int rc = 0;
	size_t i, j, size, cluster_size, refcount_bits;
	size_t table_size, table_entries, block_entries;
	struct qcow_hdr hdr;
	uint32_t version;
	uint64_t *table = NULL;
	uint8_t *block = NULL;

	/*
	 * At first we try to scan active cluster mapping tables
	 * because of lazy refcounts we can read not relevant
	 * values for active clusters from refcount tables.
	 */
	rc = qcow_alloc_active_bitmap(fd, bitmap, bitmap_size, nr_clusters);
	if (rc)
		return rc;

	size = pread(fd, &hdr, sizeof(hdr), 0);
	if (size != sizeof(hdr)) {
		ploop_err(errno, "Can't read header of qcow2");
		rc = SYSEXIT_READ;
		goto err;
	}

	version = bswap_32(hdr.version);
	cluster_size = 1ull << bswap_32(hdr.cluster_bits);
	table_entries = bswap_32(hdr.refcount_table_clusters);
	if (version == 2)
		refcount_bits = 16; /* Always use fixed value for version 2 */
	else
		refcount_bits = 1ull << bswap_32(hdr.refcount_order);

	ploop_log(0, "qcow2 refcount bits: %lu", refcount_bits);
	if (version == 3)
		ploop_log(0, "qcow2 compatible features: %016llx",
			bswap_64(hdr.compatible_features));

	table_size = table_entries * sizeof(uint64_t);
	if (p_memalign((void *)&table, sizeof(uint64_t), table_size)) {
		ploop_err(errno, "Can't allocate buffer for refcount table");
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	size = pread(fd, table, table_size, bswap_64(hdr.refcount_table_offset));
	if (size != table_size) {
		ploop_err(errno, "Can't read refcount table from qcow2");
		rc = SYSEXIT_READ;
		goto err;
	}

	block_entries = (cluster_size * 8) / refcount_bits;
	if (p_memalign((void *)&block, sizeof(uint64_t), cluster_size)) {
		ploop_err(errno, "Can't allocate buffer for refcount block");
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	for (i = 0; i < table_entries; i++) {
		uint64_t offset = bswap_64(table[i]);
		if (offset) {
			size = pread(fd, block, cluster_size, offset);
			if (size != cluster_size) {
				ploop_err(errno, "Can't read refcount block from qcow2");
				rc = SYSEXIT_READ;
				goto err;
			}

			for (j = 0; j < block_entries && (i * block_entries + j) < *bitmap_size; j++) {
				uint64_t refcount;
				switch (refcount_bits) {
				case 8:
					refcount = block[j];
					break;
				case 16:
					refcount = bswap_16(*(uint16_t*)&block[j * 2]);
					break;
				case 32:
					refcount = bswap_32(*(uint32_t*)&block[j * 4]);
					break;
				case 64:
					refcount = bswap_64(*(uint64_t*)&block[j * 8]);
					break;
				default:
					ploop_err(0, "Incorrect value of refcount bits %lu", refcount_bits);
					rc = SYSEXIT_PLOOPFMT;
					goto err;
				}

				if (refcount && !BMAP_GET(*bitmap, i * block_entries + j)) {
					ploop_log(3, "[%lu]->%lu", i * block_entries + j, refcount);
					BMAP_SET(*bitmap, i * block_entries + j);
					(*nr_clusters)++;
				}
			}
		}
	}

	ploop_log(0, "total found %d/%u used clusters", *nr_clusters, *bitmap_size);

err:
	free(block);
	free(table);

	if (rc) {
		free(*bitmap);
		*bitmap = NULL;
	}

	return rc;
}
