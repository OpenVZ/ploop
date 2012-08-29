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
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <mntent.h>

#include "ploop.h"
#include "cleanup.h"

static int ploop_mount_fs(struct ploop_mount_param *param);

static int is_old_snapshot_format(struct ploop_disk_images_data *di)
{
	if (di->top_guid != NULL && !guidcmp(di->top_guid, TOPDELTA_UUID))
		return 0;

	ploop_err(0, "Snapshot is in old format");
	return 1;
}

/* set cancel flag
 * Note: this function also clear the flag
 */
static int is_operation_cancelled(void)
{
	struct ploop_cancel_handle *cancel_data;

	cancel_data = ploop_get_cancel_handle();
	if (cancel_data->flags) {
		cancel_data->flags = 0;
		return 1;
	}
	return 0;
}

void free_mount_param(struct ploop_mount_param *param)
{
	free(param->target);
	free(param->guid);
}

static off_t bytes2sec(__u64 bytes)
{
	return (bytes >> PLOOP1_SECTOR_LOG) + ((bytes % SECTOR_SIZE) ? 1 : 0);
}

int sys_fallocate(int fd, int mode, off_t offset, off_t len)
{
	return syscall(__NR_fallocate, fd, mode, offset, len);
}

int sys_syncfs(int fd)
{
	return syscall(__NR_syncfs, fd);
}

int get_list_size(char **list)
{
	int i;
	for (i = 0; list[i] != NULL; i++);

	return i;
}

static char **make_images_list(struct ploop_disk_images_data *di, char *guid, int reverse)
{
	int n;
	char **images;
	char *file;
	int done = 0;
	int snap_id;

	assert(guid);

	if (di->nimages == 0) {
		ploop_err(0, "No images");
		return NULL;
	}

	images = malloc(sizeof(char *) * (di->nimages + 1));
	if (images == NULL)
		return NULL;

	for (n = 0; n < di->nsnapshots; n++) {
		snap_id = find_snapshot_by_guid(di, guid);
		if (snap_id == -1) {
			ploop_err(0, "Can't find snapshot by uuid %s", guid);
			goto err;
		}
		file = find_image_by_guid(di, guid);
		if (file == NULL) {
			ploop_err(0, "Can't find image by guid %s", guid);
			goto err;
		}
		images[n] = strdup(file);
		if (images[n] == NULL)
			goto err;
		if (n == di->nimages) {
			ploop_err(0, "Inconsistency detected: snapshots > images");
			goto err;
		}
		guid = di->snapshots[snap_id]->parent_guid;
		if (!strcmp(guid, NONE_UUID)) {
			done = 1;
			break;
		}
	}
	if (!done) {
		ploop_err(0, "Inconsistency detected, base image not found");
		goto err;
	}
	images[++n] = NULL;

	if (!reverse) {
		int i;

		for (i = 0; i < n / 2; i++) {
			file = images[n-i-1];
			images[n-i-1] = images[i];
			images[i] = file;
		}
	}
	return images;

err:
	images[n] = NULL;
	free_images_list(images);
	return NULL;
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

void free_images_list(char **images)
{
	int i;

	if (images == NULL)
		return;
	for (i = 0; images[i] != NULL; i++)
		free(images[i]);

	free(images);
}

static int WRITE(int fd, void * buf, unsigned int size)
{
	ssize_t res;

	res = write(fd, buf, size);
	if (res == size)
		return 0;

	if (res >= 0)
		errno = EIO;
	ploop_err(errno, "WRITE");

	return -1;
}

int PWRITE(struct delta * delta, void * buf, unsigned int size, off_t off)
{
	ssize_t res;

	res = delta->fops->pwrite(delta->fd, buf, size, off);
	if (res == size)
		return 0;
	if (res >= 0)
		errno = EIO;
	ploop_err(errno, "pwrite %d", size);

	return -1;
}

int PREAD(struct delta * delta, void *buf, unsigned int size, off_t off)
{
	ssize_t res;

	res = delta->fops->pread(delta->fd, buf, size, off);
	if (res == size)
		return 0;
	if (res >= 0)
		errno = EIO;
	ploop_err(errno, "pread %d", size);

	return -1;
}

static int get_temp_mountpoint(const char *file, int create, char *buf, int len)
{
	struct stat st;

	snprintf(buf, len, "%s.mnt", file);

	if (create) {
		if (stat(buf, &st) == 0)
			return 0;
		if (mkdir(buf, 0700)) {
			ploop_err(errno, "mkdir %s", buf);
			return SYSEXIT_MKDIR;
		}
	}
	return 0;
}

static int check_blockdev_size(off_t sectors)
{
	const off_t max = (__u32)-1;

	if (sectors > max) {
		ploop_err(0, "An incorrect block device size specified: %lu sectors."
				" The maximum allowed size is %lu sectors.",
				sectors, max);
		return -1;
	}

	return 0;
}

static int create_empty_delta(const char *path, __u32 blocksize, off_t bdsize)
{
	int fd;
	void * buf = NULL;
	struct ploop_pvd_header *vh;
	__u32 SizeToFill;
	__u64 cluster = S2B(blocksize);

	assert(blocksize);

	if (check_blockdev_size(bdsize))
		return -1;

	if (posix_memalign(&buf, 4096, cluster)) {
		ploop_err(errno, "posix_memalign");
		return -1;
	}

	ploop_log(0, "Creating delta %s bs=%d size=%ld sectors",
			path, blocksize, (long)bdsize);
	fd = open(path, O_RDWR|O_CREAT|O_DIRECT|O_EXCL, 0600);
	if (fd < 0) {
		ploop_err(errno, "Can't open %s", path);
		free(buf);
		return -1;
	}

	memset(buf, 0, cluster);

	vh = buf;
	SizeToFill = generate_pvd_header(vh, bdsize, blocksize);
	vh->m_Flags = CIF_Empty;

	if (WRITE(fd, buf, cluster))
		goto out_close;

	if (SizeToFill > cluster) {
		int i;
		memset(buf, 0, cluster);
		for (i = 1; i < SizeToFill / cluster; i++)
			if (WRITE(fd, buf, cluster))
				goto out_close;
	}

	if (fsync(fd)) {
		ploop_err(errno, "fsync %s", path);
		goto out_close;
	}
	free(buf);

	return fd;

out_close:
	close(fd);
	unlink(path);
	free(buf);
	return -1;
}

static int create_empty_preallocated_delta(const char *path, __u32 blocksize, off_t bdsize)
{
	struct delta odelta = {};
	int rc, clu, i;
	void * buf = NULL;
	struct ploop_pvd_header vh;
	__u32 SizeToFill;
	__u32 l2_slot = 0;
	off_t off;
	__u64 cluster = S2B(blocksize);

	if (check_blockdev_size(bdsize))
		return -1;

	if (posix_memalign(&buf, 4096, cluster)) {
		ploop_err(errno, "posix_memalign");
		return -1;
	}

	ploop_log(0, "Creating preallocated delta %s bs=%d size=%ld sectors",
			path, blocksize, (long)bdsize);
	rc = open_delta_simple(&odelta, path, O_RDWR|O_CREAT|O_EXCL, OD_OFFLINE);
	if (rc) {
		free(buf);
		return -1;
	}

	memset(buf, 0, cluster);
	SizeToFill = generate_pvd_header(&vh, bdsize, blocksize);
	memcpy(buf, &vh, sizeof(struct ploop_pvd_header));
	vh.m_Flags = CIF_Empty;

	rc = sys_fallocate(odelta.fd, 0, 0, S2B(vh.m_FirstBlockOffset + vh.m_SizeInSectors));
	if (rc) {
		if (errno == ENOTSUP)
			ploop_err(errno, "fallocate");
		ploop_err(errno, "Failed to create %s", path);
		goto out_close;
	}

	for (clu = 0; clu < SizeToFill / cluster; clu++) {
		if (is_operation_cancelled())
			goto out_close;

		if (clu > 0)
			memset(buf, 0, cluster);
		for (i = (clu == 0 ? PLOOP_MAP_OFFSET : 0); i < (cluster / sizeof(__u32)) &&
				l2_slot < vh.m_Size;
				i++, l2_slot++)
		{
			off = vh.m_FirstBlockOffset + (l2_slot * blocksize);
			((__u32*)buf)[i] = off;
		}
		if (WRITE(odelta.fd, buf, cluster))
			goto out_close;
	}

	if (fsync(odelta.fd)) {
		ploop_err(errno, "fsync %s", path);
		goto out_close;
	}
	free(buf);

	return odelta.fd;

out_close:
	close(odelta.fd);
	unlink(path);
	free(buf);
	return -1;
}

static int create_raw_delta(const char * path, off_t bdsize)
{
	int fd;
	void * buf = NULL;
	off_t pos;

	ploop_log(0, "Creating raw delta %s size=%ld sectors",
			path, (long)bdsize);

	if (posix_memalign(&buf, 4096, DEF_CLUSTER)) {
		ploop_err(errno, "posix_memalign");
		return -1;
	}

	fd = open(path, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		ploop_err(errno, "Can't open %s", path);
		free(buf);
		return -1;
	}

	memset(buf, 0, DEF_CLUSTER);

	pos = 0;
	while (pos < bdsize) {
		if (is_operation_cancelled())
			goto out_close;
		off_t copy = bdsize - pos;
		if (copy > DEF_CLUSTER/512)
			copy = DEF_CLUSTER/512;
		if (WRITE(fd, buf, copy*512))
			goto out_close;
		pos += copy;
	}

	if (fsync(fd)) {
		ploop_err(errno, "fsync");
		goto out_close;
	}

	free(buf);
	close(fd);

	return fd;

out_close:
	close(fd);
	unlink(path);
	free(buf);
	return -1;
}

void get_disk_descriptor_fname(struct ploop_disk_images_data *di, char *buf, int size)
{
	if (di->runtime->xml_fname == NULL) {
		// Use default DiskDescriptor.xml
		const char *image = di->images[0]->file;

		get_basedir(image, buf, size - sizeof(DISKDESCRIPTOR_XML));

		strcat(buf, "/"DISKDESCRIPTOR_XML);
	} else {
		// Use custom
		snprintf(buf, size, "%s", di->runtime->xml_fname);
	}
}

static void fill_diskdescriptor(struct ploop_pvd_header *vh, struct ploop_disk_images_data *di)
{
	di->size = vh->m_SizeInSectors;
	di->heads = vh->m_Heads;
	di->cylinders = vh->m_Cylinders;
	di->sectors = vh->m_Sectors;
}

static int create_image(struct ploop_disk_images_data *di,
		const char *file, __u32 blocksize, off_t size_sec, int mode)
{
	int fd = -1;
	int ret;
	struct ploop_pvd_header vh = {};
	char fname[PATH_MAX];
	struct stat st;

	if (size_sec == 0 || file == NULL)
		return SYSEXIT_PARAM;
	if (stat(file, &st) == 0) {
		ploop_err(0, "File already exists %s", file);
		return SYSEXIT_PARAM;
	}

	ret = SYSEXIT_NOMEM;
	di->size = size_sec;
	di->mode = mode;

	ret = SYSEXIT_CREAT;
	if (mode == PLOOP_RAW_MODE)
		fd = create_raw_delta(file, size_sec);
	else if (mode == PLOOP_EXPANDED_MODE)
		fd = create_empty_delta(file, blocksize, size_sec);
	else if (mode == PLOOP_EXPANDED_PREALLOCATED_MODE)
		fd = create_empty_preallocated_delta(file, blocksize, size_sec);
	if (fd < 0)
		goto err;
	close(fd);

	generate_pvd_header(&vh, size_sec, blocksize);
	fill_diskdescriptor(&vh, di);

	if (realpath(file, fname) == NULL) {
		ploop_err(errno, "failed realpath(%s)", file);
		goto err;
	}

	if (ploop_di_add_image(di, fname, TOPDELTA_UUID, NONE_UUID)) {
		ret = SYSEXIT_NOMEM;
		goto err;
	}

	get_disk_descriptor_fname(di, fname, sizeof(fname));
	if (ploop_store_diskdescriptor(fname, di))
		goto err;
	ret = 0;
err:
	if (ret)
		unlink(file);

	return ret;
}

static int create_balloon_file(struct ploop_disk_images_data *di,
		char *device, char *fstype)
{
	int fd, ret;
	char mnt[PATH_MAX];
	char fname[PATH_MAX + sizeof(BALLOON_FNAME)];
	struct ploop_mount_param mount_param = {};

	if (device == NULL)
		return -1;
	ploop_log(0, "Creating balloon file " BALLOON_FNAME);
	ret = get_temp_mountpoint(di->images[0]->file, 1, mnt, sizeof(mnt));
	if (ret)
		return ret;
	strcpy(mount_param.device, device);
	mount_param.target = mnt;
	ret = ploop_mount_fs(&mount_param);
	if (ret)
		goto out;
	snprintf(fname, sizeof(fname), "%s/"BALLOON_FNAME, mnt);

	fd = open(fname, O_CREAT|O_RDONLY|O_TRUNC, 0600);
	if (fd == -1) {
		ploop_err(errno, "Can't create balloon file %s", fname);
		ret = SYSEXIT_CREAT;
		goto out;
	}
	close(fd);
	ret = 0;
out:
	umount(mnt);
	rmdir(mnt);

	return ret;
}

static int ploop_init_image(struct ploop_disk_images_data *di, struct ploop_create_param *param)
{
	int ret;
	struct ploop_mount_param mount_param = {};

	if (param->fstype == NULL)
		return SYSEXIT_PARAM;

	if (di->nimages == 0) {
		ploop_err(0, "No images specified");
		return SYSEXIT_PARAM;
	}
	ret = ploop_mount_image(di, &mount_param);
	if (ret)
		return ret;
	if (!param->without_partition) {
		off_t size;

		ret = ploop_get_size(mount_param.device, &size);
		if (ret)
			goto err;

		ret = create_gpt_partition(mount_param.device, size, di->blocksize);
		if (ret)
			goto err;
	}
	ret = make_fs(mount_param.device, param->fstype);
	if (ret)
		goto err;
	ret = create_balloon_file(di, mount_param.device, param->fstype);
	if (ret)
		goto err;

err:
	if (ploop_umount_image(di))
		if (ret == 0)
			ret = SYSEXIT_UMOUNT;

	return ret;
}

static int ploop_drop_image(struct ploop_disk_images_data *di)
{
	int i;
	char fname[PATH_MAX];

	if (di->nimages == 0)
		return SYSEXIT_PARAM;

	get_disk_descriptor_fname(di, fname, sizeof(fname));
	unlink(fname);

	get_disk_descriptor_lock_fname(di, fname, sizeof(fname));
	unlink(fname);

	for (i = 0; i < di->nimages; i++) {
		ploop_log(1, "Dropping image %s", di->images[i]->file);
		unlink(di->images[i]->file);
	}

	get_temp_mountpoint(di->images[0]->file, 0, fname, sizeof(fname));
	unlink(fname);

	return 0;
}

int ploop_create_image(struct ploop_create_param *param)
{
	struct ploop_disk_images_data *di;
	int ret;
	__u32 blocksize;

	blocksize = param->blocksize ?
			param->blocksize : (1 << PLOOP1_DEF_CLUSTER_LOG);
	if (!is_valid_blocksize(blocksize)) {
		ploop_err(0, "Incorrect blocksize specified: %d",
				blocksize);
		return SYSEXIT_PARAM;
	}

	di = ploop_alloc_diskdescriptor();
	if (di == NULL)
		return SYSEXIT_NOMEM;
	di->blocksize = blocksize;
	ret = create_image(di, param->image, di->blocksize,
			param->size, param->mode);
	if (ret)
		return ret;
	if (param->fstype != NULL) {
		ret = ploop_init_image(di, param);
		if (ret)
			ploop_drop_image(di);
	}
	ploop_free_diskdescriptor(di);

	return ret;
}

#define PROC_PLOOP_MINOR	"/proc/vz/ploop_minor"

int ploop_getdevice(int *minor)
{
	int fd, ret;
	char buf[64];

	fd = open(PROC_PLOOP_MINOR, O_RDONLY);
	if (fd < 0) {
		ploop_err(errno, "Can't open " PROC_PLOOP_MINOR);
		return -1;
	}
	ret = read(fd, buf, sizeof(buf));
	if (ret == -1) {
		ploop_err(errno, "Can't read from " PROC_PLOOP_MINOR);
		close(fd);
		return -1;
	}
	if (sscanf(buf, "%d", minor) != 1) {
		ploop_err(0, "Can't get ploop minor '%s'", buf);
		close(fd);
		return -1;
	}

	return fd;
}

/* Workaround for bug #PCLIN-30116 */
static int do_ioctl(int fd, int req)
{
	int i, ret;

	for (i = 0; i < 60; i++) {
		ret = ioctl(fd, req, 0);
		if (ret == 0 || (ret == -1 && errno != EBUSY))
			return ret;
		sleep(1);
	}
	return ret;
}

static int do_umount(const char *mnt)
{
	int i, ret;

	for (i = 0; i < 6; i++) {
		ret = umount(mnt);
		if (ret == 0 || (ret == -1 && errno != EBUSY))
			return ret;
		ploop_log(3, "retry umount %s", mnt);
		sleep(1);
	}
	return ret;
}

static int delete_deltas(int devfd, const char *devname)
{
	int top;

	if (ploop_get_top_level(devfd, devname, &top))
		return errno;

	while (top >= 0) {
		if (ioctl(devfd, PLOOP_IOC_DEL_DELTA, &top) < 0) {
			ploop_err(errno, "PLOOP_IOC_DEL_DELTA dev=%s lvl=%d",
					devname, top);
			return errno;
		}
		top--;
	}

	return 0;
}

static int ploop_stop(int fd, const char *devname)
{
	if (do_ioctl(fd, PLOOP_IOC_STOP) < 0) {
		if (errno != EINVAL) {
			ploop_err(errno, "PLOOP_IOC_STOP");
			return SYSEXIT_DEVIOC;
		}
		if (delete_deltas(fd, devname))
			return SYSEXIT_DEVIOC;
	}

	if (ioctl(fd, PLOOP_IOC_CLEAR, 0) < 0) {
		ploop_err(errno, "PLOOP_IOC_CLEAR");
		return SYSEXIT_DEVIOC;
	}
	return 0;
}

static int get_mount_dir(const char *dev, char *buf, int size)
{
	FILE *fp;
	struct mntent *ent, mntbuf;
	int ret = 1;
	int len;
	const char *ep;
	char tmp[512];

	len = strlen(dev);
	if (len == 0)
		return -1;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		ploop_err(errno, "Can't open /proc/mounts");
		return -1;
	}
	while ((ent = getmntent_r(fp, &mntbuf, tmp, sizeof(tmp)))) {
		ep = ent->mnt_fsname + len;
		// check for /dev/ploopN or /dev/ploopNp1
		if (strncmp(dev, ent->mnt_fsname, len) == 0 &&
			(*ep == '\0' || strcmp(ep, "p1") == 0))
		{
			snprintf(buf, size, "%s", ent->mnt_dir);
			ret = 0;
			break;
		}
	}
	fclose(fp);
	return ret;
}

int ploop_get_mnt_by_dev(const char *dev, char *buf, int size)
{
	return get_mount_dir(dev, buf, size);
}

int ploop_fname_cmp(const char *p1, const char *p2)
{
	struct stat st1, st2;

	if (stat(p1, &st1)) {
		ploop_err(errno, "stat %s", p1);
		return -1;
	}
	if (stat(p2, &st2)) {
		ploop_err(errno, "stat %s", p2);
		return -1;
	}
	if (st1.st_dev == st2.st_dev &&
	    st1.st_ino == st2.st_ino)
		return 0;
	return 1;
}

static int get_dev_by_mnt(const char *path, int dev, char *buf, int size)
{
	FILE *fp;
	struct mntent *ent;
	int len;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		ploop_err(errno, "Can't open /proc/mounts");
		return -1;
	}
	while ((ent = getmntent(fp))) {
		if (strncmp(ent->mnt_fsname, "/dev/ploop", 10) != 0)
			continue;
		if (ploop_fname_cmp(path, ent->mnt_dir) == 0 ) {
			fclose(fp);
			len = strlen(ent->mnt_fsname);
			if (dev) {
				// return device in case partition used ploop1p1 -> ploop1
				if (strcmp(ent->mnt_fsname + len - 2, "p1") == 0 &&
						isdigit(ent->mnt_fsname[len - 3]))
					len -= 2; // strip p1
			}
			if (len + 1 > size) {
				ploop_err(0, "Buffer is too short");
				return -1;
			}

			snprintf(buf, len + 1, "%s", ent->mnt_fsname);
			return 0;
		}
	}
	fclose(fp);
	return 1;
}

int ploop_get_partition_by_mnt(const char *path, char *buf, int size)
{
	return get_dev_by_mnt(path, 0, buf, size);
}

int ploop_get_dev_by_mnt(const char *path, char *buf, int size)
{
	return get_dev_by_mnt(path, 1, buf, size);
}

char *ploop_get_base_delta_uuid(struct ploop_disk_images_data *di)
{
	int i;

	for (i = 0; i < di->nsnapshots; i++)
		if (strcmp(di->snapshots[i]->parent_guid, NONE_UUID) == 0)
			return di->snapshots[i]->guid;

	return NULL;
}

static const char *get_top_delta_guid(struct ploop_disk_images_data *di)
{
	return di->top_guid;
}

int ploop_get_top_delta_fname(struct ploop_disk_images_data *di, char *out, int len)
{
	const char *fname;

	fname = find_image_by_guid(di, get_top_delta_guid(di));
	if (fname == NULL){
		ploop_err(0, "Can't find image by uuid %s", di->top_guid);
		return -1;
	}
	if (snprintf(out, len, "%s", fname) > len -1) {
		ploop_err(0, "Not enough space to store data");
		return -1;
	}
	return 0;
}

int ploop_find_dev_by_uuid(struct ploop_disk_images_data *di,
		int check_state, char *out, int len)
{
	int ret;
	int running = 0;

	if (di->nimages <= 0) {
		ploop_err(0, "No images found in " DISKDESCRIPTOR_XML);
		return -1;
	}
	ret = ploop_find_dev(di->runtime->component_name, di->images[0]->file,
			out, len);
	if (ret == 0 && check_state) {
		if (ploop_get_attr(out, "running", &running)) {
			ploop_err(0, "Can't get running attr for %s",
					out);
			return -1;
		}
		if (!running) {
			ploop_err(0, "Unexpectedly found stopped ploop device %s",
					out);
			return -1;
		}
	}

	return ret;
}

int ploop_get_dev(struct ploop_disk_images_data *di, char *out, int len)
{
	int ret;

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev(di->runtime->component_name, di->images[0]->file, out, len);

	ploop_unlock_di(di);

	return ret;
}

static int reread_part(char *device)
{
	int fd;

	fd = open(device, O_RDONLY);
	if (fd == -1) {
		ploop_err(errno, "Can't open %s", device);
		return -1;
	}
	if (ioctl(fd, BLKRRPART, 0) < 0)
		ploop_err(errno, "BLKRRPART %s", device);
	close(fd);

	return 0;
}

static int ploop_mount_fs(struct ploop_mount_param *param)
{
	unsigned long flags =
		(param->flags & MS_NOATIME) |
		(param->ro ? MS_RDONLY : 0);
	char buf[PATH_MAX + sizeof(BALLOON_FNAME)];
	struct stat st;
	char *fstype = param->fstype == NULL ? DEFAULT_FSTYPE : param->fstype;
	char data[1024];
	char balloon_ino[64] = "";
	char part_device[64];

	if (reread_part(param->device))
		return SYSEXIT_MOUNT;

	if (get_partition_device_name(param->device, part_device, sizeof(part_device)))
		return SYSEXIT_MOUNT;
	/* Two step mount
	 * 1 mount ro and read balloon inode
	 * 2 remount with balloon_ino=ino
	 */
	if (mount(part_device, param->target,	fstype, MS_RDONLY, NULL)) {
		ploop_err(errno, "Can't mount file system dev=%s target=%s",
				part_device, param->target);
		return SYSEXIT_MOUNT;
	}
	snprintf(buf, sizeof(buf), "%s/" BALLOON_FNAME, param->target);
	if (stat(buf, &st) == 0)
		sprintf(balloon_ino, "balloon_ino=%llu,",
				(unsigned long long) st.st_ino);

	snprintf(data, sizeof(data), "%s%s%s",
			balloon_ino,
			param->quota ? "usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0," : "",
			param->mount_data ? param->mount_data : "");

	ploop_log(0, "Mounting %s at %s fstype=%s data='%s' %s",
			part_device, param->target, fstype,
			data, param->ro  ? "ro":"");

	if (mount(part_device, param->target, fstype, flags | MS_REMOUNT, data)) {
		ploop_err(errno, "Can't mount file system dev=%s target=%s",
				part_device, param->target);
		umount(param->target);
		return SYSEXIT_MOUNT;
	}

	return 0;
}

static int add_delta(int lfd, char *image, struct ploop_ctl_delta *req)
{
	int fd;
	int ro = (req->c.pctl_flags == PLOOP_FMT_RDONLY);

	fd = open(image, O_DIRECT | (ro ? O_RDONLY : O_RDWR));
	if (fd < 0) {
		ploop_err(errno, "Can't open file %s", image);
		close(fd);
		return SYSEXIT_OPEN;
	}

	req->f.pctl_fd = fd;

	if (ioctl(lfd, PLOOP_IOC_ADD_DELTA, req) < 0) {
		ploop_err(0, "Can't add image %s: %s", image,
				(errno == ENOTSUP) ?
					"unsupported underlying filesystem"
					: strerror(errno));
		close(fd);
		return SYSEXIT_DEVIOC;
	}
	close(fd);
	return 0;
}

static int create_ploop_dev(int minor)
{
	char device[64];
	char devicep1[64];
	struct stat st;

	strcpy(device, "/dev/");
	make_sysfs_dev_name(minor, device + 5, sizeof(device) - 5);
	/* Create pair /dev/ploopN & /dev/ploopNp1 */
	if (stat(device, &st)) {
		if (mknod(device, S_IFBLK, gnu_dev_makedev(PLOOP_DEV_MAJOR, minor))) {
			ploop_err(errno, "mknod %s", device);
			return SYSEXIT_MKNOD;
		}
		chmod(device, 0600);
	}
	snprintf(devicep1, sizeof(devicep1), "%sp1", device);
	if (stat(devicep1, &st)) {
		if (mknod(devicep1, S_IFBLK, gnu_dev_makedev(PLOOP_DEV_MAJOR, minor+1))) {
			ploop_err(errno, "mknod %s", devicep1);
			return SYSEXIT_MKNOD;
		}
		chmod(devicep1, 0600);
	}
	return 0;
}

/* NB: caller will take care about *lfd_p even if we fail */
static int add_deltas(struct ploop_disk_images_data *di,
		char **images, struct ploop_mount_param *param,
		int raw, __u32 blocksize, int *lfd_p)
{
	int lckfd = -1;
	char *device = param->device;
	int i;
	int ret = 0;
	struct ploop_ctl_delta req = {};

	if (device[0] == '\0') {
		char buf[64];
		int minor;

		lckfd = ploop_getdevice(&minor);
		if (lckfd == -1)
			return SYSEXIT_DEVICE;

		snprintf(device, sizeof(param->device), "/dev/%s",
				make_sysfs_dev_name(minor, buf, sizeof(buf)));
		ret = create_ploop_dev(minor);
		if (ret)
			goto err;
	}

	*lfd_p = open(device, O_RDONLY);
	if (*lfd_p < 0) {
		ploop_err(errno, "Can't open device %s", device);
		ret = SYSEXIT_DEVICE;
		goto err;
	}

	ret = register_ploop_dev(di ? di->runtime->component_name : NULL,
			images[0], device);
	if (ret)
		goto err;

	req.c.pctl_format = PLOOP_FMT_PLOOP1;
	req.c.pctl_cluster_log = ffs(blocksize) - 1;
	req.c.pctl_size = 0;
	req.c.pctl_chunks = 1;

	req.f.pctl_fd = -1;
	req.f.pctl_type = PLOOP_IO_AUTO;

	for (i = 0; images[i] != NULL; i++) {
		int ro = (images[i+1] != NULL || param->ro) ? 1: 0;
		char *image = images[i];

		if (raw && i == 0)
			req.c.pctl_format = PLOOP_FMT_RAW;
		if (ro)
			req.c.pctl_flags = PLOOP_FMT_RDONLY;
		else
			req.c.pctl_flags &= ~PLOOP_FMT_RDONLY;

		ploop_log(0, "Adding delta dev=%s img=%s (%s)",
				device, image, ro ? "ro" : "rw");
		ret = add_delta(*lfd_p, image, &req);
		if (ret)
			goto err1;
	}
	if (ioctl(*lfd_p, PLOOP_IOC_START, 0) < 0) {
		ploop_err(errno, "PLOOP_IOC_START");
		ret = SYSEXIT_DEVIOC;
		goto err;
	}

err1:
	if (ret) {
		int err = 0;

		for (i = i - 1; i >= 0; i--) {
			err = ioctl(*lfd_p, PLOOP_IOC_DEL_DELTA, &i);
			if (err < 0) {
				ploop_err(errno, "PLOOP_IOC_DEL_DELTA level=%d", i);
				break;
			}
		}
		if (err == 0 && ioctl(*lfd_p, PLOOP_IOC_CLEAR, 0) < 0)
			ploop_err(errno, "PLOOP_IOC_CLEAR");

		unregister_ploop_dev(di ? di->runtime->component_name : NULL, images[0]);
	}
err:
	if (lckfd != -1)
		close(lckfd);
	return ret;
}

int ploop_mount(struct ploop_disk_images_data *di, char **images,
		struct ploop_mount_param *param, int raw)
{
	int lfd = -1;
	struct stat st;
	int i;
	int ret = 0;
	__u32 blocksize = 0;

	if (images == NULL || images[0] == NULL) {
		ploop_err(0, "ploop_mount: no deltas to mount");
		return SYSEXIT_PARAM;
	}

	if (param->target != NULL && stat(param->target, &st)) {
		ploop_err(0, "Mount point %s does not exist", param->target);
		return SYSEXIT_PARAM;
	}

	if (raw) {
		if (param->blocksize)
			blocksize = param->blocksize;
		else if (di)
			blocksize = di->blocksize;
		else {
			ploop_err(0, "Blocksize is not specified");
			return SYSEXIT_PARAM;
		}
	} else if (di)
		blocksize = di->blocksize;

	for (i = 0; images[i] != NULL; i++) {
		int ro;
		int flags = FSCK_CHECK | (di ? FSCK_DROPINUSE : 0);
		__u32 cur_blocksize;

		if (raw && i == 0)
			continue;

		ro  = (images[i+1] != NULL || param->ro) ? 1 : 0;
		ret = ploop_fsck(images[i], flags, ro, 0, &cur_blocksize);
		if (ret) {
			ploop_err(0, "%s (%s): irrecoverable errors",
					images[i], ro ? "ro" : "rw");
			goto err;
		}
		if (blocksize == 0)
			blocksize = cur_blocksize;
		if (cur_blocksize != blocksize) {
			ploop_err(0, "Incorrect blocksize %s bs=%d [current bs=%d]",
					images[i], blocksize, cur_blocksize);
			ret = SYSEXIT_PARAM;
			goto err;
		}
	}

	ret = add_deltas(di, images, param, raw, blocksize, &lfd);

	if (ret)
		goto err;

	if (param->target != NULL) {
		ret = ploop_mount_fs(param);
		if (ret)
			ploop_stop(lfd, param->device);
	}

err:
	if (lfd >= 0)
		close(lfd);

	if (ret == 0 && di != NULL &&
			di->runtime->component_name == NULL &&
			param->target != NULL)
		drop_statfs_info(di->images[0]->file);

	return ret;
}

static int mount_image(struct ploop_disk_images_data *di, struct ploop_mount_param *param, int flags)
{
	int ret;
	char **images;
	char *guid;

	if (param->guid != NULL) {
		if (find_image_by_guid(di, param->guid) == NULL) {
			ploop_err(0, "Uuid %s not found", param->guid);
			return SYSEXIT_PARAM;
		}
		guid = param->guid;
	} else
		guid = di->top_guid;

	if (!param->ro) {
		int nr_ch = ploop_get_child_count_by_uuid(di, guid);
		if (nr_ch != 0) {
			ploop_err(0, "Unable to mount (rw) snapshot %s: "
				"it has %d child%s", guid,
				nr_ch, (nr_ch == 1) ? "" : "ren");
			return SYSEXIT_PARAM;
		}
	}

	images = make_images_list(di, guid, 0);
	if (images == NULL)
		return SYSEXIT_NOMEM;
	ret = ploop_mount(di, images, param, (di->mode == PLOOP_RAW_MODE));
	free_images_list(images);

	return ret;
}

int auto_mount_image(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param)
{
	char mnt[PATH_MAX];
	int ret;

	ret = get_temp_mountpoint(di->images[0]->file, 1, mnt, sizeof(mnt));
	if (ret)
		return ret;
	param->target = strdup(mnt);

	return mount_image(di, param, 0);
}

int ploop_mount_image(struct ploop_disk_images_data *di, struct ploop_mount_param *param)
{
	int ret;
	char dev[64];

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev_by_uuid(di, 1, dev, sizeof(dev));
	if (ret == -1) {
		ploop_unlock_di(di);
		return -1;
	}
	if (ret == 0) {
		ploop_err(0, "Image %s already mounted to %s",
				di->images[0]->file, dev);

		ret = SYSEXIT_MOUNT;
		goto err;
	}

	ret = mount_image(di, param, 0);
err:
	ploop_unlock_di(di);

	return ret;
}

int ploop_mount_snapshot(struct ploop_disk_images_data *di, struct ploop_mount_param *param)
{
	if (param->guid == NULL) {
		ploop_err(0, "Snapshot guid is not specified");
		return SYSEXIT_PARAM;
	}
	return ploop_mount_image(di, param);
}

static int ploop_stop_device(const char *device)
{
	int lfd, ret;

	ploop_log(0, "Unmounting device %s", device);
	lfd = open(device, O_RDONLY);
	if (lfd < 0) {
		ploop_err(errno, "Can't open dev %s", device);
		return SYSEXIT_DEVICE;
	}

	ret = ploop_stop(lfd, device);
	close(lfd);

	return ret;
}

int ploop_umount(const char *device, struct ploop_disk_images_data *di)
{
	int ret;
	char mnt[PATH_MAX] = "";

	if (!device) {
		ploop_err(0, "ploop_umount: device is not specified");
		return -1;
	}

	if (get_mount_dir(device, mnt, sizeof(mnt)) == 0) {
		/* The component_name feature allows multiple image mount.
		 * Skip store statfs in custom case.
		 */
		if (di != NULL && di->runtime->component_name == NULL)
			store_statfs_info(mnt, di->images[0]->file);
		ploop_log(0, "Unmounting file system at %s", mnt);
		if (do_umount(mnt)) {
			ploop_err(errno, "umount %s failed", mnt);
			return SYSEXIT_UMOUNT;
		}
	}

	ret = ploop_stop_device(device);

	if (ret == 0 && di != NULL)
		unregister_ploop_dev(di->runtime->component_name, di->images[0]->file);

	return ret;
}

int ploop_umount_image(struct ploop_disk_images_data *di)
{
	int ret;
	char dev[PATH_MAX];

	if (di->nimages == 0) {
		ploop_err(0, "No images specified");
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev_by_uuid(di, 0, dev, sizeof(dev));
	if (ret == -1) {
		ploop_unlock_di(di);
		return -1;
	}
	if (ret != 0) {
		ploop_unlock_di(di);
		ploop_err(0, "Image %s is not mounted", di->images[0]->file);
		return -1;
	}

	ret = ploop_complete_running_operation(dev);
	if (ret) {
		ploop_unlock_di(di);
		return ret;
	}

	ret = ploop_umount(dev, di);

	ploop_unlock_di(di);

	return ret;
}

int ploop_grow_device(const char *device, __u32 blocksize, off_t new_size)
{
	int fd, ret;
	struct ploop_ctl ctl;
	off_t size;

	ret = ploop_get_size(device, &size);
	if (ret)
		return ret;
	ploop_log(0, "Growing dev=%s size=%llu sectors (new size=%llu)",
				device, (unsigned long long)size,
				(unsigned long long)new_size);
	if (new_size == size)
		return 0;

	if (new_size < size) {
		ploop_err(0, "Incorrect new size specified %ld current size %ld",
				(long)new_size, (long)size);
		return SYSEXIT_PARAM;
	}

	fd = open(device, O_RDONLY);
	if (fd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		return SYSEXIT_DEVICE;
	}

	memset(&ctl, 0, sizeof(ctl));

	ctl.pctl_cluster_log = ffs(blocksize) - 1;
	ctl.pctl_size = new_size;

	if (ioctl(fd, PLOOP_IOC_GROW, &ctl) < 0) {
		ploop_err(errno, "PLOOP_IOC_GROW");
		close(fd);
		return SYSEXIT_DEVIOC;
	}
	close(fd);

	return 0;
}

int ploop_resize_image(struct ploop_disk_images_data *di, struct ploop_resize_param *param)
{
	int ret;
	struct ploop_mount_param mount_param = {};
	char buf[PATH_MAX];
	int mounted = 0;
	int balloonfd = -1;
	struct stat st;
	off_t dev_size = 0;
	__u64 balloon_size = 0;
	__u64 new_balloon_size = 0;
	struct statfs fs;

	if (di->nimages == 0) {
		ploop_err(0, "No images in DiskDescriptor");
		return -1;
	}

	if (check_blockdev_size(param->size))
		return -1;

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev_by_uuid(di, 1, buf, sizeof(buf));
	if (ret == -1)
		goto err;
	if (ret != 0) {
		ret = auto_mount_image(di, &mount_param);
		if (ret)
			goto err;
		mounted = 1;
	} else {
		ret = ploop_complete_running_operation(buf);
		if (ret)
			goto err;

		strncpy(mount_param.device, buf, sizeof(mount_param.device));
		if (get_mount_dir(mount_param.device, buf, sizeof(buf))) {
			ploop_err(0, "Can't find mount point for %s", buf);
			ret = SYSEXIT_PARAM;
			goto err;
		}
		mount_param.target = strdup(buf);
	}

	ret = ploop_get_size(mount_param.device, &dev_size);
	if (ret)
		goto err;

	ret = get_balloon(mount_param.target, &st, &balloonfd);
	if (ret)
		goto err;
	balloon_size = bytes2sec(st.st_size);

	if (param->size == 0) {
		int delta = 1024 * 1024;

		/* Inflate balloon up to max free space */
		if (statfs(mount_param.target, &fs) != 0) {
			ploop_err(errno, "statfs(%s)", mount_param.target);
			ret = SYSEXIT_FSTAT;
			goto err;
		}
		if (fs.f_bfree <= delta / fs.f_bsize) {
			ret = 0; // no free space
			goto err;
		}

		new_balloon_size = balloon_size + B2S(fs.f_bfree * fs.f_bsize);
		new_balloon_size -= B2S(delta);
		ret = ploop_balloon_change_size(mount_param.device,
				balloonfd, new_balloon_size);
	} else if (param->size > dev_size) {
		char conf[PATH_MAX];
		char conf_tmp[PATH_MAX];

		// GROW
		if (balloon_size != 0) {
			ret = ploop_balloon_change_size(mount_param.device,
					balloonfd, 0);
			if (ret)
				goto err;
		}
		// Update size in the DiskDescriptor.xml
		di->size = param->size;
		get_disk_descriptor_fname(di, conf, sizeof(conf));
		snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
		ret = ploop_store_diskdescriptor(conf_tmp, di);
		if (ret)
			goto err;

		ret = ploop_grow_device(mount_param.device, di->blocksize, param->size);
		if (ret) {
			unlink(conf_tmp);
			goto err;
		}

		if (rename(conf_tmp, conf)) {
			ploop_err(errno, "Can't rename %s to %s",
					conf_tmp, conf);
			ret = SYSEXIT_RENAME;
			goto err;
		}

		ret = resize_fs(mount_param.device);
		if (ret)
			goto err;
		tune_fs(mount_param.target, mount_param.device, param->size);
	} else {
		off_t available_balloon_size;
		// SHRINK
		/* FIXME: resize file system in case fs_size != dev_size
		 */
		if (statfs(mount_param.target, &fs) != 0) {
			ploop_err(errno, "statfs(%s)", mount_param.target);
			ret = SYSEXIT_FSTAT;
			goto err;
		}
		new_balloon_size = dev_size - param->size;
		available_balloon_size = balloon_size + B2S(fs.f_bfree * fs.f_bsize);
		if (available_balloon_size < new_balloon_size) {
			ploop_err(0, "Unable to change image size to %llu "
					"sectors, minimal size is %lu",
					param->size,
					(long unsigned)(dev_size - available_balloon_size));
			ret = SYSEXIT_PARAM;
			goto err;
		}

		if (new_balloon_size != balloon_size) {
			ret = ploop_balloon_change_size(mount_param.device,
					balloonfd, new_balloon_size);
			if (ret)
				goto err;
			tune_fs(mount_param.target, mount_param.device, param->size);
		}
	}

err:
	close(balloonfd);
	if (mounted)
		ploop_umount(mount_param.device, di);
	ploop_unlock_di(di);
	free_mount_param(&mount_param);

	return ret;
}

static int expanded2raw(struct ploop_disk_images_data *di)
{
	struct delta delta = {};
	struct delta odelta = {};
	__u32 clu;
	void *buf = NULL;
	char tmp[PATH_MAX];
	int ret = -1;
	__u64 cluster;

	ploop_log(0, "Converting image to raw...");
	// FIXME: deny snapshots
	if (open_delta(&delta, di->images[0]->file, O_RDONLY, OD_OFFLINE))
		return SYSEXIT_OPEN;
	cluster = S2B(delta.blocksize);

	if (posix_memalign(&buf, 4096, cluster)) {
		ploop_err(errno, "posix_memalign");
		goto err;
	}

	snprintf(tmp, sizeof(tmp), "%s.tmp",
			di->images[0]->file);
	ret = open_delta_simple(&odelta, tmp, O_RDWR|O_CREAT|O_EXCL|O_TRUNC, OD_OFFLINE);
	if (ret)
		goto err;

	for (clu = 0; clu < delta.l2_size; clu++) {
		int l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));

		if (l2_cluster >= delta.l1_size) {
			ploop_err(0, "abort: l2_cluster >= delta.l1_size");

			goto err;
		}

		if (delta.l2_cache != l2_cluster) {
			if (PREAD(&delta, delta.l2, cluster, (off_t)l2_cluster * cluster))
				goto err;
			delta.l2_cache = l2_cluster;
		}
		if ((delta.l2[l2_slot] % delta.blocksize) != 0) {
			ploop_err(0, "Image corrupted: delta.l2[%d]=%d",
					l2_slot, delta.l2[l2_slot]);
			goto err;
		}
		if (delta.l2[l2_slot] != 0) {
			if (PREAD(&delta, buf, cluster, S2B(delta.l2[l2_slot])))
				goto err;
		} else {
			bzero(buf, cluster);
		}

		if (PWRITE(&odelta, buf, cluster, clu * cluster))
			goto err;
	}

	if (fsync(odelta.fd))
		ploop_err(errno, "fsync");

	if (rename(tmp, di->images[0]->file)) {
		ploop_err(errno, "rename %s %s",
			tmp, di->images[0]->file);
		goto err;
	}
	ret = 0;
err:
	close(odelta.fd);
	if (ret)
		unlink(tmp);
	close_delta(&delta);
	free(buf);

	return ret;
}

static int expanded2preallocated(struct ploop_disk_images_data *di)
{
	struct delta delta = {};
	__u32 clu;
	off_t data_off;
	int ret = -1;
	__u64 cluster;
	void *buf = NULL;

	ploop_log(0, "Converting image to preallocated...");
	// FIXME: deny on snapshots
	if (open_delta(&delta, di->images[0]->file, O_RDWR, OD_OFFLINE))
		return SYSEXIT_OPEN;
	cluster = S2B(delta.blocksize);
	data_off = delta.alloc_head;
	if (fsync(delta.fd)) {
		ploop_err(errno, "fsync");
		goto err;
	}
	// Second stage: update index
	for (clu = 0; clu < delta.l2_size; clu++) {
		int l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));

		if (l2_cluster >= delta.l1_size) {
			ploop_err(0, "abort: l2_cluster >= delta.l1_size");
			goto err;
		}

		if (delta.l2_cache != l2_cluster) {
			if (PREAD(&delta, delta.l2, cluster, (off_t)l2_cluster * cluster))
				goto err;
			delta.l2_cache = l2_cluster;
		}
		if (delta.l2[l2_slot] == 0) {
			off_t idx_off = (off_t)l2_cluster * cluster + (l2_slot*sizeof(__u32));

			delta.l2[l2_slot] = data_off * delta.blocksize;

			ret = sys_fallocate(delta.fd, 0, data_off * cluster, cluster);
			if (ret) {
				if (errno == ENOTSUP) {
					if (buf == NULL) {
						ploop_log(0, "Warning: fallocate is not supported,"
								" using write instead");
						buf = calloc(1, cluster);
						if (buf == NULL) {
							ploop_err(errno, "malloc");
							goto err;
						}
					}
					ret = PWRITE(&delta, buf, cluster, data_off * cluster);
				}
				if (ret) {
					ploop_err(errno, "Failed to expand %s", di->images[0]->file);
					goto err;
				}
			}

			if (PWRITE(&delta, &delta.l2[l2_slot], sizeof(__u32), idx_off))
				goto err;
			data_off++;
		}
	}

	if (fsync(delta.fd)) {
		ploop_err(errno, "fsync");
		goto err;
	}
	ret = 0;
err:
	close_delta(&delta);
	free(buf);
	return ret;
}

int ploop_convert_image(struct ploop_disk_images_data *di, int mode, int flags)
{
	char conf_tmp[PATH_MAX];
	char conf[PATH_MAX];
	int ret = -1;

	if (di->mode == PLOOP_RAW_MODE) {
		ploop_err(0, "Converting raw image is not supported");
		return SYSEXIT_PARAM;
	}
	if (di->nimages == 0) {
		ploop_err(0, "No images specified");
		return SYSEXIT_PARAM;
	}
	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	di->mode = mode;
	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err;

	if (mode == PLOOP_EXPANDED_PREALLOCATED_MODE)
		ret = expanded2preallocated(di);
	else if (mode == PLOOP_RAW_MODE)
		ret = expanded2raw(di);
	/* else if (mode == PLOOP_EXPANDED)
	 * do nothing because di->mode = mode and store DiskDescriptot.xml (see above) is enough;
	 */
	if (ret) {
		unlink(conf_tmp);
		goto err;
	}

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
	}

err:
	ploop_unlock_di(di);

	return ret;
}

int ploop_get_info(struct ploop_disk_images_data *di, struct ploop_info *info)
{
	char mnt[PATH_MAX];
	char dev[64];

	if (read_statfs_info(di->images[0]->file, info) == 0)
		return 0;

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;
	if (ploop_find_dev_by_uuid(di, 1, dev, sizeof(dev)) == 0 &&
			get_mount_dir(dev, mnt, sizeof(mnt)) == 0)
	{
		ploop_unlock_di(di);
		if (get_statfs_info(mnt, info) == 0)
			return 0;
	}

	ploop_unlock_di(di);
	return -1;
}

int ploop_get_info_by_descr(const char *descr, struct ploop_info *info)
{
	struct ploop_disk_images_data *di;
	int ret;

	/* Try the fast path first, for stopped ploop */
	if (read_statfs_info(descr, info) == 0)
		return 0;

	di = ploop_alloc_diskdescriptor();
	if (di == NULL)
		return SYSEXIT_MALLOC;

	if (ploop_read_diskdescriptor(descr, di)) {
		ploop_free_diskdescriptor(di);
		return SYSEXIT_DISKDESCR;
	}

	ret = ploop_get_info(di, info);

	ploop_free_diskdescriptor(di);

	return ret;
}

static int do_snapshot(int lfd, int fd, struct ploop_ctl_delta *req)
{
	req->f.pctl_fd = fd;

	if (ioctl(lfd, PLOOP_IOC_SNAPSHOT, req) < 0) {
		ploop_err(errno, "PLOOP_IOC_SNAPSHOT");
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

int create_snapshot(const char *device, const char *delta, __u32 blocksize, int syncfs)
{
	int ret;
	int lfd = -1;
	int fd = -1;
	__u64 bdsize;
	struct ploop_ctl_delta req;

	ret = ploop_complete_running_operation(device);
	if (ret)
		return ret;

	lfd = open(device, O_RDONLY);
	if (lfd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, BLKGETSIZE64, &bdsize) < 0) {
		ploop_err(errno, "ioctl(BLKGETSIZE) %s", device);
		ret = SYSEXIT_BLKDEV;
		goto err;
	}
	bdsize = bytes2sec(bdsize);

	if (bdsize == 0) {
		ploop_err(0, "Can't get block device %s size", device);
		ret = SYSEXIT_BLKDEV;
		goto err;
	}

	fd = create_empty_delta(delta, blocksize, bdsize);
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
	ret = do_snapshot(lfd, fd, &req);

	if (ret)
		unlink(delta);
err:
	close(lfd);
	close(fd);

	return ret;
}

static int get_image_size(struct ploop_disk_images_data *di, const char *guid, off_t *size)
{
	int ret;
	struct delta delta;
	const char *image;
	int raw = 0;

	image = find_image_by_guid(di, guid);
	if (image == NULL) {
		ploop_err(0, "Can't find image by top guid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	if (di->mode == PLOOP_RAW_MODE) {
		int i;

		i = find_snapshot_by_guid(di, guid);
		if (i == -1) {
			ploop_err(0, "Can't find snapshot by guid %s",
					guid);
			return SYSEXIT_PARAM;
		}
		if (strcmp(di->snapshots[i]->parent_guid, NONE_UUID) == 0)
			raw = 1;
	}
	if (raw) {
		struct stat st;

		if (stat(image, &st)) {
			ploop_err(errno, "Failed to stat %s",
					image);
			return SYSEXIT_FSTAT;
		}
		*size = st.st_size / SECTOR_SIZE;
	} else {
		ret = open_delta(&delta, image, O_RDONLY, OD_OFFLINE);
		if (ret)
			return ret;
		*size = delta.l2_size * delta.blocksize;
		close_delta(&delta);
	}

	return 0;
}

int ploop_create_snapshot(struct ploop_disk_images_data *di, struct ploop_snapshot_param *param)
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

	if (di->nimages == 0) {
		ploop_err(0, "No images");
		return SYSEXIT_PARAM;
	}
	if (param->guid != NULL && !is_valid_guid(param->guid)) {
		ploop_err(0, "Incorrect guid %s", param->guid);
		return SYSEXIT_PARAM;
	}

	if (is_old_snapshot_format(di))
		return SYSEXIT_PARAM;

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = gen_uuid_pair(snap_guid, sizeof(snap_guid),
			file_guid, sizeof(file_guid));
	if (ret) {
		ploop_err(errno, "Can't generate uuid");
		goto err_cleanup1;
	}

	if (param->guid != NULL) {
		if (find_snapshot_by_guid(di, param->guid) != -1) {
			ploop_err(0, "The snapshot %s already exist",
				param->guid);
			ret = SYSEXIT_PARAM;
			goto err_cleanup1;
		}
		strcpy(snap_guid, param->guid);
	}
	n = get_snapshot_count(di);
	if (n == -1) {
		ret = SYSEXIT_PARAM;
		goto err_cleanup1;
	} else if (n > 128-2) {
		/* The number of images limited by 128
		   so the snapshot limit 128 - base_image - one_reserverd
		 */
		ret = SYSEXIT_PARAM;
		ploop_err(errno, "Unable to create a snapshot."
			" The maximum number of snapshots (%d) has been reached.",
			n-1);
		goto err_cleanup1;
	}

	snprintf(fname, sizeof(fname), "%s.%s",
			di->images[0]->file, file_guid);
	ploop_di_change_guid(di, di->top_guid, snap_guid);
	ret = ploop_di_add_image(di, fname, TOPDELTA_UUID, snap_guid);
	if (ret)
		goto err_cleanup1;

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err_cleanup1;

	ret = ploop_find_dev_by_uuid(di, 1, dev, sizeof(dev));
	if (ret == -1)
		goto err_cleanup2;

	if (ret != 0) {
		// offline snapshot
		ret = get_image_size(di, snap_guid, &size);
		if (ret)
			goto err_cleanup2;
		fd = create_empty_delta(fname, di->blocksize, size);
		if (fd < 0) {
			ret = SYSEXIT_CREAT;
			goto err_cleanup2;
		}
		close(fd);
	} else {
		// Always sync fs
		online = 1;
		ret = create_snapshot(dev, fname, di->blocksize, 1);
		if (ret)
			goto err_cleanup2;

	}

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
	}

	if (ret && !online && unlink(fname))
		ploop_err(errno, "Can't unlink %s",
				fname);

	ploop_log(0, "ploop snapshot %s has been successfully created",
			snap_guid);
err_cleanup2:
	if (ret && !online && unlink(conf_tmp))
		ploop_err(errno, "Can't unlink %s", conf_tmp);

err_cleanup1:
	ploop_unlock_di(di);

	return ret;
}

int ploop_switch_snapshot(struct ploop_disk_images_data *di, const char *guid, int flags)
{
	int ret;
	int fd;
	char dev[64];
	char uuid[61];
	char file_uuid[61];
	char new_top_delta_fname[PATH_MAX];
	char *old_top_delta_fname = NULL;
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX];
	off_t size;

	if (guid == NULL || !is_valid_guid(guid)) {
		ploop_err(0, "Incorrect guid %s", guid);
		return SYSEXIT_PARAM;
	}

	if (is_old_snapshot_format(di))
		return SYSEXIT_PARAM;

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = SYSEXIT_PARAM;
	if (strcmp(di->top_guid, guid) == 0) {
		ploop_err(errno, "Nothing to do, already on %s snapshot",
				guid);
		goto err_cleanup1;

	}
	if (find_snapshot_by_guid(di, guid) == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		goto err_cleanup1;
	}
	// Read image size from image header
	ret = get_image_size(di, guid, &size);
	if (ret)
		goto err_cleanup1;

	ret = gen_uuid_pair(uuid, sizeof(uuid), file_uuid, sizeof(file_uuid));
	if (ret) {
		ploop_err(errno, "Can't generate uuid");
		goto err_cleanup1;
	}

	ret = ploop_di_remove_image(di, di->top_guid, 0, &old_top_delta_fname);
	if (ret)
		goto err_cleanup1;

	if (!(flags & PLOOP_SNAP_SKIP_TOPDELTA_DESTROY)) {
		// device should be stopped
		ret = ploop_find_dev_by_uuid(di, 1, dev, sizeof(dev));
		if (ret == -1) {
			ret = SYSEXIT_PARAM;
			goto err_cleanup1;
		} else if (ret == 0) {
			ret = SYSEXIT_PARAM;
			ploop_err(0, "Unable to perform switch to snapshot operation"
					" on running device (%s)",
					dev);
			goto err_cleanup1;
		}
	} else
		old_top_delta_fname = NULL;

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
	fd = create_empty_delta(new_top_delta_fname, di->blocksize, size);
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
	ploop_unlock_di(di);
	free(old_top_delta_fname);

	return ret;
}

int ploop_delete_top_delta(struct ploop_disk_images_data *di)
{
	return ploop_delete_snapshot(di, di->top_guid);
}

/* delete snapshot by guid
 * 1) if guid is not active and last -> delete guid
 * 2) if guid is not last merge with child -> delete child
 */
int ploop_delete_snapshot(struct ploop_disk_images_data *di, const char *guid)
{
	int ret;
	char conf[PATH_MAX];
	char *fname = NULL;
	int nelem = 0;
	char dev[64];
	int snap_id;

	if (is_old_snapshot_format(di))
		return SYSEXIT_PARAM;

	if (ploop_lock_di(di))
		return SYSEXIT_LOCK;

	ret = SYSEXIT_PARAM;
	snap_id = find_snapshot_by_guid(di, guid);
	if (snap_id == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		goto err;
	}
	ret = ploop_find_dev_by_uuid(di, 1, dev, sizeof(dev));
	if (ret == -1)
		goto err;
	else if (ret == 0 && strcmp(di->top_guid, guid) == 0) {
		ret = SYSEXIT_PARAM;
		ploop_err(0, "Unable to delete active snapshot %s",
				guid);
		goto err;
	}

	nelem = ploop_get_child_count_by_uuid(di, guid);
	if (nelem == 0) {
		if (strcmp(di->snapshots[snap_id]->parent_guid, NONE_UUID) == 0) {
			ret = SYSEXIT_PARAM;
			ploop_err(0, "Unable to delete base image");
			goto err;
		}
		/* snapshot is not active and last -> delete */
		ret = ploop_di_remove_image(di, guid, 1, &fname);
		if (ret)
			goto err;
		get_disk_descriptor_fname(di, conf, sizeof(conf));
		ret = ploop_store_diskdescriptor(conf, di);
		if (ret)
			goto err;
		ploop_log(0, "Removing %s", fname);
		if (fname != NULL && unlink(fname)) {
			ploop_err(errno, "unlink %s", fname);
			ret = SYSEXIT_UNLINK;
		}
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

err:
	free(fname);
	ploop_unlock_di(di);

	return ret;
}
