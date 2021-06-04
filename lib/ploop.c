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
#include <ext2fs/ext2_fs.h>
#include <stdint.h>
#include <time.h>

#include "ploop.h"
#include "cleanup.h"
#include "cbt.h"

static int ploop_mount_fs(struct ploop_disk_images_data *di,
		const char *partname,	struct ploop_mount_param *param,
		int need_balloon);
static int ploop_umount_fs(const char *mnt, struct ploop_disk_images_data *di);

static off_t round_bdsize(off_t size, __u32 blocksize, int version)
{
	if (version == PLOOP_FMT_V1 &&
			(size > 0xffffffff - blocksize))
		return (size / blocksize * blocksize);
	else if (version == PLOOP_FMT_V2 &&
			(size / blocksize > 0xffffffff - 1))
		return (size / blocksize * blocksize);

	return ROUNDUP(size, blocksize);
}

int get_part_devname(struct ploop_disk_images_data *di,
		const char *device, char *devname, int dlen,
		char *partname, int plen)
{
	int ret, luks, gpt;

	ret = is_luks(device, &luks);
	if (ret)
		return ret;

	if (luks) {
		crypt_get_device_name(device, devname, dlen);
		ret = has_partition(devname, &gpt);
		if (ret)
			return ret;
		if (gpt)
			snprintf(partname, plen, "%sp1", devname);
		else
			snprintf(partname, plen, "%s", devname);
		return 0;
	}
	/* old dm-crypt schema */
	if (di && di->enc && di->enc->keyid) {
		snprintf(devname, dlen, "%sp1", device);
		crypt_get_device_name(devname, partname, plen);
		return 0;
	}

	snprintf(devname, dlen, "%s", device);
	return get_partition_device_name(device, partname, plen);
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

char **make_images_list(struct ploop_disk_images_data *di, const char *guid, int reverse)
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
	ploop_free_array(images);
	return NULL;
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

	res = pwrite(delta->fd, buf, size, off);
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

	res = pread(delta->fd, buf, size, off);
	if (res == size)
		return 0;
	if (res >= 0)
		errno = EIO;
	ploop_err(errno, "pread off=%lu size=%d", off, size);

	return -1;
}

static int get_temp_mountpoint(const char *file, int create, char *buf, int len)
{
	snprintf(buf, len, "%s.mnt", file);

	if (create) {
		if (access(buf, F_OK) == 0)
			return 0;
		if (mkdir(buf, 0700)) {
			ploop_err(errno, "mkdir %s", buf);
			return SYSEXIT_MKDIR;
		}
	}
	return 0;
}

int ploop_is_large_disk_supported(void)
{
	return 1;
}

static int is_fmt_version_valid(int version)
{
	return version >= PLOOP_FMT_V1;
}

static int default_fmt_version(void)
{
	return PLOOP_FMT_V2;
}

static int get_max_ploop_size(int version, unsigned int blocksize, unsigned long long *max)
{
	switch(version) {
	case PLOOP_FMT_V1:
		*max = (__u32)-1;
		break;
	case PLOOP_FMT_V2:
		*max = 0xffffffffUL * blocksize;
		break;
	case PLOOP_FMT_UNDEFINED:
		*max = UINT64_MAX;
		break;
	default:
		ploop_err(0, "Unknown ploop image version: %d", version);
		return -1;
	}
	return 0;
}

/* Returns maximum ploop size
 *
 * blocksize	- blocksize in sectors, defaults to
 *		  2048 sectors (1Mb block) if unset
 *
 * Note: default ploop format version is used
 */
int ploop_get_max_size(unsigned int blocksize, unsigned long long *max)
{
	blocksize = blocksize ?  blocksize : (1 << PLOOP1_DEF_CLUSTER_LOG);

	if (get_max_ploop_size(default_fmt_version(), blocksize, max))
		return SYSEXIT_PARAM;

	if (*max > B2S(PLOOP_MAX_FS_SIZE))
		*max = B2S(PLOOP_MAX_FS_SIZE);

	return 0;
}

static int do_check_size(unsigned long long sectors, __u32 blocksize, int version,
		__u64 max_fs_size)
{
	unsigned long long max;

	if (version == PLOOP_FMT_UNDEFINED)
		return 0;

	if (get_max_ploop_size(version, blocksize, &max))
		return -1;

	if (max_fs_size != 0 && max > B2S(max_fs_size))
		max = B2S(max_fs_size);

	if (sectors > max) {
		ploop_err(0, "An incorrect block device size is specified: %llu sectors."
				" The maximum allowed size is %llu sectors",
				sectors, max);
		return -1;
	}
	return 0;
}

static int check_size(unsigned long long sectors, __u32 blocksize, int version)
{
	return do_check_size(sectors, blocksize, version, PLOOP_MAX_FS_SIZE);
}

int check_blockdev_size(unsigned long long sectors, __u32 blocksize, int version)
{
	if (sectors % blocksize) {
		ploop_err(0, "An incorrect block device size is specified: %llu sectors."
				" The block device size must be aligned to the cluster block size %d",
				sectors, blocksize);
		return -1;
	}

	return 0;
}

static int do_create_delta(const char *path, __u32 blocksize, off_t bdsize, int version)
{
	int fd;
	void * buf = NULL;
	struct ploop_pvd_header *vh;
	__u32 SizeToFill;
	__u64 cluster = S2B(blocksize);

	assert(blocksize);

	if (!is_fmt_version_valid(version)) {
		ploop_err(0, "Unknown ploop image version: %d",
				version);
		return -1;
	}

	if (p_memalign(&buf, 4096, cluster))
		return -1;

	ploop_log(0, "Creating delta %s bs=%d size=%ld sectors v%d",
			path, blocksize, (long)bdsize, version);
	fd = open(path, O_RDWR|O_CREAT|O_DIRECT|O_EXCL, 0600);
	if (fd < 0) {
		ploop_err(errno, "Can't open %s", path);
		free(buf);
		return -1;
	}

	memset(buf, 0, cluster);

	vh = buf;
	SizeToFill = generate_pvd_header(vh, bdsize, blocksize, version);
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

	if (grow_image(path, blocksize, bdsize))
		goto out_close;

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

int create_snapshot_delta(const char *path, __u32 blocksize, off_t bdsize,
		int version)
{
	if (check_blockdev_size(bdsize, blocksize, version))
		return -1;

	/* select version for new delta on top of RAW image */
	if (version == PLOOP_FMT_UNDEFINED)
		version = default_fmt_version();

	return do_create_delta(path, blocksize, bdsize, version);
}

static int create_empty_preallocated_delta(const char *path, __u32 blocksize,
		off_t bdsize, int version)
{
	struct delta odelta = {};
	int rc, clu, i;
	void * buf = NULL;
	struct ploop_pvd_header vh = {};
	__u32 SizeToFill;
	__u32 l2_slot = 0;
	off_t off;
	__u64 cluster = S2B(blocksize);
	__u64 sizeBytes;

	if (check_blockdev_size(bdsize, blocksize, version))
		return -1;

	if (p_memalign(&buf, 4096, cluster))
		return -1;

	ploop_log(0, "Creating preallocated delta %s bs=%d size=%ld sectors v%d",
			path, blocksize, (long)bdsize, version);
	rc = open_delta_simple(&odelta, path, O_RDWR|O_CREAT|O_EXCL, OD_OFFLINE);
	if (rc) {
		free(buf);
		return -1;
	}

	memset(buf, 0, cluster);
	SizeToFill = generate_pvd_header(&vh, bdsize, blocksize, version);
	vh.m_Flags = CIF_Empty;
	memcpy(buf, &vh, sizeof(struct ploop_pvd_header));

	sizeBytes = S2B(vh.m_FirstBlockOffset + get_SizeInSectors(&vh));
	rc = sys_fallocate(odelta.fd, 0, 0, sizeBytes);
	if (rc) {
		if (errno == ENOTSUP) {
			ploop_log(0, "Warning: fallocate is not supported, using truncate instead");
			rc = ftruncate(odelta.fd, sizeBytes);
		}
		if (rc) {
			ploop_err(errno, "Failed to create %s", path);
			goto out_close;
		}
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
			off = (off_t)vh.m_FirstBlockOffset + (l2_slot * blocksize);
			((__u32*)buf)[i] = ploop_sec_to_ioff(off, blocksize, version);
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

static int create_raw_delta(const char * path, off_t bdsize, int flags)
{
	int fd;
	void * buf = NULL;
	off_t pos;

	ploop_log(0, "Creating raw delta %s size=%ld sectors",
			path, (long)bdsize);

	if (p_memalign(&buf, 4096, DEF_CLUSTER))
		return -1;

	fd = open(path, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		ploop_err(errno, "Can't open %s", path);
		free(buf);
		return -1;
	}
	if (flags & PLOOP_CREATE_SPARSE) {
		if (ftruncate(fd, bdsize * SECTOR_SIZE) < 0) {
			ploop_err(errno, "Unable to truncate %s", path);
			goto out_close;
		}
	} else {
		memset(buf, 0, DEF_CLUSTER);

		pos = 0;
		while (pos < bdsize) {
			if (is_operation_cancelled())
				goto out_close;
			off_t copy = bdsize - pos;
			if (copy > DEF_CLUSTER/SECTOR_SIZE)
				copy = DEF_CLUSTER/SECTOR_SIZE;
			if (WRITE(fd, buf, copy*SECTOR_SIZE))
				goto out_close;
			pos += copy;
		}
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

static void get_disk_descriptor_fname_by_image(const char *image,
		char *buf, int size)
{
	get_basedir(image, buf, size - sizeof(DISKDESCRIPTOR_XML));
	strcat(buf, DISKDESCRIPTOR_XML);
}

void get_disk_descriptor_fname(struct ploop_disk_images_data *di, char *buf, int size)
{
	if (di->runtime->xml_fname == NULL) {
		// Use default DiskDescriptor.xml
		get_disk_descriptor_fname_by_image(di->images[0]->file,
				buf, size);
	} else {
		// Use custom
		snprintf(buf, size, "%s", di->runtime->xml_fname);
	}
}

static void fill_diskdescriptor(struct ploop_pvd_header *vh, struct ploop_disk_images_data *di)
{
	di->size = get_SizeInSectors(vh);
	di->heads = vh->m_Heads;
	di->cylinders = vh->m_Cylinders;
	di->sectors = vh->m_Sectors;
}

int create_image(const char *file, __u32 blocksize, off_t size_sec, int mode,
		int version, int flags)
{
	int fd = -1;

	if (size_sec == 0) {
		ploop_err(0, "Incorrect block device size specified: "
				"%lu sectors", (long)size_sec);
		return SYSEXIT_PARAM;
	}

	if (file == NULL) {
		ploop_err(0, "Image file name not specified");
		return SYSEXIT_PARAM;
	}

	if (access(file, F_OK) == 0) {
		ploop_err(EEXIST, "Can't create %s", file);
		return SYSEXIT_PARAM;
	}

	else if (mode == PLOOP_RAW_MODE)
		fd = create_raw_delta(file, size_sec, flags);
	else if (mode == PLOOP_EXPANDED_MODE)
		fd = create_snapshot_delta(file, blocksize, size_sec, version);
	else if (mode == PLOOP_EXPANDED_PREALLOCATED_MODE)
		fd = create_empty_preallocated_delta(file, blocksize, size_sec, version);
	if (fd < 0)
		return SYSEXIT_CREAT;

	close(fd);

	return 0;
}

int create_balloon_file(struct ploop_disk_images_data *di,
		const char *device, const char *partname)
{
	int fd, ret;
	char mnt[PATH_MAX];
	char fname[PATH_MAX + sizeof(BALLOON_FNAME)];
	struct ploop_mount_param mount_param = {};

	ploop_log(0, "Creating balloon file " BALLOON_FNAME);
	ret = get_temp_mountpoint(di->images[0]->file, 1, mnt, sizeof(mnt));
	if (ret)
		return ret;
	mount_param.target = mnt;
	ret = ploop_mount_fs(di, partname, &mount_param, 0);
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

int ploop_init_device(const char *device, struct ploop_create_param *param)
{
	int ret;
	unsigned int blocksize;
	char partname[PATH_MAX];

	blocksize = param->blocksize ?
		param->blocksize : (1 << PLOOP1_DEF_CLUSTER_LOG);

	if (!is_valid_blocksize(blocksize)) {
		ploop_err(0, "Incorrect blocksize specified: %d",
		blocksize);
		return SYSEXIT_PARAM;
	}

	if (access(device, F_OK)) {
		ploop_err(errno, "Can't open device %s", device);
		return SYSEXIT_DEVICE;
	}

	if (!param->without_partition) {
		ret = create_gpt_partition(device, blocksize);
		if (ret)
			return ret;
	}

	ret = get_partition_device_name(device, partname, sizeof(partname));
	if (ret)
		return ret;

	ret = make_fs(partname, param->fstype, param->fsblocksize,
			param->flags, param->fslabel);

	return ret;
}

int ploop_init_image(struct ploop_disk_images_data *di,
		struct ploop_create_param *param)
{
	int ret;
	char devname[64];
	char partname[64];
	struct ploop_mount_param mount_param = {};

	if (di->nimages == 0) {
		ploop_err(0, "No images specified");
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	/* Drop encryption keyid from dd.xml */
	free_encryption_data(di);
	ret = mount_image(di, &mount_param);
	if (ret)
		goto err;


	snprintf(devname, sizeof(devname), "%s", mount_param.device);
	if (param->keyid) {
		ret = crypt_init(mount_param.device, param->keyid);
		if (ret)
			goto err;
		ret = crypt_open(mount_param.device, param->keyid);
		if (ret)
			goto err;
		ret = store_encryption_keyid(di, param->keyid);
		if (ret)
			goto err;
	}

	ret = get_part_devname(di, mount_param.device, devname, sizeof(devname),
			partname, sizeof(partname));
	if (ret)
		goto err;

	ret = make_fs(partname, param->fstype ?: DEFAULT_FSTYPE,
			param->fsblocksize, param->flags, param->fslabel);
	if (ret)
		goto err;

	ret = create_balloon_file(di, mount_param.device, partname);
	if (ret)
		goto err;

err:
	if (ploop_umount(mount_param.device, di)) {
		if (ret == 0)
			ret = SYSEXIT_UMOUNT;
	}

	ploop_unlock_dd(di);

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

static int init_dd(struct ploop_disk_images_data **di, const char *ddxml,
		const char *path, struct ploop_create_param *param)
{
	struct ploop_pvd_header vh = {};
	int fmt_version;
	__u32 blocksize;

	if (access(ddxml, F_OK) == 0) {
		ploop_err(EEXIST, "Can't create %s", ddxml);
		return SYSEXIT_PARAM;
	}

	fmt_version = param->fmt_version == PLOOP_FMT_UNDEFINED ?
		default_fmt_version() : param->fmt_version;

	blocksize = param->blocksize ?
		param->blocksize : (1 << PLOOP1_DEF_CLUSTER_LOG);

	if (!is_fmt_version_valid(fmt_version)) {
		ploop_err(0, "Unknown ploop image version: %d",
				fmt_version);
		return SYSEXIT_PARAM;
	}

	if (param->fstype != NULL &&
			check_size(param->size, blocksize, fmt_version))
		return SYSEXIT_PARAM;

	if (!is_valid_blocksize(blocksize)) {
		ploop_err(0, "Incorrect blocksize specified: %d",
				blocksize);
		return SYSEXIT_PARAM;
	}

	*di = alloc_diskdescriptor();
	if (*di == NULL)
		return SYSEXIT_MALLOC;

	if (path != NULL) {
		(*di)->vol = calloc(1, sizeof(struct volume_data));
		if ((*di)->vol == NULL) {
			ploop_close_dd(*di);
			return SYSEXIT_MALLOC;
		}
	}

	(*di)->size = round_bdsize(param->size, blocksize, fmt_version);
	(*di)->blocksize = blocksize;
	(*di)->mode = param->mode;

	generate_pvd_header(&vh, (*di)->size, blocksize, fmt_version);
	fill_diskdescriptor(&vh, *di);

	return 0;
}

int ploop_create_dd(const char *ddxml, struct ploop_create_param *param)
{
	int ret;
	struct ploop_disk_images_data *di = NULL;

	ret = init_dd(&di, ddxml, NULL, param);
	if (ret)
		return ret;

	ret = ploop_di_add_image(di, param->image, TOPDELTA_UUID, NONE_UUID);
	if (ret)
		goto err;

	ret = ploop_store_diskdescriptor(ddxml, di);
	if (ret)
		goto err;

err:
	ploop_close_dd(di);

	return ret;
}

int ploop_create(const char *path, const char *ipath,
		 struct ploop_create_param *param)
{
	struct ploop_disk_images_data *di = NULL;
	char ddxml[PATH_MAX];
	char fname[PATH_MAX];
	char image[PATH_MAX];
	int ret;
	int fmt_version;
	int image_created = 0;
	char *basedir;

	if (path != NULL) {
		snprintf(ddxml, sizeof(ddxml), "%s/"DISKDESCRIPTOR_XML, path);
		if (ipath)
			snprintf(image, sizeof(image), "%s", ipath);
		else
			snprintf(image, sizeof(image), "%s/image.hds", path);
	} else {
		if (param->image == NULL) {
			ploop_err(0, "Image file name not specified");
			return SYSEXIT_PARAM;
		}

		get_disk_descriptor_fname_by_image(param->image, ddxml,
				sizeof(ddxml));
		snprintf(image, sizeof(image), "%s", param->image);
	}

	get_basedir(ddxml, fname, sizeof(fname));
	basedir = realpath(*fname != '\0' ? fname : "./", NULL);
	if (basedir == NULL) {
		ploop_err(errno, "Can't resolve %s", fname);
		return SYSEXIT_CREAT;
	}
	snprintf(ddxml, sizeof(ddxml), "%s/"DISKDESCRIPTOR_XML, basedir);
	free(basedir);

	ret = init_dd(&di, ddxml, path, param);
	if (ret)
		return ret;

	fmt_version = param->fmt_version == PLOOP_FMT_UNDEFINED ?
		default_fmt_version() : param->fmt_version;

	ret = create_image(image, di->blocksize, di->size,
			param->mode, fmt_version, param->flags);
	if (ret)
		goto out;
	image_created = 1;

	if (realpath(image, fname) == NULL) {
		ploop_err(errno, "failed realpath(%s)", image);
		ret = SYSEXIT_CREAT;
		goto out;
	}

	ret = ploop_di_add_image(di, fname, TOPDELTA_UUID, NONE_UUID);
	if (ret)
		goto out;

	ret = ploop_store_diskdescriptor(ddxml, di);
	if (ret)
		goto out;

	if (param->fstype != NULL) {
		ret = ploop_init_image(di, param);
		if (ret)
			goto out;
	}

out:
	if (ret) {
		if (di)
			ploop_drop_image(di);
		if (image_created)
			unlink(image);
		unlink(ddxml);
	}

	ploop_close_dd(di);

	return ret;
}

int ploop_create_image(struct ploop_create_param *param)
{
	return ploop_create(NULL, param->image, param);
}

/* Device might be used by blkid binary (see #PSBM-10590), in such case
 * kernel returns EBUSY and we need to retry ioctl() after some delay.
 * Start with a small delay, increasing it exponentially.
 */
int do_ioctl_tm(int fd, int req, const char *dev, int tm_sec)
{
	useconds_t total = 0;
	useconds_t wait = 10000; // initial wait time 0.01s
	useconds_t maxwait = 500000; // max wait time per iteration 0.5s
	useconds_t maxtotal = tm_sec * 1000000; // max total wait time

	do {
		int ret = ioctl(fd, req, 0);
		if (ret == 0 || (ret == -1 && errno != EBUSY))
			return ret;
		if (total > maxtotal) {
			print_output(-1, "lsof", dev);
			return ret;
		}
		usleep(wait);
		total += wait;
		wait *= 2;
		if (wait > maxwait)
			wait = maxwait;
	} while (1);
}

int print_output(int level, const char *cmd, const char *arg)
{
	FILE *fp;
	char command[PATH_MAX];
	char buffer[LOG_BUF_SIZE/2];
	int ret = -1;
	int eno = errno;
	int i;

	snprintf(command, sizeof(command), DEF_PATH_ENV " %s %s 2>&1",
			cmd, arg);
	if ((fp = popen(command, "r")) == NULL) {
		ploop_err(errno, "Can't exec %s %s", cmd, arg);
		goto out;
	}

	ploop_log(level, "--- %s %s output ---", cmd, arg);
	while (fgets(buffer, sizeof(buffer), fp)) {
		char *p = strrchr(buffer, '\n');
		if (p != NULL)
			*p = '\0';
		ploop_log(level, "%s", buffer);
	}

	i = pclose(fp);
	if (i == -1) {
		ploop_err(errno, "Error in pclose() for %s", cmd);
		goto out;
	} else if (WIFEXITED(i)) {
		ret = WEXITSTATUS(i);
		switch (ret) {
			case 0:
				ploop_log(level, "--- %s finished ---", cmd);
				break;
			case 127: /* "command not found" from shell */
				/* error is printed by shell*/
				break;
			default:
				ploop_err(0, "Command %s exited with "
						"status %d", cmd, ret);
		}
	} else if (WIFSIGNALED(i)) {
		ploop_err(0, "Command %s received signal %d",
				cmd, WTERMSIG(i));
	} else
		ploop_err(0, "Command %s died", cmd);

out:
	errno = eno;
	return ret;
}

int do_umount(const char *mnt, int tmo_sec)
{
	useconds_t total = 0;
	useconds_t wait = 10000; // initial wait time 0.01s
	useconds_t maxwait = 500000; // max wait time per iteration 0.5s
	useconds_t maxtotal = tmo_sec * 1000000; // max total wait

	do {
		if (umount(mnt) == 0)
			return 0;

		if (errno != EBUSY) {
			ploop_err(errno, "Failed to umount %s", mnt);
			return SYSEXIT_UMOUNT;
		}

		if (total > maxtotal) {
			print_output(-1, "lsof", mnt);
			return SYSEXIT_UMOUNT_BUSY;
		}

		usleep(wait);
		total += wait;
		wait *= 2;
		if (wait > maxwait)
			wait = maxwait;
	} while (1);
}

static int ploop_stop(const char *devname,
		struct ploop_disk_images_data *di)
{
	int rc;
	char partname[64];

	rc = get_dev_from_sys(devname, "holders", partname, sizeof(partname));
	if (rc == -1) {
		ploop_err(0, "Can not get part device name by %s", devname);
		return SYSEXIT_SYS;
	} else if (rc == 0) {
		rc = dm_remove(partname);
		if (rc)
			return rc;
	}

	return dm_remove(devname);
}

/* Convert escape sequences used in /proc/mounts, /etc/mtab
 * and /proc/self/mountinfo files, such as:
 *
 *	\040 -> space
 *	\011 -> tab
 *	\012 -> newline
 *	\134 -> \
 *
 * Taken as is from util-linux-2.24.2, licensed under GNU LGPL 2.1
 */
#define isoctal(a)		(((a) & ~7) == '0')
void unmangle_to_buffer(const char *s, char *buf, size_t len)
{
	size_t sz = 0;

	if (!s)
		return;

	while(*s && sz < len - 1) {
		if (*s == '\\' && sz + 3 < len - 1 && isoctal(s[1]) &&
				isoctal(s[2]) && isoctal(s[3])) {

			*buf++ = 64*(s[1] & 7) + 8*(s[2] & 7) + (s[3] & 7);
			s += 4;
			sz += 4;
		} else {
			*buf++ = *s++;
			sz++;
		}
	}
	*buf = '\0';
}
#undef isoctal

/* Returns:
 *  0 mount point is found and saved to *out
 *  1 mount point not found (fs not mounted)
 * -1 some system error
 */
int get_mount_dir(const char *device, int pid, char *out, int size)
{
	FILE *fp;
	int ret = 1;
	int n;
	char buf[PATH_MAX];
	char target[4097];
	unsigned _major, _minor, major, minor, u;
	struct stat st;

	if (stat(device, &st)) {
		ploop_err(errno, "get_mount_dir stat(%s)", device);
		return -1;
	}

	if (pid > 0)
		snprintf(buf, sizeof(buf), "/proc/%d/mountinfo", pid);
	else
		snprintf(buf, sizeof(buf), "/proc/self/mountinfo");
	fp = fopen(buf, "r");
	if (fp == NULL) {
		ploop_err(errno, "Can't open %s", buf);
		return -1;
	}

	major = major(st.st_rdev);
	minor = minor(st.st_rdev);
	while (fgets(buf, sizeof(buf), fp)) {
		n = sscanf(buf, "%u %u %u:%u %*s %4096s", &u, &u, &_major, &_minor, target);
		if (n != 5)
			continue;
		if (_major == major && _minor == minor)	{
			if (out != NULL) {
				unmangle_to_buffer(target, buf, sizeof(buf));
				if (pid > 0)
					snprintf(out, size, "/proc/%d/root/%s", pid, buf);
				else
					snprintf(out, size, "%s", buf);
			}
			ret = 0;
			break;
		}
	}
	fclose(fp);
	return ret;
}

int ploop_get_mnt_by_dev(const char *dev, char *buf, int size)
{
	int ret;
	char path[PATH_MAX];
	char partname[64];
	char **dirs = NULL;

	ret = get_partition_device_name(dev, partname, sizeof(partname));
	if (ret)
		return ret;

	snprintf(path, sizeof(path), "/sys/class/block/%s/holders", partname+5);
	if (get_dir_entry(path, &dirs) == 0 && dirs != NULL) {
		snprintf(partname, sizeof(partname), "/dev/%s", dirs[0]);
		ploop_free_array(dirs);
	}

	return get_mount_dir(partname, 0, buf, size);
}

int fname_cmp(const char *p1, struct stat *st)
{
	struct stat st1;

	if (stat(p1, &st1)) {
		ploop_err(errno, "Can't stat %s", p1);
		return -1;
	}

	if (st1.st_dev == st->st_dev &&
			st1.st_ino == st->st_ino)
		return 0;
	return 1;
}

static int get_dev_by_mnt(const char *path, int dev, char *buf, int size)
{
	FILE *fp;
	struct mntent *ent;
	int len;
	struct stat st1, st2;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		ploop_err(errno, "Can't open /proc/mounts");
		return -1;
	}

	if (stat(path, &st1)) {
		ploop_err(errno, "Can't stat %s", path);
		fclose(fp);
		return -1;
	}
	while ((ent = getmntent(fp))) {
		if (strstr(ent->mnt_fsname, "ploop") == NULL)
			continue;

		if (stat(ent->mnt_dir, &st2))
			continue;

	        if (st1.st_dev == st2.st_dev &&
		            st1.st_ino == st2.st_ino)
		{
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

const char *get_base_delta_uuid(struct ploop_disk_images_data *di)
{
	int i;

	for (i = 0; i < di->nsnapshots; i++)
		if (strcmp(di->snapshots[i]->parent_guid, NONE_UUID) == 0)
			return di->snapshots[i]->guid;

	return NULL;
}

const char *get_top_delta_guid(struct ploop_disk_images_data *di)
{
	return di->top_guid;
}

int get_delta_fname(struct ploop_disk_images_data *di, const char *guid,
	char *out, int len)
{
	const char *fname;

	fname = find_image_by_guid(di, guid);
	if (fname == NULL){
		ploop_err(0, "Can't find image by uuid %s", guid);
		return SYSEXIT_PARAM;
	}
	if (snprintf(out, len, "%s", fname) > len -1) {
		ploop_err(0, "Not enough space to store data");
		return SYSEXIT_PARAM;
	}
	return 0;
}

int ploop_get_top_delta_fname(struct ploop_disk_images_data *di, char *out, int len)
{
	int ret;
	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = get_delta_fname(di, get_top_delta_guid(di), out, len);
	ploop_unlock_dd(di);
	return ret;
}

int ploop_get_base_delta_fname(struct ploop_disk_images_data *di, char *out, int len)
{
	int ret;
	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = get_delta_fname(di, get_base_delta_uuid(di), out, len);
	ploop_unlock_dd(di);
	return ret;
}

int ploop_get_dev(struct ploop_disk_images_data *di, char *out, int len)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = find_dev(di, out, len);

	ploop_unlock_dd(di);

	return ret;
}

int ploop_get_devs(struct ploop_disk_images_data *di, char ***out)
{
	if (di->nimages == 0 && ploop_read_dd(di))
		return -1;

	return find_devs(di, out);
}

int ploop_get_part(struct ploop_disk_images_data *di, const char *dev,
		char *partname, int len)
{
	char t[64];

	return get_part_devname(di, dev, t, sizeof(t), partname, len);
}

int ploop_get_devname(struct ploop_disk_images_data *di, const char *dev,
		char *devname, int dlen, char *partname, int plen)
{
	return get_part_devname(di, dev, devname, dlen, partname, plen);
}

int ploop_is_mounted(struct ploop_disk_images_data *di)
{
	int ret;
	char device[64];

	if (di->nimages == 0 && ploop_read_dd(di))
		return -1;

	ret = ploop_find_dev_by_dd(di, device, sizeof(device));

	return (ret == -1 ? -1 : !ret);
}


int reread_part(const char *device)
{
	return partprobe(device);
}

static int ploop_mount_fs(struct ploop_disk_images_data *di,
		const char *partname, struct ploop_mount_param *param,
		int need_balloon)
{
	unsigned long flags =
		(param->flags & MS_NOATIME) |
		(param->ro | (di && di->vol && di->vol->ro) ? MS_RDONLY : 0);
	char buf[PATH_MAX + sizeof(BALLOON_FNAME)];
	struct stat st;
	char *fstype = param->fstype == NULL ? DEFAULT_FSTYPE : param->fstype;
	char data[1024];
	int len;
	int mounted = 0;

	if (param->fsck_flags && (strncmp(fstype, "ext", 3) == 0))
		if (e2fsck(partname, param->fsck_flags, &param->fsck_rc))
			return SYSEXIT_FSCK;

	if (param->target == NULL)
		return 0;

	/* Two step mount
	 * 1 mount and find balloon inode
	 * 2 remount with balloon_ino=ino
	 */
	snprintf(data, sizeof(data), "%s%s",
			param->quota ? "usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0," : "",
			param->mount_data ? param->mount_data : "");
	if (mount(partname, param->target, fstype, flags, data))
		goto mnt_err;
	mounted = 1;

	if (!need_balloon)
		goto done;

	snprintf(buf, sizeof(buf), "%s/" BALLOON_FNAME, param->target);
	if (stat(buf, &st) < 0) {
		ploop_err(errno, "Can't stat balloon file %s", buf);
		goto mnt_err;
	}

	len = strlen(data);
	snprintf(data + len, sizeof(data) - len, ",balloon_ino=%llu",
			(unsigned long long) st.st_ino);

	flags |= MS_REMOUNT;
	if (mount(partname, param->target, fstype, flags, data))
		goto mnt_err;

done:
	ploop_log(0, "Mounted %s at %s fstype=%s data='%s' %s",
			partname, param->target, fstype,
			data, param->ro  ? "ro":"");
	return 0;

mnt_err:
	ploop_err(errno, "Can't mount file system "
			"(dev=%s target=%s fstype=%s flags=%lx data=%s)",
			partname, param->target, fstype, flags, data);
	if (mounted)
		umount(param->target);

	return SYSEXIT_MOUNT;
}

static void print_sys_block_ploop(void)
{
	print_output(-1, "find",
			"/sys/block/ploop[0-9]*/pdelta/ -type f "
			"\\( -name image -or -name io -or -name ro \\) "
			"| xargs grep -HF ''");
}

static const char *get_dev_name(char *out, int size)
{
	int i;

	srand(time(NULL));
	for (i = 0; i < 0xffff; i++) {
		int m = rand() % 0xffff + 1000;
		snprintf(out, size, "/dev/mapper/ploop%d", m);
		if (access(out, F_OK))
			break;
	}
	return out; 
}

static int add_delta(char **images, int blocksize, int raw, int ro,
		char *devname, int size)
{
	int rc, i, n = 0;
	int *fds = NULL;
	char t[1024];
	char *p = t, *e = t + sizeof(t);
	struct delta d;
	off_t sz;

	for (n = 0; images[n] != NULL; ++n);
	if (raw) {
		struct stat st;

		if (stat(images[n-1], &st)) {
			ploop_err(errno, "Can't stat %s", images[n-1]); 
			return SYSEXIT_FSTAT;
		}
		sz = st.st_size;
	} else {
		if (open_delta(&d, images[n-1], O_RDWR, OD_OFFLINE|OD_ALLOW_DIRTY))
			return SYSEXIT_OPEN;
		sz = d.l2_size * d.blocksize;
	}

	if (devname[0] == '\0')
		get_dev_name(devname, size);

	fds = alloca(n * sizeof(int));
	p += snprintf(p, e-p, "%d", ffs(blocksize) - 1);
	for (i = 0; i < n; i++) {
		int r = ro || i < n-1;

		ploop_log(0, "Adding delta dev=%s img=%s (%s)",
				devname, images[i], r ? "ro":"rw");
		fds[i] = open(images[i], O_DIRECT | (r?O_RDONLY:O_RDWR));
		if (fds[i] < 0) {
			ploop_err(errno, "Can't open file %s", images[i]);
			n = i;
			rc = SYSEXIT_OPEN;
			goto err;
		}
		p += snprintf(p, e-p, " %s%d", raw && i == 0 ? "raw@" : "", fds[i]);
	}

	if (!raw) {
		rc = update_delta_inuse(images[n-1], SIGNATURE_DISK_IN_USE);
		if (rc)
			goto err;
	}

	rc = dm_create(devname, 0, sz, ro, t);
	if (rc)
		goto err;

err:
	close_delta(&d);
	for (i = 0; i < n; i++)
		close(fds[i]);

	return rc;
}

int do_replace_delta(int devfd, int level, int imgfd, __u32 blocksize,
		const char *image, int raw, int flags)
{
	struct ploop_ctl_delta req = {};

	req.c.pctl_cluster_log = ffs(blocksize) - 1;
	req.c.pctl_level = level;
	req.c.pctl_chunks = 1;
	req.c.pctl_format = PLOOP_FMT_PLOOP1;
	if (raw)
		req.c.pctl_format = PLOOP_FMT_RAW;
	req.c.pctl_flags = flags;

	req.f.pctl_type = PLOOP_IO_AUTO;
	req.f.pctl_fd = imgfd;

	if (ioctl(devfd, PLOOP_IOC_REPLACE_DELTA, &req) < 0) {
		ploop_err(errno, "Can't replace image %s", image);
		if (errno == EBUSY)
			print_sys_block_ploop();
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

int replace_delta(const char *device, int level, const char *image, int raw, int flags)
{
	int fd = -1, lfd = -1;
	int top_level = 0;
	int ret;
	__u32 blocksize = 0;
	int img_flags, check_flags;
	int ro = flags & PLOOP_FMT_RDONLY;

	img_flags = O_DIRECT;
	if (ro)
		img_flags |= O_RDONLY;
	else
		img_flags |= O_RDWR;

	fd = open(image, img_flags);
	if (fd < 0) {
		ploop_err(errno, "Can't open file %s", image);
		return SYSEXIT_OPEN;
	}

	lfd = open(device, O_RDONLY);
	if (lfd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		ret = SYSEXIT_DEVICE;
		goto out;
	}
	if (ploop_get_attr(device, "top", &top_level)) {
		ret = SYSEXIT_SYSFS;
		goto out;
	}

	if (level < 0 || level > top_level) {
		ploop_err(0, "Invalid level %d specified, allowed values "
				"are 0 to %d", level, top_level - 1);
		ret = SYSEXIT_PARAM;
		goto out;
	}

	if (ploop_get_attr(device, "block_size", (int*) &blocksize)) {
		ret = SYSEXIT_SYSFS;
		goto out;
	}

	check_flags = CHECK_DETAILED | CHECK_DROPINUSE | CHECK_REPAIR_SPARSE |
			(ro ? CHECK_READONLY : 0) |
			(raw ? CHECK_RAW : 0);
	ret = ploop_check(image, check_flags, &blocksize, NULL);
	if (ret)
		goto out;

	ret = do_replace_delta(lfd, level, fd, blocksize, image, raw, flags);

out:
	if (lfd >= 0)
		close(lfd);
	if (fd >= 0)
		close(fd);

	return ret;
}

/* Check if f1 can be rename()d to f2.
 * This is not a thorough check, currenty it just checks
 * both files are on the same file system.
 *
 * Returns:
 *  1	rename() will likely fail
 *  0	rename() will likely succeed
 * -1	internal error
 */
static int cant_rename(const char *f1, const char *f2) {
	struct stat st1, st2;

	if (lstat(f1, &st1)) {
		ploop_err(errno, "Can't stat %s", f1);
		return -1;
	}
	if (lstat(f2, &st2)) {
		if (errno == ENOENT)
			return 0; /* can rename */
		ploop_err(errno, "Can't stat %s", f2);
		return -1;
	}
	if (st1.st_dev != st2.st_dev) {
		ploop_err(0, "Files %s and %s are on different file systems, "
				"can't rename", f1, f2);
		return 1; /* rename will return EXDEV */
	}

	/* FIXME: any other checks to add? */
	return 0;
}

/* Return number of hardlinks for the file */
static int st_nlink(const char *file)
{
	struct stat st;

	if (stat(file, &st))
		return -1;

	return st.st_nlink;
}

int ploop_replace_image(struct ploop_disk_images_data *di,
		struct ploop_replace_param *param)
{
	char dev[PATH_MAX];
	char *file = NULL, *oldfile, *tmp;
	char conf[PATH_MAX], conf_tmp[PATH_MAX] = "";
	int ret, idx, level;
	int keep_name = (param->flags & PLOOP_REPLACE_KEEP_NAME);
	int flags, check_flags;
	int offline = 0;
	int raw = param->mode == PLOOP_RAW_MODE;
	int ro = !(param->flags & PLOOP_REPLACE_RW);

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = SYSEXIT_PARAM;

	if (!param->file) {
		ploop_err(0, "New image file not specified");
		goto err;
	}

	file = realpath(param->file, NULL);
	if (file == NULL) {
		ploop_err(errno, "Error in realpath(%s)", param->file);
		goto err;
	}

	if (ploop_find_dev_by_dd(di, dev, sizeof(dev))) {
		ploop_log(1, "Can't find running ploop device, "
				"doing offline replace");
		offline = 1;
	}

	/* Image to be replaced is specified by one of the following
	 * (in the order of preference):
	 *  1 guid
	 *  2 current image file name
	 *  3 level
	 *
	 * Try to find out level (if not set) and idx (as in di->images[idx])
	 */
	level = idx = -1;
	if (param->guid) {
		if (!is_valid_guid(param->guid)) {
			ploop_err(0, "Invalid guid specified: %s", param->guid);
			goto err;
		}

		idx = find_image_idx_by_guid(di, param->guid);
		if (idx == -1) {
			ploop_err(0, "Can't find image by guid %s", param->guid);
			goto err;
		}
	}
	else if (param->cur_file) {
		idx = find_image_idx_by_file(di, param->cur_file);
		if (idx == -1) {
			ploop_err(0, "Can't find image %s "
					"in DiskDescriptor.xml",
					param->cur_file);
			goto err;
		}
	}
	else { /* by param->level */
		char img[PATH_MAX];

		if (offline) {
			ploop_err(0, "Can't specify level for "
					"offline replace");
			goto err;
		}
		level = param->level;
		/* Proper level check (against top_level) is to be done later
		 * in replace_delta(). Here is just some basic sanity check.
		 */
		if (level < 0 || level >= di->nimages) {
			ploop_err(0, "Invalid level %d", level);
			goto err;
		}

		/* get delta file name and figure out idx */
		if (ploop_get_delta_attr_str(dev, level, "image",
					img, sizeof(img))) {
			ret = SYSEXIT_SYSFS;
			goto err;
		}

		idx = find_image_idx_by_file(di, img);
		if (idx < 0) {
			ploop_err(0, "Can't find image %s "
					"in DiskDescriptor.xml", img);
			/* This could only happen if dd.xml is wrong/bad */
			ret = SYSEXIT_DISKDESCR;
			goto err;
		}
	}

	if (level < 0 && !offline) {
		/* find level by idx */
		ret = find_level_by_delta(dev, di->images[idx]->file, &level);
		if (ret) {
			ploop_log(0, "Can't find %s level by delta %s, "
					"assuming offline replace",
					dev, di->images[idx]->file);
			offline = 1;
		}
	}

	check_flags = CHECK_DETAILED;
	if (ro)
		check_flags |= CHECK_READONLY;
	if (raw)
		check_flags |= CHECK_RAW;
	/* check a new image */
	ret = ploop_check(file, check_flags, NULL, NULL);
	if (ret)
		goto err;

	oldfile = param->cur_file ? : di->images[idx]->file;

	if (keep_name && cant_rename(file, oldfile)) {
		ret = SYSEXIT_RENAME;
		goto err;
	}

	/* Write new dd.xml with changed image file */
	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	tmp = di->images[idx]->file;
	di->images[idx]->file = file;
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	di->images[idx]->file = tmp;
	if (ret)
		goto err;

	/* Do replace */
	ploop_log(0, "Replacing %s with %s (%s, level %d)", oldfile, file,
			(offline) ? "offline" : "online", level);
	if (!offline) {
		flags = 0;
		if (ro)
			flags |= PLOOP_FMT_RDONLY;
	       ret = replace_delta(dev, level, file, raw, flags);
	       if (ret)
		       goto err;
	}

	if (keep_name) {
		char tmp[PATH_MAX];
		int tmpfd = -1;

		ret = SYSEXIT_SYS;

		if (!offline && st_nlink(file) < 2) {
			/* If ploop is running, we can't just rename
			 * the file if its st.st_nlink < 2 as it is used
			 * by ploop and the kernel checks that the last
			 * reference to the file is not removed.
			 *
			 * We need to create a hardlink to it,
			 * rename the file, then remove the hardlink.
			 */
			snprintf(tmp, sizeof(tmp), "%s.XXXXXX", file);
			tmpfd = mkstemp(tmp);
			if (tmpfd < 0) {
				ploop_err(errno, "Can't mkstemp(%s)", tmp);
				goto undo_keep;
			}
			if (link(file, tmp)) {
				ploop_err(errno, "Can't hardlink %s to %s",
						tmp, file);
				goto undo_keep;
			}
		}
		if (rename(file, oldfile)) {
			ploop_err(errno, "Can't rename %s to %s",
					file, oldfile);
			goto undo_keep;
		}

		ret = 0;

undo_keep:
		if (tmpfd >= 0) {
			if (unlink(tmp))
				ploop_err(errno, "Can't delete %s", tmp);
			close(tmpfd);
		}

		if (ret && !offline) {
			ploop_log(0, "Rollback: replacing %s with %s",
					file, oldfile);
			if (replace_delta(dev, level, oldfile, 0, PLOOP_FMT_RDONLY)) {
				/* Hmm. We can't roll back the replace, so
				 * let's at least keep the dd.xml consistent
				 * with the in-kernel ploop state.
				 */
				ploop_log(0, "Rollback replace failed, "
						"saving new image name "
						"to DiskDescriptor.xml");
				ret = 0; /* FIXME: do we want error code? */
				keep_name = 0;
			}
		}
	}

	if (!keep_name) {
		/* Put a new dd.xml */
		ret = rename(conf_tmp, conf);
		conf_tmp[0] = '\0'; /* prevent unlink() below */
		if (ret) {
			ploop_err(errno, "Can't rename %s to %s",
					conf_tmp, conf);
			ret = SYSEXIT_RENAME;
			/* FIXME: how to rollback now? */
			goto err;
		}
		/* Change image in di */
		free(di->images[idx]->file);
		di->images[idx]->file = file; /* malloc()ed by realpath */
		file = NULL; /* prevent free(file) below */
	}

	ret = 0;
err:
	if (file)
		free(file);
	if (conf_tmp[0])
		unlink(conf_tmp);
	ploop_unlock_dd(di);

	return ret;
}

static int set_max_delta_size(int fd, unsigned long long size)
{
	/* Set max delta size for the last added (top) delta */
	ploop_log(0, "Setting maximum delta size to %llu sec", size);

	return ioctl_device(fd, PLOOP_IOC_MAX_DELTA_SIZE, &size);
}

/* NB: caller will take care about *lfd_p even if we fail */
static int add_deltas(struct ploop_disk_images_data *di,
		char **images, struct ploop_mount_param *param,
		int raw, __u32 blocksize, int *load_cbt)
{
	int n = 0, ret = 0;
	int format_extension_loaded = 0;
	struct ext_context *ctx = NULL;

	int ro = param->ro || (di && di->vol && di->vol->ro) ? 1: 0;
	for (n = 0; images[n] != NULL; ++n);

	/* we should load format extension here, before sending delta
	 * to kernel by
	 * add_delta
	 * for now, if load_cbt == 0 no extensions will be loaded.
	 * because we have only dirty bitmap (cbt) extension */
	if (!ro && load_cbt && !raw) {
		int rc;

		ctx = create_ext_context();
		if (ctx == NULL) {
			ret = SYSEXIT_MALLOC;
			goto err;
		}

		rc = read_optional_header_from_image(ctx, images[n-1], DIRTY_BITMAP_TRUNCATE);
		if (rc)
			ploop_log(0, "Error while loding optional header: %d", rc);
		else
			format_extension_loaded = 1;
	}


	ret = add_delta(images, blocksize, raw, ro, param->device, sizeof(param->device));
	if (ret)
		goto err;

//	if (di != NULL && di->max_delta_size != 0 &&
//			(ret = set_max_delta_size(*lfd_p, di->max_delta_size)))
//		goto err1;

	if (format_extension_loaded)
		send_dirty_bitmap_to_kernel(ctx, param->device, images[n-1]);

//	ret = check_and_repair_gpt(param->device, blocksize);
//	if (ret)
//		goto err1;

err:
	free_ext_context(ctx);

	return ret;
}

/* Checks a mount point hosting a ploop image
 * for bad (i.e. not recommended) mount options
 * and display a warning message if such an option
 * is present.
 *
 * Returns:
 *  -1: internal error
 *   1: bad mount option found
 *   0: everything is fine
 *
 * TODO: change a warning into an error
 */
static int check_host_ext4_mount_opts(const char *file)
{
	struct stat st;
	char buf[PATH_MAX * 4];
	FILE *fp;
	const char *bad_opt="data=writeback";
	int ret = -1;

	if (stat(file, &st)) {
		ploop_err(errno, "Can't stat %s", file);
		return -1;
	}

	fp = fopen("/proc/self/mountinfo", "r");
	if (!fp) {
		ploop_err(errno, "Can't open /proc/self/mountinfo");
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		int n;
		unsigned int major, minor;
		char target[PATH_MAX];
		char *opt;

		n = sscanf(buf, "%*u %*u %u:%u %*s %s",
				&major, &minor, target);
		if (n != 3) {
			ploop_err(0, "Can't parse /proc/self/mountinfo "
					"line: %s", buf);
			continue; /* just skip it */
		}
		if (makedev(major, minor) != st.st_dev)
			continue;
		/* found our device */
		opt = strrchr(buf, ' ');
		if (opt == NULL) /* should never happen */
			break;

		ret = 0;
		/* check mount options */
		if (strstr(opt, bad_opt) != NULL) {
			/* ret = 1; FIXME: warning for now */
			ploop_log(-1, "WARNING: %s is mounted with %s "
					"not recommended for ploop; "
					"please use data=ordered instead",
					target, bad_opt);
		}
		goto out;
	}

	ploop_log(0, "Warning: mount point not found for %s", file);

out:
	fclose(fp);

	return ret;
}

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS	_IOR('f', 1, long)
#endif
#ifndef EXT4_EXTENTS_FL
#define EXT4_EXTENTS_FL		0x00080000 /* Inode uses extents */
#endif

static int check_ext4_mount_restrictions(const char *fname)
{
	struct statfs st;
	int fd, ret;
	long flags;

	if (statfs(fname, &st) < 0) {
		ploop_err(errno, "Unable to statfs %s", fname);
		return -1;
	}

	if (st.f_type != EXT4_SUPER_MAGIC)
		return 0;

	ret = check_host_ext4_mount_opts(fname);
	if (ret)
		return ret;

	if (getenv("PLOOP_SKIP_EXT4_EXTENTS_CHECK") == NULL) {
		fd = open(fname, O_RDONLY);
		if (fd < 0) {
			ploop_err(errno, "Can't open %s", fname);
			return -1;
		}

		if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
			ploop_err(errno, "FS_IOC_GETFLAGS %s", fname);
			close(fd);
			return -1;
		}
		close(fd);

		if (!(flags & EXT4_EXTENTS_FL)) {
			ploop_err(0, "The ploop image can not be used on ext3 or ext4 file"
					" system without extents");
			return 1;
		}
	}

	return 0;
}

static int check_mount_restrictions(char **images)
{
	int i, ret;
	struct stat st;
	dev_t prev_dev = 0;

	for (i = 0; images[i] != NULL; i++) {
		if (stat(images[i], &st) < 0) {
			ploop_err(errno, "Unable to stat %s", images[i]);
			return -1;
		}
		/* device already checked */
		if (st.st_dev == prev_dev)
			continue;

		ret = check_ext4_mount_restrictions(images[i]);
		if (ret)
			return ret;

		prev_dev = st.st_dev;
	}
	return 0;
}

int ploop_mount(struct ploop_disk_images_data *di, char **images,
		struct ploop_mount_param *param, int raw)
{
	struct stat st;
	int ret = 0;
	__u32 blocksize = 0;
	int load_cbt;
	char devname[64] = "";
	char partname[64] = "";

	if (images == NULL || images[0] == NULL) {
		ploop_err(0, "ploop_mount: no deltas to mount");
		return SYSEXIT_PARAM;
	}

	if (param->target != NULL) {
		if (stat(param->target, &st)) {
			ploop_err(errno, "Failed to stat mount point %s", param->target);
			return SYSEXIT_PARAM;
		}
		if (!S_ISDIR(st.st_mode)) {
			ploop_err(0, "Mount point %s not a directory", param->target);
			return SYSEXIT_PARAM;
		}
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

	if (check_mount_restrictions(images))
		return SYSEXIT_MOUNT;

	if (di && (ret = check_and_restore_fmt_version(di)))
		goto err;

	ret = check_deltas(di, images, raw, &blocksize, &load_cbt,
			di ? CHECK_DROPINUSE : 0);
	if (ret)
		goto err;

	ret = add_deltas(di, images, param, raw, blocksize, &load_cbt);
	if (ret)
		goto err;

	if (di && di->enc) {
		ret = crypt_open(param->device, di->enc->keyid);
		if (ret)
			goto err_stop;
	} else {
		/* Dummy call to recreate devices */
		reread_part(param->device);
	}

	ret = get_part_devname(di, param->device, devname, sizeof(devname),
			partname, sizeof(partname));
	if (ret)
		goto err_stop;

	if (param->target != NULL || param->fsck) {
		ret = ploop_mount_fs(di, partname, param, 1);
		if (ret)
			goto err_stop;
	}

err_stop:
	if (ret) {
		if (di && di->enc && devname[0] != '\0') {
			crypt_close(devname, partname);
		}
		ploop_stop(param->device, di);
	}

err:

	if (ret == 0) {
		ret = cn_register(param->device, di);
		if (ret)
			goto err_stop;
		if (di && di->runtime->component_name == NULL &&
				param->target != NULL)
			drop_statfs_info(di->images[0]->file);
	}

	return ret;
}

int mount_image(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param)
{
	int ret;
	char **images;
	char *guid;

	if (param->guid != NULL) {
		if (find_image_by_guid(di, param->guid) == NULL) {
			ploop_err(0, "Uuid %s not found", param->guid);
			return SYSEXIT_NOSNAP;
		}
		guid = param->guid;
	} else
		guid = di->top_guid;

	if (!param->ro && di && di->vol && !di->vol->ro) {
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
		return SYSEXIT_MALLOC;

	ret = ploop_mount(di, images, param, (di->mode == PLOOP_RAW_MODE));

	ploop_free_array(images);

	return ret;
}

int mount_fs(const char *part, const char *target)
{
	ploop_log(0, "Mounting %s at %s", part, target);
	if (mount(part, target, DEFAULT_FSTYPE, 0, 0)) {
		ploop_err(errno, "Can't mount dev=%s target=%s",
				part, target);
		return SYSEXIT_MOUNT;
	}

	return 0;
}

int auto_mount_fs(struct ploop_disk_images_data *di, pid_t pid,
		const char *partname, struct ploop_mount_param *param)
{
	int ret;
	char target[PATH_MAX];

	ret = get_temp_mountpoint(di->images[0]->file, 1, target, sizeof(target));
	if (ret)
		return ret;

	param->target = strdup(target);

	if (pid) {
		ret = get_mount_dir(partname, pid, NULL, 0);
		if (ret < 0)
			return SYSEXIT_SYS;
		if (ret == 0)
			return mount_fs(partname, target);
	}

	ret = ploop_mount_fs(di, partname, param, 1);
	if (ret && errno == EPERM)
		return mount_fs(partname, target);

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

	return mount_image(di, param);
}

static int remount_image(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param, const char *dev)
{
	int ret;
	char path[PATH_MAX];
	char part[64];

	if (ploop_get_part(di, dev, part, sizeof(part)))
		 return SYSEXIT_MOUNT;

	ret = get_mount_dir(part, 0, path, sizeof(path));
	if (ret == -1) {
		return SYSEXIT_MOUNT;
	} else if (ret == 0) {
		ret = ploop_umount_fs(path, di);
		if (ret)
			return ret;
	}

	return ploop_mount_fs(di, part, param, 1);
}

int ploop_mount_image(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param)
{
	int ret;
	char dev[64];

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	}
	if (ret == 0) {
		if (param->flags & MS_REMOUNT) {
			ret = remount_image(di, param, dev);
		} else {

			ploop_err(0, "Image %s already used by device %s",
					di->images[0]->file, dev);

			ret = SYSEXIT_MOUNT;
		}
		goto err;
	}

	ret = mount_image(di, param);
	if (ret == 0 && di->runtime->component_name == NULL)
		merge_temporary_snapshots(di);
err:
	ploop_unlock_dd(di);

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

static int ploop_stop_device(const char *device,
		struct ploop_disk_images_data *di)
{

	ploop_log(0, "Unmounting device %s", device);
	return ploop_stop(device, di);

}

static int ploop_umount_fs(const char *mnt, struct ploop_disk_images_data *di)
{
	int ret;

	/* The component_name feature allows multiple image mount.
	 * Skip store statfs in custom case.
	 */
	if (di != NULL && di->runtime->component_name == NULL)
		store_statfs_info(mnt, di->images[0]->file);

	ploop_log(0, "Unmounting file system at %s", mnt);
	ret = do_umount(mnt, di ? di->runtime->umount_timeout : PLOOP_UMOUNT_TIMEOUT);

	return ret;
}

int ploop_umount(const char *device, struct ploop_disk_images_data *di)
{
	int ret;
	char devname[64];
	char partname[64];
	char mnt[PATH_MAX] = "";
	char cn[PATH_MAX] = "";
	char *top = NULL;
	int fmt;
	struct delta d = {.fd = -1};
	struct ploop_pvd_header *vh;

	if (!device) {
		ploop_err(0, "ploop_umount: device is not specified");
		return SYSEXIT_SYS; /* internal error */
	}

	ploop_log(0, "Umount %s", device);
	ret = get_part_devname_from_sys(device, devname, sizeof(devname),
			partname, sizeof(partname));
	if (ret)
		return ret;

	if (get_mount_dir(partname, 0, mnt, sizeof(mnt)) == 0) {
		ret = ploop_umount_fs(mnt, di);
		if (ret)
			return ret;
	}

	if (get_crypt_layout(devname, partname))
		crypt_close(devname, partname);

	ret = get_image_param_online(device, &top, NULL, NULL, &fmt);
	if (ret)
		return ret;

	if (open_delta(&d, top, O_RDWR, OD_ALLOW_DIRTY)) {
		free(top);
		return SYSEXIT_OPEN;
	}

	if (fmt == PLOOP_FMT_V2) {
		int lfd, rc;

		ret = wait_for_open_count(device);
		if (ret)
			goto err;

		ret = ploop_suspend_device(device);
		if (ret)
			goto err;

		lfd = open(device, O_RDONLY|O_CLOEXEC);
		if (lfd < 0) {
			ploop_err(errno, "Can't open dev %s", device);
			ploop_resume_device(device);
			ret = SYSEXIT_DEVICE;
			goto err;
		}

		rc = delta_save_optional_header(lfd, &d, NULL, NULL);
		if (rc)
			ploop_err(errno, "Warning: saving format extension failed: %d", rc);

		rc = cbt_stop(lfd);
		if (rc && rc != SYSEXIT_NOCBT)
			ploop_err(errno, "Warning: stopping cbt failed: %d", rc);
		ploop_resume_device(device);

		close(lfd);
	}

	cn_find_name(device, cn, sizeof(cn), 1);
	ret = ploop_stop_device(device, di);
	if (ret)
		goto err;

	if (cn[0] != '\0') {
		ploop_log(3, "Unregister %s",  cn);
		unlink(cn);
	}

	if (di != NULL) {
		get_temp_mountpoint(di->images[0]->file, 0, mnt, sizeof(mnt));
		if (access(mnt, F_OK) == 0)
			rmdir(mnt);
	}

	vh = (struct ploop_pvd_header *) d.hdr0;
	if (vh->m_DiskInUse == SIGNATURE_DISK_IN_USE) {
		ret = clear_delta(&d);
		if (ret)
			goto err;
	}

	ret = check_deltas_live(di);
err:

	close_delta(&d);
	free(top);

	return ret;
}

int ploop_umount_image(struct ploop_disk_images_data *di)
{
	int ret;
	char dev[64];

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1)
		return SYSEXIT_SYS;
	else if (ret == 1) {
		ploop_err(0, "Image %s is not mounted",
			find_image_by_guid(di, get_base_delta_uuid(di)));
		return SYSEXIT_DEV_NOT_MOUNTED;
	}

	ret = ploop_umount(dev, di);

	ploop_unlock_dd(di);

	return ret;
}

int get_image_param_offline(struct ploop_disk_images_data *di,
		const char *guid, off_t *size, __u32 *blocksize,
		int *version)
{
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
		*version = PLOOP_FMT_UNDEFINED;
		*blocksize = di->blocksize;
	} else {
		if (open_delta(&delta, image, O_RDONLY, OD_OFFLINE|OD_ALLOW_DIRTY))
			return SYSEXIT_OPEN;

		*size = delta.l2_size * delta.blocksize;
		*version = delta.version;
		*blocksize = delta.blocksize;
		close_delta(&delta);
	}

	return 0;
}

int get_image_param(struct ploop_disk_images_data *di, const char *guid,
		off_t *size, __u32 *blocksize, int *version)
{
	int ret;
	char dev[64];

	/* The 'size' parameter is delta specific so
	 * get offline for non top delta.
	 */
	if (strcmp(di->top_guid, guid) == 0) {
		ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
		if (ret == -1)
			return SYSEXIT_SYS;
		if (ret == 0)
			return get_image_param_online(dev, NULL, size, blocksize, version);
	}
	return get_image_param_offline(di, guid, size, blocksize, version);
}

int ploop_grow_device(struct ploop_disk_images_data *di,
		const char *device, off_t new_size)
{
	int rc, version;
	off_t size;
	char *top = NULL;
	__u32 blocksize;

	rc = get_image_param_online(device, &top, &size, &blocksize, &version);
	if (rc)
		return rc;
	rc = ploop_get_size(device, &size);
	if (rc)
		goto err;
	ploop_log(0, "Growing dev=%s size=%llu sectors (new size=%llu)",
			device, (unsigned long long)size,
			(unsigned long long)new_size);

	rc = grow_image(top, blocksize, new_size);
	if (rc)
		goto err;

	rc = dm_resize(device, new_size);
	if (rc)
		goto err;

	rc = dm_reload2(device, new_size, 0);
err:
	free(top);

	return rc;
}

int ploop_grow_image(struct ploop_disk_images_data *di, off_t size, int sparse)
{
	int ret;
	char device[64];
	char conf[PATH_MAX];
	char conf_tmp[PATH_MAX] = "";
	int mounted = 1;
	int raw = 0;
	int i;
	const char *fname = NULL;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	// Update size in the DiskDescriptor.xml
	di->size = size;
	get_disk_descriptor_fname(di, conf, sizeof(conf));
	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
	ret = ploop_store_diskdescriptor(conf_tmp, di);
	if (ret)
		goto err;

	ret = ploop_find_dev_by_dd(di, device, sizeof(device));
	if (ret == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	}

	mounted = (ret == 0);

	if (!mounted) {
		i = find_snapshot_by_guid(di, di->top_guid);
		if (i == -1) {
			ploop_err(0, "Unable to find top delta file name");
			ret = SYSEXIT_PARAM;
			goto err;
		}

		fname = find_image_by_guid(di, di->top_guid);
		if (!fname) {
			ploop_err(0, "Unable to find top delta file name");
			ret = SYSEXIT_PARAM;
			goto err;
		}

		if (strcmp(di->snapshots[i]->parent_guid, NONE_UUID) == 0 &&
				di->mode == PLOOP_RAW_MODE) {
			raw = 1;
		} else {
			struct ploop_mount_param m = {};
			ret = mount_image(di, &m);
			if (ret)
				goto err;
			snprintf(device, sizeof(device), "%s", m.device);
		}
	}

	if (raw)
		ret = ploop_grow_raw_delta_offline(fname, size, sparse);
	else
		ret = ploop_grow_device(di, device, size);
	if (ret)
		goto err;

	if (rename(conf_tmp, conf)) {
		ploop_err(errno, "Can't rename %s to %s",
				conf_tmp, conf);
		ret = SYSEXIT_RENAME;
	}
err:
	unlink(conf_tmp);
	if (!mounted)
		 ploop_umount(device, di);
		
	ploop_unlock_dd(di);

	return ret;
}

static int ploop_raw_discard(struct ploop_disk_images_data *di, const char *device,
		const char *partname, __u32 blocksize, off_t start, off_t end)
{
	int ret, part;
	char conf[PATH_MAX];
	off_t new_end;

	new_end = ROUNDUP(start, blocksize);

	if (new_end >= end)
		return 0;

	ret = has_partition(device, &part);
	if (ret)
		return ret;

	if (part) {
		ret = resize_gpt_partition(device, partname, new_end, blocksize);
		if (ret)
			return ret;
	}

	ret = ploop_stop_device(device, di);
	if (ret)
		return ret;

	ploop_log(0, "Truncate %s %lu",	di->images[0]->file, S2B(new_end));
	if (truncate(di->images[0]->file, S2B(new_end))) {
		ploop_err(errno, "Failed to truncate %s",
				di->images[0]->file);
		return SYSEXIT_FTRUNCATE;
	}

	di->size = new_end;
	get_disk_descriptor_fname(di, conf, sizeof(conf));
	return ploop_store_diskdescriptor(conf, di);
}

/* The code below works correctly only if
 *	device=/dev/ploopN
 *	part_dev_size=/dev/ploopNp1
 */
static int shrink_device(struct ploop_disk_images_data *di,
		const char *device, const char *part_device,
		off_t new_size, __u32 blocksize)
{
	struct dump2fs_data data;
	int ret;
	int top, raw;
	off_t start, end, part_dev_size;

	ret = ploop_get_size(part_device, &part_dev_size);
	if (ret)
		return ret;

	ret = ploop_get_attr(device, "top", &top);
	if (ret)
		return SYSEXIT_SYSFS;

	ret = e2fsck(part_device, E2FSCK_FORCE | E2FSCK_PREEN, NULL);
	if (ret)
		return ret;

	/* offline resize */
	ret = resize_fs(part_device, new_size);
	if (ret)
		return ret;

	ret = dumpe2fs(part_device, &data);
	if (ret)
		return ret;

	raw = (di->mode == PLOOP_RAW_MODE && top == 0);
	start = B2S(data.block_count * data.block_size);
	end = part_dev_size;

	ploop_log(0, "Offline shrink %s dev=%s size=%lu new_size=%lu, start=%lu:%lu",
			(raw) ? "raw" : "",
			part_device, (long)part_dev_size, (long)new_size, start, end);

	if (raw)
		ret = ploop_raw_discard(di, device, part_device, blocksize, start, end);
	else
		ret = ploop_blk_discard(part_device, blocksize, start, end);

	return ret;
}

int ploop_resize_image(struct ploop_disk_images_data *di,
		struct ploop_resize_param *param)
{
	int ret, rc;
	char buf[PATH_MAX];
	char partname[64];
	char dev[64];
	char devname[64];
	char *target = NULL;
	int mounted = 0;
	int balloonfd = -1;
	struct stat st;
	off_t part_dev_size = 0;
	off_t dev_size = 0;
	__u64 balloon_size = 0;
	__u64 new_balloon_size = 0;
	struct statfs fs;
	unsigned long long new_size;
	__u32 blocksize = 0;
	int version;
	off_t new_fs_size = 0;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = get_dev_and_mnt(di, param->mntns_pid,  1, dev, sizeof(dev),
			buf, sizeof(buf), &mounted);

	if (!mounted) {
		ret = check_deltas_live(di);
		if (ret)
			goto err;
	}

	target = strdup(buf);

	//FIXME: Deny resize image if there are childs
	ret = get_image_param_online(dev, NULL, &dev_size,
			&blocksize, &version);
	if (ret)
		goto err;

	ret = get_part_devname(di, dev, devname, sizeof(devname),
			partname, sizeof(partname));
	if (ret)
		goto err;

	if (check_size(param->size, blocksize, version)) {
		ret = SYSEXIT_PARAM;
		goto err;
	}

	new_size = round_bdsize(param->size, blocksize, version);
	ret = ploop_get_size(partname, &part_dev_size);
	if (ret)
		goto err;

	if (new_size != 0) {
		/* use (4 * blocksize) as reserved space for alignment */
		if (new_size <= (4 * blocksize)) {
			ploop_err(0, "Unable to change image size to %llu sectors",
					new_size);
			ret = SYSEXIT_PARAM;
			goto err;
		}
		new_fs_size = new_size - (4 * blocksize);
	}

	ret = get_balloon(target, &st, &balloonfd);
	if (ret)
		goto err;
	balloon_size = bytes2sec(st.st_size);

	if (param->size == 0) {
		__u64 delta = di->blocksize ?: 2048;
		__u64 free_space;

		/* Iteratively inflate balloon up to max free space */
		if (statfs(target, &fs) != 0) {
			ploop_err(errno, "statfs(%s)", target);
			ret = SYSEXIT_FSTAT;
			goto err;
		}

		free_space = B2S(fs.f_bfree * fs.f_bsize);

		for (new_balloon_size = balloon_size + free_space;
				delta < free_space && new_balloon_size > balloon_size;
				delta *= 2)
		{
			ret = ploop_balloon_change_size(dev,
					balloonfd, new_balloon_size - delta);
			if (ret != SYSEXIT_FALLOCATE)
				break;
		}
	} else if (new_size > dev_size) {
		char conf[PATH_MAX];
		char conf_tmp[PATH_MAX];

		/* GROW */
		if (balloon_size != 0) {
			ret = ploop_balloon_change_size(dev, balloonfd, 0);
			if (ret)
				goto err;
		}
		close(balloonfd);
		balloonfd = -1;
		if (mounted && param->offline_resize) {
			/* offline */
			ret = ploop_umount_fs(target, di);
			if (ret)
				goto err;

			ret = e2fsck(partname, E2FSCK_FORCE | E2FSCK_PREEN, NULL);
			if (ret)
				goto err;
		}

		// Update size in the DiskDescriptor.xml
		di->size = new_size;
		get_disk_descriptor_fname(di, conf, sizeof(conf));
		snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", conf);
		ret = ploop_store_diskdescriptor(conf_tmp, di);
		if (ret)
			goto err;

		ret = ploop_grow_device(di, dev, new_size);
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

		ret = resize_gpt_partition(devname, partname, 0, blocksize);
		if (ret)
			goto err;

		/* resize up to the end of device */
		ret = resize_fs(partname, 0);
		if (ret)
			goto err;
	} else {
		/* Grow or shrink fs but do not change block device size */
		if (part_dev_size < new_fs_size) {
			/* sync gpt with new_size */
			ret = resize_gpt_partition(devname, partname, new_size, blocksize);
			if (ret)
				goto err;
		}

		if (mounted && param->offline_resize) {
			/* Offline */
			if (balloon_size != 0) {
				/* FIXME: restore balloon size on failure */
				ret = ploop_balloon_change_size(dev, balloonfd, 0);
				if (ret)
					goto err;
			}
			close(balloonfd); /* close to make umount possible */
			balloonfd = -1;

			ret = ploop_umount_fs(target, di);
			if (ret)
				goto err;

			drop_statfs_info(di->images[0]->file);

			ret = shrink_device(di, dev, partname, new_fs_size, blocksize);
			if (ret)
				goto err;
		} else {
			/* Online */
			struct dump2fs_data data = {};
			__u64 available_balloon_size;
			__u64 blocks;
			__u64 reserved_blocks;

			ret = dumpe2fs(partname, &data);
			if (ret)
				goto err;

			blocks = data.block_count * B2S(data.block_size);
			if (new_fs_size < blocks) {
				/* shrink fs */
				if (statfs(target, &fs) != 0) {
					ploop_err(errno, "statfs(%s)", target);
					ret = SYSEXIT_FSTAT;
					goto err;
				}

				new_balloon_size = blocks - new_fs_size;
				/* exclude data accounted by ext4 by assumption that
				 * overhead is inodes * inode size
				 */
				reserved_blocks = B2S(fs.f_files * 256);
				if (reserved_blocks > new_balloon_size) {
					ret = ploop_balloon_change_size(dev,
							balloonfd, 0);
					goto err;
				}

				new_balloon_size -= reserved_blocks;
				available_balloon_size = balloon_size + (fs.f_bfree * B2S(fs.f_bsize));
				if (available_balloon_size < new_balloon_size) {
					ploop_err(0, "Unable to change image size to %lu "
							"sectors, minimal size is %" PRIu64,
							(long)new_fs_size,
							(uint64_t)(blocks - available_balloon_size - reserved_blocks));
					ret = SYSEXIT_PARAM;
					goto err;
				}
			} else {
				/* grow fs */
				new_balloon_size = 0;
			}

			if (new_balloon_size != balloon_size) {
				ret = ploop_balloon_change_size(dev,
						balloonfd, new_balloon_size);
				if (ret)
					goto err;
				tune_fs(balloonfd, partname, new_fs_size);
			}

			if (new_fs_size > blocks) {
				ret = resize_fs(partname, new_fs_size);
				if (ret)
					goto err;
			}
		}
	}

err:
	if (balloonfd != -1)
		close(balloonfd);


	if (!mounted) {
		rc = check_deltas_live(di);
		if (ret == 0)
			ret = rc;
	} else
		umnt(di, dev, target, mounted);

	ploop_unlock_dd(di);
	free(target);

	return ret;
}

int ploop_resize_blkdev(const char *device, off_t new_size)
{
	int ret, part_num;
	unsigned long long part_start, part_end;
	char partname[64];

	ret = get_last_partition_num(device, &part_num);
	if (ret)
		return ret;

	ret = get_partition_range(device, part_num, &part_start, &part_end);
	if (ret)
		return ret;

	ret = sgdisk_resize_gpt(device, part_num, part_start);
	if (ret)
		return ret;

	reread_part(device);

	ret = get_partition_device_name_by_num(device, part_num, partname, sizeof(partname));
	if (ret)
		return ret;

	ret = e2fsck(partname, E2FSCK_FORCE | E2FSCK_PREEN, NULL);
	if (ret)
		return ret;

	ret = resize_fs(partname, 0);
	return ret;
}

static int expanded2raw(struct ploop_disk_images_data *di)
{
	struct delta delta = {};
	struct delta odelta = {};
	__u32 clu;
	void *buf = NULL;
	char tmp[PATH_MAX] = "";
	int ret = -1;
	__u64 cluster;

	ploop_log(0, "Converting image to raw...");
	// FIXME: deny snapshots
	if (open_delta(&delta, di->images[0]->file, O_RDONLY, OD_OFFLINE))
		return SYSEXIT_OPEN;
	cluster = S2B(delta.blocksize);

	if (p_memalign(&buf, 4096, cluster))
		goto err;

	snprintf(tmp, sizeof(tmp), "%s.tmp",
			di->images[0]->file);
	if (open_delta_simple(&odelta, tmp, O_RDWR|O_CREAT|O_EXCL|O_TRUNC, OD_OFFLINE))
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
		if (delta.version == PLOOP_FMT_V1 &&
				(delta.l2[l2_slot] % delta.blocksize) != 0) {
			ploop_err(0, "Image corrupted: delta.l2[%d]=%d",
					l2_slot, delta.l2[l2_slot]);
			goto err;
		}
		if (delta.l2[l2_slot] != 0) {
			if (PREAD(&delta, buf, cluster, S2B(ploop_ioff_to_sec(delta.l2[l2_slot],
								delta.blocksize, delta.version))))
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
	if (ret && tmp[0])
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
			int rc;

			delta.l2[l2_slot] = ploop_sec_to_ioff(data_off * delta.blocksize,
					delta.blocksize, delta.version);

			rc = sys_fallocate(delta.fd, 0, data_off * cluster, cluster);
			if (rc) {
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
					rc = PWRITE(&delta, buf, cluster, data_off * cluster);
				}
				if (rc) {
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


	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	if (di->mode == PLOOP_RAW_MODE) {
		ploop_err(0, "Converting raw image is not supported");
		ret =  SYSEXIT_PARAM;
		goto err;
	}

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
	ploop_unlock_dd(di);

	return ret;
}

#define BACKUP_IDX_FNAME(fname, image)	snprintf(fname, sizeof(fname), "%s.idx", image)
static int backup_idx_table(struct delta *d, const char *image)
{
	char fname[PATH_MAX];
	int fd, ret;
	__u32 clu, cluster;

	BACKUP_IDX_FNAME(fname, image);

	ploop_log(0, "Backing up index table %s", fname);
	fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0 ) {
		ploop_err(errno, "Failed to create %s", fname);
		return SYSEXIT_OPEN;
	}

	cluster = S2B(d->blocksize);
	for (clu = 0; clu < d->l1_size; clu++) {
		if (PREAD(d, d->l2, cluster, (off_t)clu * cluster)) {
			ret = SYSEXIT_WRITE;
			goto err;
		}

		if (WRITE(fd, d->l2, cluster)) {
			ret = SYSEXIT_READ;
			goto err;
		}
	}
	if (fsync(fd)) {
		ploop_err(errno, "Failed to sync %s", fname);
		ret = SYSEXIT_FSYNC;
		goto err;
	}
	ret = 0;
err:
	close(fd);
	return ret;
}

/* Write index table */
static int writeback_idx(struct delta *delta)
{
	__u32 l1_cluster = delta->l2_cache;
	__u8 *buf = (__u8 *)delta->l2;
	int skip = l1_cluster == 0 ? sizeof(struct ploop_pvd_header) : 0;

	if (PWRITE(delta, (__u8 *)buf + skip, S2B(delta->blocksize) - skip,
				(off_t)l1_cluster * S2B(delta->blocksize) + skip))
		return SYSEXIT_WRITE;

	delta->dirtied = 0;
	return 0;
}

static int change_fmt_version(struct delta *d, int new_version)
{
	__u32 clu, l2_cluster, l2_slot;
	int ret, n;
	off_t off;
	__u32 cluster = S2B(d->blocksize);

	n = cluster / sizeof(__u32);
	d->dirtied = 0;
	for (clu = 0; clu < d->l1_size * n - PLOOP_MAP_OFFSET; clu++) {
		l2_cluster = (clu + PLOOP_MAP_OFFSET) / n;
		l2_slot    = (clu + PLOOP_MAP_OFFSET) % n;

		if (d->l2_cache != l2_cluster) {
			if (d->dirtied && (ret = writeback_idx(d)))
				goto err;

			if (PREAD(d, d->l2, cluster, (off_t)l2_cluster * cluster)) {
				ret = SYSEXIT_READ;
				goto err;
			}

			d->l2_cache = l2_cluster;
		}
		if (d->l2[l2_slot] == 0)
			continue;

		off = ploop_ioff_to_sec(d->l2[l2_slot], d->blocksize, d->version);
		if (new_version == PLOOP_FMT_V1 && check_size(off, d->blocksize, new_version)) {
			ret = SYSEXIT_PARAM;
			goto err;
		}
		d->l2[l2_slot] = ploop_sec_to_ioff(off, d->blocksize, new_version);
		d->dirtied = 1;
	}

	if (d->dirtied && (ret = writeback_idx(d)))
		goto err;

	/* update header and sync */
	ret = change_delta_version(d, new_version);
	if (ret)
		goto err;
err:
	return ret;
}

int ploop_change_fmt_version(struct ploop_disk_images_data *di, int new_version, int flags)
{
	char fname[PATH_MAX];
	struct delta_array da = {};
	int ret = 0, rc, i;
	struct ploop_pvd_header *vh;

	init_delta_array(&da);
	if (new_version != PLOOP_FMT_V1 && new_version != PLOOP_FMT_V2) {
		ploop_err(0, "Incorrect version is specified");
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	if (di->mode == PLOOP_RAW_MODE) {
		ploop_err(0, "Changing image version format"
				" on raw image is not supported");
		goto err;
	}

	rc = ploop_find_dev_by_dd(di, fname, sizeof(fname));
	if (rc == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	} else if (rc == 0) {
		ret = SYSEXIT_PARAM;
		ploop_err(0, "Image is mounted: changing image version "
				" online is not supported");
		goto err;
	}
	/* 0. Validate */
	for (i = 0; i < di->nimages; i++) {
		if (extend_delta_array(&da, di->images[i]->file,
					O_RDWR, OD_OFFLINE)) {
			ret = SYSEXIT_OPEN;
			goto err;
		}
		if (new_version == PLOOP_FMT_V1 &&
		    ((off_t)da.delta_arr[i].l2_size * da.delta_arr[i].blocksize) > 0xffffffff)
		{
			ret = SYSEXIT_PARAM;
			ploop_err(0, "Unable to convert image to PLOOP_FMT_V1:"
					" the image size is not compatible");
			goto err;
		}
	}
	/* 1. Backup index table */
	for (i = 0; i < di->nimages; i++) {
		ret = backup_idx_table(&da.delta_arr[i], di->images[i]->file);
		if (ret)
			goto err_rm;
	}
	/* 2. Lock deltas */
	for (i = 0; i < di->nimages; i++) {
		if (dirty_delta(&da.delta_arr[i])) {
			ret = SYSEXIT_WRITE;
			goto err;
		}
		vh = (struct ploop_pvd_header *) da.delta_arr[i].hdr0;
		ret = change_delta_flags(&da.delta_arr[i],
				(vh->m_Flags | CIF_FmtVersionConvert));
		if (ret)
			goto err;
	}

	/* Recheck ploop state after locking */
	rc = ploop_find_dev_by_dd(di, fname, sizeof(fname));
	if (rc == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	} else if (rc == 0) {
		ret = SYSEXIT_PARAM;
		ploop_err(0, "Image is mounted: changing image version "
				" online is not supported");
		goto err;
	}

	/* 3. Convert */
	for (i = 0; i < di->nimages; i++) {
		ploop_log(0, "Converting %s to version %d",
				di->images[i]->file, new_version);
		ret = change_fmt_version(&da.delta_arr[i], new_version);
		if (ret)
			goto err;
	}

	/* 4. Unlock */
	for (i = 0; i < di->nimages; i++) {
		vh = (struct ploop_pvd_header *) da.delta_arr[i].hdr0;
		ret = change_delta_flags(&da.delta_arr[i],
				(vh->m_Flags & ~CIF_FmtVersionConvert));
		if (ret)
			goto err;

		if (clear_delta(&da.delta_arr[i])) {
			ret = SYSEXIT_WRITE;
			goto err;
		}
	}

err_rm:
	/* 5. Drop index table backup */
	for (i = 0; i < di->nimages; i++) {
		BACKUP_IDX_FNAME(fname, di->images[i]->file);
		if (unlink(fname) && errno != ENOENT)
			ploop_err(errno, "Failed to unlink %s", fname);
	}

err:
	deinit_delta_array(&da);
	ploop_unlock_dd(di);

	if (ret == 0)
		ploop_log(0, "ploop image has been successfully converted");

	return ret;
}

static int do_restore_fmt_version(struct delta *d, struct delta *idelta)
{
	int ret = 1;
	__u32 cluster;
	__u32 clu;
	void *buf = NULL;

	if (d->l1_size != idelta->l1_size ||
			d->l2_size != idelta->l2_size ||
			d->blocksize != idelta->blocksize)
	{
		ret = SYSEXIT_PARAM;
		ploop_err(0, "Unable to restore: header mismatch");
		goto err;
	}

	cluster = S2B(idelta->blocksize);
	if (p_memalign(&buf, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto err;
	}

	for (clu = 0; clu < idelta->l1_size; clu++) {
		off_t off = clu * cluster;

		if (PREAD(idelta, buf, cluster, off)) {
			ret = SYSEXIT_READ;
			goto err;
		}

		if (clu == 0) {
			struct ploop_pvd_header *vh = (struct ploop_pvd_header *)buf;
			vh->m_DiskInUse = 1;
			vh->m_Flags |= CIF_FmtVersionConvert;
		}

		if (PWRITE(d, buf, cluster, off)) {
			ret = SYSEXIT_WRITE;
			goto err;
		}
	}
	if (fsync(d->fd)) {
		ploop_err(errno, "Failed to sync");
		ret = SYSEXIT_FSYNC;
		goto err;
	}
	ret = 0;
err:
	free(buf);
	return ret;
}

static int restore_fmt_version(const char *file)
{
	char fname[PATH_MAX];
	int ret;
	struct ploop_pvd_header *vh;
	struct delta d = {};
	struct delta idelta = {};

	ret = open_delta(&d, file, O_RDWR, OD_ALLOW_DIRTY | OD_OFFLINE);
	if (ret)
		return ret;

	vh = (struct ploop_pvd_header *) d.hdr0;
	if (!(vh->m_Flags & CIF_FmtVersionConvert)) {
		close_delta(&d);
		return 0;
	}

	BACKUP_IDX_FNAME(fname, file);
	ret = open_delta(&idelta, fname, O_RDONLY, OD_ALLOW_DIRTY | OD_OFFLINE);
	if (ret)
		goto err;

	ploop_log(0, "Restore index table %s", file);
	ret = do_restore_fmt_version(&d, &idelta);
	if (ret)
		goto err;

	ret = change_delta_flags(&d,(vh->m_Flags & ~CIF_FmtVersionConvert));
	if (ret)
		goto err;

	if (clear_delta(&d)) {
		ret = SYSEXIT_WRITE;
		goto err;
	}

	if (unlink(fname) && errno != ENOENT)
		ploop_err(errno, "Failed to unlink %s", fname);

err:
	close_delta(&d);
	close_delta(&idelta);

	return ret;
}

int check_and_restore_fmt_version(struct ploop_disk_images_data *di)
{
	int i, base_id, ret;
	struct ploop_pvd_header *vh;
	struct delta d = {};
	const char *guid;

	if (di->mode == PLOOP_RAW_MODE)
		return 0;

	if ((guid = get_base_delta_uuid(di)) == NULL ||
		 (base_id = find_image_idx_by_guid(di, guid)) == -1)
	{
		ploop_log(-1, "Unable to find base image");
		return SYSEXIT_PARAM;
	}

	/* Check CIF_FmtVersionConvert mark on root image */
	ret = open_delta(&d, di->images[base_id]->file, O_RDONLY, OD_ALLOW_DIRTY | OD_OFFLINE);
	if (ret)
		return ret;

	vh = (struct ploop_pvd_header *) d.hdr0;
	if (!(vh->m_Flags & CIF_FmtVersionConvert)) {
		close_delta(&d);
		return 0;
	}

	close_delta(&d);

	ploop_log(0, "Image remains in converting fmt version state, restoring...");
	for (i = 0; i < di->nimages; i++) {
		if (i == base_id)
			continue;
		ret = restore_fmt_version(di->images[i]->file);
		if (ret)
			goto err;
	}
	/* Do restore base image at the end */
	ret = restore_fmt_version(di->images[base_id]->file);

err:
	return ret;
}

static int get_fs_info(struct ploop_disk_images_data *di, struct ploop_fs_info *info,
		int size, int automount)
{
	struct ploop_fs_info i = {};
	char mnt[PATH_MAX];
	char dev[64];
	int ret = -1;

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1)
		return SYSEXIT_SYS;
	if (ret == 0) {
		char devname[64];
		char partname[64];

		ret = get_part_devname(di, dev, devname, sizeof(devname),
				partname, sizeof(partname));
		if (ret)
			return ret;

		ret = get_mount_dir(partname, 0, mnt, sizeof(mnt));
		if (ret == -1)
			return SYSEXIT_SYS;

		if (ret == 1 || get_statfs_info(mnt, &i.fs))
			ret = SYSEXIT_FSTAT;

		memcpy(i.dev, devname, sizeof(i.dev));
		memcpy(i.part, partname, sizeof(i.part));
	} else {
		if (!automount)
			return SYSEXIT_SYS;   
		/* reinit .statfs */
		struct ploop_mount_param param = {};

		ret = auto_mount_image(di, &param);
		if (ret == 0)
			ploop_umount(param.device, di);
		free_mount_param(&param);
		ret = read_statfs_info(di->images[0]->file, &i.fs);
		if (ret)
			return ret;
	}
	memcpy(info, &i, size);

	return ret;
}


int ploop_get_info_by_descr(const char *descr, struct ploop_info *info)
{
	struct ploop_fs_info i = {};
	struct ploop_disk_images_data *di;
	int ret;

	/* Try the fast path first, for stopped ploop */
	if (read_statfs_info(descr, info) == 0)
		return 0;

	ret = ploop_open_dd(&di, descr);
	if (ret)
		return ret;

	if (ploop_lock_dd(di)) {
		ploop_close_dd(di);
		return SYSEXIT_LOCK;
	}

	ret = get_fs_info(di, &i, sizeof(struct ploop_fs_info), 1);

	memcpy(info, &i.fs, sizeof(i.fs));

	ploop_unlock_dd(di);
	ploop_close_dd(di);

	return ret;
}

int ploop_get_fs_info(const char *fname, struct ploop_fs_info *info, int size)
{
	int ret;
	struct ploop_disk_images_data *di;

	bzero(info, size);
	/* Try the fast path first, for stopped ploop */
	if (read_statfs_info(fname, &info->fs) == 0)
		return 0;

	di = alloc_diskdescriptor();
	if (di == NULL)
		return SYSEXIT_MALLOC;
	di->runtime->xml_fname = strdup(fname);

	ret = ploop_read_dd(di);
	if (ret)
		goto err;
	ret = get_fs_info(di, info, size, 0);

err:
	ploop_close_dd(di);

	return ret;
}

int ploop_get_spec(struct ploop_disk_images_data *di, struct ploop_spec *spec)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = get_image_param(di, di->top_guid, &spec->size, &spec->blocksize,
			&spec->fmt_version);

	ploop_unlock_dd(di);

	return ret;
}

int ploop_set_max_delta_size(struct ploop_disk_images_data *di, unsigned long long size)
{
	char conf[PATH_MAX];
	char dev[64];
	int fd = -1;
	int rc;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	rc = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (rc == -1) {
		rc = SYSEXIT_SYS;
		goto err;
	} else if (rc == 0) {
		fd = open(dev, O_RDONLY|O_CLOEXEC);
		if (fd == -1) {
			ploop_err(errno, "Can't open device %s", dev);
			rc = SYSEXIT_DEVICE;
			goto err;
		}
		rc = set_max_delta_size(fd, size);
		if (rc)
			goto err;
	}

	get_disk_descriptor_fname(di, conf, sizeof(conf));
	di->max_delta_size = size;
	rc = ploop_store_diskdescriptor(conf, di);
err:
	if (fd != -1)
		close(fd);
	ploop_unlock_dd(di);

	return rc;

}

int copy_delta(const char *src, const char *dst)
{
	void *buf = NULL;
	int sfd = -1, dfd = -1;
	struct ploop_pvd_header *vh;
	int version, cluster = DEF_CLUSTER;
	struct stat st;
	off_t i;
	int ret = 0;

	sfd = open(src, O_DIRECT | O_RDONLY);
	if (sfd < 0) {
		ploop_err(errno, "Can't open %s", src);
		return SYSEXIT_OPEN;
	}

	dfd = open(dst, O_RDWR | O_CREAT | O_DIRECT | O_EXCL, 0600);
	if (dfd < 0) {
		ploop_err(errno, "Can't create %s", dst);
		ret = SYSEXIT_CREAT;
		goto out;
	}

	if (fstat(sfd, &st)) {
		ploop_err(errno, "Can't fstat %s", src);
		ret = SYSEXIT_OPEN;
		goto out;
	}

	if (p_memalign(&buf, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto out;
	}

	/* Read header */
	ret = read_safe(sfd, buf, 4096, 0, "read PVD header");
	if (ret)
		goto out;
	vh = buf;

	/* Do some minor checks on header */
	ret = SYSEXIT_PLOOPFMT;
	version = ploop1_version(vh);
	if (version == PLOOP_FMT_ERROR) {
		ploop_err(0, "Wrong signature in image %s", src);
		goto out;
	}
	if (vh->m_Type != PRL_IMAGE_COMPRESSED) {
		ploop_err(0, "Wrong type in image %s", src);
		goto out;
	}
	if (!is_valid_blocksize(vh->m_Sectors)) {
		ploop_err(0, "Wrong cluster size %d in image %s",
				vh->m_Sectors, src);
		goto out;
	}
	if (vh->m_FirstBlockOffset % vh->m_Sectors != 0) {
		ploop_err(0, "Wrong first block offset in image %s", src);
		goto out;
	}
	if (vh->m_DiskInUse) {
		ploop_err(0, "Image %s is in use", src);
		ret = SYSEXIT_PLOOPINUSE;
		goto out;
	}

	/* Does cluster size differs from default? */
	if (cluster != S2B(vh->m_Sectors)) {
		/* realloc */
		cluster = S2B(vh->m_Sectors);
		free(buf);
		if (p_memalign(&buf, 4096, cluster)) {
			ret = SYSEXIT_MALLOC;
			goto out;
		}
	}

	/* Check file size for sanity, should be X clusters */
	if (st.st_size % cluster != 0) {
		ploop_err(0, "Bad file size of image %s", src);
		ret = SYSEXIT_PLOOPFMT;
		goto out;
	}

	ploop_log(0, "Copying %lu MB delta %s to %s",
			(unsigned long)(st.st_size >> 20), src, dst);

	/* Preallocate disk space */
	if (sys_fallocate(dfd, 0, 0, st.st_size) && errno != ENOTSUP) {
		ploop_err(errno, "Can't fallocate(%s, %lu)",
				dst, (unsigned long)st.st_size);
		ret = SYSEXIT_FALLOCATE;
		goto out;
	}

	/* Copy data */
	for (i = 0; i < st.st_size; i+=cluster) {
		ret = read_safe(sfd, buf, cluster, i, "read cluster");
		if (ret)
			goto out;
		ret = write_safe(dfd, buf, cluster, i, "write cluster");
		if (ret)
			goto out;
	}

	if (fsync(dfd)) {
		ploop_err(errno, "Failed to sync %s", dst);
		ret = SYSEXIT_FSYNC;
		goto out;
	}

	ret = 0;
out:
	if (buf)
		free(buf);
	if (sfd >= 0)
		close(sfd);
	if (dfd >= 0)
		close(dfd);
	if (ret && ret != SYSEXIT_CREAT)
		unlink(dst);

	return ret;
}

/*
 * Find best blocksize for raw image.
 * Select largest possible blocksize between 1M and 32K.
 *
 * Returns blocksize in sectors or -1 in case of error.
 */
static int select_best_blocksize(off_t size)
{
	int i;

	for (i = 20; i >= 15; i--)
		if (size % (1 << i) == 0)
			return 1 << (i - PLOOP1_SECTOR_LOG);

	return -1;
}

int ploop_restore_descriptor(const char *dir, char *delta_path, int raw, int blocksize)
{
	struct delta delta;
	struct ploop_disk_images_data *di = NULL;
	struct ploop_create_param param = {};
	char ddxml[PATH_MAX];
	char fname[PATH_MAX];
	int ret;

	if (strlen(dir) == 0)
		return SYSEXIT_PARAM;

	ret = snprintf(ddxml, sizeof(ddxml), "%s/" DISKDESCRIPTOR_XML, dir);
	if (ret >= sizeof(ddxml)) {
		ploop_err(0, "Output path is too long");
		return SYSEXIT_PARAM;
	}

	if (raw) {
		struct stat st;

		param.mode = PLOOP_RAW_MODE;
		if (stat(delta_path, &st)) {
			ploop_err(errno, "stat %s", delta_path);
			return SYSEXIT_OPEN;
		}

		if(blocksize) {
			if (st.st_size % (blocksize * SECTOR_SIZE)) {
				ploop_err(0, "Image size must be aligned "
						"to the blocksize specified");
				return SYSEXIT_PARAM;
			}

			param.blocksize = blocksize;
		} else {
			blocksize = select_best_blocksize(st.st_size);
			if (blocksize < 0) {
				ploop_err(0, "Image size must be aligned to 32K");
				return SYSEXIT_PARAM;
			}
			param.blocksize = blocksize;
		}

		param.size = st.st_size / SECTOR_SIZE;
		param.image = delta_path;
	} else {
		if (open_delta(&delta, delta_path, O_RDONLY, OD_ALLOW_DIRTY))
			return SYSEXIT_OPEN;

		param.size = delta.blocksize * delta.l2_size;
		param.mode = PLOOP_EXPANDED_MODE;
		param.image = delta_path;
		param.blocksize = delta.blocksize;
		param.fmt_version = delta.version;
		close_delta(&delta);
	}

	ret = init_dd(&di, ddxml, NULL, &param);
	if (ret)
		return ret;

	if (realpath(param.image, fname) == NULL) {
		ploop_err(errno, "failed realpath(%s)", param.image);
		ret = SYSEXIT_CREAT;
		goto out;
	}

	ret = ploop_di_add_image(di, fname, TOPDELTA_UUID, NONE_UUID);
	if (ret)
		goto out;

	ret = ploop_store_diskdescriptor(ddxml, di);
	if (ret)
		goto out;

out:
	ploop_close_dd(di);
	return ret;
}

static const char *get_devs_str(char **devs, char *buf, int size)
{
	char **p;
	char *sp = buf;
	char *ep = buf + size;

	for (p = devs; *p != NULL; p++) {
		sp += snprintf(sp, ep - sp, "%s ", *p);
		if (sp >= ep)
			break;
	}
	return buf;
}

int check_snapshot_mount(struct ploop_disk_images_data *di,
		const char *guid, const char *fname, int temp)
{
	int ret = 0;
	char **devs = NULL, **p;
	char buf[512];

	/* Don't check top delta */
	if (guidcmp(guid, di->top_guid) == 0)
		return 0;

	ret = find_devs_by_delta(fname, &devs);
	if (ret == 1)
		return 0;
	if (ret == -1)
		return SYSEXIT_SYS;

	/* There is one or more ploop devices found */
	if (!temp) {
		ploop_err(0, "Snapshot %s is busy by device(s): %s", guid,
				get_devs_str(devs, buf, sizeof(buf)));
		ret = SYSEXIT_EBUSY;
		goto out;
	}

	/* Try to unmount temp snapshot(s) */
	for (p = devs; *p != NULL; p++) {
		int retry = 0;
retry:
		if (!is_device_inuse(*p))
			ret = ploop_umount(*p, NULL);
		else {
			ret = SYSEXIT_EBUSY;
			if (retry++ < 3) {
				sleep(1);
				goto retry;
			}
		}

		if (ret) {
			print_output(0, "lsof", *p);
			/* print current device and remaining ones */
			ploop_err(0, "Snapshot %s is busy by device(s): %s", guid,
					get_devs_str(p, buf, sizeof(buf)));
			goto out;
		}
	}

	ret = 0;
out:
	ploop_free_array(devs);

	return ret;
}
