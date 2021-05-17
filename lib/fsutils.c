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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>

#include "ploop.h"
#ifndef EXT4_IOC_SET_RSV_BLOCKS
#define EXT4_IOC_SET_RSV_BLOCKS         _IOW('f', 44, __u64)
#endif
#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

/* A macro to create a list of versions of an e2fs utility
 * (such as tune2fs, resize2fs or dumpe2fs) to look for,
 * ordered by priority:
 *  1 Our own private version from /usr/libexec
 *  2 A version from e4fsprogs (for RHEL5 systems)
 *  3 A standard one from /sbin
 *  4 Just a name without a path, letting run_prg()
 *    to look it up in all the standard locations.
 */
#define GEN_E2FS_PROG(name) \
static char * name ## 2fs_progs[] = {			\
	"/usr/libexec/"	__stringify(name) "2fs",	\
	"/sbin/"	__stringify(name) "4fs",	\
	"/sbin/"	__stringify(name) "2fs",	\
	__stringify(name) "2fs",			\
	NULL};						\

GEN_E2FS_PROG(tune)
GEN_E2FS_PROG(resize)
GEN_E2FS_PROG(dumpe)

#undef GEN_E2FS_PROG

static char *get_prog(char *progs[])
{
	int i;

	for (i = 0; progs[i] != NULL; i++)
		if (access(progs[i], X_OK) == 0)
			return progs[i];
	/* the last in the list is default */
	return progs[i - 1];
}

int dmsetup_create_part(const char *devname, off_t size)
{
	char t[128];
	char partname[64];
	char *a[] = {"dmsetup", "create", (char *) partname,
		"--table", t, NULL};

	snprintf(partname, sizeof(partname), "%sp1",
			get_basename(devname));
	snprintf(t, sizeof(t), "0 %lu linear %s 2048", size, devname);

	return run_prg(a);
}

int create_gpt_partition(const char *device, __u32 blocksize)
{
	int ret;
	off_t size;
	unsigned long long end,  start = blocksize;

	ret = ploop_get_size(device, &size);
	if (ret)
		return ret;

	ret = parted_mklabel_gpt(device);
	if (ret)
		return ret;

	end = (size - blocksize) / blocksize * blocksize;
	ret = sgdisk_mkpart(device, 1, start, end);
	if (ret)
		return ret;
#if 0
	ret = dmsetup_create_part(device, end-start);
	if (ret)
		return ret;
#endif
	reread_part(device);

	return 0;
}

int parted_mklabel_gpt(const char *device)
{
	char *argv[5];

	argv[0] = "parted";
	argv[1] = "-s";
	argv[2] = (char *)device;
	argv[3] = "mklabel gpt";
	argv[4] = NULL;

	if (run_prg(argv)) {
		ploop_err(0, "Failed to create GPT table");
		return SYSEXIT_SYS;
	}

	return 0;
}

/* Create partition
 * device - path to a device
 * part_num - partition number
 * part_start - beginning of the partition in sectors
 * part_end - end of the partition in sectors
 */
int sgdisk_mkpart(const char *device,
			int part_num,
			unsigned long long part_start,
			unsigned long long part_end)
{
	char *argv[5];
	char s1[100];

	snprintf(s1, sizeof(s1), "%d:%lluk:%lluk",
			part_num, part_start/2, part_end/2);

	argv[0] = "sgdisk";
	argv[1] = "-n";
	argv[2] = s1;
	argv[3] = (char *)device;
	argv[4] = NULL;

	if (run_prg(argv)) {
		ploop_err(0, "Failed to create partition %d", part_num);
		return SYSEXIT_SYS;
	}
	return 0;
}

int sgdisk_resize_gpt(const char *device, int part_num, off_t part_start)
{
	char n[64];
	char *argv[] = {"sgdisk", "-e", "-d1", "-n", n,  (char *)device, NULL};

	snprintf(n, sizeof(n), "%d:%lu:0", part_num, part_start);
	if (run_prg(argv)) {
		ploop_err(0, "Failed to resize GPT partition %d", part_num);
		return SYSEXIT_SYS;
	}
	return 0;
}


#define FOUND_START_SECTOR_BIT 1
#define FOUND_END_SECTOR_BIT 2

int get_partition_range(const char *device,
		int part_num,
		unsigned long long *part_start,
		unsigned long long *part_end)
{
	char cmd[PATH_MAX];
	char buf[512];
	FILE *fp;
	int ret = SYSEXIT_SYS;
	int found = FOUND_START_SECTOR_BIT | FOUND_END_SECTOR_BIT;

	snprintf(cmd, sizeof(cmd), "LANG=C " DEF_PATH_ENV " sgdisk -i %d %s",
			part_num, device);
	fp = popen(cmd, "r");
	if (fp == NULL) {
		ploop_err(0, "Failed %s", cmd);
		return SYSEXIT_SYS;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if ((found & FOUND_START_SECTOR_BIT) &&
				sscanf(buf, "First sector: %llu", part_start) == 1)
			found &= ~FOUND_START_SECTOR_BIT;
		else if ((found & FOUND_END_SECTOR_BIT) &&
				sscanf(buf, "Last sector: %llu", part_end) == 1)
			found &= ~FOUND_END_SECTOR_BIT;
	}

	if (found) {
		ploop_err(0, "Can't get a range of partition %d", part_num);
		goto out;
	}

	ret = 0;
out:
	if (pclose(fp)) {
		ploop_err(0, "Error in pclose() for %s", cmd);
		return SYSEXIT_SYS;
	}

	return ret;
}

int partprobe(const char *device)
{
	char *argv[] = {"partprobe", (char *)device, NULL};

	if (run_prg(argv)) {
		ploop_err(0, "Failed to run partprobe %s", device);
		return SYSEXIT_SYS;
	}
	return 0;
}

int get_last_partition_num(const char *device, int *part_num)
{
	char cmd[PATH_MAX];
	char buf[512];
	FILE *fp;
	int ret = SYSEXIT_SYS;
	int found_title = 0;
	unsigned long long start = 0;
	unsigned long long end = 0;
	int num = 0;
	int last_part = 0;
	char title[] = "Number ";

	snprintf(cmd, sizeof(cmd), "LANG=C " DEF_PATH_ENV " parted -s %s unit b print",
			device);
	fp = popen(cmd, "r");
	if (fp == NULL) {
		ploop_err(0, "Failed %s", cmd);
		return SYSEXIT_SYS;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (!found_title) {
			if (!strncmp(buf, title, sizeof(title) - 1))
				found_title = 1;
			continue;
		}
		if (3 != sscanf(buf, "%d %lluB %lluB", &num, &start, &end))
			continue;
		last_part = num;
	}

	if (!last_part) {
		ploop_err(0, "Can't find the last partition");
		goto out;
	}

	*part_num = last_part;
	ret = 0;
out:
	if (pclose(fp)) {
		ploop_err(0, "Error in pclose() for %s", cmd);
		return SYSEXIT_SYS;
	}

	return ret;
}

int make_fs(const char *part_device, const char *fstype, unsigned int fsblocksize,
		unsigned int flags, const char *fslabel)
{
	int i;
	char fsblock_size[14];
	char *argv[12];
	char ext_opts[1024];
	uint64_t max_online_resize;
	const int lazy = !(flags & PLOOP_CREATE_NOLAZY);

	fsblocksize = fsblocksize != 0 ? fsblocksize : 4096;

	i = 0;
	argv[i++] = "mkfs";
	argv[i++] = "-t";
	argv[i++] = (char*)fstype;
	argv[i++] = "-j";
	if (fslabel != NULL) {
		argv[i++] = "-L";
		argv[i++] = (char*)fslabel;
	}
	snprintf(fsblock_size, sizeof(fsblock_size), "-b%u",
			fsblocksize);
	argv[i++] = fsblock_size;
	/* Reserve enough space so that the block group descriptor table can grow to 16T
	 */
	max_online_resize = PLOOP_MAX_FS_SIZE / fsblocksize;
	snprintf(ext_opts, sizeof(ext_opts), "-Elazy_itable_init=%d,resize=%" PRIu64,
			lazy, max_online_resize);
	argv[i++] = ext_opts;
	/* Set the journal size to 128M to allow online resize up to 16T
	 * independly on the initial image size
	*/
	argv[i++] = "-Jsize=128";
	argv[i++] = (char *)part_device;
	argv[i++] = NULL;

	if (run_prg(argv))
		return SYSEXIT_MKFS;

	i = 0;
	argv[i++] = get_prog(tune2fs_progs);
	argv[i++] =  "-ouser_xattr,acl";
	argv[i++] = "-c0";
	argv[i++] = "-i0";
	argv[i++] = "-eremount-ro";
	argv[i++] = (char *)part_device;
	argv[i++] = NULL;

	if (run_prg(argv))
		return SYSEXIT_MKFS;

	return 0;
}

void tune_fs(int balloonfd, const char *device, unsigned long long size_sec)
{
	unsigned long long reserved_blocks;
	struct statfs fs;
	char *argv[5];
	char buf[21];
	int ret;

	if (fstatfs(balloonfd, &fs) != 0) {
		ploop_err(errno, "tune_fs: can't statfs %s", device);
		return;
	}

	reserved_blocks = size_sec / 100 * 5 * SECTOR_SIZE / fs.f_bsize;
	if (reserved_blocks == 0) {
		ploop_err(0, "Can't set reserved blocks for size %llu",
				size_sec);
		return;
	}

	/* First try to use kernel API, if available */
	ret = ioctl(balloonfd, EXT4_IOC_SET_RSV_BLOCKS, &reserved_blocks);
	if (!ret)
		return;
	if (errno != ENOTTY) {
		ploop_err(errno, "Can't set reserved blocks to %llu",
				reserved_blocks);
		return;
	}

	/* Fallback to manual modification via tune2fs */
	argv[0] = get_prog(tune2fs_progs);
	argv[1] = "-r";
	snprintf(buf, sizeof(buf), "%llu", reserved_blocks);
	argv[2] = buf;
	argv[3] = (char *)device;
	argv[4] = NULL;

	run_prg(argv);
}

int resize_fs(const char *device, off_t size_sec)
{
	char *argv[5];
	char buf[22];

	argv[0] = get_prog(resize2fs_progs);
	argv[1] = "-p";
	argv[2] = (char *)device;
	if (size_sec) {
		// align size to 4K
		snprintf(buf, sizeof(buf), "%luk", (long)(size_sec >> 3 << 3) >> 1);
		argv[3] = buf;
	} else
		argv[3] = NULL;
	argv[4] = NULL;

	if (run_prg(argv))
		return SYSEXIT_RESIZE_FS;
	return 0;
}

enum {
	BLOCK_COUNT,
	BLOCK_FREE,
	BLOCK_SIZE,
};

#define BLOCK_COUNT_BIT (1 << BLOCK_COUNT)
#define BLOCK_FREE_BIT (1 << BLOCK_FREE)
#define BLOCK_SIZE_BIT (1 << BLOCK_SIZE)

int dumpe2fs(const char *device, struct dump2fs_data *data)
{
	char cmd[512];
	char buf[512];
	FILE *fp;
	int found = BLOCK_COUNT_BIT | BLOCK_FREE_BIT | BLOCK_SIZE_BIT;

	snprintf(cmd, sizeof(cmd), "LANG=C " DEF_PATH_ENV " %s -h %s",
			get_prog(dumpe2fs_progs), device);
	fp = popen(cmd, "r");
	if (fp == NULL) {
		ploop_err(0, "Failed %s", cmd);
		return SYSEXIT_SYS;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if ((found & BLOCK_COUNT_BIT) &&
				sscanf(buf, "Block count: %" SCNu64, &data->block_count) == 1)
			found &= ~BLOCK_COUNT_BIT;
		else if ((found & BLOCK_FREE_BIT) &&
				sscanf(buf, "Free blocks: %" SCNu64, &data->block_free) == 1)
			found &= ~BLOCK_FREE_BIT;
		else if ((found & BLOCK_SIZE_BIT) &&
				sscanf(buf, "Block size: %u", &data->block_size) == 1)
			found &= ~BLOCK_SIZE_BIT;
	}

	if (pclose(fp)) {
		ploop_err(0, "failed %s", cmd);
		return SYSEXIT_SYS;
	}
	if (found) {
		ploop_err(0, "Not enough data: %s (0x%x)", cmd, found);
		return SYSEXIT_SYS;
	}

	return 0;
}

int e2fsck(const char *device, int flags, int *rc)
{
	char *arg[5];
	int i = 0;
	int ret;

	arg[i++] = "fsck.ext4";
	if (flags & E2FSCK_PREEN)
		arg[i++] = "-p";
	else if (flags & E2FSCK_FORCE_REPAIR)
		arg[i++] = "-y";
	if (flags & E2FSCK_FORCE)
		arg[i++] = "-f";
	arg[i++] = (char *)device;
	arg[i++] = NULL;

	/* there is no quiet option for fsck, so hide stdout */
	if (run_prg_rc(arg, NULL, HIDE_STDOUT, &ret))
		return SYSEXIT_FSCK;

	if (rc)
		*rc = ret;

	/* exit code < 4 is OK, see man e2fsck */
	if (ret >= 4) {
		ploop_err(0, "e2fsck failed (exit code %d)\n", ret);
		return SYSEXIT_FSCK;
	}

	return 0;
}

int get_major_by_driver_name(const char* device_driver)
{
	FILE *fd;
	char buf[512];
	char title[] = "Block devices:";
	int found_title = 0;
	char name[512];
	int major = -1;

	fd = fopen ("/proc/devices", "r");
	if (fd == NULL) {
		ploop_err(errno, "Failed to read /proc/devices");
		return major;
	}

	while (fgets(buf, sizeof(buf), fd) != NULL) {
		if (!found_title) {
			if (!strncmp(buf, title, sizeof(title) - 1))
				found_title = 1;
			continue;
		}
		if (2 == sscanf(buf, "%d %s", &major, name) &&
				!strcmp(name, device_driver)) {
			break;
		}
		major = -1;
	}

	pclose(fd);
	return major;
}

int is_device_from_devmapper(const char *device)
{
	struct stat st;
	int mapper_major;

	mapper_major = get_major_by_driver_name("device-mapper");
	if (mapper_major > 0) {
		if (stat(device, &st)) {
			ploop_err(errno, "Failed stat(%s)", device);
			return -1;
		}
		if (major(st.st_rdev) == mapper_major)
			return 1;
	} else {
		ploop_log(1, "Module device-mapper is not found");
	}
	return 0;
}

int grow_image(const char *delta, __u32 blocksize, __u64 size)
{
	int rc, fd;
	__u64 s, upb, l1_size;

	upb = S2B(blocksize)  / sizeof(__u32);

	l1_size = ((size / blocksize) + upb -1) / upb;
	s = l1_size * blocksize + size;

	fd = open(delta, O_RDWR|O_CLOEXEC);
	if (fd == -1) {
		ploop_err(errno, "Cannot open %s", delta);
		return SYSEXIT_OPEN;
	}

	ploop_log(0, "Grow %s up to %llusec", delta, s);
	if (ftruncate(fd, S2B(s))) {
		ploop_err(errno, "Can not tuncate %s to %llusec",
				delta, s);
		close(fd);
		return SYSEXIT_SYS;
	}

	rc = fsync_safe(fd);
	close(fd);
	if (rc)
		return rc;

	return 0;
}
