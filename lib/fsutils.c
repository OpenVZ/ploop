/*
 *  Copyright (C) 2008-2013, Parallels, Inc. All rights reserved.
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

int create_gpt_partition(const char *device, off_t size, __u32 blocksize)
{
	unsigned long long start = blocksize;
	unsigned long long end = (size - blocksize) / blocksize * blocksize;
	char *argv[7];
	char s1[22], s2[22];

	if (size <= start + blocksize) {
		ploop_err(0, "Image size should be greater than %llu", start);
		return SYSEXIT_PARAM;
	}
	argv[0] = "parted";
	argv[1] = "-s";
	argv[2] = (char *)device;
	argv[3] = "mklabel gpt mkpart primary";
	snprintf(s1, sizeof(s1), "%llub", start << PLOOP1_SECTOR_LOG);
	argv[4] = s1;
	snprintf(s2, sizeof(s2), "%llub", (end << PLOOP1_SECTOR_LOG)-1);
	argv[5] = s2;
	argv[6] = NULL;

	if (run_prg(argv)) {
		ploop_err(0, "Failed to create partition");
		return SYSEXIT_SYS;
	}

	return 0;
}

int make_fs(const char *device, const char *fstype, unsigned int fsblocksize)
{
	int i;
	char part_device[64];
	char fsblock_size[14];
	char *argv[10];
	char ext_opts[1024];
	uint64_t max_online_resize;

	fsblocksize = fsblocksize != 0 ? fsblocksize : 4096;

	if (get_partition_device_name(device, part_device, sizeof(part_device)))
		return SYSEXIT_MKFS;

	i = 0;
	argv[i++] = "mkfs";
	argv[i++] = "-t";
	argv[i++] = (char*)fstype;
	argv[i++] = "-j";
	snprintf(fsblock_size, sizeof(fsblock_size), "-b%u",
			fsblocksize);
	argv[i++] = fsblock_size;
	/* Reserve enough space so that the block group descriptor table can grow to 16T
	 * Note: the max_online_resize is u32 in mkfs.ext4
	 */
	max_online_resize = PLOOP_MAX_FS_SIZE / fsblocksize;
	if (max_online_resize > (uint32_t)~0)
		max_online_resize = (uint32_t)~0;
	snprintf(ext_opts, sizeof(ext_opts), "-Elazy_itable_init,resize=%" PRIu64,
			 max_online_resize);
	argv[i++] = ext_opts;
	/* Set the journal size to 128M to allow online resize up to 16T
	 * independly on the initial image size
	*/
	argv[i++] = "-Jsize=128";
	argv[i++] = "-i16384"; /* 1 inode per 16K disk space */
	argv[i++] = part_device;
	argv[i++] = NULL;

	if (run_prg(argv))
		return SYSEXIT_MKFS;

	i = 0;
	argv[i++] = get_prog(tune2fs_progs);
	argv[i++] =  "-ouser_xattr,acl";
	argv[i++] = "-c0";
	argv[i++] = "-i0";
	argv[i++] = "-eremount-ro";
	argv[i++] = part_device;
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
	if (flags & E2FSCK_FORCE)
		arg[i++] = "-f";
	arg[i++] = (char *)device;
	arg[i++] = NULL;

	/* there no quiet option for fsck, so close stdout */
	if (run_prg_rc(arg, 0x1, &ret))
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
