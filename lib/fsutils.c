#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/vfs.h>

#include "ploop.h"

int create_gpt_partition(const char *device, off_t size)
{
	char cmd[512];
	unsigned long long start = 1UL << PLOOP1_DEF_CLUSTER_LOG;
	unsigned long long end = size - start;

	if (size <= start) {
		ploop_err(0, "Image size should be greater than %llu", start);
		return -1;
	}
	snprintf(cmd, sizeof(cmd), "/sbin/parted -s %s mklabel gpt mkpart primary %llus %llus",
			device,	start, end);

	ploop_log(1, "%s", cmd);
	if (system(cmd)) {
		ploop_err(0, "Failed to create partition (cmd: %s)", cmd);
		return -1;
	}

	return 0;
}

int make_fs(const char *device, const char *fstype)
{
	char part_device[64];
	char cmd[512];

	if (get_partition_device_name(device, part_device, sizeof(part_device)))
		return -1;
	snprintf(cmd, sizeof(cmd), "/sbin/mkfs -t %s -j -b4096 %s </dev/null",
			fstype, part_device);
	ploop_log(0, "%s", cmd);
	if (system(cmd))
		return SYSEXIT_MKFS;
	return 0;
}

void tune_fs(const char *target, const char *device, unsigned long long size_sec)
{
	char part_device[64];
	char cmd[512];
	unsigned long long reserved_blocks;
	struct statfs fs;

	if (get_partition_device_name(device, part_device, sizeof(part_device))) {
		ploop_err(0, "tune_fs: unable to get partition device name for %s",
				device);
		return;
	}

	if (statfs(target, &fs) != 0) {
		ploop_err(errno, "tune_fs: can't statfs %s", target);
		return;
	}
	reserved_blocks = size_sec / 100 * 5 * 512 / fs.f_bsize;
	if (reserved_blocks == 0) {
		ploop_err(0, "Can't set reserved blocks for size %llu",
				size_sec);
		return;
	}
	snprintf(cmd, sizeof(cmd), "/sbin/tune2fs -r %llu %s",
			reserved_blocks, part_device);
	ploop_log(0, "%s", cmd);
	system(cmd);
}

static char *get_resize_prog(void)
{
	int i;
	struct stat st;
	static char *progs[] = {"/sbin/resize4fs", "/sbin/resize2fs", NULL};

	for (i = 0; progs[i] != NULL; i++)
		if (stat(progs[i], &st) == 0)
			return progs[i];

	return NULL;
}

int resize_fs(const char *device)
{
	int ret;
	char buf[256];
	char part_device[64];
	char *prog;

	prog = get_resize_prog();
	if (prog == NULL) {
		ploop_err(0, "ext4 file system resizer not found");
		return -1;
	}
	if (get_partition_device_name(device, part_device, sizeof(part_device)))
		return -1;
	if (strcmp(device, part_device) != 0) {
		ret = resize_gpt_partition(device);
		if (ret)
			return ret;
	}
	snprintf(buf, sizeof(buf), "%s -p %s", prog, part_device);
	ploop_err(0, "%s", buf);
	ret = system(buf);
	if (ret) {
		ploop_err(0, "Failed to resize fs (cmd: %s)", buf);
		return SYSEXIT_RESIZE_FS;
	}
	return 0;
}
