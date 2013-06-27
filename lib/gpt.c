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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/blkpg.h>

#include "ploop.h"

#ifndef BLKPG_RESIZE_PARTITION
#define BLKPG_RESIZE_PARTITION	3
#endif

#define GPT_SIGNATURE 0x5452415020494645LL // EFI PART
typedef struct
{
	__u32 time_low;
	__u16 time_mid;
	__u16 time_hi_and_version;
	__u8 clock_seq_hi_and_reserved;
	__u8 clock_seq_low;
	__u8 node[6];
} guid_t;

struct GptHeader
{
	__u64 signature;
	__u32 revision;
	__u32 header_size;
	__u32 header_crc32;
	__u32 reserved1;
	__u64 my_lba;
	__u64 alternate_lba;
	__u64 first_usable_lba;
	__u64 last_usable_lba;
	guid_t disk_guid;
	__u64 partition_entry_lba;
	__u32 num_partition_entries;
	__u32 size_partition_entry;
	__u32 partition_entry_array_crc32;
	__u8 *reserved2;
};

struct GptEntry
{
	guid_t partition_type_guid;
	guid_t unique_partition_guid;
	__u64 starting_lba;
	__u64 ending_lba;
};

static int has_partition(const char *device, int *res)
{
	int ret;
	unsigned long long signature;
	int fd;

	fd = open(device, O_RDONLY);
	if (fd == -1) {
		ploop_err(errno, "Can't open %s", device);
		return SYSEXIT_OPEN;
	}
	ret = pread(fd, &signature, sizeof(signature), 512);
	if (ret != sizeof(signature)) {
		if (ret == -1)
			ploop_err(errno, "Can't read %s", device);
		else
			ploop_err(0, "short read from %s %d != %u",
					device, ret,
					(unsigned)sizeof(signature));
		close(fd);
		return SYSEXIT_READ;
	}
	*res = (signature == GPT_SIGNATURE) ? 1 : 0;

	close(fd);
	return 0;
}

int get_partition_device_name(const char *device, char *out, int size)
{
	int ret, part;
	const char *p;
	struct stat st;

	ret = has_partition(device, &part);
	if (ret)
		return ret;

	if (part) {
		p = device;
		if (strncmp(device, "/dev/", 5) == 0)
			p += 5;

		snprintf(out, size, "/dev/%sp1", p);
		if (stat(out, &st) == 0)
			return 0;
		if (stat(device, &st)) {
			ploop_err(errno, "failed stat %s", device);
			return -1;
		}
		if (mknod(out, S_IFBLK, st.st_rdev + 1) != 0) {
			ploop_err(errno, "failed mknod %s", out);
			return -1;
		}
		chmod(device, 0600);
	} else
		snprintf(out, size, "%s", device);

	return 0;
}

static int blkpg_resize_partition(int fd, struct GptEntry *pe)
{
	struct blkpg_ioctl_arg ioctl_arg;
	struct blkpg_partition part;

	bzero(&part, sizeof(part));
	part.pno = 1;
	part.start = S2B(pe->starting_lba);
	part.length = S2B(pe->ending_lba - pe->starting_lba + 1);

	ploop_log(3, "update partition table start=%llu length=%llu",
			part.start, part.length);
	ioctl_arg.op = BLKPG_RESIZE_PARTITION;
	ioctl_arg.flags = 0;
	ioctl_arg.datalen = sizeof(struct blkpg_partition);
	ioctl_arg.data = &part;

	return ioctl_device(fd, BLKPG, &ioctl_arg);
}

int resize_gpt_partition(const char *devname, __u64 new_size)
{
	unsigned char buf[SECTOR_SIZE*GPT_DATA_SIZE]; // LBA1 header, LBA2-34 partition entry
	int fd;
	int part, ret;
	struct GptHeader *pt;
	struct GptEntry *pe;
	__u32 pt_crc32, pe_crc32, orig_crc;
	off_t size;
	__u64 tmp;

	ret = has_partition(devname, &part);
	if (ret)
		return ret;

	if (!part)
		return 0;

	ret = ploop_get_size(devname, &size);
	if (ret)
		return ret;

	// Resize up to max available space
	if (new_size == 0)
		new_size = size;

	if (new_size > size) {
		ploop_err(0, "Unable to resize GPT partition:"
				" incorrect parameter new_size=%llu size=%lu",
				new_size, (long)size);
		return SYSEXIT_PARAM;
	}

	ploop_log(1, "Resizing GPT partition to %ld", (long)new_size);
	fd = open(devname, O_RDWR);
	if (fd == -1) {
		ploop_err(errno, "open %s", devname);
		return SYSEXIT_OPEN;
	}
	// skip LBA0 Protective MBR
	ret = pread(fd, buf, sizeof(buf), SECTOR_SIZE);
	if (ret == -1) {
		ploop_err(errno, "pread %s", devname);
		goto err;
	}
	pt = (struct GptHeader *)buf;
	pe = (struct GptEntry *)(&buf[SECTOR_SIZE * GPT_HEADER_SIZE]);

	// Validate crc
	orig_crc = pt->header_crc32;
	pt->header_crc32 = 0;
	pt_crc32 = ploop_crc32((unsigned char *)pt, pt->header_size);
	if (pt_crc32 != orig_crc) {
		ploop_err(0, "GPT validation failed orig crc %x != %x",
				orig_crc, pt_crc32);
		ret = -1;
		goto err;
	}
	// change GPT header
	pt->alternate_lba = new_size - 1;
	pt->last_usable_lba = new_size - GPT_DATA_SIZE - 1;
	pe->ending_lba = (pt->last_usable_lba >> 3 << 3) - 1;

	// Recalculate crc32
	pe_crc32 = ploop_crc32((unsigned char *)pe, SECTOR_SIZE * GPT_PT_ENTRY_SIZE);
	pt->partition_entry_array_crc32 = pe_crc32;

	pt->header_crc32 = 0;
	pt_crc32 = ploop_crc32((unsigned char *)pt, pt->header_size);
	pt->header_crc32 = pt_crc32;

	ploop_log(0, "Storing GPT");
	ret = pwrite(fd, pt, SECTOR_SIZE * GPT_DATA_SIZE, SECTOR_SIZE);
	if (ret == -1) {
		ploop_err(errno, "Failed to store primary GPT %s", devname);
		goto err;
	}
	ret = fsync(fd);
	if (ret) {
		ploop_err(errno, "Can't fsync %s", devname);
		ret = SYSEXIT_FSYNC;
		goto err;
	}

	// Store secondary GPT entries
	tmp = pt->my_lba;
	pt->my_lba = pt->alternate_lba;
	pt->alternate_lba = tmp;
	pt->partition_entry_lba = pt->last_usable_lba + 1;

	// Recalculate crc32
	pt->header_crc32 = 0;
	pt_crc32 = ploop_crc32((unsigned char *)pt, pt->header_size);
	pt->header_crc32 = pt_crc32;

	ret = pwrite(fd, pe, SECTOR_SIZE * GPT_PT_ENTRY_SIZE,
			(new_size - GPT_DATA_SIZE)*SECTOR_SIZE);
	if (ret == -1) {
		ploop_err(errno, "Failed to store secondary GPT %s", devname);
		goto err;
	}

	// Store Secondary GPT header
	ret = pwrite(fd, pt, SECTOR_SIZE, (new_size - GPT_HEADER_SIZE)*SECTOR_SIZE);
	if (ret == -1) {
		ploop_err(errno, "Failed to store secondary GPT header %s", devname);
		goto err;
	}
	fsync(fd);
	blkpg_resize_partition(fd, pe);
	ret = 0;
err:
	close(fd);
	if (ret < 0)
		ret = SYSEXIT_CHANGE_GPT;
	return ret;
}
