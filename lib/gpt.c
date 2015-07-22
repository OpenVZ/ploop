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

/* GPT */
#define GPT_PT_ENTRY_SIZE       16384

#define GPT_SIGNATURE 0x5452415020494645LL // EFI PART
#define XXX_SIGNATURE 0x5452415020585858LL // XXX PART

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

struct MbrPartEntry
{
	char active;
	char start_head;
	char start_sector;
	char start_sylinder;
	char type;
	char end_head;
	char end_sector;
	char end_cylinder;
	__u32 start_lba;
	__u32 count;
};

static int get_sector_size(int fd, int *sector_size)
{
	return ioctl_device(fd, BLKSSZGET, sector_size);
}

static int has_partition(const char *device, int *res)
{
	int fd, sector_size, ret;
	__u64 signature;

	fd = open(device, O_RDONLY);
	if (fd == -1) {
		ploop_err(errno, "Can't open %s", device);
		return SYSEXIT_OPEN;
	}

	ret = get_sector_size(fd, &sector_size);
	if (ret)
		goto err;

	ret = read_safe(fd, &signature, sizeof(signature), sector_size,
			"Failed to read the GPT signaturer");
	if (ret)
		goto err;

	*res = (signature == GPT_SIGNATURE) ? 1 : 0;
err:
	close(fd);

	return ret;
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
		if (access(out, F_OK) == 0)
			return 0;
		if (stat(device, &st)) {
			ploop_err(errno, "failed stat %s", device);
			return -1;
		}
		if (mknod(out, S_IFBLK, st.st_rdev + 1) != 0) {
			ploop_err(errno, "failed mknod %s", out);
			return -1;
		}
		if (chmod(out, 0600)) {
			ploop_err(errno, "failed chmod %s", out);
			return -1;
		}
	} else
		snprintf(out, size, "%s", device);

	return 0;
}

static int blkpg_resize_partition(int fd, struct GptEntry *pe, int sector_size)
{
	struct blkpg_ioctl_arg ioctl_arg;
	struct blkpg_partition part;

	bzero(&part, sizeof(part));
	part.pno = 1;
	part.start = pe->starting_lba * sector_size;
	part.length = (pe->ending_lba - pe->starting_lba + 1) * sector_size;

	ploop_log(3, "update partition table start=%llu length=%llu",
			part.start, part.length);
	ioctl_arg.op = BLKPG_RESIZE_PARTITION;
	ioctl_arg.flags = 0;
	ioctl_arg.datalen = sizeof(struct blkpg_partition);
	ioctl_arg.data = &part;

	return ioctl_device(fd, BLKPG, &ioctl_arg);
}

static void update_protective_mbr(int fd, __u64 new_size)
{
	char buf[SECTOR_SIZE];
	struct MbrPartEntry *part1;

	// skip LBA0 Protective MBR
	if (pread(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
		ploop_err(errno, "Failed to read MBR");
		return;
	}

	part1 = (struct MbrPartEntry *)(buf + 0x1be);

	part1->end_head = 0xfe;
	part1->end_sector = 0xff;
	part1->end_cylinder = 0xff;
	part1->count = (new_size - part1->start_lba) > (__u32)~0 ?
				(__u32)~0 : new_size - part1->start_lba;

	write_safe(fd, buf, sizeof(buf), 0,
			"Failed to update protective MBR");
}

static int update_gpt_partition(int fd, const char *devname, __u64 new_size512,
		int sector_size, int image_sector_size, __u32 blocksize512)
{
	unsigned char buf[GPT_PT_ENTRY_SIZE];
	int ret;
	struct GptHeader hdr;
	struct GptEntry *pe;
	__u32 pt_crc32, pe_crc32, orig_crc;
	__u32 blocksize;
	off_t size, new_size, gpt_size_bytes;
	__u64 tmp;
	int convert = (sector_size != image_sector_size);

	ret = ploop_get_size(devname, &size);
	if (ret)
		return ret;

	// Resize up to max available space
	if (new_size512 == 0)
		new_size512 = size;

	if (new_size512 > size) {
		ploop_err(0, "Unable to resize GPT partition:"
				" incorrect parameter new_size=%" PRIu64 " size=%lu",
				(uint64_t)new_size512, (long)size);
		return SYSEXIT_PARAM;
	}

	/* convert size from 512 to logical sector size */
	new_size = new_size512 * SECTOR_SIZE / sector_size;
	/* convert blocksize from 512 to logical sector size
	 * use blocksize == 1Mbytes if not specified
	 */
	blocksize = (blocksize512 ?: DEF_CLUSTER) * SECTOR_SIZE / sector_size;
	/* GPT header (1sec) + partition entries (16K) alligned to sector size */
	gpt_size_bytes = sector_size + ROUNDUP(GPT_PT_ENTRY_SIZE, sector_size);

	ploop_log(1, "Update GPT partition to %ldsec (%d)",
			(long)new_size, sector_size);

	/* 1'st sector */
	ret = read_safe(fd, &hdr, sizeof(hdr), image_sector_size,
			"Failed to read the GPT header");
	if (ret)
		return ret;

	/* 2'nd sector */
	ret = read_safe(fd, buf, sizeof(buf), image_sector_size * 2,
			"Failed to read the GPT partition entries");
	if (ret)
		return ret;
	pe = (struct GptEntry *)buf;

	/* Validate crc */
	orig_crc = hdr.header_crc32;
	hdr.header_crc32 = 0;
	pt_crc32 = ploop_crc32((unsigned char *)&hdr, hdr.header_size);
	if (pt_crc32 != orig_crc) {
		ploop_err(0, "GPT validation failed orig crc %x != %x",
				orig_crc, pt_crc32);
		return SYSEXIT_PARAM;
	}
	/* change GPT header */
	hdr.alternate_lba = new_size - 1;
	hdr.last_usable_lba = new_size - (gpt_size_bytes / sector_size) - 1;
	/* allign partition to blocksize */
	pe->ending_lba = (hdr.last_usable_lba / blocksize * blocksize) - 1;

	if (convert) {
		hdr.my_lba = 1;
		hdr.partition_entry_lba = 2;
		hdr.first_usable_lba = (sector_size + gpt_size_bytes) / sector_size;
		pe->starting_lba = (pe->starting_lba * image_sector_size) / sector_size;

		/*TODO:
		 * Store GPT is not atomic, it needed to implement
		 * backup/restore original GPT (or recreate)
		 */
		/* Invalidate old GPT */
		__u64 signature = XXX_SIGNATURE;
		ret = write_safe(fd, &signature, sizeof(signature), image_sector_size,
				"Failed to clear the GPT signature");
		if (ret)
			return ret;
	}

	/* Recalculate crc32 */
	pe_crc32 = ploop_crc32((unsigned char *)pe, GPT_PT_ENTRY_SIZE);
	hdr.partition_entry_array_crc32 = pe_crc32;

	hdr.header_crc32 = 0;
	pt_crc32 = ploop_crc32((unsigned char *)&hdr, hdr.header_size);
	hdr.header_crc32 = pt_crc32;

	/* Store GPT header */
	ret = write_safe(fd, &hdr, sizeof(hdr), sector_size,
			"Failed to write the GPT header");
	if (ret)
		return ret;

	/* Store partition entries */
	ret = write_safe(fd, buf, sizeof(buf), sector_size * 2,
			"Failed to write the GPT partition entries");
	if (ret)
		return ret;

	if (fsync(fd)) {
		ploop_err(errno, "Can't fsync %s", devname);
		return SYSEXIT_FSYNC;
	}

	/* Store secondary GPT entries */
	tmp = hdr.my_lba;
	hdr.my_lba = hdr.alternate_lba;
	hdr.alternate_lba = tmp;
	hdr.partition_entry_lba = hdr.last_usable_lba + 1;

	/* Recalculate crc32 */
	hdr.header_crc32 = 0;
	pt_crc32 = ploop_crc32((unsigned char *)&hdr, hdr.header_size);
	hdr.header_crc32 = pt_crc32;

	/* Store secondary partition entries */
	ret = write_safe(fd, buf, sizeof(buf), (hdr.last_usable_lba + 1) * sector_size,
			"Failed to write secondary GPT partition entries");
	if (ret)
		return ret;

	/* Store secondary GPT header LBA-1*/
	ret = write_safe(fd, &hdr, sizeof(hdr), (new_size - 1) * sector_size,
			"Failed to write secondary GPT header");
	if (ret)
		return ret;

	update_protective_mbr(fd, new_size);
	fsync(fd);
	blkpg_resize_partition(fd, pe, sector_size);

	return 0;
}

int resize_gpt_partition(const char *device, __u64 new_size512, __u32 blocksize512)
{
	int fd, ret, part, sector_size;

	ret = has_partition(device, &part);
	if (ret)
		return ret;

	if (!part)
		return 0;

	fd = open(device, O_RDWR);
	if (fd == -1) {
		ploop_err(errno, "Failed to open %s", device);
		return SYSEXIT_OPEN;
	}

	ret = get_sector_size(fd, &sector_size);
	if (ret)
		goto err;
	/* resize is performed only on mounted fs so sectors are equals */
	ret = update_gpt_partition(fd, device, new_size512, sector_size,
			sector_size, blocksize512);

err:
	close(fd);
	return ret;
}

/* Detect image sector size by GPT signature mark
 * support up to 4K sector size.
 */
#define MAX_SECTOR_SIZE	4096
static int detect_image_sector_size(int fd, int *sector_size)
{
	int ret, i;
	char buf[MAX_SECTOR_SIZE * 2];

	ret = read_safe(fd, buf, sizeof(buf), 0, "Failed to read");
	if (ret) {
		ploop_err(0, "Unable to detect device sector size");
		return ret;
	}

	/* Find signature in the 1'st sector */
	*sector_size = 0;
	for (i = SECTOR_SIZE; i <= MAX_SECTOR_SIZE; i *= 2) {
		struct GptHeader *hdr = (struct GptHeader *)&buf[i];

		if (hdr->signature == GPT_SIGNATURE) {
			if (*sector_size) {
				ploop_err(0, "Unable to detect the device sector size:"
					" multiple GPT signature found");
				return SYSEXIT_PARAM;
			}
			*sector_size = i;
		}
	}

	return 0;
}

int check_and_repair_gpt(const char *device, __u32 blocksize512)
{
	int ret, fd;
	int image_sector_size, sector_size;
	__u64 signature;

	fd = open(device, O_RDWR);
	if (fd == -1) {
		ploop_err(errno, "Failed to open %s", device);
		return SYSEXIT_OPEN;
	}

	ret = get_sector_size(fd, &sector_size);
	if (ret)
		goto err;

	ret = read_safe(fd, &signature, sizeof(signature), sector_size,
			"Failed to read the GPT signaturer");
	if (ret)
		goto err;

	if (signature == GPT_SIGNATURE) {
		close(fd);
		return 0;
	}

	ret = detect_image_sector_size(fd, &image_sector_size);
	if (ret)
		goto err;

	if (image_sector_size == 0 ||
			(image_sector_size == sector_size)) {
		close(fd);
		return 0;
	}

	ploop_log(0, "GPT sector size incompatibility detected %d/%d",
			image_sector_size, sector_size);
	ret = update_gpt_partition(fd, device, 0, sector_size,
			image_sector_size, blocksize512);

err:
	close(fd);
	return ret;
}
