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
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"
#include "common.h"

static int raw;
static struct delta delta;
static struct ploop_pvd_header new_vh;
static char *device;

static void usage(char *pname)
{
	fprintf(stderr, "Usage: %s [-s NEW_SIZE] -d DEVICE\n"
		        "       %s [-s NEW_SIZE] [-f raw] DELTA\n",
		pname, pname);
}

static int grow_raw_device_offline(const char *image, off_t new_size)
{
	int ret;
	off_t old_size;

	ret = read_size_from_image(image, 1, &old_size);
	if (ret)
		return ret;

	if (!new_size) {
		printf("%s size is %llu sectors\n",
			image, (unsigned long long)old_size);
		return 0;
	}

	new_size = (new_size + (4096 >> 9) - 1) & ~((4096 >> 9) - 1);

	if (new_size == old_size)
		return 0;

	if (new_size < old_size) {
		fprintf(stderr, "Use truncate(1) for offline truncate "
			"of raw delta\n");
		return -1;
	} else {
		grow_raw_delta(image, (new_size - old_size) << 9);
	}

	return 0;
}

static int grow_delta_offline(char *image, off_t new_size)
{
	off_t old_size;
	struct ploop_pvd_header *vh;
	void *buf;

	if (open_delta(&delta, image, new_size ? O_RDWR : O_RDONLY, OD_OFFLINE)) {
		perror("open_delta");
		return SYSEXIT_OPEN;
	}

	vh = (struct ploop_pvd_header *)delta.hdr0;
	old_size = vh->m_SizeInSectors;

	if (!new_size) {
		printf("%s size is %llu sectors\n",
			image, (unsigned long long)old_size);
		return 0;
	}

	generate_pvd_header(&new_vh, new_size, delta.blocksize);

	if (new_vh.m_SizeInSectors == old_size)
		return 0;

	if (new_vh.m_SizeInSectors < old_size) {
		fprintf(stderr, "Error: new size is less than the old size\n");
		return -1;
	}

	if (dirty_delta(&delta)) {
		perror("dirty_delta");
		return SYSEXIT_WRITE;
	}

	if (posix_memalign(&buf, 4096, S2B(delta.blocksize)))
		return -1;

	grow_delta(&delta, new_vh.m_SizeInSectors, buf, NULL);

	if (clear_delta(&delta)) {
		perror("clear_delta");
		exit(SYSEXIT_WRITE);
	}

	if (fsync(delta.fd)) {
		perror("fsync");
		exit(SYSEXIT_FSYNC);
	}
	return 0;
}

int
main(int argc, char ** argv)
{
	char *pname = argv[0];
	int i, f;
	off_t new_size = 0; /* in sectors */

	while ((i = getopt(argc, argv, "f:d:s:")) != EOF) {
		switch (i) {
		case 'f':
			f = parse_format_opt(optarg);
			if (f < 0) {
				usage(pname);
				return -1;
			}
			raw = (f == PLOOP_RAW_MODE);
			break;
		case 'd':
			device = optarg;
			break;
		case 's':
			if (parse_size(optarg, &new_size)) {
				usage(pname);
				return -1;
			}
			break;
		default:
			usage(pname);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (((argc != 0 || !device) && (argc != 1 || device)) ||
	    (raw && device)) {
		usage(pname);
		return -1;
	}

	ploop_set_verbose_level(3);

	if (device) {
		__u32 blocksize = 0;

		if (ploop_get_attr(device, "block_size", (int*) &blocksize))
			return 1;
		return ploop_grow_device(device, blocksize, new_size);
	}
	else if (raw)
		return grow_raw_device_offline(argv[0], new_size);
	else
		return grow_delta_offline(argv[0], new_size);

	return 0;
}
