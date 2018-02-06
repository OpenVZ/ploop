/*
 *  Copyright (c) 2008-2017 Parallels International GmbH.
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


static void usage(void)
{
	fprintf(stderr, "Usage: ploop grow -s NEW_SIZE -d DEVICE\n"
			"       ploop grow -s NEW_SIZE [-f raw] DELTA\n"
			"       ploop grow -s NEW_SIZE [--sparse] DiskDescriptor.xml\n"
		);
}

int plooptool_grow(int argc, char **argv)
{
	int i, f;
	off_t new_size = 0; /* in sectors */
	int raw = 0, sparse = 0;
	char *device = NULL;
	static struct option long_opts[] = {
		{ "sparse", no_argument, 0, 'S' },
		{},
	};

	while ((i = getopt_long(argc, argv, "f:d:s:S", long_opts, NULL)) != EOF) {
		switch (i) {
		case 'f':
			f = parse_format_opt(optarg);
			if (f < 0) {
				usage();
				return SYSEXIT_PARAM;
			}
			raw = (f == PLOOP_RAW_MODE);
			break;
		case 'd':
			device = optarg;
			break;
		case 'S':
			sparse = 1;
			break;
		case 's':
			if (parse_size(optarg, &new_size, "-s")) {
				usage();
				return SYSEXIT_PARAM;
			}
			break;
		default:
			usage();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (((argc != 0 || !device) && (argc != 1 || device)) ||
	    (raw && device) || (new_size == 0)) {
		usage();
		return SYSEXIT_PARAM;
	}

	if (argc == 1 && is_xml_fname(argv[0]))
	{
		int ret;

		struct ploop_disk_images_data *di;
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		ret = ploop_grow_image(di, new_size, sparse);
		ploop_close_dd(di);

		return ret;
	}
	else if (device)
		return ploop_grow_device(device, new_size);
	else if (raw)
		return ploop_grow_raw_delta_offline(argv[0], new_size, sparse);
	else
		return ploop_grow_delta_offline(argv[0], new_size);
}
