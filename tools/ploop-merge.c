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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"
#include "common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ploop merge -d DEVICE [-l LEVEL[..TOP_LEVEL]]\n"
			"       ploop merge [-f raw] DELTAS_TO_MERGE BASE_DELTA\n"
			"       ploop merge [-u <uuid> | -A] DiskDescriptor.xml\n");
}

int plooptool_merge(int argc, char ** argv)
{
	int raw = 0;
	int start_level = 0;
	int end_level = 0;
	int merge_top = 0;
	char *device = NULL;
	char **names = NULL;
	int i, f, ret;
	struct ploop_merge_param param = {};

	while ((i = getopt(argc, argv, "f:d:l:u:A")) != EOF) {
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
		case 'l':
			if (sscanf(optarg, "%d..%d", &start_level, &end_level) != 2) {
				if (sscanf(optarg, "%d", &start_level) != 1) {
					usage();
					return SYSEXIT_PARAM;
				}
				end_level = start_level + 1;
			}
			if (start_level >= end_level || start_level < 0) {
				usage();
				return SYSEXIT_PARAM;
			}
			break;
		case 'u':
			param.guid = parse_uuid(optarg);
			if (!param.guid)
				return SYSEXIT_PARAM;
			break;
		case 'A':
			param.merge_all = 1;
			break;
		default:
			usage();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1 && is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di;

		if (param.guid != NULL && param.merge_all != 0) {
			fprintf(stderr, "Options -u and -A can't be used together\n");
			usage();
			return SYSEXIT_PARAM;
		}

		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;
		ret = ploop_merge_snapshot(di, &param);
		ploop_close_dd(di);
	} else {
		if (device == NULL) {
			if (argc < 2) {
				usage();
				return SYSEXIT_PARAM;
			}
			end_level = argc;
			names = argv;
		} else {
			struct merge_info info = {};

			if (argc || raw) {
				usage();
				return SYSEXIT_PARAM;
			}

			info.start_level = start_level;
			info.end_level = end_level;
			if ((ret = get_delta_info(device, &info)))
				return ret;
			start_level = info.start_level;
			end_level = info.end_level;
			raw = info.raw;
			names = info.names;
			merge_top = info.merge_top;
		}

		ret = merge_image(device, start_level, end_level, raw, merge_top, names);
	}

	return ret;
}
