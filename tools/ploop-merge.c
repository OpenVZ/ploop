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
	fprintf(stderr, "Usage: ploop merge -d DEVICE [-l LEVEL[..TOP_LEVEL]] [-n NEW_DELTA]\n"
			"       ploop merge [-f raw] [-n NEW_DELTA] DELTAS_TO_MERGE BASE_DELTA\n"
	       );
}

int plooptool_merge(int argc, char ** argv)
{
	int raw = 0;
	int start_level = 0;
	int end_level = 0;
	int merge_top = 0;
	char *device = NULL;
	char **names = NULL;
	const char *new_delta = NULL;
	int i, f, ret;
	int is_dm = ploop_is_devicemapper();

	while ((i = getopt(argc, argv, "f:d:l:n:u:A")) != EOF) {
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
		case 'n':
			new_delta = optarg;
			break;
		case 'u':
		case 'A':
			/* ignore */
			break;
		default:
			usage();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1 && is_xml_fname(argv[0])) {
		fprintf(stderr, "Please use ploop snapshot-merge command\n");
		return SYSEXIT_PARAM;
	} else {
		if (device == NULL) {
			if (argc < 2) {
				usage();
				return SYSEXIT_PARAM;
			}
			end_level = argc;
			names = argv;
		} else {
#if 0
			char *f;
			int blocksize;
			if (argc || raw) {
				usage();
				return SYSEXIT_PARAM;
			}

			if ((ret = get_delta_names(device, &names, &f, &blocksize)))
				return ret;
			merge_top = get_list_size(names) == start_level;
#endif
		}

		if (is_dm && !qcow_check_valid_images(argv, argc)) {
			/* we only support backward merge all */
			// need to reload with last two deltas writeable otherwise we get EACCESS
			int ret;
			struct ploop_disk_images_data *di;
			ret = ploop_make_dd_from_imgs(&di, argv);
			if (ret)
				return ret;

			ret = ploop_dmreplace_qcow(di, NULL, device, RELOAD_RW2);
			if (!ret)
				ret = merge_qcow2_backward(device);

			ploop_close_dd(di);

			return ret;

		} else {
			ret = merge_image(device, start_level, end_level, raw, merge_top, names, new_delta);
		}
	}

	return ret;
}
