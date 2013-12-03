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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>
#include <stdlib.h>

#include "ploop.h"
#include "common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ploop check [options] DELTA | DiskDescriptor.xml\n"
"	DELTA := path to image file\n"
"	-f, --force          - force check even if dirty flag is clear\n"
"	-F, --hard-force     - -f and try to fix even fatal errors (dangerous)\n"
"	-c, --check          - check for duplicated blocks and holes\n"
"	-r, --ro             - do not modify DELTA (read-only access)\n"
"	-s, --silent         - be silent, report only errors\n"
"	-d, --drop-inuse     - drop image \"in use\" flag\n"
"	-R, --raw            - DELTA is a raw ploop image\n"
"	-b, --blocksize SIZE - cluster block size in sectors (for raw images)\n"
"	-S, --repair-sparse  - repair sparse image\n"
	);
}

int main(int argc, char ** argv)
{
	int i, idx;
	int flags = 0;
	int raw = 0;
	int ro = 0;	/* read-only access to image file */
	int silent = 0;	/* print messages only if errors detected */
	unsigned int blocksize = 0;
	char *endptr;
	static struct option options[] = {
		{"force", no_argument, NULL, 'f'},
		{"hard-force", no_argument, NULL, 'F'},
		{"check", no_argument, NULL, 'c'},
		{"drop-inuse", no_argument, NULL, 'd'},
		{"ro", no_argument, NULL, 'r'},
		{"silent", no_argument, NULL, 's'},
		{"raw", no_argument, NULL, 'R'},
		{"blocksize", required_argument, NULL, 'b'},
		{"repair-sparse", no_argument, NULL, 'S'},
		{ NULL, 0, NULL, 0 }
	};

	while ((i = getopt_long(argc, argv, "fFcrsdRbS", options, &idx)) != EOF) {
		switch (i) {
		case 'f':
			/* try to repair non-fatal conditions */
			flags |= CHECK_FORCE;
			break;
		case 'F':
			/* try to repair even fatal conditions */
			flags |= (CHECK_FORCE | CHECK_HARDFORCE);
			break;
		case 'c':
			/* build bitmap and check for duplicate blocks */
			flags |= CHECK_DETAILED;
			break;
		case 'd':
			flags |= CHECK_DROPINUSE;
			break;
		case 'r':
			ro = 1;
			break;
		case 'R':
			raw = 1;
			break;
		case 'b':
			blocksize = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				usage();
				return SYSEXIT_PARAM;
			}
			break;
		case 's':
			silent = 1;
			break;
		case 'S':
			flags |= CHECK_REPAIR_SPARSE;
			break;
		default:
			usage();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		return SYSEXIT_PARAM;
	}

	ploop_set_verbose_level(3);

	if (is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di;
		int ret;

		ret = read_dd(&di, argv[0]);
		if (ret)
			return ret;

		blocksize = di->blocksize;
		raw = (di->mode == PLOOP_RAW_MODE);

		for (i = 0; i < di->nimages; i++) {
			int delta_ro = 1; /* do read-only... */

			if (!guidcmp(di->images[i]->guid, di->top_guid))
				delta_ro = ro; /* except for top image */
			if (!silent)
				printf("Checking %s\n", di->images[i]->file);
			ret = ploop_check(di->images[i]->file, flags,
					delta_ro, raw, !silent, &blocksize);
			if (ret)
				goto err;
		}
err:
		ploop_free_diskdescriptor(di);

		return ret;
	}

	return ploop_check(argv[0], flags, ro, raw, !silent, &blocksize);
}
