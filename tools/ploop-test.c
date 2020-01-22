/*
 *  Copyright (c) 2020 Virtuozzo International GmbH. All rights reserved.
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
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#include "ploop.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ploop MODE IMAGE\n");
}

int main(int argc, char **argv)
{
	int n = 1, i;
	const char *cmd;


	cmd = argv[1];
	argc--;
	argv++;

	while ((i = getopt(argc, argv, "n:")) != EOF) {
		switch (i) {
		case 'n':
			n = atoi(optarg);
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
	if (strcmp(cmd, "shuffle") == 0)
		return ploop_image_shuffle(argv[0], n, 0);
	
	usage();
	return SYSEXIT_PARAM;

}
