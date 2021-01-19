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
#include <errno.h>

#include "ploop.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ploop shuffle [-n <num>] IMAGE\n");
	fprintf(stderr, "	ploop dup [-n num] IMAGE\n");
}

static int image_dup(const char *image, int n)
{
	int rc = 1, dirty, ndup = 0, cluster;
	unsigned int i, j, first = 0, l2_slot = 0;
	struct delta d;

	rc = open_delta(&d, image, O_RDWR, OD_ALLOW_DIRTY);
	if (rc)
		return rc;

	cluster = S2B(d.blocksize);
	for (i = 0; i < d.l1_size; i++) {
		int skip = (i == 0) ? sizeof(struct ploop_pvd_header) / sizeof(__u32) : 0;

		if (pread(d.fd, d.l2, cluster, (off_t)i * cluster) != cluster) {
			printf("pwrite: %m\n");
			goto err;
		}

		dirty = 0;
		for (j = skip; j < cluster/4; j++, l2_slot++) {
			if (d.l2[j] == 0)
				continue;
			if (first == 0) {
				first = d.l2[j];
				continue;
			}

			printf("Dup %d[%d]=%d\n", l2_slot, d.l2[j], first);
			d.l2[j] = first;
			ndup++;
			dirty = 1;
			if (n == ndup)
				break;
		}
		if (dirty) {
			if (pwrite(d.fd, d.l2, cluster,  (off_t)i * cluster) != cluster) {
				printf("pwrite: %m\n");
				goto err;
			}
		}
		if (n == ndup)
			break;
	}
	rc = 0;
err:
	return rc;
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
	else if (strcmp(cmd, "dup") == 0)
		return image_dup(argv[0], n);
	
	usage();
	return SYSEXIT_PARAM;

}
