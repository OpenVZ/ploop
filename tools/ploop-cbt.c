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
#include <sys/file.h>
#include <sys/mount.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>
#include <limits.h>

#include "ploop.h"
#include "cbt.h"
#include "common.h"

static void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop-cbt { dump | drop | show } DiskDescriptor.xml\n");

}

static int dump(int argc, char **argv)
{
	int ret, i;
	struct ploop_disk_images_data *di = NULL;
	const char *src = NULL, *dst = NULL;
	static struct option long_opts[] = {
		{ "src", required_argument, 0, 1 },
		{ "dst", required_argument, 0, 2 },
		{},
	};

	while ((i = getopt_long(argc, argv, "", long_opts, NULL)) != EOF) {
		switch (i) {
		case 1:
			src = optarg;
			break;
		case 2:
			dst = optarg;
			break;
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0 && src != NULL && dst != NULL)
		return ploop_move_cbt(dst, src);

	if (argc != 1 || !is_xml_fname(argv[0])) {
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_dump_cbt(di, dst);

	ploop_close_dd(di);

	return ret;
}

static int drop(int argc, char **argv)
{
	int ret;
	struct ploop_disk_images_data *di = NULL;

	argc--;
	argv++;
	if (argc != 1 || !is_xml_fname(argv[0])) {
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_drop_cbt(di);

	ploop_close_dd(di);

	return ret;
}

static int show(int argc, char **argv)
{
	int ret, i;
	struct ploop_disk_images_data *di = NULL;
	const char *fname = NULL;
	static struct option long_opts[] = {
		{ "image", required_argument, 0, 1 },
		{},
	};

	while ((i = getopt_long(argc, argv, "", long_opts, NULL)) != EOF) {
		switch (i) {
		case 1:
			fname = optarg;
			break;
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1 && is_xml_fname(argv[0])) {
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		ret = ploop_cbt_dump_info(di);

		ploop_close_dd(di);
	} else
		ret = ploop_cbt_dump_info_from_image(fname ?:argv[0]);

	return ret;
}

int main(int argc, char **argv)
{
	char *cmd;

	if (argc < 2) {
		usage_summary();
		return SYSEXIT_PARAM;
	}

	cmd = argv[1];
	argc--;
	argv++;

	init_signals();

	if (strcmp(cmd, "dump") == 0)
		return dump(argc, argv);
	if (strcmp(cmd, "drop") == 0)
		return drop(argc, argv);
	if (strcmp(cmd, "show") == 0)
		return show(argc, argv);



	usage_summary();

	return SYSEXIT_PARAM;
}
