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
#include "common.h"

static char  *device;	   /* ploop device name (e.g. /dev/ploop0) */
static char  *mount_point;
static char  *disk_descriptor;
static int    force;	   /* do not flock hidden balloon */

#define GET_DD(argc, argv)					\
	do {							\
		if (argc == 1 && is_xml_fname(argv[0])) {	\
			disk_descriptor = argv[0];		\
			argc--; argv++;				\
		}						\
	} while (0)

static int fill_opts(void)
{
	static char _device[PATH_MAX];
	static char _mount_point[PATH_MAX];

	if (device && mount_point)
		return 0;

	if (disk_descriptor) {
		int ret;
		struct ploop_disk_images_data *di;

		ret = ploop_open_dd(&di, disk_descriptor);
		if (ret)
			return ret;

		ret = ploop_get_dev(di, _device, sizeof(_device));
		ploop_close_dd(di);
		if (ret < 0)
			return SYSEXIT_PARAM;

		if (ret == 1) {
			fprintf(stderr, "The image is not mounted\n");
			return SYSEXIT_PARAM;
		}

		device = _device;
	}

	if (!device && mount_point) {
		if (ploop_get_dev_by_mnt(mount_point, _device, sizeof(_device))) {
			fprintf(stderr, "Unable to find ploop device by %s\n", mount_point);
			return SYSEXIT_PARAM;
		}
		device = _device;
		return 0;
	}

	if (!mount_point && device) {
		if (ploop_get_mnt_by_dev(device, _mount_point, sizeof(_mount_point))) {
			fprintf(stderr, "Unable to find mount point for %s\n", device);
			return SYSEXIT_PARAM;
		}
		mount_point = _mount_point;
		return 0;
	}

	fprintf(stderr, "Error: one of -d, -m or DiskDescriptor.xml argument is required\n");
	return 1;
}

static void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop-balloon { show | status | clear | change | complete | check | repair | discard } ...\n"
			"Use \"ploop-balloon cmd\" to get more info about cmd\n"
		);
}

static void usage_show(void)
{
	fprintf(stderr, "Usage: ploop-balloon show [-f] {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"	-f	    - do not flock hidden balloon\n"
			"Action: show current ploop balloon size\n"
		);
}

static int pb_show(int argc, char **argv)
{
	int i, ret;
	struct stat st;

	while ((i = getopt(argc, argv, "fd:m:")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
			break;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_show();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	GET_DD(argc, argv);
	if (argc != 0 || fill_opts()) {
		usage_show();
		return SYSEXIT_PARAM;
	}

	ret = get_balloon(mount_point, &st, NULL);
	if (ret)
		return ret;
	fprintf(stdout, "Current size of hidden balloon is %llu bytes\n",
		(unsigned long long) st.st_size);
	return 0;
}

static void usage_status(void)
{
	fprintf(stderr, "Usage: ploop-balloon status [-f] {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"	-f	    - do not flock hidden balloon\n"
			"Action: inquire current in-kernel status of maintenance\n"
		);
}

static int pb_status(int argc, char **argv)
{
	int i, ret;
	__u32 state;

	while ((i = getopt(argc, argv, "fd:m:")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
			break;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_status();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	GET_DD(argc, argv);
	if (argc != 0 || fill_opts()) {
		usage_status();
		return SYSEXIT_PARAM;
	}

	ret = ploop_balloon_get_state(device, &state);
	if (ret)
		return ret;

	fprintf(stdout, "Current state of in-kernel maintenance: %s\n",
			mntn2str(state));
	return 0;
}

static void usage_clear(void)
{
	fprintf(stderr, "Usage: ploop-balloon clear {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: clear stale in-kernel \"BALLOON\" state of maintenance\n"
		);
}

static int pb_clear(int argc, char **argv)
{
	int i, ret;
	int fd2;

	while ((i = getopt(argc, argv, "d:m:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_clear();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	GET_DD(argc, argv);
	if (argc != 0 || fill_opts()) {
		usage_clear();
		return SYSEXIT_PARAM;
	}

	ret = get_balloon(mount_point, NULL, &fd2);
	if (ret)
		return ret;

	ret = ploop_balloon_clear_state(device);
	if (ret)
		return ret;
	fprintf(stdout, "Current state of in-kernel maintenance is OFF now\n");
	return 0;
}

static void usage_change(void)
{
	fprintf(stderr, "Usage: ploop-balloon change -s SIZE {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	SIZE	    := NUMBER[kmg] (new size of balloon)\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: inflate or truncate hidden balloon (dependently on new_size vs. old_size)\n"
		);
}

static int pb_change(int argc, char **argv)
{
	int    fd;
	int    i, ret;
	off_t  new_size = 0;
	int    new_size_set = 0;

	while ((i = getopt(argc, argv, "s:d:m:")) != EOF) {
		switch (i) {
		case 's':
			/* NB: currently, new_size is in 'sector' units */
			if (parse_size(optarg, &new_size, "-s")) {
				usage_change();
				return SYSEXIT_PARAM;
			}
			new_size_set++;
			break;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_change();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	GET_DD(argc, argv);
	if (argc != 0 || !new_size_set || fill_opts()) {
		usage_change();
		return SYSEXIT_PARAM;
	}
	ret = get_balloon(mount_point, NULL, &fd);
	if (ret)
		return ret;

	return ploop_balloon_change_size(device, fd, new_size);
}

static void usage_complete(void)
{
	fprintf(stderr, "Usage: ploop-balloon complete {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: complete previously interrupted balloon operation\n"
			"	 (sensible only if kernel is in \"FBLOAD\" or \"RELOC\"\n"
			"	  state of maintenance)\n"
		);
}

static int pb_complete(int argc, char **argv)
{
	int i, ret, fd;

	while ((i = getopt(argc, argv, "d:m:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_complete();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	GET_DD(argc, argv);
	if (argc != 0 || fill_opts()) {
		usage_complete();
		return SYSEXIT_PARAM;
	}

	ret = get_balloon(mount_point, NULL, &fd);
	if (ret)
		return ret;

	return ploop_balloon_complete(device);
}

static void usage_check(void)
{
	fprintf(stderr, "Usage: ploop-balloon check {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: check whether hidden balloon has free blocks\n"
		);
}

static void usage_repair(void)
{
	fprintf(stderr, "Usage: ploop-balloon repair {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"	DEVICE	    := ploop device, e.g. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: repair hidden balloon (i.e. relocate all free blocks\n"
			"	 present in hidden balloon (w/o inflate))\n"
		);
}

static int pb_check_and_repair(int argc, char **argv, int repair)
{
	int i;

	while ((i = getopt(argc, argv, "fd:m:")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
			break;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			if (repair)
				usage_repair();
			else
				usage_check();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	GET_DD(argc, argv);
	if (argc != 0 || fill_opts()) {
		if (repair)
			usage_repair();
		else
			usage_check();
		return SYSEXIT_PARAM;
	}

	return ploop_balloon_check_and_repair(device, mount_point, repair);

}

static void usage_discard(void)
{
	fprintf(stderr, "Usage: ploop-balloon discard {-d DEVICE | -m MOUNT_POINT | DiskDescriptor.xml}\n"
			"                     { [--automount] [--to-free SIZE] [--min-block MIN_SIZE]\n"
			"                       [--defrag] | [--stat] }\n"
			"       DEVICE      := ploop device, e.g. /dev/ploop0\n"
			"       MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"       SIZE        := NUMBER[KMGT] (maximum space to free)\n"
			"       MIN_SIZE    := NUMBER[KMGT] (minimum size of a linear slice to be freed)\n"
			"Action: discard unused blocks from the image.\n"
		);
}

static void print_discard_stat(struct ploop_discard_stat *stat)
{
	fprintf(stdout, "Balloon size: %8lluMB\n",
			(unsigned long long)stat->balloon_size >> 20);
	fprintf(stdout, "Data size:    %8lluMB\n",
			(unsigned long long)stat->data_size >> 20);
	fprintf(stdout, "Ploop size:   %8lluMB\n",
			(unsigned long long)stat->ploop_size >> 20);
	fprintf(stdout, "Image size:   %8lluMB\n",
			(unsigned long long)stat->image_size >> 20);
}

static int pb_discard(int argc, char **argv)
{
	int ret, i;
	off_t val;
	int stat = 0;
	static struct option long_opts[] = {
		{ "to-free", required_argument, 0, 666 },
		{ "min-block", required_argument, 0, 667 },
		{ "stat", no_argument, 0, 668 },
		{ "automount", no_argument, 0, 669 },
		{ "defrag", no_argument, 0, 670 },
		{},
	};
	struct ploop_disk_images_data *di = NULL;
	struct ploop_discard_param param = {};

	while ((i = getopt_long(argc, argv, "d:m:", long_opts, NULL)) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		case 666:
			if (parse_size(optarg, &val, "--to-free")) {
				usage_discard();
				return SYSEXIT_PARAM;
			}
			param.to_free = S2B(val);
			break;
		case 667:
			if (parse_size(optarg, &val, "--min-block")) {
				usage_discard();
				return SYSEXIT_PARAM;
			}
			param.minlen_b = S2B(val);
			break;
		case 668:
			stat = 1;
			break;
		case 669:
			param.automount = 1;
			break;
		case 670:
			param.defrag = 1;
			break;
		default:
			usage_discard();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1 && is_xml_fname(argv[0])) {
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		argc--;
		argv++;
	}

	if (argc != 0 || (di != NULL && (device || mount_point)) ||
			(di == NULL && fill_opts())) {
		usage_discard();

		if (di)
			ploop_close_dd(di);

		return 1;
	}

	if (stat) {
		struct ploop_discard_stat d_stat;

		if (di)
			ret = ploop_discard_get_stat(di, &d_stat);
		else
			ret = ploop_discard_get_stat_by_dev(device, mount_point, &d_stat);

		if (ret == 0)
			print_discard_stat(&d_stat);
	} else {
		if (di)
			ret = ploop_discard(di, &param);
		else
			ret = ploop_discard_by_dev(device, mount_point,
					param.minlen_b, param.to_free, NULL);
	}

	if (di)
		ploop_close_dd(di);

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

	ploop_set_verbose_level(3);
	init_signals();

	if (strcmp(cmd, "show") == 0)
		return pb_show(argc, argv);
	if (strcmp(cmd, "status") == 0)
		return pb_status(argc, argv);
	if (strcmp(cmd, "clear") == 0)
		return pb_clear(argc, argv);
	if (strcmp(cmd, "change") == 0)
		return pb_change(argc, argv);
	if (strcmp(cmd, "complete") == 0)
		return pb_complete(argc, argv);
	if (strcmp(cmd, "check") == 0)
		return pb_check_and_repair(argc, argv, 0); /* check only */
	if (strcmp(cmd, "repair") == 0)
		return pb_check_and_repair(argc, argv, 1); /* check and repair */
	if (strcmp(cmd, "discard") == 0)
		return pb_discard(argc, argv);

	usage_summary();
	return SYSEXIT_PARAM;
}
