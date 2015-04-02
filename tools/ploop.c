/*
 *  Copyright (C) 2008-2015, Parallels, Inc. All rights reserved.
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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <getopt.h>

#include "ploop.h"
#include "common.h"

extern int plooptool_snapshot_list(int argc, char **argv);
extern int plooptool_check(int argc, char **argv);
extern int plooptool_grow(int argc, char **argv);
extern int plooptool_merge(int argc, char ** argv);
extern int plooptool_stat(int argc, char ** argv);
extern int plooptool_copy(int argc, char ** argv);

#define USAGE_FORMATS	"{ raw | ploop1 | expanded | preallocated }"
#define USAGE_VERSIONS	"{ 1 | 2 } (default 2, if supported)"

static void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop init -s SIZE [-f FORMAT] NEW_DELTA\n"
			"       ploop mount [-r] [-m DIR] DiskDescriptor.xml\n"
			"       ploop umount { -d DEVICE | -m DIR | DELTA | DiskDescriptor.xml }\n"
			"       ploop check [-fFcrsdS] [-R -b BLOCKSIZE] { DELTA | DiskDescriptor.xml }\n"
			"       ploop convert [-f FORMAT] [-v VERSION] DiskDescriptor.xml\n"
			"       ploop resize -s SIZE DiskDescriptor.xml\n"
			"       ploop balloon { show | status | clear | change | complete | check |\n"
			"                       repair | discard } ... DiskDescriptor.xml\n"
			"       ploop snapshot DiskDescriptor.xml\n"
			"       ploop snapshot-delete -u UUID DiskDescriptor.xml\n"
			"       ploop snapshot-merge [-u UUID] DiskDescriptor.xml\n"
			"       ploop snapshot-switch -u UUID DiskDescriptor.xml\n"
			"       ploop snapshot-list [-o field[,field...]] [-u UUID] DiskDescriptor.xml\n"
			"Also:  ploop { start | stop | delete | clear | merge | grow | copy |\n"
			"               stat | info | list} ...\n"
			"\n"
			"       ploop <command> -- to get detailed syntax for a specific command\n"
		);
}

static void usage_init(void)
{
	fprintf(stderr,
"Usage: ploop init -s SIZE [-f FORMAT] [-v VERSION] [-t FSTYPE]\n"
"                 [-b BLOCKSIZE] [-B FSBLOCKSIZE] DELTA\n"
"\n"
"       SIZE        := NUMBER[KMGT]\n"
"       FORMAT      := " USAGE_FORMATS "\n"
"       VERSION     := " USAGE_VERSIONS "\n"
"       FSTYPE      := { none | ext3 | ext4 } (create filesystem, default ext4)\n"
"       BLOCKSIZE   := cluster block size, sectors\n"
"       FSBLOCKSIZE := file system block size, bytes\n"
"       DELTA       := path to a new image file\n"
	);
}

static int parse_version_opt(const char *arg)
{
	if (!strcmp(arg, "1"))
		return PLOOP_FMT_V1;
	else if (!strcmp(arg, "2"))
		return PLOOP_FMT_V2;

	fprintf(stderr, "Invalid -v argument: %s\n", arg);
	return -1;
}

static int plooptool_init(int argc, char **argv)
{
	int i, f, ret;
	off_t size_sec = 0;
	char * endptr;
	struct ploop_create_param param = {
		.fstype		= "ext4",
		.mode		= PLOOP_EXPANDED_MODE,
		.fmt_version	= PLOOP_FMT_UNDEFINED,
	};

	while ((i = getopt(argc, argv, "s:b:B:f:t:v:")) != EOF) {
		switch (i) {
		case 's':
			if (parse_size(optarg, &size_sec, "-s")) {
				usage_init();
				return SYSEXIT_PARAM;
			}
			break;
		case 'b':
			  param.blocksize = strtoul(optarg, &endptr, 0);
			  if (*endptr != '\0') {
				  usage_init();
				  return SYSEXIT_PARAM;
			  }
			  break;
		case 'B' :
			  param.fsblocksize = strtoul(optarg, &endptr, 0);
			  if (*endptr != '\0') {
				  usage_init();
				  return SYSEXIT_PARAM;
			  }
			  break;
		case 'f':
			f = parse_format_opt(optarg);
			if (f < 0) {
				usage_init();
				return SYSEXIT_PARAM;
			}
			param.mode = f;
			break;
		case 't':
			if (!strcmp(optarg, "none"))
				param.fstype = NULL;
			else if (!strcmp(optarg, "ext4") ||
					!strcmp(optarg, "ext3")) {
				param.fstype = strdup(optarg);
			} else {
				fprintf(stderr, "Incorrect file system type "
						"specified: %s\n", optarg);
				return SYSEXIT_PARAM;
			}
			break;
		case 'v':
			f = parse_version_opt(optarg);
			if (f < 0) {
				usage_init();
				return SYSEXIT_PARAM;
			}
			param.fmt_version = f;
			break;
		default:
			usage_init();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || size_sec == 0) {
		usage_init();
		return SYSEXIT_PARAM;
	}
	param.size = (__u64) size_sec;
	param.image = argv[0];
	ret = ploop_create_image(&param);
	if (ret)
		return ret;

	return 0;
}

static void usage_mount(void)
{
	fprintf(stderr, "Usage: ploop mount [-r] [-f FORMAT] [-b BLOCKSIZE] [-d DEVICE]\n"
			"             [-m MOUNT_POINT] [-t FSTYPE] [-o MOUNT_OPTS]\n"
			"             BASE_DELTA [ ... TOP_DELTA ]\n"
			"       ploop mount [-r] [-m MOUNT_POINT] [-u UUID] DiskDescriptor.xml\n"
			"       FORMAT := { raw | ploop1 }\n"
			"       BLOCKSIZE := block size (for raw image format)\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			"       MOUNT_POINT := directory to mount in-image filesystem to\n"
			"       FSTYPE := in-image filesystem type (ext4 by default)\n"
			"       MOUNT_OPTS := additional mount options, comma-separated\n"
			"       *DELTA := path to image file\n"
			"       -r     - mount images read-only\n"
			"       -F     - run fsck on inner filesystem before mounting it\n"
		);
}

static int plooptool_mount(int argc, char **argv)
{
	int i, f, ret = 0;
	int raw = 0;
	struct ploop_mount_param mountopts = {};
	const char *component_name = NULL;

	while ((i = getopt(argc, argv, "rFf:d:m:t:u:o:b:c:")) != EOF) {
		switch (i) {
		case 'd':
			strncpy(mountopts.device, optarg, sizeof(mountopts.device)-1);
			break;
		case 'r':
			mountopts.ro = 1;
			break;
		case 'F':
			mountopts.fsck = 1;
			break;
		case 'f':
			f = parse_format_opt(optarg);
			if (f < 0) {
				usage_mount();
				return SYSEXIT_PARAM;
			}
			raw = (f == PLOOP_RAW_MODE);
			break;
		case 'm':
			mountopts.target = strdup(optarg);
			break;
		case 't':
			mountopts.fstype = strdup(optarg);
			break;
		case 'u':
			mountopts.guid = parse_uuid(optarg);
			if (!mountopts.guid)
				return SYSEXIT_PARAM;

			break;
		case 'o':
			mountopts.mount_data = strdup(optarg);
			break;
		case 'b': {
			  char * endptr;

			  mountopts.blocksize = strtoul(optarg, &endptr, 0);
			  if (*endptr != '\0') {
				  usage_mount();
				  return SYSEXIT_PARAM;
			  }
			  break;
		case 'c':
			component_name = optarg;
			break;
		}
		default:
			usage_mount();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage_mount();
		return SYSEXIT_PARAM;
	}

	if (argc == 1 && is_xml_fname(argv[0]))
	{
		struct ploop_disk_images_data *di;
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		if (component_name != NULL)
			ploop_set_component_name(di, component_name);

		ret = ploop_mount_image(di, &mountopts);

		ploop_close_dd(di);
	}
	else
		ret = ploop_mount(NULL, argv, &mountopts, raw);

	return ret;
}

static void usage_start(void)
{
	fprintf(stderr, "Usage: ploop start -d DEVICE\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			);
}

static int plooptool_start(int argc, char **argv)
{
	int i;
	int lfd;
	struct {
		char * device;
	} startopts = { };

	while ((i = getopt(argc, argv, "d:")) != EOF) {
		switch (i) {
		case 'd':
			startopts.device = optarg;
			break;
		default:
			usage_start();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc || !startopts.device) {
		usage_start();
		return SYSEXIT_PARAM;
	}

	lfd = open(startopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, PLOOP_IOC_START, 0) < 0) {
		perror("PLOOP_IOC_START");
		close(lfd);
		return SYSEXIT_DEVIOC;
	}

	if (ioctl(lfd, BLKRRPART, 0) < 0) {
		perror("BLKRRPART");
	}

	close(lfd);
	return 0;
}

static void usage_stop(void)
{
	fprintf(stderr, "Usage: ploop stop -d DEVICE\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n");
}

static int plooptool_stop(int argc, char **argv)
{
	int i;
	int lfd;
	struct {
		char * device;
	} stopopts = { };

	while ((i = getopt(argc, argv, "d:")) != EOF) {
		switch (i) {
		case 'd':
			stopopts.device = optarg;
			break;
		default:
			usage_stop();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc || !stopopts.device) {
		usage_stop();
		return SYSEXIT_PARAM;
	}

	lfd = open(stopopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, PLOOP_IOC_STOP, 0) < 0) {
		perror("PLOOP_IOC_STOP");
		close(lfd);
		return SYSEXIT_DEVIOC;
	}

	close(lfd);
	return 0;
}

static void usage_clear(void)
{
	fprintf(stderr, "Usage: ploop clear -d DEVICE\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n");
}

static int plooptool_clear(int argc, char **argv)
{
	int i;
	int lfd;
	struct {
		char * device;
	} stopopts = { };

	while ((i = getopt(argc, argv, "d:")) != EOF) {
		switch (i) {
		case 'd':
			stopopts.device = optarg;
			break;
		default:
			usage_clear();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc || !stopopts.device) {
		usage_clear();
		return SYSEXIT_PARAM;
	}

	lfd = open(stopopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, PLOOP_IOC_CLEAR, 0) < 0) {
		perror("PLOOP_IOC_CLEAR");
		close(lfd);
		return SYSEXIT_DEVIOC;
	}

	close(lfd);
	return 0;
}

static void usage_umount(void)
{
	fprintf(stderr, "Usage: ploop umount -d DEVICE\n"
			"       ploop umount -m DIR\n"
			"       ploop umount DiskDescriptor.xml\n"
			"       ploop umount DELTA\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			"       DIR := mount point\n"
			"       DELTA := path to (mounted) image file\n");
}

static int plooptool_umount(int argc, char **argv)
{
	int i, ret;
	char *mnt = NULL;
	char device[PATH_MAX];
	struct {
		char * device;
	} umountopts = { };
	const char *component_name = NULL;

	while ((i = getopt(argc, argv, "d:m:c:")) != EOF) {
		switch (i) {
		case 'd':
			umountopts.device = optarg;
			break;
		case 'm':
			mnt = optarg;
			break;
		case 'c':
			component_name = optarg;
			break;
		default:
			usage_umount();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 && !umountopts.device && !mnt) {
		usage_umount();
		return SYSEXIT_PARAM;
	}

	if (umountopts.device != NULL) {
		int len = strlen(umountopts.device);

		/* if partition is provided, strip it */
		if (strcmp(umountopts.device + len - 2, "p1") == 0 &&
				isdigit(umountopts.device[len - 3]))
			umountopts.device[len - 2] = '\0';

		ret = ploop_umount(umountopts.device, NULL);
	}else if (mnt != NULL) {
		if (ploop_get_dev_by_mnt(mnt, device, sizeof(device))) {
			fprintf(stderr, "Unable to find ploop device by %s\n",
					mnt);
			return SYSEXIT_PARAM;
		}
		ret = ploop_umount(device, NULL);
	} else if (is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di;
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		if (component_name != NULL)
			ploop_set_component_name(di, component_name);

		ret = ploop_umount_image(di);

		ploop_close_dd(di);
	} else {
		if (ploop_find_dev(component_name, argv[0], device, sizeof(device)) != 0) {
			fprintf(stderr, "Image %s is not mounted\n", argv[0]);
			return SYSEXIT_PARAM;
		}
		ret = ploop_umount(device, NULL);
	}

	return ret;
}

static void usage_rm(void)
{
	fprintf(stderr, "Usage: ploop { delete | rm } -d DEVICE -l LEVEL\n"
			"       LEVEL := NUMBER, distance from base delta\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n");
}

static int plooptool_rm(int argc, char **argv)
{
	int i;
	int lfd;
	__u32 level;

	struct {
		int level;
		char * device;
	} rmopts = { .level = -1, };

	while ((i = getopt(argc, argv, "d:l:")) != EOF) {
		switch (i) {
		case 'd':
			rmopts.device = optarg;
			break;
		case 'l':
			rmopts.level = atoi(optarg);
			break;
		default:
			usage_rm();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc || !rmopts.device || rmopts.level < 0 || rmopts.level > 127) {
		usage_rm();
		return SYSEXIT_PARAM;
	}

	lfd = open(rmopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	level = rmopts.level;
	if (ioctl(lfd, PLOOP_IOC_DEL_DELTA, &level) < 0) {
		perror("PLOOP_IOC_DEL_DELTA");
		close(lfd);
		return SYSEXIT_DEVIOC;
	}

	close(lfd);
	return 0;
}

static void usage_snapshot(void)
{
	fprintf(stderr, "Usage: ploop snapshot [-u UUID] DiskDescriptor.xml\n"
			"       ploop snapshot [-F] -d DEVICE DELTA\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			"       DELTA := path to new image file\n"
			"       -F     - synchronize file system before taking snapshot\n"
		);
}

static int plooptool_snapshot(int argc, char **argv)
{
	int i, ret;
	char *device = NULL;
	int syncfs = 0;
	struct ploop_snapshot_param param = {};

	while ((i = getopt(argc, argv, "Fd:u:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'F':
			syncfs = 1;
			break;
		case 'u':
			param.guid = parse_uuid(optarg);
			if (!param.guid)
				return SYSEXIT_PARAM;
			break;
		default:
			usage_snapshot();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_snapshot();
		return SYSEXIT_PARAM;
	}

	if (is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di;
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		ret = ploop_create_snapshot(di, &param);

		ploop_close_dd(di);
	} else {
		if (!device) {
			usage_snapshot();
			return SYSEXIT_PARAM;
		}
		ret = create_snapshot(device, argv[0], syncfs);
	}

	return ret;
}

static void usage_tsnapshot(void)
{
	fprintf(stderr, "Usage: ploop tsnapshot -u UUID -c COMPONENT\n"
			"       [-m MOUNT_POINT] DiskDescriptor.xml\n"
		);
}

static int plooptool_tsnapshot(int argc, char **argv)
{
	int i, ret;
	struct ploop_disk_images_data *di;
	struct ploop_tsnapshot_param param = {};

	while ((i = getopt(argc, argv, "u:c:m:")) != EOF) {
		switch (i) {
		case 'u':
			param.guid = parse_uuid(optarg);
			if (!param.guid)
				return SYSEXIT_PARAM;
			break;
		case 'c':
			param.component_name = optarg;
			break;
		case 'm':
			param.target = optarg;
			break;
		default:
			usage_tsnapshot();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || !is_xml_fname(argv[0]) ||
			param.guid == NULL ||
			param.component_name == NULL) {
		usage_tsnapshot();
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_create_temporary_snapshot(di, &param, NULL);

	ploop_close_dd(di);

	return ret;
}

static void usage_snapshot_switch(void)
{
	fprintf(stderr, "Usage: ploop snapshot-switch -u UUID DiskDescriptor.xml\n"
			"       UUID := snapshot UUID\n");
}

static int plooptool_snapshot_switch(int argc, char **argv)
{
	int i, ret;
	char *uuid = NULL;
	int flags = 0;
	struct ploop_disk_images_data *di = NULL;

	while ((i = getopt(argc, argv, "u:D")) != EOF) {
		switch (i) {
		case 'u':
			uuid = parse_uuid(optarg);
			if (!uuid)
				return SYSEXIT_PARAM;
			break;
		case 'D':
			/* for test purposes */
			flags = PLOOP_SNAP_SKIP_TOPDELTA_DESTROY;
			break;
		default:
			usage_snapshot_switch();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if ((argc != 1 && !is_xml_fname(argv[0])) || uuid == NULL) {
		usage_snapshot_switch();
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_switch_snapshot(di, uuid, flags);

	ploop_close_dd(di);

	return ret;
}

static void usage_snapshot_delete(void)
{
	fprintf(stderr, "Usage: ploop snapshot-delete -u UUID DiskDescriptor.xml\n"
			"       UUID := snapshot id\n");
}

static int plooptool_snapshot_delete(int argc, char **argv)
{
	int i, ret;
	char *uuid = NULL;
	struct ploop_disk_images_data *di = NULL;

	while ((i = getopt(argc, argv, "u:")) != EOF) {
		switch (i) {
		case 'u':
			uuid = parse_uuid(optarg);
			if (!uuid)
				return SYSEXIT_PARAM;
			break;
		default:
			usage_snapshot_delete();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || !is_xml_fname(argv[0]) || uuid == NULL) {
		usage_snapshot_delete();
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_delete_snapshot(di, uuid);

	ploop_close_dd(di);

	return ret;
}

static void usage_snapshot_merge(void)
{
	fprintf(stderr, "Usage: ploop snapshot-merge [-u UUID | -A] [-n DELTA] DiskDescriptor.xml\n"
			"       -u UUID       snapshot to merge (top delta if not specified)\n"
			"       -n DELTA      new delta file to merge to\n");
}

static int plooptool_snapshot_merge(int argc, char ** argv)
{
	int i, ret;
	struct ploop_merge_param param = {};

	while ((i = getopt(argc, argv, "u:n:A")) != EOF) {
		switch (i) {
		case 'u':
			param.guid = parse_uuid(optarg);
			if (!param.guid)
				return SYSEXIT_PARAM;
			break;
		case 'A':
			param.merge_all = 1;
			break;
		case 'n':
			param.new_delta = strdup(optarg);
			break;
		default:
			usage_snapshot_merge();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (param.guid != NULL && param.merge_all != 0) {
		fprintf(stderr, "Options -u and -A can't be used together\n");
		usage_snapshot_merge();
		return SYSEXIT_PARAM;
	}

	if (argc == 1 && is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di;
		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		ret = ploop_merge_snapshot(di, &param);

		ploop_close_dd(di);
	} else {
		usage_snapshot_merge();
		return SYSEXIT_PARAM;
	}

	return ret;
}


static void usage_getdevice(void)
{
	fprintf(stderr, "Usage: ploop getdev\n"
			"(ask /dev/ploop0 about first unused minor number)\n"
		);
}

static int plooptool_getdevice(int argc, char **argv)
{
	int minor, fd;

	if (argc != 1) {
		usage_getdevice();
		return SYSEXIT_PARAM;
	}
	fd = ploop_getdevice(&minor);
	if (fd < 0)
		return 1;
	close(fd);
	printf("Next unused minor: %d\n", minor);

	return 0;
}

static void usage_resize(void)
{
	fprintf(stderr, "Usage: ploop resize -s NEW_SIZE DiskDescriptor.xml\n"
			"       NEW_SIZE := NUMBER[KMGT]\n");
}

static int plooptool_resize(int argc, char **argv)
{
	int i, ret;
	off_t new_size = 0; /* in sectors */
	int max_balloon_size = 0; /* make balloon file of max possible size */
	struct ploop_resize_param param = {
		.size		= 0,
		.offline_resize	= 1,
	};
	struct ploop_disk_images_data *di;

	while ((i = getopt(argc, argv, "s:b")) != EOF) {
		switch (i) {
		case 's':
			if (parse_size(optarg, &new_size, "-s")) {
				usage_resize();
				return SYSEXIT_PARAM;
			}
			param.size = new_size;
			break;
		case 'b':
			max_balloon_size = 1;
			break;
		default:
			usage_resize();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 ||
			(new_size == 0 && !max_balloon_size) ||
			!is_xml_fname(argv[0]))
	{
		usage_resize();
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_resize_image(di, &param);

	ploop_close_dd(di);

	return ret;
}

static void usage_convert(void)
{
	fprintf(stderr, "Usage: ploop convert {-f FORMAT | -v VERSION} DiskDescriptor.xml\n"
			"       FORMAT := { raw | preallocated }\n"
			"       VERSION := { 1 | 2 }\n"
			);
}

static int plooptool_convert(int argc, char **argv)
{
	int i, ret;
	struct ploop_disk_images_data *di;
	int mode = -1;
	int version = -1;

	while ((i = getopt(argc, argv, "f:v:")) != EOF) {
		switch (i) {
		case 'f':
			mode = parse_format_opt(optarg);
			break;
		case 'v':
			version = parse_version_opt(optarg);
			if (version < 0) {
				 usage_convert();
				 return SYSEXIT_PARAM;
			}
			break;
		default:
			usage_convert();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0 ||
		(mode == -1 && version == -1) ||
		(mode != -1 && version != -1))
	{
		usage_convert();
		return SYSEXIT_PARAM;
	}

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;
	if (mode != -1)
		ret = ploop_convert_image(di, mode, 0);
	else if (version != -1)
		ret = ploop_change_fmt_version(di, version, 0);

	ploop_close_dd(di);

	return ret;
}

static void usage_info(void)
{
	fprintf(stderr, "Usage: ploop info [-s] [-d] DiskDescriptor.xml\n");
}

static void print_info(struct ploop_info *info)
{
	printf("%11s %14s %14s\n",
			"resource", "Size", "Used");
	printf("%11s %14llu %14llu\n",
			"1k-blocks",
			(info->fs_blocks * info->fs_bsize) >> 10,
			((info->fs_blocks - info->fs_bfree) * info->fs_bsize) >> 10);
	printf("%11s %14llu %14llu\n",
			"inodes",
			info->fs_inodes,
			(info->fs_inodes - info->fs_ifree));
}

static int plooptool_info(int argc, char **argv)
{
	int ret, i;
	int spec = 0;
	int device = 0;
	struct ploop_info info = {};

	while ((i = getopt(argc, argv, "sd")) != EOF) {
		switch (i) {
		case 's':
			spec = 1;
			break;
		case 'd':
			device = 1;
			break;
		default:
			usage_info();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || !is_xml_fname(argv[0])) {
		usage_info();
		return SYSEXIT_PARAM;
	}

	if (spec || device) {
		struct ploop_disk_images_data *di;

		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		if (spec) {
			struct ploop_spec spec = {};

			ret = ploop_get_spec(di, &spec);
			if (ret)
				goto exit;

			printf("size:\t\t%llu\nblocksize:\t%d\nfmt_version:\t%d\n",
					(unsigned long long)spec.size,
					spec.blocksize,
					spec.fmt_version);
		}

		if (device) {
			char dev[PATH_MAX] = {};

			if (ploop_get_dev(di, dev, sizeof(dev)) == -1) {
				ret = SYSEXIT_SYS;
				goto exit;
			}

			printf("device:\t\t%s\n", dev);
		}

exit:
		ploop_close_dd(di);
	} else {
		ret = ploop_get_info_by_descr(argv[0], &info);
		if (ret == 0)
			print_info(&info);
	}

	return ret;
}

static void usage_list(void)
{
	fprintf(stderr, "Usage: ploop list [-a]\n");
}

static int plooptool_list(int argc, char **argv)
{
	char fname[PATH_MAX];
	char image[PATH_MAX];
	char mnt[PATH_MAX] = "";
	char dev[64];
	DIR *dp;
	struct dirent *de;
	char cookie[PLOOP_COOKIE_SIZE];
	int all = 0;
	int i;

	while ((i = getopt(argc, argv, "a")) != EOF) {
		switch (i) {
		case 'a':
			all = 1;
			break;
		default:
			usage_list();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage_list();
		return SYSEXIT_PARAM;
	}

	snprintf(fname, sizeof(fname) - 1, "/sys/block/");
	dp = opendir(fname);
	if (dp == NULL) {
		fprintf(stderr, "Can't opendir %s: %m", fname);
		return 1;
	}
	while ((de = readdir(dp)) != NULL) {
		if (strncmp("ploop", de->d_name, 5))
			continue;

		snprintf(fname, sizeof(fname), "/sys/block/%s/pdelta/0/image",
				de->d_name);
		if (access(fname, F_OK))
			continue;
		if (read_line(fname, image, sizeof(image)))
			continue;
		snprintf(fname, sizeof(fname), "/sys/block/%s/pstate/cookie",
				de->d_name);
		if (access(fname, F_OK) == 0) {
			if (read_line(fname, cookie, sizeof(cookie)))
				continue;
		}

		if (all) {
			mnt[0] = '\0';
			snprintf(dev, sizeof(dev), "/dev/%s", de->d_name);
			ploop_get_mnt_by_dev(dev, mnt, sizeof(mnt));
		}
		printf("%-12s %s %s %s\n", de->d_name, image, mnt, cookie);
	}
	closedir(dp);

	return 0;
}

static void usage_replace(void)
{
	fprintf(stderr, "Usage: ploop replace {-d DEVICE | -m MNT} {-l LVL | -o СDELTA} [-k] -i DELTA\n"
			"       ploop replace {-u UUID|-l LVL|-o CDELTA} [-k] -i DELTA DiskDescriptor.xml\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			"       MNT := directory where ploop is mounted to\n"
			"       LVL := NUMBER, distance from base delta\n"
			"       UUID := UUID of image to be replaced\n"
			"       CDELTA := path to currently used image file\n"
			"       DELTA := path to new image file\n"
			"       -k, --keep-name    keep the file name (rename DELTA to CDELTA)\n"
	       );
}


static int plooptool_replace(int argc, char **argv)
{
	int i, idx;
	char dev[PATH_MAX];
	char *device = NULL;
	char *mnt = NULL;
	struct ploop_replace_param param = {
		.level = -1,
	};
	static struct option options[] = {
		{"keep-name", no_argument, NULL, 'k'},
		{NULL, 0, NULL, 0 }
	};

	while ((i = getopt_long(argc, argv, "d:m:l:i:u:o:k",
					options, &idx)) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'm':
			mnt = optarg;
			break;
		case 'l':
			param.level = atoi(optarg);
			break;
		case 'u':
			param.guid = parse_uuid(optarg);
			if (!param.guid)
				return SYSEXIT_PARAM;
			break;
		case 'i':
			param.file = strdup(optarg);
			break;
		case 'o':
			param.cur_file = strdup(optarg);
			break;
		case 'k':
			param.flags |= PLOOP_REPLACE_KEEP_NAME;
			break;
		default:
			usage_replace();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (!param.file) {
		fprintf(stderr, "Error: image file not specified (use -i)\n");
		usage_replace();
		return SYSEXIT_PARAM;
	}

	if ((argc == 1) && is_xml_fname(argv[0])) {
		int ret;
		struct ploop_disk_images_data *di;

		/* only one way of choosing delta to replace */
		if ( (!!param.guid) + (param.level != -1) +
				(!!param.cur_file) != 1)  {
			fprintf(stderr, "Error: either one of uuid (-u), "
					"level (-l) or current file (-o) "
					"must be specified\n");
			usage_replace();
			return SYSEXIT_PARAM;
		}

		ret = ploop_open_dd(&di, argv[0]);
		if (ret)
			return ret;

		ret = ploop_replace_image(di, &param);
		ploop_close_dd(di);

		return ret;
	}
	else {
		int level = param.level;

		if (argc > 0) {
			usage_replace();
			return SYSEXIT_PARAM;
		}
		if ((!!device) + (!!mnt) != 1) {
			fprintf(stderr, "Error: either device (-d), mount "
					"point (-m) or DiskDescriptor.xml "
					"must be specified\n");
			usage_replace();
			return SYSEXIT_PARAM;
		}
		if (mnt) {
			if (ploop_get_dev_by_mnt(mnt, dev, sizeof(dev))) {
				fprintf(stderr, "Unable to find ploop device "
						"by mount point %s\n", mnt);
				return SYSEXIT_PARAM;
			}
			device = dev;
		}
		/* Either level or current delta must be specified */
		if ((level != -1) + (!!param.cur_file) != 1) {
			fprintf(stderr, "Error: either one of level (-l) or "
					"current delta file (-o) must be "
					"specified\n");
			usage_replace();
			return SYSEXIT_PARAM;
		}
		if (param.cur_file) {
			int ret;

			level = find_level_by_delta(device, param.cur_file);
			if (level < 0) {
				fprintf(stderr, "Can't find level by "
						"delta file name %s",
						param.cur_file);
				return SYSEXIT_PARAM;
			}

			ret = check_deltas_same(param.cur_file, param.file);
			if (ret)
				return ret;
		}

		return replace_delta(device, level, param.file);
	}
}

static void usage_restore_descriptor(void)
{
	fprintf(stderr, "Usage: ploop restore-descriptor [-f FORMAT] [-b BLOCKSIZE] IMAGE_DIR BASE_DELTA\n"
			"       FORMAT := { raw | ploop1 }\n"
			"       BLOCKSIZE := block size in sectors (for raw image format)"
			"       *IMAGE_DIR := directory where to place DiskDescriptor.xml\n"
			"       *BASE_DELTA := path to image file\n"
		);
}

static int plooptool_restore_descriptor(int argc, char **argv)
{
	int i, f;
	int raw = 0;
	int blocksize = 0;
	char *endptr;

	while ((i = getopt(argc, argv, "f:b:")) != EOF) {
		switch (i) {
		case 'f':
			f = parse_format_opt(optarg);
			if (f < 0) {
				usage_restore_descriptor();
				return SYSEXIT_PARAM;
			}
			raw = (f == PLOOP_RAW_MODE);
			break;
		case 'b':
			  blocksize = strtoul(optarg, &endptr, 0);
			  if (*endptr != '\0') {
				  usage_restore_descriptor();
				  return SYSEXIT_PARAM;
			  }
			  break;
		default:
			  usage_restore_descriptor();
			  return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage_restore_descriptor();
		return SYSEXIT_PARAM;
	}

	return ploop_restore_descriptor(argv[0], argv[1], raw, blocksize);
}

int main(int argc, char **argv)
{
	char * cmd;
	int v = 3;

	/* global options */
	while (argc > 1 && argv[1][0] == '-') {
		switch (argv[1][1]) {
			case 'v':
				switch (argv[1][2]) {
				    case '\0':
					v++;
					break;
				    case 'v': /* -vvv... */
					v += strlen(&argv[1][1]);
					break;
				    default: /* -vNN */
					v = atoi(&argv[1][2]);
				}
				break;
			case '-': /* long option */
				/* fall through */
			default:
				fprintf(stderr, "Bad option %s\n", argv[1]);
				usage_summary();
				return SYSEXIT_PARAM;
		}
		argc--;
		argv++;
	}

	if (argc < 2) {
		usage_summary();
		return SYSEXIT_PARAM;
	}

	cmd = argv[1];
	argc--;
	argv++;

	ploop_set_verbose_level(v);
	init_signals();

	if (strcmp(cmd, "init") == 0)
		return plooptool_init(argc, argv);
	if (strcmp(cmd, "start") == 0)
		return plooptool_start(argc, argv);
	if (strcmp(cmd, "stop") == 0)
		return plooptool_stop(argc, argv);
	if (strcmp(cmd, "clear") == 0)
		return plooptool_clear(argc, argv);
	if (strcmp(cmd, "mount") == 0)
		return plooptool_mount(argc, argv);
	if (strcmp(cmd, "umount") == 0)
		return plooptool_umount(argc, argv);
	if (strcmp(cmd, "delete") == 0 || strcmp(cmd, "rm") == 0)
		return plooptool_rm(argc, argv);
	if (strcmp(cmd, "snapshot") == 0)
		return plooptool_snapshot(argc, argv);
	if (strcmp(cmd, "tsnapshot") == 0)
		return plooptool_tsnapshot(argc, argv);
	if (strcmp(cmd, "snapshot-switch") == 0)
		return plooptool_snapshot_switch(argc, argv);
	if (strcmp(cmd, "snapshot-delete") == 0)
		return plooptool_snapshot_delete(argc, argv);
	if (strcmp(cmd, "snapshot-merge") == 0)
		return plooptool_snapshot_merge(argc, argv);
	if (strcmp(cmd, "snapshot-list") == 0)
		return plooptool_snapshot_list(argc, argv);
	if (strcmp(cmd, "getdev") == 0)
		return plooptool_getdevice(argc, argv);
	if (strcmp(cmd, "resize") == 0)
		return plooptool_resize(argc, argv);
	if (strcmp(cmd, "convert") == 0)
		return plooptool_convert(argc, argv);
	if (strcmp(cmd, "info") == 0)
		return plooptool_info(argc, argv);
	if (strcmp(cmd, "list") == 0)
		return plooptool_list(argc, argv);
	if (strcmp(cmd, "check") == 0)
		return plooptool_check(argc, argv);
	if (strcmp(cmd, "fsck") == 0) {
		fprintf(stderr, "WARNING: ploop fsck command is obsoleted, "
				"please use ploop check\n");
		return plooptool_check(argc, argv);
	}
	if (strcmp(cmd, "grow") == 0)
		return plooptool_grow(argc, argv);
	if (strcmp(cmd, "merge") == 0)
		return plooptool_merge(argc, argv);
	if (strcmp(cmd, "stat") == 0)
		return plooptool_stat(argc, argv);
	if (strcmp(cmd, "copy") == 0)
		return plooptool_copy(argc, argv);
	if (strcmp(cmd, "replace") == 0)
		return plooptool_replace(argc, argv);
	if (strcmp(cmd, "restore-descriptor") == 0)
		return plooptool_restore_descriptor(argc, argv);

	if (cmd[0] != '-') {
		char ** nargs;

		nargs = calloc(argc+1, sizeof(char*));
		nargs[0] = malloc(sizeof("ploop-") + strlen(cmd));
		sprintf(nargs[0], "ploop-%s", cmd);
		memcpy(nargs + 1, argv + 1, (argc - 1)*sizeof(char*));
		nargs[argc] = NULL;

		execvp(nargs[0], nargs);
	}

	usage_summary();
	return SYSEXIT_PARAM;
}
