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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <string.h>
#include <signal.h>

#include "ploop.h"

static struct ploop_cancel_handle *_s_cancel_handle;

void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop init -s SIZE [-f FORMAT] NEW_DELTA\n"
			"       ploop mount [-rP] [-f raw] -d DEVICE BASE_DELTA [ ... TOP_DELTA ]\n"
			"       ploop umount -d DEVICE\n"
			"       ploop { delete | rm } -d DEVICE -l LEVEL\n"
			"       ploop merge -d DEVICE [-l LEVEL[..TOP_LEVEL]]\n"
			"       ploop fsck [-fcr] DELTA\n"
			"       ploop getdev\n"
			"       ploop resize -s SIZE BASE_DELTA\n"
			"       ploop snapshot [-F] -d DEVICE NEW_DELTA\n"
			"       ploop snapshot DiskDescriptor.xml\n"
			"       ploop snapshot-delete -u <uuid> DiskDescriptor.xml\n"
			"       ploop snapshot-merge [-u <uuid>] DiskDescriptor.xml\n"
			"       ploop snapshot-switch -u <uuid> DiskDescriptor.xml\n"
			"Also:  ploop { stat | start | stop | clear } ...\n"
	       );
}

static void usage_init(void)
{
	fprintf(stderr, "Usage: ploop init -s SIZE [-f FORMAT] [-t FSTYPE] [-b BLOCKSIZE] DELTA\n"
			"       SIZE := NUMBER[kmg], \n"
			"       FORMAT := { raw | ploop1 }\n"
			"       DELTA := path to new image file\n"
			"       BLOCKSIZE := block size\n"
			"       FSTYPE := make file system\n");
}

static int is_xml_fname(const char *fname)
{
	char *p;

	p = strrchr(fname, '.');
	if (p != NULL && !strcmp(p, ".xml"))
		return 1;
	return 0;
}

static int plooptool_init(int argc, char **argv)
{
	int i, ret;
	off_t size_sec = 0;
	struct ploop_create_param param = {};

	param.mode = PLOOP_EXPANDED_MODE;
	while ((i = getopt(argc, argv, "s:b:f:t:")) != EOF) {
		switch (i) {
		case 's':
			if (parse_size(optarg, &size_sec)) {
				usage_init();
				return -1;
			}
			break;
		case 'b': {
			  char * endptr;

			  param.blocksize = strtoul(optarg, &endptr, 0);
			  if (optarg == endptr) {
				  usage_init();
				  return -1;
			  }
			  break;
		}
		case 'f':
			if (strcmp(optarg, "raw") == 0)
				param.mode = PLOOP_RAW_MODE;
			else if ((strcmp(optarg, "ploop1") == 0) ||
				 (strcmp(optarg, "expanded") == 0))
				param.mode = PLOOP_EXPANDED_MODE;
			else if (strcmp(optarg, "preallocated") == 0)
				param.mode = PLOOP_EXPANDED_PREALLOCATED_MODE;
			else {
				usage_init();
				return -1;
			}
			break;
		case 't':
			if (!strcmp(optarg, "ext4") || !strcmp(optarg, "ext3")) {
				param.fstype = strdup(optarg);
			} else {
				fprintf(stderr, "Incorrect file system type specified: %s\n",
						optarg);
				return -1;
			}
			break;
		default:
			usage_init();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || size_sec == 0) {
		usage_init();
		return -1;
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
	fprintf(stderr, "Usage: ploop mount [-rP] [-f FORMAT] [-b BLOCKSIZE] [-d DEVICE]\n"
			"             BASE_DELTA [ ... TOP_DELTA ]\n"
			"       ploop mount [-rP] [-m DIR] [-u UUID] DiskDescriptor.xml\n"
			"       FORMAT := { raw | ploop1 }\n"
			"       BLOCKSIZE := block size (for raw image format)\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			"       *DELTA := path to image file\n"
			"       -r     - mount images read-only\n"
			"       -P     - rescan partition table upon mount\n"
			"       -t     - file system type\n"
			"       -m     - target mount point\n"
		);
}

static int plooptool_mount(int argc, char **argv)
{
	int i, ret;
	int raw = 0;
	int base = 0;
	struct ploop_mount_param mountopts = {};

	while ((i = getopt(argc, argv, "rf:Pd:m:t:u:o:b:")) != EOF) {
		switch (i) {
		case 'd':
			strncpy(mountopts.device, optarg, sizeof(mountopts.device)-1);
			break;
		case 'r':
			mountopts.ro = 1;
			break;
		case 'f':
			if (strcmp(optarg, "raw") == 0)
				raw = 1;
			else if (strcmp(optarg, "ploop1") != 0) {
				usage_mount();
				return -1;
			}
			break;
		case 'P':
			mountopts.partitioned = 1;
			break;
		case 'm':
			mountopts.target = strdup(optarg);
			break;
		case 't':
			mountopts.fstype = strdup(optarg);
			break;
		case 'u':
			if (!strcmp(optarg, "base"))
				base = 1;
			else
				mountopts.guid = strdup(optarg);
			break;
		case 'o':
			mountopts.mount_data = strdup(optarg);
			break;
		case 'b': {
			  char * endptr;

			  mountopts.blocksize = strtoul(optarg, &endptr, 0);
			  if (optarg == endptr) {
				  usage_mount();
				  return -1;
			  }
			  break;
		}
		default:
			usage_mount();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage_mount();
		return -1;
	}

	if (argc == 1 && is_xml_fname(argv[0]))
	{
		struct ploop_disk_images_data *di = ploop_alloc_diskdescriptor();

		ret = ploop_read_diskdescriptor(argv[0], di);
		if (ret)
			goto err;
		if (base) {
			mountopts.guid = ploop_get_base_delta_uuid(di);
			if (mountopts.guid == NULL) {
				ret = 1;
				fprintf(stderr, "Unable to find base delta uuid");
				goto err;
			}
		}
		ret = ploop_mount_image(di, &mountopts);
err:
		ploop_free_diskdescriptor(di);
	}
	else
		ret = ploop_mount(NULL, argv, &mountopts, raw);

	return ret;

}

static void usage_start(void)
{
	fprintf(stderr, "Usage: ploop start [-P] -d DEVICE\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n"
			"       -P     - rescan partition table\n");
}

static int plooptool_start(int argc, char **argv)
{
	int i;
	int lfd;
	struct {
		int partitioned;
		char * device;
	} startopts = { };

	while ((i = getopt(argc, argv, "d:P")) != EOF) {
		switch (i) {
		case 'd':
			startopts.device = optarg;
			break;
		case 'P':
			startopts.partitioned = 1;
			break;
		default:
			usage_start();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		usage_start();
		return -1;
	}

	lfd = open(startopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, PLOOP_IOC_START, 0) < 0) {
		perror("PLOOP_IOC_START");
		return SYSEXIT_DEVIOC;
	}

	if (startopts.partitioned && ioctl(lfd, BLKRRPART, 0) < 0) {
		perror("BLKRRPART");
		return SYSEXIT_BLKDEV;
	}

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
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		usage_stop();
		return -1;
	}

	lfd = open(stopopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, PLOOP_IOC_STOP, 0) < 0) {
		perror("PLOOP_IOC_START");
		return SYSEXIT_DEVIOC;
	}

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
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		usage_clear();
		return -1;
	}

	lfd = open(stopopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("Can't open device");
		return SYSEXIT_DEVICE;
	}

	if (ioctl(lfd, PLOOP_IOC_CLEAR, 0) < 0) {
		perror("PLOOP_IOC_START");
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

static void usage_umount(void)
{
	fprintf(stderr, "Usage: ploop umount -d DEVICE\n"
			"       DEVICE := ploop device, e.g. /dev/ploop0\n");
}

static int plooptool_umount(int argc, char **argv)
{
	int i, ret;
	char *mnt = NULL;
	char device[MAXPATHLEN];
	struct {
		char * device;
	} umountopts = { };

	while ((i = getopt(argc, argv, "d:m:")) != EOF) {
		switch (i) {
		case 'd':
			umountopts.device = optarg;
			break;
		case 'm':
			mnt = optarg;
			break;
		default:
			usage_umount();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 && !umountopts.device && !mnt) {
		usage_umount();
		return -1;
	}

	if (umountopts.device != NULL) {
		ret = ploop_umount(umountopts.device, NULL);
	}else if (mnt != NULL) {
		if (ploop_get_dev_by_mnt(mnt, device, sizeof(device))) {
			ploop_err(0, "Unable to find ploop device by %s", mnt);
			return -1;
		}
		ret = ploop_umount(device, NULL);
	} else if (is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di = ploop_alloc_diskdescriptor();

		ret = ploop_read_diskdescriptor(argv[0], di);
		if (ret == 0)
			ret = ploop_umount_image(di);
		ploop_free_diskdescriptor(di);
	} else {
		if (ploop_find_dev_by_delta(argv[0], device, sizeof(device)) != 0) {
			ploop_err(0, "Image %s is not mounted", argv[0]);
			return -1;
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
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc || !rmopts.device || rmopts.level < 0 || rmopts.level > 127) {
		usage_rm();
		return -1;
	}

	lfd = open(rmopts.device, O_RDONLY);
	if (lfd < 0) {
		perror("open dev");
		return SYSEXIT_DEVICE;
	}

	level = rmopts.level;
	if (ioctl(lfd, PLOOP_IOC_DEL_DELTA, &level) < 0) {
		perror("PLOOP_IOC_DEL_DELTA");
		return SYSEXIT_DEVIOC;
	}
	return 0;
}

static void usage_snapshot(void)
{
	fprintf(stderr, "Usage: ploop snapshot [-u <uuid>] DiskDescriptor.xml\n"
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

	while ((i = getopt(argc, argv, "b:Fd:u:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'F':
			syncfs = 1;
			break;
		case 'u':
			param.guid = optarg;
			break;
		default:
			usage_snapshot();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_snapshot();
		return -1;
	}

	if (is_xml_fname(argv[0])) {
		struct ploop_disk_images_data *di = ploop_alloc_diskdescriptor();

		if (ploop_read_diskdescriptor(argv[0], di))
			return -1;

		ret = ploop_create_snapshot(di, &param);

		ploop_free_diskdescriptor(di);
	} else {
		__u32 blocksize = 0;
		if (!device) {
			usage_snapshot();
			return -1;
		}
		if (ploop_get_attr(device, "block_size", (int*) &blocksize))
			return 1;
		ret = create_snapshot(device, argv[0], blocksize, syncfs);
	}

	return ret;
}

static void usage_snapshot_switch(void)
{
	fprintf(stderr, "Usage: ploop snapshot-switch -u <uuid> DiskDescriptor.xml\n"
			"       -u <uuid>     snapshot uuid\n");
}

static int plooptool_snapshot_switch(int argc, char **argv)
{
	int i, ret;
	char *uuid = NULL;
	struct ploop_disk_images_data *di = NULL;

	while ((i = getopt(argc, argv, "u:")) != EOF) {
		switch (i) {
		case 'u':
			uuid = optarg;
			break;
		default:
			usage_snapshot_switch();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if ((argc != 1 && !is_xml_fname(argv[0])) || uuid == NULL) {
		usage_snapshot_switch();
		return -1;
	}

	di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(argv[0], di))
		return -1;

	ret = ploop_switch_snapshot(di, uuid, 0);

	ploop_free_diskdescriptor(di);

	return ret;
}

static void usage_snapshot_delete(void)
{
	fprintf(stderr, "Usage: ploop snapshot-delete -u <uuid> DiskDescriptor.xml\n"
			"       -u <uuid>     snapshot uuid\n");
}

static int plooptool_snapshot_delete(int argc, char **argv)
{
	int i, ret;
	char *uuid = NULL;
	struct ploop_disk_images_data *di = NULL;

	while ((i = getopt(argc, argv, "u:")) != EOF) {
		switch (i) {
		case 'u':
			uuid = optarg;
			break;
		default:
			usage_snapshot_delete();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || !is_xml_fname(argv[0]) || uuid == NULL) {
		usage_snapshot_delete();
		return -1;
	}

	di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(argv[0], di))
		return -1;

	ret = ploop_delete_snapshot(di, uuid);

	ploop_free_diskdescriptor(di);

	return ret;
}

void usage_snapshot_merge(void)
{
	fprintf(stderr, "Usage: ploop snapshot-merge [-u <uuid>] DiskDescriptor.xml]\n"
			"       -u <uuid>     snapshot uuid (top delta if not specified)\n");
}

int plooptool_snapshot_merge(int argc, char ** argv)
{
	int i, ret;
	struct ploop_merge_param param = {};

	while ((i = getopt(argc, argv, "u:A")) != EOF) {
		switch (i) {
		case 'u':
			param.guid = optarg;
			break;
		case 'A':
			param.merge_all = 1;
			break;
		default:
			usage_snapshot_merge();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (param.guid != NULL && param.merge_all != 0) {
		usage_snapshot_merge();
		return 1;
	}

	if (argc == 1 && strstr(argv[0], DISKDESCRIPTOR_XML)) {
		struct ploop_disk_images_data *di;


		di = ploop_alloc_diskdescriptor();
		ret = ploop_read_diskdescriptor(argv[0], di);
		if (ret == 0)
			ret = ploop_merge_snapshot(di, &param);
		ploop_free_diskdescriptor(di);
	} else {
		usage_snapshot_merge();
		return 1;
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
	int minor, ret;

	if (argc != 1) {
		usage_getdevice();
		return -1;
	}
	ret = ploop_getdevice(&minor);
	if (ret == 0)
		printf("Next unused minor: %d\n", minor);

	return ret;
}

static void usage_resize(void)
{
	fprintf(stderr, "Usage: ploop resize -s NEW_SIZE DiskDescriptor.xml\n");
}

static int plooptool_resize(int argc, char **argv)
{
	int i, ret;
	off_t new_size = 0; /* in sectors */
	int max_balloon_size = 0; /* make balloon file of max possible size */
	struct ploop_resize_param param = {};
	struct ploop_disk_images_data *di;

	while ((i = getopt(argc, argv, "s:b")) != EOF) {
		switch (i) {
		case 's':
			if (parse_size(optarg, &new_size)) {
				usage_resize();
				return -1;
			}
			param.size = new_size;
			break;
		case 'b':
			max_balloon_size = 1;
			break;
		default:
			usage_resize();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 ||
			(new_size == 0 && !max_balloon_size) ||
			!is_xml_fname(argv[0]))
	{
		usage_resize();
		return -1;
	}
	di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(argv[0], di))
		return -1;

	ret = ploop_resize_image(di, &param);
	ploop_free_diskdescriptor(di);

	return ret;
}

static void usage_convert(void)
{
	fprintf(stderr, "Usage: ploop convert -t <raw|preallocated>\n");
}

static int plooptool_convert(int argc, char **argv)
{
	int i, ret;
	struct ploop_disk_images_data *di;
	int mode = -1;

	while ((i = getopt(argc, argv, "t:")) != EOF) {
		switch (i) {
		case 't':
			if (!strcmp(optarg, "raw"))
				mode = PLOOP_RAW_MODE;
			else if (!strcmp(optarg, "preallocated"))
				mode = PLOOP_EXPANDED_PREALLOCATED_MODE;
			else {
				usage_convert();
				return -1;
			}
			break;
		default:
			usage_convert();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0 || mode == -1) {
		usage_convert();
		return -1;
	}

	di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(argv[0], di))
		return -1;

	ret = ploop_convert_image(di, mode, 0);

	ploop_free_diskdescriptor(di);

	return ret;
}

static void usage_info(void)
{
	fprintf(stderr, "Usage: ploop info\n");
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
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_info info = {};

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		usage_info();
		return -1;
	}

	di = ploop_alloc_diskdescriptor();

	if (ploop_read_diskdescriptor(argv[0], di))
		return -1;

	ret = ploop_get_info(di, &info);
	if (ret == 0)
		print_info(&info);

	ploop_free_diskdescriptor(di);

	return ret;
}

static void cancel_callback(int sig)
{
	ploop_cancel_operation(_s_cancel_handle);
}

static void init_signals(void)
{
	struct sigaction act = {};

	_s_cancel_handle = ploop_get_cancel_handle();
	sigemptyset(&act.sa_mask);
	act.sa_handler = cancel_callback;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
}

int main(int argc, char **argv)
{
	char * cmd;

	if (argc < 2) {
		usage_summary();
		return -1;
	}

	cmd = argv[1];
	argc--;
	argv++;

	ploop_set_verbose_level(3);
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
	if (strcmp(cmd, "snapshot-switch") == 0)
		return plooptool_snapshot_switch(argc, argv);
	if (strcmp(cmd, "snapshot-delete") == 0)
		return plooptool_snapshot_delete(argc, argv);
	if (strcmp(cmd, "snapshot-merge") == 0)
		return plooptool_snapshot_merge(argc, argv);
	if (strcmp(cmd, "getdev") == 0)
		return plooptool_getdevice(argc, argv);
	if (strcmp(cmd, "resize") == 0)
		return plooptool_resize(argc, argv);
	if (strcmp(cmd, "convert") == 0)
		return plooptool_convert(argc, argv);
	if (strcmp(cmd, "info") == 0)
		return plooptool_info(argc, argv);

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
	return -1;
}
