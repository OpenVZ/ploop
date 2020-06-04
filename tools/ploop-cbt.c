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
#include <sys/file.h>
#include <sys/mount.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>
#include <limits.h>

#include "ploop.h"
#include "cbt.h"
#include "common.h"
#include "bit_ops.h"

static void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop-cbt { dump | drop | show } DiskDescriptor.xml\n");

}

static void usage_dump(void)
{
	fprintf(stderr, "Usage: ploop-cbt dump --dst <to> DiskDescriptor.xml\n"
		"\t\tdump --src <from> --dst <to>\n");
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

	if (argc != 1 || !is_xml_fname(argv[0]) || dst == NULL) {
		usage_dump();
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

static void usage_diff(void)
{
	fprintf(stderr, "Usage: ploop-cbt diff [-b BLOCKSIZE] [-o OUT] file1 file2\n");
}

static int diff(int argc, char **argv)
{
	int ret = 0, i, f1, f2;
	unsigned long n, r, off, bits, bytes;
	unsigned long *map;
	void *b1, *b2;
	struct stat st;
	int bsize = 64 * 1024;
	const char *out = NULL;

	while ((i = getopt(argc, argv, "b:o:")) != EOF) {
		switch (i) {
		case 'b':
			bsize = atoi(optarg);
			break;
		case 'o':
			out = optarg;
			break;
		default:
			usage_diff();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage_diff();
		return SYSEXIT_PARAM;
	}

	f1 = open(argv[0], O_RDONLY);
	if (f1 == -1) {
		fprintf(stderr, "Error: Cannot open %s: %m\n", argv[0]);
		return 1;
	}
	if (fstat(f1, &st)) {
		fprintf(stderr, "Error: Cannot fstat %s: %m", argv[0]);
		close(f1);
		return 1;
	}

	f2 = open(argv[1], O_RDONLY);
	if (f2 == -1) {
		fprintf(stderr, "Error: Cannot open %s: %m\n", argv[1]);
		close(f1);
		return 1;
	}

	printf("Create diff %s %s\n", argv[0], argv[1]);
	b1 = malloc(bsize);
	b2 = malloc(bsize);

	bits = st.st_size / bsize;
	bytes = (bits + 7) / 8;
	map = (unsigned long *)calloc(1, bytes);
	for (off = 0, n = 0; n < bits; n++, off += bsize) {
		if (read_safe(f1, b1, bsize, off, "")) {
			fprintf(stderr, "Error: failed read %s off %lu: %m\n", argv[0], off);
			ret = 1;
			break;
		}
		if (read_safe(f2, b2, bsize, off, "")) {
			fprintf(stderr, "Error: failed read %s off %lu: %m\n", argv[1], off);
			ret = 1;
			break;
		}
		if (memcmp(b1, b2, bsize)) {
			BMAP_SET(map, n);
		}
	}

	if (ret == 0 && out) {
		int o;

		printf("Store CBT %s\n", out);
		o = open(out, O_WRONLY|O_TRUNC|O_CREAT, 0600);
		if (o == -1) {
			fprintf(stderr, "Error: Cannot open %s: %m\n", out);
			return 1;
		}

		r = write(o, map, bytes);
		if (r != bytes) {
			fprintf(stderr, "Error: failed read %s off %lu: %m\n", argv[1], off);
			ret = 1;
		}
		close(o);
	}
	close(f1);
	close(f2);
	free(map);
	free(b1);
	free(b2);

	return ret;
}

static void usage_cmp(void)
{
	fprintf(stderr, "Usage: ploop-cbt cmp file1 file2\n");
}

static int cmp(int argc, char **argv)
{
	int ret = 0, f1, f2;
	unsigned long n, r, i;
	struct stat st;

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage_cmp();
		return SYSEXIT_PARAM;
	}

	f1 = open(argv[0], O_RDONLY);
	if (f1 == -1) {
		fprintf(stderr, "Error: Cannot open %s: %m\n", argv[0]);
		return 1;
	}
	if (fstat(f1, &st)) {
		fprintf(stderr, "Error: Cannot fstat %s: %m", argv[0]);
		close(f1);
		return 1;
	}

	f2 = open(argv[1], O_RDONLY);
	if (f2 == -1) {
		fprintf(stderr, "Error: Cannot open %s: %m\n", argv[1]);
		close(f1);
		return 1;
	}

	n = st.st_size / sizeof(unsigned long);
	for (i = 0; i < n; i++) {
		unsigned long b1, b2;
		r = read(f1, &b1, sizeof(b1));
		if (r != sizeof(b1)) {
			fprintf(stderr, "Error: failed read %s off %lu: %m\n", argv[0], n * sizeof(unsigned long));
			ret = 1;
			break;
		}
		r = read(f2, &b2, sizeof(b2));
		if (r != sizeof(b2)) {
			fprintf(stderr, "Error: failed read %s off %lu: %m\n", argv[1], n * sizeof(unsigned long));
			ret = 1;
			break;
		}
		if (b1 != b2) {
			printf("differ off %lu %lx %lx\n", n * sizeof(unsigned long), b1, b2);
			if (~b1 & b2) {
				fprintf(stderr, "Failed");
				ret = 1;
				break;
			}
		}
	}

	close(f1);
	close(f2);

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
	ploop_set_verbose_level(3);

	if (strcmp(cmd, "dump") == 0)
		return dump(argc, argv);
	if (strcmp(cmd, "drop") == 0)
		return drop(argc, argv);
	if (strcmp(cmd, "show") == 0)
		return show(argc, argv);
	if (strcmp(cmd, "diff") == 0)
		return diff(argc, argv);
	if (strcmp(cmd, "cmp") == 0)
		return cmp(argc, argv);

	usage_summary();

	return SYSEXIT_PARAM;
}
