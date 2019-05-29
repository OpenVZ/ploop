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

#include <json/json.h>

#include "ploop.h"
#include "libvolume.h"
#include "common.h"

static void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop-volume {create|clone|snapshot|delete|switch} path\n");

}

static void usage_create(void)
{
	fprintf(stderr, "Usage: ploop-volume create -s SIZE [--image <path>] <VOL>\n");
}

static int create(int argc, char **argv)
{
	int i, f;
	off_t size_sec = 0;
	char *endptr;
	struct ploop_volume_data vol = {};
        struct ploop_create_param param = {
                .fstype         = "ext4",
                .mode           = PLOOP_EXPANDED_MODE,
                .fmt_version    = PLOOP_FMT_UNDEFINED,
        };

	static struct option opts[] = {
		{ "image", required_argument, 0, 1 },
		{ "size", required_argument, 0, 's' },
		{}
	};

	while ((i = getopt_long(argc, argv, "s:b:B:f:t:L:v:n:k:",
				opts, NULL)) != EOF) {
		switch (i) {
		case 1:
			vol.i_path = optarg;
			break;
		case 's':
			if (parse_size(optarg, &size_sec, "-s")) {
				usage_create();
				return SYSEXIT_PARAM;
			}
			break;
		case 'b':
			  param.blocksize = strtoul(optarg, &endptr, 0);
			  if (*endptr != '\0') {
				  usage_create();
				  return SYSEXIT_PARAM;
			  }
			  break;
		case 'B' :
			  param.fsblocksize = strtoul(optarg, &endptr, 0);
			  if (*endptr != '\0') {
				  usage_create();
				  return SYSEXIT_PARAM;
			  }
			  break;
		case 'f':
			f = parse_format_opt(optarg);
			if (f < 0) {
				usage_create();
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
		case 'L':
			param.fslabel = strdup(optarg);
			break;
		case 'n':
			param.flags |= PLOOP_CREATE_NOLAZY;
			break;
		case 'k':
			param.keyid = optarg;
			break;
		default:
			usage_create();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_create();
		return SYSEXIT_PARAM;
	}

	if (size_sec == 0) {
		usage_create();
		return SYSEXIT_PARAM;
	}

	param.size = (__u64) size_sec;
	vol.m_path = argv[0];

	return ploop_volume_create(&vol, &param);
}

static void usage_clone(void)
{
	fprintf(stderr, "Usage: ploop-volume clone <SRC> <DST>\n");
}

static int clone(int argc, char **argv)
{
	int i;
	struct ploop_volume_data vol = {};
	static struct option opts[] = {
		{ "image", required_argument, 0, 1 },
		{}
	};

	while ((i = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
		switch (i) {
		case 1:
			vol.i_path = optarg;
			break;
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage_clone();
		return SYSEXIT_PARAM;
	}

	vol.m_path = argv[1];

	return ploop_volume_clone(argv[0], &vol);
}

static void usage_info(void)
{
	fprintf(stderr, "Usage: ploop-voulume info <VOL>\n");
}

static int print_info(int argc, char **argv)
{
	int i, rc;
	static struct option opts[] = {
		{}
	};
	struct ploop_volume_info info;
	struct json_object *result;

	while ((i = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
		switch (i) {
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_info();
		return SYSEXIT_PARAM;
	}

	if ((rc = ploop_volume_get_info(argv[0], &info, sizeof(info))))
		return rc;

	result = json_object_new_object();
	json_object_object_add(result, "size", json_object_new_int64((int64_t) info.size));
	printf("%s\n", json_object_to_json_string_ext(result, JSON_C_TO_STRING_PRETTY));
	json_object_put(result);
	return 0;
}

static void usage_snapshot(void)
{
	fprintf(stderr, "Usage: ploop-volume snapshot <SRC> <DST>\n");
}

static int snapshot(int argc, char **argv)
{
	int i;
	struct ploop_volume_data vol = {};
	static struct option opts[] = {
		{ "image", required_argument, 0, 1 },
		{}
	};

	while ((i = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
		switch (i) {
			vol.i_path = optarg;
			break;
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage_snapshot();
		return SYSEXIT_PARAM;
	}

	vol.m_path = argv[1];

	return ploop_volume_snapshot(argv[0], &vol);
}

static void usage_switch(void)
{
	fprintf(stderr, "Usage: ploop-volume switch <FROM> <TO>\n");
}

static int volume_switch(int argc, char **argv)
{
	if (argc != 3) {
		usage_switch();
		return SYSEXIT_PARAM;
	}

	return ploop_volume_switch(argv[1], argv[2]);
}

static void usage_tree(void)
{
	fprintf(stderr, "Usage: ploop-voulume tree <VOL>\n");
}

static int print_tree(int argc, char **argv)
{
	int i, rc;
	static struct option opts[] = {
		{}
	};
	struct ploop_volume_list_head head, *children;
	struct ploop_volume_tree_element *vol;
	struct json_object *json_result, *json_children;

	while ((i = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
		switch (i) {
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_tree();
		return SYSEXIT_PARAM;
	}

	SLIST_INIT(&head);
	rc = ploop_volume_get_tree(argv[0], &head, sizeof(head));
	if (rc)
		return rc;

	vol = SLIST_FIRST(&head);
	children = &vol->children;

	json_result = json_object_new_object();
	json_children = json_object_new_array();
	json_object_object_add(json_result, "path", json_object_new_string(vol->path));
	SLIST_FOREACH(vol, children, next) {
		struct json_object *child = json_object_new_object();
		json_object_object_add(child, "path", json_object_new_string(vol->path));
		json_object_array_add(json_children, child);
	}
	json_object_object_add(json_result, "children", json_children);
	printf("%s\n", json_object_to_json_string_ext(json_result, JSON_C_TO_STRING_PRETTY));
	json_object_put(json_result);
	ploop_volume_clear_tree(&head);
	return 0;
}

static void usage_delete(void)
{
	fprintf(stderr, "Usage: ploop-voulume delete <VOL>\n");
}

static int delete(int argc, char **argv)
{
	int i;
	static struct option opts[] = {
		{}
	};

	while ((i = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
		switch (i) {
		default:
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage_delete();
		return SYSEXIT_PARAM;
	}

	return ploop_volume_delete(argv[0]);
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

	if (strcmp(cmd, "create") == 0)
		return create(argc, argv);
	if (strcmp(cmd, "clone") == 0)
		return clone(argc, argv);
	if (strcmp(cmd, "info") == 0)
		return print_info(argc, argv);
	if (strcmp(cmd, "snapshot") == 0)
		return snapshot(argc, argv);
	if (strcmp(cmd, "switch") == 0)
		return volume_switch(argc, argv);
	if (strcmp(cmd, "tree") == 0)
		return print_tree(argc, argv);
	if (strcmp(cmd, "delete") == 0)
		return delete(argc, argv);

	usage_summary();

	return SYSEXIT_PARAM;
}
