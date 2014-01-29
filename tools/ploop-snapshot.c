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
#include <getopt.h>

#include "ploop.h"
#include "list.h"
#include "common.h"

struct id_entry {
	list_elem_t list;
	int id;
};

static const char *default_field_order = "parent_uuid,current,uuid,fname";
static int g_last_field;
static LIST_HEAD(g_field_order_head);
static LIST_HEAD(g_uuid_list_head);
static struct ploop_disk_images_data *g_di;
static int g_snapshot_mode;
static char *g_current_snap_guid;

static const char *FMT(const char *fmt)
{
	return g_last_field ? "%-s\n" : fmt;
}

static void print_uuid(struct ploop_snapshot_data *p)
{
	printf(FMT("%-38s "), p->guid);
}

static void print_parent_uuid(struct ploop_snapshot_data *p)
{
	printf(FMT("%-38s "), p->parent_guid);
}

static void print_current(struct ploop_snapshot_data *p)
{
	if (g_snapshot_mode) {
		if (g_current_snap_guid == NULL)
			g_current_snap_guid = ploop_find_parent_by_guid(g_di, g_di->top_guid);
		printf(FMT("%1s "), !guidcmp(p->guid, g_current_snap_guid ?: "") ? "*" : "");
	} else
		printf(FMT("%1s "), !guidcmp(p->guid, g_di->top_guid) ? "*" : "");
}

static void print_fname(struct ploop_snapshot_data *p)
{
	// FIXME: error if not found?
	char *fname = find_image_by_guid(g_di, p->guid);

	printf(FMT("%-32s "), fname ? fname : "");
}

struct snapshot_field {
	char *name;
	char *hdr;
	char *fmt;
	void (* print_fn)(struct ploop_snapshot_data *p);
} field_tbl[] =
{
{"uuid", "UUID", "%-38s", print_uuid},
{"parent_uuid", "PARENT_UUID", "%-38s", print_parent_uuid},
{"current", "C", "%1s", print_current},
{"fname", "FNAME", "%-32s", print_fname},
};

static int get_field_tbl_id(const char *name)
{
	int i;

	for (i = 0; i < sizeof(field_tbl) / sizeof(field_tbl[0]); i++)
		if (!strcasecmp(name, field_tbl[i].name))
			return i;
	return -1;
}

static int add_entry(list_head_t *head, int id)
{
	struct id_entry *p;

	p = malloc(sizeof( struct id_entry));
	if (p == NULL) {
		fprintf(stderr, "ENOMEM\n");
		return 1;
	}
	p->id = id;
	list_add_tail(&p->list, head);
	return 0;
}

static int build_field_order_list(const char *fields)
{
	int len, id;
	const char *sp, *ep, *p;
	char name[256];

	sp = fields != NULL ? fields : default_field_order;

	ep = sp + strlen(sp);
	do {
		if ((p = strchr(sp, ',')) == NULL)
			p = ep;
		len = p - sp + 1;
		if (len > sizeof(name) - 1) {
			fprintf(stderr, "Field name %s is unknown.\n", sp);
			return 1;
		}
		snprintf(name, len, "%s", sp);
		sp = p + 1;
		id = get_field_tbl_id(name);
		if (id == -1) {
			fprintf(stderr, "Unknown field: %s\n", name);
			return 1;
		}
		if (add_entry(&g_field_order_head, id))
			return 1;
	} while (sp < ep);

	return 0;
}

static int build_uuid_list(const char *guid)
{
	int done = 0;
	int id, n;

	// List all snapshots
	if (guid == NULL) {
		for (n = 0; n < g_di->nsnapshots; n++) {
			if (add_entry(&g_uuid_list_head, n))
				return 1;
		}
		return 0;
	}
	for (n = 0; n < g_di->nsnapshots; n++) {
		id = find_snapshot_by_guid(g_di, guid);
		if (id == -1) {
			fprintf(stderr, "Can't find snapshot by uuid %s\n", guid);
			return 1;
		}

		if (find_image_by_guid(g_di, guid) == NULL) {
			fprintf(stderr, "Can't find image by guid %s\n", guid);
			return 1;
		}

		if (n == g_di->nimages) {
			fprintf(stderr, "Inconsistency detected: snapshots > images\n");
			return 1;
		}

		if (add_entry(&g_uuid_list_head, id))
			return 1;

		guid = g_di->snapshots[id]->parent_guid;
		if (!strcmp(guid, NONE_UUID)) {
			done = 1;
			break;
		}
	}
	if (!done) {
		fprintf(stderr, "Inconsistency detected, base image not found\n");
		return 1;
	}

	return 0;
}

static void usage_snapshot_list(void)
{
	printf("ploop snapshot-list [-H] [-o field[,field...]] [-u <UUID>] DiskDescriptor.xml\n");
}

int plooptool_snapshot_list(int argc, char **argv)
{
	int c;
	int no_hdr = 0;
	struct id_entry *field_entry = NULL;
	struct id_entry * uuid_entry = NULL;
	const char *output = NULL;
	const char *guid =  NULL;
	struct option list_options[] =
	{
		{"no-header",	no_argument, NULL, 'H'},
		{"output",	required_argument, NULL, 'o'},
		{"help",	no_argument, NULL, 'h'},
		{"uuid",	required_argument, NULL, 'u'},
			{"id",	required_argument, NULL, 'u'},
		{"snapshot",  required_argument, NULL, 's'},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;
		c = getopt_long(argc, argv, "Hho:u:s",
				list_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'H':
			no_hdr = 1;
			break;
		case 'o' :
			output = optarg;
			break;
		case 'u':
			if (!is_valid_guid(optarg)) {
				fprintf(stderr, "Incorrect guid '%s' is specified.\n",
						optarg);
				return 1;
			}
			guid = optarg;
			break;
		case 's':
			g_snapshot_mode = 1;
			break;
		case 'h':
			usage_snapshot_list();
			return 0;
		default:
			usage_snapshot_list();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage_snapshot_list();
		return 1;
	}
	if (read_dd(&g_di, argv[0])) {
		fprintf(stderr, "failed to read %s: %s\n",
				argv[0], ploop_get_last_error());
		return 1;
	}

	if (build_field_order_list(output))
		return 1;

	if (build_uuid_list(guid))
		return 1;

	if (!no_hdr) {
		list_for_each(field_entry, &g_field_order_head, list) {
			printf(field_tbl[field_entry->id].fmt,
					field_tbl[field_entry->id].hdr);
			printf(" ");
		}
		printf("\n");
	}

	list_for_each(uuid_entry, &g_uuid_list_head, list) {
		if (g_snapshot_mode &&
				guidcmp(g_di->snapshots[uuid_entry->id]->guid, g_di->top_guid) == 0)
			continue;

		list_for_each(field_entry, &g_field_order_head, list) {
			g_last_field = ((void *)g_field_order_head.prev == (void *)field_entry);
			field_tbl[field_entry->id].print_fn(g_di->snapshots[uuid_entry->id]);
		}
	}
	return 0;
}
