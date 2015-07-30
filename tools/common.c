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

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#include "ploop.h"

int parse_size(const char *opt, off_t *sz, const char *name)
{
	__u64 val;
	char * endptr;

	val = strtoul(opt, &endptr, 0);

	if (opt == endptr)
		goto err;

	if (strlen(endptr) > 1)
		goto err;

	switch (*endptr) {
	case 'T': case 't':
		if (val >= ~0ULL/(1024ULL*1024*1024*1024/SECTOR_SIZE))
			goto large;
		val *= 1024ULL*1024*1024*1024/SECTOR_SIZE;
		*sz = val;
		break;
	case 'G': case 'g':
		if (val >= ~0ULL/(1024*1024*1024/SECTOR_SIZE))
			goto large;
		val *= 1024*1024*1024/SECTOR_SIZE;
		*sz = val;
		break;
	case 'M': case 'm':
		if (val >= ~0ULL/(1024*1024/SECTOR_SIZE))
			goto large;
		val *= 1024*1024/SECTOR_SIZE;
		*sz = val;
		break;
	case 'K': case 'k':
		if (val >= ~0ULL/(1024/SECTOR_SIZE))
			goto large;
		val *= 1024/SECTOR_SIZE;
		*sz = val;
		break;
	case 0:
		*sz = (off_t)val;
		break;
	default:
		goto err;
	}

	if (val >= (0xffffffffULL << PLOOP1_SECTOR_LOG))
		goto large;

	return 0;

err:
	fprintf(stderr, "ERROR: Invalid argument for option %s: %s\n", name, opt);
	return -1;

large:
	fprintf(stderr, "ERROR: Too large value for option %s: %s\n", name, opt);
	return -1;
}

int parse_format_opt(const char *opt)
{
	if (strcmp(opt, "raw") == 0)
		return PLOOP_RAW_MODE;
	else if ((strcmp(opt, "ploop1") == 0) ||
		 (strcmp(opt, "expanded") == 0))
		return PLOOP_EXPANDED_MODE;
	else if (strcmp(opt, "preallocated") == 0)
		return PLOOP_EXPANDED_PREALLOCATED_MODE;

	fprintf(stderr, "Bad -f argument: %s\n", opt);
	return -1;
}

char *parse_uuid(const char *opt)
{
	char buf[] = "{fbcdf284-5345-416b-a589-7b5fcaa87673}";
	const char *id = opt;

	if (!id)
		goto err;
	if (id[0] != '{' && strlen(id) == 36) {
		/* as a courtesy, add missing brackets */
		memcpy(buf+1, id, 36);
		id = buf;
	}
	if (!is_valid_guid(id))
		goto err;

	return strdup(id);

err:
	fprintf(stderr, "Incorrect uuid specified: %s\n", opt);
	return NULL;

}

int is_xml_fname(const char *fname)
{
	const char *p;
	if (fname == NULL)
		return 0;

	p = strrchr(fname, '.');
	return (p != NULL && !strcmp(p, ".xml"));
}

static void cancel_callback(int sig)
{
	ploop_cancel_operation();
}

void init_signals(void)
{
	struct sigaction act = {};

	sigemptyset(&act.sa_mask);
	act.sa_handler = cancel_callback;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
}
