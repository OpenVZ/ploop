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
#include <assert.h>

#include "ploop.h"

/* UUID generator. We use DCE style random UUIDs, it is easy. */

#define UUID_NLEN	16
#define UUID_FMT	"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"

struct helper_uuid_t {
	__u32 time_low;
	__u16 time_mid;
	__u16 time_hi_and_version;
	__u16 clock_seq;
	__u8  node[6];
};

static int uuid_new(unsigned char * uuid)
{
	int res;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return SYSEXIT_OPEN;
	res = read(fd, uuid, UUID_NLEN);
	close(fd);
	if (res < 0)
		return SYSEXIT_READ;

	if (res != UUID_NLEN) {
		errno = EINVAL;
		return SYSEXIT_READ;
	}

	/* Version: random */
	uuid[6] = (uuid[6] & 0x0F) | 0x40;

	/* Variant: DCE. The highest bit is 1, the next is 0.
	 * Note, three bits allcoated but value of the third
	 * is arbitrary.
	 */
	uuid[8] = (uuid[8] & 0x3F) | 0x80;

	return 0;
}

static void uuid_unpack(unsigned char *in, struct helper_uuid_t *uu)
{
	unsigned char *ptr = in;
	__u32 tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	tmp = (tmp << 8) | *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->time_low = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->time_mid = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->time_hi_and_version = tmp;

	tmp = *ptr++;
	tmp = (tmp << 8) | *ptr++;
	uu->clock_seq = tmp;

	memcpy(uu->node, ptr, 6);
}

static const char *uuid2str(unsigned char *in, char *out, int len)
{
	struct helper_uuid_t uuid;

	uuid_unpack(in, &uuid);
	snprintf(out, len, UUID_FMT,
			uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
			uuid.clock_seq >> 8, uuid.clock_seq & 0xFF,
			uuid.node[0], uuid.node[1], uuid.node[2],
			uuid.node[3], uuid.node[4], uuid.node[5]);
	return out;
}

static const char *prl_uuid2str(unsigned char *in, char *out, int len)
{
	assert(!(len < 39));

	out[0] = '{';
	uuid2str(in, out + 1, len - 2);
	out[37] = '}';
	out[38] = '\0';
	return out;
}

int ploop_uuid_generate(char *uuid, int len)
{
	int ret;
	unsigned char uu[16];

	ret = uuid_new(uu);
	if (ret) {
		ploop_err(errno, "Can't generate uuid");
		return ret;
	}
	prl_uuid2str(uu, uuid, len);
	return 0;
}

int gen_uuid_pair(char *uuid1, int len1, char *uuid2, int len2)
{
	int ret;

	ret = ploop_uuid_generate(uuid1, len1);
	if (ret)
		return ret;
	ret = ploop_uuid_generate(uuid2, len2);
	if (ret)
		return ret;
	return 0;
}
