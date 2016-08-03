/*
 *  Copyright (C) 2005-2016 Parallels IP Holdings GmbH
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ploop.h"

#define CRYPT_BIN	"/usr/libexec/ploop/crypt.sh"

static const char *get_basename(const char *path)
{
	char *x = strrchr(path, '/');

	return x ? ++x : path;
}

const char *crypt_get_device_name(const char *part, char *out, int len)
{
	snprintf(out, len, "/dev/mapper/CRYPT-%s", get_basename(part));

	return out;
}

static char **get_param(const char *devname, const char *partname,
		const char *keyid)
{
	char x[256];
	int i = 0;
	char **env = (char **)malloc(sizeof(char *)* 4);

	if (env == NULL)
		return NULL;

	if (devname) {
		snprintf(x, sizeof(x), "DEVICE=%s", devname);
		env[i++] = strdup(x);
	}

	if (partname) {
		snprintf(x, sizeof(x), "DEVICE_NAME=%s", get_basename(partname));
		env[i++] = strdup(x);
	}
	if (keyid) {
		snprintf(x, sizeof(x), "KEYID=%s", keyid);
		env[i++] = strdup(x);
	}
	env[i] = NULL;

	return env;

}

static int do_crypt(const char *action, const char *devname,
		const char *partname, const char *keyid)
{
	int ret;
	char *const arg[] = {CRYPT_BIN,(char *) action, NULL};
	char **env = get_param(devname, partname, keyid);

	ploop_log(0, "Crypt %s", action);
	ret = run_prg_rc(arg, env, 0, NULL);

	ploop_free_array(env);

	return ret;
}

int crypt_init(const char *device, const char *keyid)
{
	return do_crypt("init", device, NULL, keyid);
}

int crypt_open(const char *device, const char *part, const char *keyid)
{
	return do_crypt("open", device, part, keyid);
}

int crypt_close(const char *part)
{
	return do_crypt("close", NULL, part, NULL);
}

int crypt_resize(const char *part)
{
	return do_crypt("resize", NULL, part, NULL);
}
