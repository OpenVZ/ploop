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

#include "ploop.h"

const char *crypt_get_device_name(const char *part, char *out, int len)
{
	char *x = strdupa(part);

	snprintf(out, len, "%s", x);

	return out;
}

int crypt_init(const char *device, const char *keyid)
{
	ploop_log(0, "Crypt init");
	return 0;
}

int crypt_open(const char *device, const char *part, const char *keyid)
{
	ploop_log(0, "Crypt open %s [%s]", part, device);
	return 0;
}

int crypt_close(const char *part)
{
	ploop_log(0, "Crypt close");
	return 0;
}

int crypt_resize(const char *part)
{
	return 0;
}
