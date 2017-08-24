/*
 *  Copyright (c) 2008-2017 Parallels International GmbH.
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

#ifndef _LIBVOLUME_H_
#define _LIBVOLUME_H_

#pragma GCC visibility push(default)

struct ploop_volume_data {
        const char *m_path;
        const char *i_path;
};

struct ploop_volume_info {
	off_t size;
};

struct ploop_create_param;
#ifdef __cplusplus
extern "C" {
#endif

int ploop_volume_create(struct ploop_volume_data *vol,
         struct ploop_create_param *param);
int ploop_volume_clone(const char *src, struct ploop_volume_data *vol);
int ploop_volume_snapshot(const char *src, struct ploop_volume_data *vol);
int ploop_volume_delete(const char *path);
int ploop_volume_switch(const char *from, const char *to);
int ploop_volume_get_info(const char *path, struct ploop_volume_info *info);

#ifdef __cplusplus
}
#endif

#pragma GCC visibility pop
#endif
