/*
* Copyright (c) 2005-2017 Parallels International GmbH.
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
*
* This file is part of Virtuozzo Core Libraries. Virtuozzo Core
* Libraries is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as published
* by the Free Software Foundation; either version 2.1 of the License, or
* (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library.  If not, see
* <http://www.gnu.org/licenses/> or write to Free Software Foundation,
* 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
*
* Our contact details: Virtuozzo IP Holdings GmbH, Vordergasse 59, 8200
* Schaffhausen, Switzerland; http://www.virtuozzo.com/.
*/

#ifndef CBT_H
#define CBT_H

#define CBT_DEFAULT_BLKSIZE 65536

struct ext_context;

void free_ext_context(struct ext_context *ctx);
struct ext_context *create_ext_context(void);
int check_ext(const char *image, int flags);
int read_optional_header_from_image(struct ext_context *ctx,
		const char *img_name, int flags);
int write_empty_cbt_to_image(const char *fname, const char *prev_fname,
                const __u8 *cbt_u);
int write_optional_header_to_image(int devfd, const char *img_name,
		void *or_data);
int send_dirty_bitmap_to_kernel(struct ext_context *ctx, int devfd,
		const char *img_name);
int save_dirty_bitmap(int devfd, struct delta *delta, off_t offcet, void *buf,
		__u32 *size, void *or_data, writer_fn wr, void *data);
int cbt_start(int devfd, const __u8 *uuid, __u32 blksize);
int cbt_stop(int devfd);
int cbt_get_dirty_bitmap_metadata(int devfd, __u8 *uuid, __u32 *blksize);
int cbt_get_and_clear(int devfd, void **data);
int cbt_set_uuid(int devfd, const __u8 *uuid);
int cbt_snapshot_prepare(int lfd, const unsigned char *cbt_uuid,
		void **or_data);
int cbt_snapshot(int lfd, const unsigned char *cbt_uuid, const char *prev_delta,
		void *or_data);
int cbt_dump(struct ploop_disk_images_data *di, const char *dev,
		const char *fname);
PL_EXT int ploop_move_cbt(const char *dst, const char *src);
PL_EXT int ploop_cbt_dump_info_from_image(const char *image);
PL_EXT int ploop_cbt_dump_info(struct ploop_disk_images_data *di);
PL_EXT int ploop_dump_cbt(struct ploop_disk_images_data *di, const char *fname);


#endif /* CBT_H */
