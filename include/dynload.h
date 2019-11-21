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

#ifndef _PLOOP_DYNLOAD_H_
#define _PLOOP_DYNLOAD_H_

#include <sys/types.h>
#include <linux/types.h>

struct ploop_functions {
	/* 1.5 */
	void (*obsolete_1)(void);
	int (*set_component_name)(struct ploop_disk_images_data *di, const char *component_name);
	void (*obsolete_2)(void);
	char *(*get_base_delta_uuid)(struct ploop_disk_images_data *di);
	int (*get_top_delta_fname)(struct ploop_disk_images_data *di, char *out, int len);
	void (*obsolete_3)(void);
	int (*find_dev)(const char *component_name, const char *delta, char *buf, int size);
	int (*get_dev_by_mnt)(const char *path, char *buf, int size);
	int (*get_mnt_by_dev)(const char *dev, char *buf, int size);
	int (*get_dev)(struct ploop_disk_images_data *di, char *out, int len);
	int (*get_partition_by_mnt)(const char *path, char *buf, int size);
	int (*create_image)(struct ploop_create_param *param);
	int (*mount_image)(struct ploop_disk_images_data *di, struct ploop_mount_param *param);
	int (*mount_snapshot)(struct ploop_disk_images_data *di, struct ploop_mount_param *param);
	int (*umount)(const char *device, struct ploop_disk_images_data *di);
	int (*umount_image)(struct ploop_disk_images_data *di);
	int (*resize_image)(struct ploop_disk_images_data *di, struct ploop_resize_param *param);
	int (*convert_image)(struct ploop_disk_images_data *di, int mode, int flags);
	int (*get_info_by_descr)(const char *descr, struct ploop_info *info);
	int (*create_snapshot)(struct ploop_disk_images_data *di, struct ploop_snapshot_param *param);
	int (*merge_snapshot)(struct ploop_disk_images_data *di, struct ploop_merge_param *param);
	int (*switch_snapshot)(struct ploop_disk_images_data *di, const char *uuid, int flags);
	int (*delete_snapshot)(struct ploop_disk_images_data *di, const char *guid);
	int (*delete_top_delta)(struct ploop_disk_images_data *di);
	int (*find_top_delta_name_and_format)( const char *device, char *image, size_t image_size, char *format, size_t format_size);
	char *(*find_parent_by_guid)(struct ploop_disk_images_data *di, const char *guid);
	int (*uuid_generate)(char *uuid, int len);
	const char *(*get_last_error)(void);
	int (*set_log_file)(const char *fname);
	void (*set_log_level)(int level);
	void (*set_verbose_level)(int level);
	void (*cancel_operation)(void);
	int (*discard_get_stat)(struct ploop_disk_images_data *di, struct ploop_discard_stat *pd_stat);
	int (*discard)(struct ploop_disk_images_data *di, struct ploop_discard_param *param);
	/* 1.6 */
	int (*switch_snapshot_ex)(struct ploop_disk_images_data *di, struct ploop_snapshot_switch_param *param);
	int (*complete_running_operation)(const char *device);
	/* 1.7: no new functions */
	/* 1.8 */
	int (*is_large_disk_supported)(void);
	int (*get_spec)(struct ploop_disk_images_data *di, struct ploop_spec *spec);
	/* 1.9 */
	int (*get_devs)(struct ploop_disk_images_data *di, char **out[]);
	void (*free_array)(char *array[]);
	/* 1.10: no new functions */
	/* 1.11 */
	int (*replace_image)(struct ploop_disk_images_data *di, struct ploop_replace_param *param);
	int (*open_dd)(struct ploop_disk_images_data **di, const char *fname);
	void (*close_dd)(struct ploop_disk_images_data *di);
	int (*create_temporary_snapshot)(struct ploop_disk_images_data *di, struct ploop_tsnapshot_param *param, int *holder_fd);
	int (*is_mounted)(struct ploop_disk_images_data *di);
	/* 1.12 */
	int (*copy_receiver)(struct ploop_copy_receive_param *arg);
	int (*get_max_size)(unsigned int blocksize, unsigned long long *max);
	int (*create_dd)(const char *ddxml, struct ploop_create_param *param);
	/* 1.13 */
	int (*set_max_delta_size)(struct ploop_disk_images_data *di, unsigned long long size);
	/* VZ7 7.0.27 */
	int (*get_base_delta_fname)(struct ploop_disk_images_data *di, char *out, int len);
	int (*read_dd)(struct ploop_disk_images_data *di);
	/* padding for up to 64 pointers */
	int (*get_part)(struct ploop_disk_images_data *di, const char *dev, char *partname, int len);
	int (*set_encryption_keyid)(struct ploop_disk_images_data *di, const char *keyid);
	int (*encrypt_image)(struct ploop_disk_images_data *di, struct ploop_encrypt_param *param);
	int (*init_device)(const char *device, struct ploop_create_param *param);
	int (*resize_blkdev)(const char *device, off_t new_size);
	void (*set_umount_timeout)(struct ploop_disk_images_data *di, int timeout);
	int (*init_image)(struct ploop_disk_images_data *di, struct ploop_create_param *param);
	int (*drop_cbt)(struct ploop_disk_images_data *di);
	int (*clone_dd)(struct ploop_disk_images_data *di, const char *guid, const char *target);
	struct ploop_bitmap *(*get_used_bitmap_from_image)(struct ploop_disk_images_data *di, const char *guid);
	void (*release_bitmap)(struct ploop_bitmap *bmap);
	struct ploop_bitmap *(*get_tracking_bitmap_from_image)(struct ploop_disk_images_data *di, const char *guid);
	int (*get_fs_info)(const char *descr, struct ploop_fs_info *info, int size);
	int (*get_names)(const char *devname, char **names[], char **format, int *blocksize);
	int (*dm_message)(const char *devname, const char *msg, char **out);
	int (*resume_device)(const char *devname);
	int (*suspend_device)(const char *devname);
	void (*free_dm_message)(char *msg);
	void *padding[59];
}; /* struct ploop_functions */

__attribute__ ((visibility("default")))
void ploop_resolve_functions(struct ploop_functions * f);
#endif
