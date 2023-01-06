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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>
#include <errno.h>

#include "ploop.h"

static void free_image_data(struct ploop_image_data *data)
{
	if (data != NULL) {
		free(data->guid);
		free(data->file);
		free(data);
	}
}

static void free_volume(struct ploop_disk_images_data *di)
{
	if (di->vol != NULL) {
		free(di->vol->parent);
		free(di->vol->snap_guid);
		free(di->vol);
		di->vol = NULL;
	}
}

void free_encryption_data(struct ploop_disk_images_data *di)
{
	if (di->enc != NULL) {
		free(di->enc->keyid);
		free(di->enc);
		di->enc = NULL;
	}
}

int set_encryption_keyid(struct ploop_disk_images_data *di,
		const char *keyid)
{
	if (di->enc == NULL) {
		di->enc = calloc(1, sizeof(*di->enc));
		if (di->enc == NULL)
			return SYSEXIT_MALLOC;
	}

	free(di->enc->keyid);
	di->enc->keyid = strdup(keyid);
	if (di->enc->keyid == NULL) {
		free(di->enc);
		di->enc = NULL;
		return SYSEXIT_MALLOC;
	}

	return 0;
}

int store_encryption_keyid(struct ploop_disk_images_data *di,
		const char *keyid)
{
	int ret;
	char ddxml[PATH_MAX];

	ret = set_encryption_keyid(di, keyid);
	if (ret)
		return ret;

	get_disk_descriptor_fname(di, ddxml, sizeof(ddxml));
	return ploop_store_diskdescriptor(ddxml, di);
}

int ploop_set_encryption_keyid(struct ploop_disk_images_data *di,
		const char *keyid)
{
	int ret;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = store_encryption_keyid(di, keyid);

	ploop_unlock_dd(di);

	return ret;
}

int guidcmp(const char *p1, const char *p2)
{
	return strcasecmp(p1, p2);
}

int ploop_add_image_entry(struct ploop_disk_images_data *di, const char *fname, const char *guid)
{
	struct ploop_image_data **tmp;
	struct ploop_image_data *image;

	if (!is_valid_guid(guid)) {
		ploop_err(0, "ploop_add_image_entry: invalid guid %s",
				guid);
		return SYSEXIT_PARAM;
	}

	image = calloc(1, sizeof(struct ploop_image_data));
	if (image == NULL) {
		ploop_err(0, "calloc failed");
		return SYSEXIT_MALLOC;
	}

	tmp = realloc(di->images, sizeof(struct ploop_image_data *) * (di->nimages+1));
	if (tmp == NULL) {
		ploop_err(0, "realloc failed");
		free(image);
		return SYSEXIT_MALLOC;
	}
	di->images = tmp;
	image->guid = strdup(guid);
	image->file = strdup(fname);

	if (image->guid == NULL || image->file == NULL) {
		ploop_err(ENOMEM, "strdup failed");
		free_image_data(image);
		return SYSEXIT_MALLOC;
	}

	di->images[di->nimages] = image;
	di->nimages++;

	return 0;
}

static void free_snapshot_data(struct ploop_snapshot_data *data)
{
	if (data != NULL) {
		free(data->guid);
		free(data->parent_guid);
		free(data);
	}
}

int ploop_add_snapshot_entry(struct ploop_disk_images_data *di, const char *guid,
		const char *parent_guid, int temporary)
{
	struct ploop_snapshot_data **tmp;
	struct ploop_snapshot_data *data;

	if (!is_valid_guid(guid)) {
		ploop_err(0, "ploop_add_snapshot_entry: invalid guid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	if (!is_valid_guid(parent_guid)) {
		ploop_err(0, "ploop_add_snapshot_entry: invalid parent guid %s",
				parent_guid);
		return SYSEXIT_PARAM;
	}

	data = calloc(1, sizeof(struct ploop_snapshot_data));
	if (data == NULL) {
		ploop_err(ENOMEM, "calloc failed");
		return SYSEXIT_MALLOC;
	}

	tmp = realloc(di->snapshots, sizeof(struct ploop_snapshot_data *) * (di->nsnapshots+1));
	if (tmp == NULL) {
		ploop_err(ENOMEM, "realloc failed");
		free(data);
		return SYSEXIT_MALLOC;
	}
	di->snapshots = tmp;
	data->guid = strdup(guid);
	data->parent_guid = strdup(parent_guid);
	data->temporary = temporary;

	if (data->guid == NULL || data->parent_guid == NULL) {
		ploop_err(ENOMEM, "strdup failed");
		free_snapshot_data(data);
		return SYSEXIT_MALLOC;
	}

	di->snapshots[di->nsnapshots] = data;
	di->nsnapshots++;

	return 0;
}

int ploop_di_add_image(struct ploop_disk_images_data *di, const char *fname,
		const char *guid, const char *parent_guid)
{
	int ret;
	char *top_guid;

	top_guid = strdup(guid);
	if (top_guid == NULL)
		return SYSEXIT_MALLOC;

	ret = ploop_add_image_entry(di, fname, guid);
	if (ret) {
		free(top_guid);
		return ret;
	}

	ret = ploop_add_snapshot_entry(di, guid, parent_guid, 0);
	if (ret) {
		free(top_guid);
		return ret;
	}

	ploop_log(3, "Adding snapshot %s", guid);
	free(di->top_guid);
	di->top_guid = top_guid;

	return 0;
}

void ploop_di_change_guid(struct ploop_disk_images_data *di, const char *guid, const char *new_guid)
{
	int i;

	for (i = 0; i < di->nimages; i++)
		if (guidcmp(di->images[i]->guid, guid) == 0)
			strcpy(di->images[i]->guid, new_guid);
	for (i = 0; i < di->nsnapshots; i++) {
		if (guidcmp(di->snapshots[i]->guid, guid) == 0)
			strcpy(di->snapshots[i]->guid, new_guid);
		if (guidcmp(di->snapshots[i]->parent_guid, guid) == 0)
			strcpy(di->snapshots[i]->parent_guid, new_guid);
	}

	if (guidcmp(di->top_guid, guid) == 0)
		strcpy(di->top_guid, new_guid);
}

void ploop_di_set_temporary(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	i = find_snapshot_by_guid(di, guid);
	if (i != -1)
		di->snapshots[i]->temporary = 1;
}

struct ploop_disk_images_data *alloc_diskdescriptor(void)
{
	struct ploop_disk_images_data *p;

	p = calloc(1, sizeof(struct ploop_disk_images_data));
	if (p == NULL) {
		ploop_err(ENOMEM, "calloc failed");
		return NULL;
	}

	p->runtime = calloc(1, sizeof(struct ploop_disk_images_runtime_data));
	if (p->runtime == NULL)
		goto err;

	p->runtime->lckfd = -1;
	p->runtime->umount_timeout = PLOOP_UMOUNT_TIMEOUT;

	return p;
err:
	
	ploop_err(ENOMEM, "calloc failed");
	ploop_close_dd(p);

	return NULL;
}

void ploop_clear_dd(struct ploop_disk_images_data *di)
{
	int i;

	for (i = 0; i < di->nimages; i++)
		free_image_data(di->images[i]);

	free(di->images);
	di->images = NULL;
	di->nimages = 0;

	for (i = 0; i < di->nsnapshots; i++)
		free_snapshot_data(di->snapshots[i]);

	free(di->snapshots);
	di->snapshots = NULL;
	di->nsnapshots = 0;

	free(di->top_guid);
	di->top_guid = NULL;

	free(di->cbt_uuid);
	di->cbt_uuid = NULL;

	free_encryption_data(di);
	free_volume(di);
}

void ploop_close_dd(struct ploop_disk_images_data *di)
{
	if (di == NULL)
		return;

	ploop_clear_dd(di);

	free(di->runtime->xml_fname);
	free(di->runtime->component_name);
	free(di->runtime);
	free(di);
}

void ploop_free_diskdescriptor(struct ploop_disk_images_data *di)
{
	return ploop_close_dd(di);
}

/* Lock and read DiskDescriptor.xml
 * The ploop_open_dd() should be used to get ploop_disk_images_data
 */
int ploop_lock_dd(struct ploop_disk_images_data *di)
{
	if (!di || !di->runtime || !di->runtime->xml_fname) {
		ploop_err(0, "Unable to lock: DiskDescriptor.xml is not opened");
		return -1;
	}

	return ploop_lock_di(di);
}

static int detect_image_fmt(const char *image, int *image_fmt)
{
	int fd;
	size_t n;
	__u8 magic[16];

	fd = open(image, O_RDONLY|O_CLOEXEC);
	if (fd == -1) {
		ploop_err(errno, "Can't open %s", image);
		return SYSEXIT_OPEN;
	}

	n = read(fd, &magic, sizeof(magic));
	if (n != sizeof(magic)) {
		ploop_err(errno, "Can't read header magic %s", image);
		close(fd);
		return SYSEXIT_READ;
	}

	if (!memcmp(magic, SIGNATURE_STRUCTURED_DISK_V1, sizeof(magic)) ||
			!memcmp(magic, SIGNATURE_STRUCTURED_DISK_V2, sizeof(magic)))
		*image_fmt = PLOOP_FMT;
	else
		*image_fmt = QCOW_FMT;

	close(fd);
	return 0;
}

int ploop_open_dd(struct ploop_disk_images_data **di, const char *fname)
{
	int rc, image_fmt = -1;
	char path[PATH_MAX];
	struct ploop_disk_images_data *p;
	struct stat st;

	if (stat(fname, &st)) {
		ploop_err(errno, "Can't open %s", fname);
		return SYSEXIT_OPEN;
	}

	if (realpath(fname, path) == NULL) { 
		ploop_err(errno, "Can't resolve %s", fname);
		return SYSEXIT_DISKDESCR;
	}

	if (S_ISDIR(st.st_mode)) {
		int pathLength = strlen(path);
		strcpy(path + pathLength, "/"DISKDESCRIPTOR_XML);
		if (!access(path, F_OK))
			image_fmt = PLOOP_FMT;
		else {
			//possibly it is qcow format in the directory
			strcpy(path + pathLength, "/"QCOW_IMAGE_NAME);
			if (access(path, F_OK)) {
				ploop_err(0, "Can't open ploop image %s", fname);
				return SYSEXIT_DISKDESCR;
			}
			image_fmt = QCOW_FMT;
		}
	} else if (strcmp(get_basename(path), DISKDESCRIPTOR_XML) == 0) {
		image_fmt = PLOOP_FMT;
	} else {
		rc = detect_image_fmt(path, &image_fmt);
		if (rc)
			return rc;
	}

	p = alloc_diskdescriptor();
	if (p == NULL)
		return SYSEXIT_MALLOC;

	p->runtime->xml_fname = strdup(path);

	if (image_fmt == QCOW_FMT) {
		rc = qcow_open(path, p);
		if (rc)
			goto err;

		rc = ploop_di_add_image(p, path, TOPDELTA_UUID, NONE_UUID);
		if (rc)
			goto err;
	}

	*di = p;

	return 0;
err:
	ploop_close_dd(p);

	return rc;
}

int find_image_idx_by_file(struct ploop_disk_images_data *di, const char *file)
{
	int i;
	char image[PATH_MAX];

	/* First we need to normalize the image file name
	 * to be the same as in struct ploop_disk_images_data
	 * as filled in by ploop_read_dd() and parse_xml().
	 */
	if (file[0] != '/') {
		char basedir[PATH_MAX];

		get_basedir(di->runtime->xml_fname, basedir, sizeof(basedir));
		snprintf(image, sizeof(image), "%s%s", basedir, file);
	}
	else {
		snprintf(image, sizeof(image), "%s", file);
	}

	for (i = 0; i < di->nimages; i++) {
		if (!strcmp(image, di->images[i]->file))
			return i;
	}

	return -1;
}

int find_image_idx_by_guid(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	for (i = 0; i < di->nimages; i++) {
		if (!guidcmp(guid, di->images[i]->guid))
			return i;
	}
	return -1;
}

char *find_image_by_guid(struct ploop_disk_images_data *di, const char *guid)
{
	int idx;

	if (guid == NULL)
		return NULL;

	idx = find_image_idx_by_guid(di, guid);
	if (idx == -1)
		return NULL;

	return di->images[idx]->file;
}

int find_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	if (guid == NULL)
		return -1;
	for (i = 0; i < di->nsnapshots; i++)
		if (guidcmp(di->snapshots[i]->guid, guid) == 0)
			return i;
	return -1;
}

static void remove_data_from_array(void **array, int nelem, int id)
{
	int i;

	for (i = id; i < nelem -1; i++)
		array[i] = array[i+1];
}

const char * ploop_get_child_by_uuid(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	for (i = 0; i < di->nsnapshots; i++) {
		if (guidcmp(di->snapshots[i]->parent_guid, guid) == 0) {
			return di->snapshots[i]->guid;
		}
	}

	return NULL;
}

char *ploop_find_parent_by_guid(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	i = find_snapshot_by_guid(di, guid);
	if (i == -1)
		return NULL;
	if (guidcmp(di->snapshots[i]->parent_guid, NONE_UUID) == 0)
		return NULL;
	return di->snapshots[i]->parent_guid;
}

int ploop_get_child_count_by_uuid(struct ploop_disk_images_data *di, const char *guid)
{
	int i, n = 0;

	for (i = 0; i < di->nsnapshots; i++)
		if (guidcmp(di->snapshots[i]->parent_guid, guid) == 0)
			n++;
	return n;
}

int ploop_di_remove_image(struct ploop_disk_images_data *di, const char *guid,
		int renew_top_uuid, char **fname)
{
	int snap_id, image_id, nr_ch;
	struct ploop_image_data *image = NULL;
	struct ploop_snapshot_data *snapshot = NULL;

	snap_id = find_snapshot_by_guid(di, guid);
	if (snap_id == -1) {
		ploop_err(0, "Unable to find snapshot by uuid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	snapshot = di->snapshots[snap_id];

	image_id = find_image_idx_by_guid(di, guid);
	if (image_id == -1) {
		ploop_err(0, "Unable to find image by uuid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	nr_ch = ploop_get_child_count_by_uuid(di, guid);
	if (nr_ch != 0) {
		ploop_err(0, "Unable to delete snapshot %s: "
				"it has %d child%s",
				guid, nr_ch,
				(nr_ch == 1) ? "" : "ren");
		return SYSEXIT_PARAM;
	}
	if (guidcmp(snapshot->parent_guid, NONE_UUID) == 0) {
		ploop_err(0, "Unable to delete image %s: it is a base image",
				guid);
		return SYSEXIT_PARAM;
	}
	image = di->images[image_id];
	if (fname != NULL) {
		*fname = strdup(image->file);
		if (*fname == NULL)
			return SYSEXIT_MALLOC;
	}

	ploop_log(3, "del snapshot %s", guid);
	// update top uuid
	if (renew_top_uuid && guidcmp(guid, di->top_guid) == 0)
		ploop_di_change_guid(di, snapshot->parent_guid, TOPDELTA_UUID);

	remove_data_from_array((void**)di->snapshots, di->nsnapshots, snap_id);
	di->nsnapshots--;
	remove_data_from_array((void**)di->images, di->nimages, image_id);
	di->nimages--;

	free_snapshot_data(snapshot);
	free_image_data(image);

	return 0;
}

int ploop_di_delete_snapshot(struct ploop_disk_images_data *di,
		const char *guid, int merge_to_upper_delta, char **rm_fname)
{
	int id, child_id, image_id, child_image_id, nr_ch;
	struct ploop_snapshot_data *c, *p;

	id = find_snapshot_by_guid(di, guid);
	if (id == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	p = di->snapshots[id];

	child_id = find_snapshot_by_guid(di,
			ploop_get_child_by_uuid(di, guid));
	if (child_id == -1) {
		ploop_err(0, "Can't find child snapshot by uuid %s",
				guid);
		return SYSEXIT_PARAM;
	}
	c = di->snapshots[child_id];

	if (guidcmp(c->parent_guid, NONE_UUID) == 0) {
		ploop_err(0, "Can't merge snapshot %s: "
				"it is a base image", guid);
		return SYSEXIT_PARAM;
	}

	nr_ch = ploop_get_child_count_by_uuid(di, p->guid);
	if (nr_ch > 1) {
		ploop_err(0, "Can't merge to snapshot %s: "
				"it has %d children", p->guid, nr_ch);
		return SYSEXIT_PARAM;
	}

	image_id = find_image_idx_by_guid(di, p->guid);
	if (image_id == -1) {
		ploop_err(0, "Can't find image by uuid %s",
				p->guid);
		return SYSEXIT_PARAM;
	}

	child_image_id = find_image_idx_by_guid(di, c->guid);
	if (child_image_id == -1) {
		ploop_err(0, "Can't find image by uuid %s",
				c->guid);
		return SYSEXIT_PARAM;
	}

	if (rm_fname == NULL)
		return 0; // validate only

	if (merge_to_upper_delta) {
		*rm_fname = di->images[image_id]->file;
		di->images[image_id]->file = NULL;
	} else {
		*rm_fname = di->images[child_image_id]->file;
		di->images[child_image_id]->file = di->images[image_id]->file;
		di->images[image_id]->file = NULL;
	}

	/* update parent referrence */
	strcpy(c->parent_guid, p->parent_guid);

	free_snapshot_data(p);
	remove_data_from_array((void**)di->snapshots, di->nsnapshots, id);
	di->nsnapshots--;

	free_image_data(di->images[image_id]);
	remove_data_from_array((void**)di->images, di->nimages, image_id);
	di->nimages--;

	return 0;
}
