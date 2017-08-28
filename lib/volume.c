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
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <libploop.h> 
#include "libvolume.h"
#include "ploop.h"

#define SNAP_DIR	"children"

static const char *get_ddxml_fname(const char *dir, char *buf, int size)
{
	snprintf(buf, size, "%s/" DISKDESCRIPTOR_XML, dir);

	return buf;
}

static int create_dir(const char *dir, const char *name)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%s", dir, name ?: "");
	ploop_log(0, "create %s", buf);
	if (mkdir(buf, 0700)) {
		ploop_err(errno, "Can't create %s", buf);
		return SYSEXIT_MKDIR;
	}

	return 0;
}

static int destroy_layout(const char *path, struct ploop_disk_images_data *d)
{
	char x[PATH_MAX];
	DIR *dir;
	struct dirent *de;

	dir = opendir(path);
	if (dir == NULL) {
		ploop_err(errno, "Cannot open %s", path);
		return SYSEXIT_SYS;
	}

	while ((de = readdir(dir)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		snprintf(x, sizeof(x), "%s/%s", path, de->d_name);
		if ((de->d_type == DT_DIR ? rmdir(x) : unlink(x)))
			ploop_err(errno, "Cannot remove %s", x);
	}
	closedir(dir);

	if (d)
		ploop_unlock_dd(d);

	if (rmdir(path)) {
		ploop_err(errno, "Cannot remove %s", path);
		return SYSEXIT_SYS;
	}

	return 0;
}

static int create_layout(const char *path)
{
	int rc;

	rc = create_dir(path, NULL);
	if (rc)
		return rc;

	rc = create_dir(path, SNAP_DIR);
	if (rc)
		destroy_layout(path, NULL);

	return rc;
}

static int create_snapshot_dd(const char *src, const char *dst,
		struct ploop_disk_images_data **d, const char *guid)
{
	int rc;
	char ddxml[PATH_MAX];

	get_ddxml_fname(src, ddxml, sizeof(ddxml));
	rc = ploop_open_dd(d, ddxml);
	if (rc)
		return rc;

	rc = read_dd(*d);
	if (rc)
		return rc;

	rc = ploop_di_remove_image(*d, (*d)->top_guid, 0, NULL);
	if (rc)
		return rc;

	(*d)->vol->ro = 1;
	free((*d)->top_guid);
	(*d)->top_guid = strdup(guid);

	free((*d)->runtime->xml_fname);
	(*d)->runtime->xml_fname = NULL;

	get_ddxml_fname(dst, ddxml, sizeof(ddxml));
	rc = ploop_store_diskdescriptor(ddxml, *d);

	return rc;
}

static int update_child_dd(const char *src, const char *parent,
		struct ploop_disk_images_data **d, const char *guid,
		int ro, char *ddxml, int size)
{
	int rc, i;

	get_ddxml_fname(src, ddxml, size);
	rc = ploop_open_dd(d, ddxml);
	if (rc)
		return rc;

	rc = read_dd(*d);
	if (rc)
		return rc;

	for (i = 0; i < (*d)->nimages; i++)
		if (guidcmp((*d)->images[i]->guid, (*d)->top_guid))
			(*d)->images[i]->alien = 1;

	for (i = 0; i < (*d)->nsnapshots; i++)
		if (guidcmp((*d)->snapshots[i]->guid, (*d)->top_guid))
			(*d)->snapshots[i]->alien = 1;

	free((*d)->vol->parent);
	(*d)->vol->parent = strdup(parent);
	free((*d)->vol->snap_guid);
	(*d)->vol->snap_guid = strdup(guid);
	(*d)->vol->ro = ro;

	free((*d)->runtime->xml_fname);
	(*d)->runtime->xml_fname = NULL;

	strcat(ddxml, ".vol.tmp");
	rc = ploop_store_diskdescriptor(ddxml, *d);

	return rc;
}


static int get_delta_storage_dir(struct ploop_disk_images_data *d, char *buf,
		int len)
{
	int rc;

	rc = get_delta_fname(d, get_base_delta_uuid(d), buf, len);
	if (rc)
		return rc;

	char *p = strrchr(buf, '/');
	if (p == NULL)
		p = buf;
	*p = '\0';

	return 0;
}

static int register_sibling(const char *parent, const char *child)
{
	char x[PATH_MAX];
	char dir[PATH_MAX];

	normalize_path(child, dir);

	snprintf(x, sizeof(x), "%s/"SNAP_DIR"/%s",
			parent, get_basename(dir));
	ploop_log(0, "register sibling %s -> %s", x, dir);
	if (symlink(dir, x)) {
		ploop_err(errno, "Cannot create symlink %s -> %s", x, dir);
		return SYSEXIT_CREAT;
	}

	return 0;
}

static int unregister_sibling(const char *parent, const char *child)
{
	char x[PATH_MAX];
	char dir[PATH_MAX];

	normalize_path(child, dir);

	snprintf(x, sizeof(x), "%s/"SNAP_DIR"/%s", parent, get_basename(dir));
	ploop_log(0, "unregister sibling %s (%s)", x, dir);
	if (unlink(x) && errno != ENOENT) {
		ploop_err(errno, "Cannot unlink %s", x);
		return SYSEXIT_UNLINK;
	}

	return 0;
}

static int delete_images(const char *path, struct ploop_disk_images_data *d)
{
	int i;

	for (i = 0; i < d->nimages; i++) {
		ploop_log(0, "remove %s", d->images[i]->file);
		if (unlink(d->images[i]->file) && errno != ENOENT)
			ploop_err(errno, "Cannot remove %s", d->images[i]->file);
	}

	return destroy_layout(path, d);
}

static int get_first_sibling(const char *path, char *out, int size)
{
	DIR *dir;
	char buf[PATH_MAX];
	struct dirent *de;
	int n = 0;

	snprintf(buf, sizeof(buf), "%s/"SNAP_DIR, path);
	errno = 0;
	dir = opendir(buf);
	if (dir == NULL) {
		if (errno == ENOENT)
			return 0;
		ploop_err(errno, "Cannot open %s", path);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (de->d_type != DT_LNK)
			continue;
		if (n == 0) {
			snprintf(out, size, "%s/%s", buf, de->d_name);
			char *f = realpath(out, NULL);
			if (f == NULL) {
				ploop_err(errno, "realpath(%s)", out);
				return -1;
			}
			
			snprintf(out, size, "%s", f);
			free(f);
		}
		n++;
	}
	closedir(dir);

	return n;
}

static int volume_delete_top(const char *path,
		struct ploop_disk_images_data *d_parent,
		struct ploop_disk_images_data *d)
{
	int rc;

	if (d_parent == NULL)
		return delete_images(path, d);

	char *fname = find_image_by_guid(d, d->top_guid);
	if (fname == NULL) {
		ploop_err(0, "Unable to find image by top_uuid %s in %s",
				d->top_guid, d->runtime->xml_fname);
		return SYSEXIT_PARAM;
	}

	ploop_log(3, "remove %s", fname);
	if (unlink(fname) && errno != ENOENT) {
		ploop_err(errno, "unlink %s", fname);
		return SYSEXIT_UNLINK;
	}

	rc = unregister_sibling(d->vol->parent, path);
	if (rc)
		return rc;

	rc = destroy_layout(path, d);
	if (rc)
		return rc;

	return 0;
}

static int volume_delete(const char *path, const char *child,
		struct ploop_disk_images_data *d_parent,
		struct ploop_disk_images_data *d)
{
	int rc;
	char ddxml[PATH_MAX];
	struct ploop_disk_images_data *d_child;
	char *snap_guid = NULL;

	get_ddxml_fname(child, ddxml, sizeof(ddxml) - 4);
	rc = ploop_open_dd(&d_child, ddxml);
	if (rc)
		return rc;

	rc = ploop_lock_dd(d_child);
	if (rc)
		goto err;

	free(d_child->vol->parent);
	d_child->vol->parent = NULL;
	if (d->vol->parent)
		d_child->vol->parent = strdup(d->vol->parent);

	if (d_child->vol->snap_guid != NULL) {
		snap_guid = strdupa(d_child->vol->snap_guid);
		free(d_child->vol->snap_guid);
		d_child->vol->snap_guid = NULL;
	}
	if (d->vol->snap_guid)
		d_child->vol->snap_guid = d->vol->snap_guid;

	rc = do_delete_snapshot(d_child, snap_guid);
	if (rc)
		goto err;

	unregister_sibling(path, child);
	if (d->vol->parent != NULL) {
		unregister_sibling(d->vol->parent, path);
		register_sibling(d->vol->parent, child);
	}

	rc = destroy_layout(path, d);
err:
	ploop_unlock_dd(d_child);
	ploop_close_dd(d_child);

	return rc;
}

int ploop_volume_delete(const char *path)
{
	int rc;
	struct ploop_disk_images_data *d = NULL, *d_parent = NULL;
	char buf[PATH_MAX];

	ploop_log(0, "Delete volume %s", path);
	get_ddxml_fname(path, buf, sizeof(buf));
	rc = ploop_open_dd(&d, buf);
	if (rc)
		return rc;

	rc = ploop_lock_dd(d);
	if (rc)
		goto err;

	rc = ploop_find_dev_by_cn(d, NULL, 1, buf, sizeof(buf));
	if (rc == -1) {
		rc = SYSEXIT_SYS;
		goto err;
	} else if (rc == 0) {
		ploop_err(0, "Image %s used by device %s",
				d->images[0]->file, buf);

		rc = SYSEXIT_PARAM;
		goto err;
	}

	if (d->vol->parent != NULL) {
		get_ddxml_fname(d->vol->parent, buf, sizeof(buf));
		rc = ploop_open_dd(&d_parent, buf);
		if (rc)
			goto err;

		rc = ploop_lock_dd(d_parent);
		if (rc)
			goto err;
	}

	int n = get_first_sibling(path, buf, sizeof(buf));
	if (n == -1) {
		rc = SYSEXIT_SYS;
		goto err;
	} else if (n == 1) {
		rc = volume_delete(path, buf, d_parent, d);
	} else if (n == 0) {
		rc = volume_delete_top(path, d_parent, d);
	} else {
		ploop_err(0, "Unable to delete %s: it has %d children",
				path, n);
		rc = SYSEXIT_PARAM;
	}


err:
	ploop_unlock_dd(d);
	ploop_close_dd(d);

	ploop_unlock_dd(d_parent);
	ploop_close_dd(d_parent);

	return rc;
}

int ploop_volume_create(struct ploop_volume_data *vol,
		struct ploop_create_param *param)
{
	int rc;

	if (vol->m_path == NULL)
		return SYSEXIT_PARAM;

	rc = create_layout(vol->m_path);
	if (rc)
		return rc;

	rc = ploop_create(vol->m_path, vol->i_path, param);
	if (rc) {
		destroy_layout(vol->m_path, NULL);
		return rc;
	}

	return 0;
}

static int create_volume(const char *src, const char *dst, const char *snap_dir,
		const char *guid, struct ploop_disk_images_data **d)
{
	int rc;
	char ddxml[PATH_MAX];
	char *dir;
	char fname[PATH_MAX];
	char snap_guid[UUID_SIZE];
	char file_guid[UUID_SIZE];

	if (guid == NULL) {
		ploop_err(0, "create_volume: parent snapshot guid is not specified");
		return SYSEXIT_PARAM;
	}

	get_ddxml_fname(src, ddxml, sizeof(ddxml));
	rc = ploop_open_dd(d, ddxml);
	if (rc)
		return rc;

	rc = read_dd(*d);
	if (rc)
		return rc;

	ploop_clear_dd(*d);
	(*d)->vol = calloc(1, sizeof(struct volume_data));
	if ((*d)->vol == NULL)
		return SYSEXIT_MALLOC;

	(*d)->vol->parent = strdup(src);
	(*d)->vol->snap_guid = strdup(guid);

	free((*d)->runtime->xml_fname);
	(*d)->runtime->xml_fname = NULL;

	rc = gen_uuid_pair(snap_guid, sizeof(snap_guid),
			file_guid, sizeof(file_guid));
	if (rc) {
		ploop_err(errno, "Can't generate uuid");
		return rc;
	}

	dir = realpath(snap_dir, NULL);
	if (dir == NULL) {
		ploop_err(errno, "Error in realpath(%s)", snap_dir);
		return SYSEXIT_CREAT;
	}

	snprintf(fname, sizeof(fname), "%s/%s.hds",
			dir, file_guid);
	free(dir);

	rc = ploop_di_add_image((*d), fname, snap_guid, guid);
	if (rc)
		return rc;

	int fd = create_snapshot_delta(fname, (*d)->blocksize, (*d)->size,
			PLOOP_FMT_UNDEFINED);
	if (fd < 0)
		return SYSEXIT_CREAT;
	close(fd);

	get_ddxml_fname(dst, ddxml, sizeof(ddxml));
	rc = ploop_store_diskdescriptor(ddxml, *d);
	if (rc && unlink(fname))
		ploop_err(errno, "Cannot unlink %s", fname);

	return rc;
}

int ploop_volume_clone(const char *src, struct ploop_volume_data *dst)
{
	int rc;
	struct ploop_disk_images_data *d_src = NULL, *d_dst = NULL;
	char guid[UUID_SIZE];
	char buf[PATH_MAX];

	ploop_log(0, "Clone %s to %s %s", src, dst->m_path, dst->i_path ? : "");
	get_ddxml_fname(src, buf, sizeof(buf));
	rc = ploop_open_dd(&d_src, buf);
	if (rc)
		return rc;

	rc = ploop_lock_dd(d_src);
	if (rc)
		goto err_unlock;

	if (!d_src->vol->ro) {
		rc = ploop_uuid_generate(guid, sizeof(guid));
		if (rc)
			goto err_unlock;
	} else
		snprintf(guid, sizeof(guid), "%s",
				d_src->vol->snap_guid ?: d_src->top_guid);

	rc = create_layout(dst->m_path);
	if (rc)
		goto err_unlock;

	rc = create_volume(src, dst->m_path, dst->i_path ?: dst->m_path, guid,
			&d_dst);
	if (rc)
		goto err1;

	if (!d_src->vol->ro) {
		rc = get_delta_storage_dir(d_src, buf, sizeof(buf));
		if (rc)
			goto err1;

		rc = do_create_snapshot(d_src, guid, buf, NULL, 0);
		if (rc)
			goto err1;
	}

	rc = register_sibling(src, dst->m_path);
	if (rc)
		goto err2;

err2:
	if (rc && !d_src->vol->ro)
		do_delete_snapshot(d_src, guid);
err1:
	if (rc)
		destroy_layout(dst->m_path, d_dst);

err_unlock:

	ploop_unlock_dd(d_src);
	ploop_close_dd(d_src);
	ploop_close_dd(d_dst);

	return rc;
}

int ploop_volume_get_info(const char *path, struct ploop_volume_info *info, int size)
{
	int rc;
	struct ploop_disk_images_data *d = NULL;
	char buf[PATH_MAX];
	struct stat st;
	struct ploop_volume_info tmp;

	get_ddxml_fname(path, buf, sizeof(buf));
	rc = ploop_open_dd(&d, buf);
	if (rc)
		return rc;

	rc = read_dd(d);
	if (rc)
		goto err;

	char *fname = find_image_by_guid(d, d->top_guid);
	if (fname == NULL) {
		ploop_err(0, "Unable to find image by top_uuid %s in %s\n",
				d->top_guid, d->runtime->xml_fname);
		rc = SYSEXIT_PARAM;
		goto err;
	}


	if (stat(fname, &st)) {
		ploop_err(errno, "Can't stat %s", fname);
		rc = -1;
		goto err;
	}

	tmp.size = st.st_size;
	memcpy(info, &tmp, size);

err:
	ploop_close_dd(d);
	return rc;
}

void ploop_volume_clear_tree(struct ploop_volume_list_head *head)
{
	struct ploop_volume_tree_element *vol;

	while (!SLIST_EMPTY(head)) {
		vol = SLIST_FIRST(head);
		SLIST_REMOVE_HEAD(head, next);
		ploop_volume_clear_tree(&vol->children);
		free(vol->path);
		free(vol);
	}
}

int ploop_volume_get_tree(const char *path, struct ploop_volume_list_head *out, int size)
{
	DIR *dir;
	char spath[PATH_MAX];
	char buf[PATH_MAX];
	struct dirent *de;
	int rc = 0;
	struct ploop_volume_tree_element *vol;
	struct ploop_volume_list_head *children, head;
	struct ploop_disk_images_data *d = NULL;

	SLIST_INIT(&head);

	get_ddxml_fname(path, buf, sizeof(buf));
	rc = ploop_open_dd(&d, buf);
	if (rc)
		return rc;

	rc = read_dd(d);
	if (rc)
		goto err;

	vol = calloc(1, sizeof(struct ploop_volume_tree_element));
	if (vol == NULL) {
		rc = SYSEXIT_MALLOC;
		goto err;
	}

	vol->path = strdup(path);
	children = &vol->children;

	SLIST_INSERT_HEAD(&head, vol, next);

	snprintf(spath, sizeof(spath), "%s/"SNAP_DIR, path);
	errno = 0;
	dir = opendir(spath);
	if (dir == NULL) {
		if (errno == ENOENT)
			goto exit;
		ploop_err(errno, "Cannot open %s", path);
		rc = SYSEXIT_SYS;
		goto err;
	}

	while ((de = readdir(dir)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (de->d_type != DT_LNK)
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", spath, de->d_name);
		char *f = realpath(buf, NULL);
		if (f == NULL) {
			ploop_err(errno, "realpath(%s)", buf);
			rc = -1;
			goto err;
		}

		vol = calloc(1, sizeof(struct ploop_volume_tree_element));
		if (vol == NULL) {
			free(f);
			rc = SYSEXIT_MALLOC;
			goto err;
		}

		vol->path = f;
		SLIST_INSERT_HEAD(children, vol, next);
	}

exit:
	SLIST_INSERT_HEAD(out, SLIST_FIRST(&head), next);
	SLIST_INIT(&head);

err:
	closedir(dir);
	ploop_volume_clear_tree(&head);
	ploop_close_dd(d);
	return rc;
}

int ploop_volume_snapshot(const char *src, struct ploop_volume_data *snap)
{
	int rc;
	struct ploop_disk_images_data *d = NULL, *d_src = NULL, *d_snap = NULL;
	char guid[UUID_SIZE];
	char buf[PATH_MAX];
	char tmp_ddxml[PATH_MAX];

	if (snap->m_path == NULL || src == NULL)
		return SYSEXIT_PARAM;

	rc = ploop_uuid_generate(guid, sizeof(guid));
	if (rc)
		return rc;

	ploop_log(0, "Create snapshot %s from %s uuid=%s",
			snap->m_path, src, guid);
	get_ddxml_fname(src, buf, sizeof(buf));
	rc = ploop_open_dd(&d, buf);
	if (rc)
		return rc;

	rc = ploop_lock_dd(d);
	if (rc)
		goto err_unlock;

	if (d->vol->ro) {
		ploop_err(0, "Creating a snapshot from snapshot is prohibited");
		rc = SYSEXIT_PARAM;
		goto err_unlock;
	}

	/* 1. create new snapshot layout */
	rc = create_layout(snap->m_path);
	if (rc)
		goto err_unlock;

	rc = register_sibling(snap->m_path, src);
	if (rc)
		goto err1;

	/* 2. make SRC as child from snapshot */
	rc = get_delta_storage_dir(d, buf, sizeof(buf));
	if (rc)
		goto err1;

	rc = do_create_snapshot(d, guid, buf, NULL, 0);
	if (rc)
		goto err1;

	rc = create_snapshot_dd(src, snap->m_path, &d_snap, guid);
	if (rc)
		goto err2;

	rc = update_child_dd(src, snap->m_path, &d_src, guid, 0,
			tmp_ddxml, sizeof(tmp_ddxml));
	if (rc)
		goto err2;

	/* 3. update children links */
	if (d->vol->parent != NULL) {
		rc = register_sibling(d->vol->parent, snap->m_path);
		if (rc)
			goto err2;

		rc = unregister_sibling(d->vol->parent, src);
		if (rc)
			goto err2;
	}

	get_ddxml_fname(src, buf, sizeof(buf));
	if (rename(tmp_ddxml, buf)) {
		ploop_err(errno, "Can't rename %s %s", tmp_ddxml, src);
		rc = SYSEXIT_RENAME;
	}
		
err2:
	if (rc)
		do_delete_snapshot(d, guid);

err1:
	if (rc) {	
		unregister_sibling(snap->m_path, src);
		destroy_layout(snap->m_path, d_snap);
	}

err_unlock:
	ploop_unlock_dd(d);
	ploop_close_dd(d);
	ploop_close_dd(d_src);
	ploop_close_dd(d_snap);

	return rc;
}

int ploop_volume_switch(const char *from, const char *to)
{
	int rc;
	struct ploop_disk_images_data *d_from = NULL, *d_to = NULL, *d = NULL;
	char buf[PATH_MAX];
	const char *snap_guid;
	char *old_delta = NULL;

	ploop_log(0, "Switch %s to %s", from, to);

	get_ddxml_fname(from, buf, sizeof(buf));
	rc = ploop_open_dd(&d_from, buf);
	if (rc)
		return rc;

	rc = ploop_lock_dd(d_from);
	if (rc)
		goto err_unlock;

	if (d_from->vol->ro) {
		ploop_err(0, "Switching from snapshot is prohibited");
		rc = SYSEXIT_PARAM;
		goto err_unlock;
	}

	rc = ploop_find_dev_by_cn(d_from, NULL, 1, buf, sizeof(buf));
	if (rc == -1) {
		rc = SYSEXIT_SYS;
		goto err_unlock;
	} else if (rc == 0) {
		ploop_err(0, "Image %s used by device %s",
				d_from->images[0]->file, buf);

		rc = SYSEXIT_PARAM;
		goto err_unlock;
	}

	int n = get_first_sibling(from, buf, sizeof(buf));
	if (n == -1) {
		rc = SYSEXIT_SYS;
		goto err_unlock;
	} else if (n != 0) {
		ploop_err(0, "Unable to switch from %s: it has %d children",
				from, n);
		rc = SYSEXIT_PARAM;
		goto err_unlock;
	}

        rc = get_delta_fname(d_from, get_top_delta_guid(d_from), buf, sizeof(buf));
        if (rc)
		goto err_unlock;

	old_delta = strdupa(buf);

	get_ddxml_fname(to, buf, sizeof(buf));
	rc = ploop_open_dd(&d_to, buf);
	if (rc)
		goto err_unlock;

	rc = ploop_lock_dd(d_to);
	if (rc)
		goto err_unlock;

	rc = get_delta_storage_dir(d_from, buf, sizeof(buf));
	if (rc)
		goto err_unlock;

	if (d_to->vol->ro)
		snap_guid = d_to->top_guid;
	else
		snap_guid = d_to->vol->snap_guid ?:
				ploop_find_parent_by_guid(d_to, d_to->top_guid);

	rc = create_volume(to, from, buf, snap_guid, &d);
	if (rc)
		goto err_unlock;

	unregister_sibling(d_from->vol->parent, from);
	rc = register_sibling(to, from);

	if (old_delta) {
		ploop_log(0, "remove old rw delta %s", old_delta);
		if (unlink(old_delta))
			ploop_err(errno, "Cannot remove %s", old_delta);
	}

err_unlock:
	ploop_unlock_dd(d_from);
	ploop_close_dd(d_from);

	ploop_unlock_dd(d_to);
	ploop_close_dd(d_to);

	ploop_close_dd(d);

	return rc;
}
