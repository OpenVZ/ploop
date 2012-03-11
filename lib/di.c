#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
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
		return SYSEXIT_NOMEM;
	}

	tmp = realloc(di->images, sizeof(struct ploop_image_data *) * (di->nimages+1));
	if (tmp == NULL) {
		ploop_err(0, "realloc failed");
		free(image);
		return SYSEXIT_NOMEM;
	}
	di->images = tmp;
	image->guid = strdup(guid);
	image->file = strdup(fname);

	if (image->guid == NULL || image->file == NULL) {
		ploop_err(ENOMEM, "strdup failed");
		free_image_data(image);
		return SYSEXIT_NOMEM;
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
		const char *parent_guid)
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
		return SYSEXIT_NOMEM;
	}

	tmp = realloc(di->snapshots, sizeof(struct ploop_snapshot_data *) * (di->nsnapshots+1));
	if (tmp == NULL) {
		ploop_err(ENOMEM, "realloc failed");
		free(data);
		return SYSEXIT_NOMEM;
	}
	di->snapshots = tmp;
	data->guid = strdup(guid);
	data->parent_guid = strdup(parent_guid);

	if (data->guid == NULL || data->parent_guid == NULL) {
		ploop_err(ENOMEM, "strdup failed");
		free_snapshot_data(data);
		return SYSEXIT_NOMEM;
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
		return SYSEXIT_NOMEM;

	ret = ploop_add_image_entry(di, fname, guid);
	if (ret) {
		free(top_guid);
		return ret;
	}

	ret = ploop_add_snapshot_entry(di, guid, parent_guid);
	if (ret) {
		free(top_guid);
		return ret;
	}

	ploop_log(3, "add snapshot %s", guid);
	free(di->top_guid);
	di->top_guid = top_guid;

	return 0;
}

void ploop_di_change_guid(struct ploop_disk_images_data *di, const char *guid, const char *new_guid)
{
	int i;

	for (i = 0; i < di->nimages; i++)
		if (strcmp(di->images[i]->guid, guid) == 0)
			strcpy(di->images[i]->guid, new_guid);
	for (i = 0; i < di->nsnapshots; i++) {
		if (strcmp(di->snapshots[i]->guid, guid) == 0)
			strcpy(di->snapshots[i]->guid, new_guid);
		if (strcmp(di->snapshots[i]->parent_guid, guid) == 0)
			strcpy(di->snapshots[i]->parent_guid, new_guid);
	}

	if (strcmp(di->top_guid, guid) == 0)
		strcpy(di->top_guid, new_guid);
}

struct ploop_disk_images_data *ploop_alloc_diskdescriptor(void)
{
	struct ploop_disk_images_data *p;

	p = calloc(1, sizeof(struct ploop_disk_images_data));
	if (p != NULL) {
		p->runtime = calloc(1, sizeof(struct ploop_disk_images_runtime_data));
		if (p->runtime == NULL) {
			free(p);
			return NULL;
		}
		p->runtime->lckfd = -1;
	}

	return p;
}

void ploop_free_diskdescriptor(struct ploop_disk_images_data *di)
{
	int i;

	if (di == NULL)
		return;

	for (i = 0; i < di->nimages; i++)
		free_image_data(di->images[i]);
	for (i = 0; i < di->nsnapshots; i++)
		free_snapshot_data(di->snapshots[i]);

	free(di->images);
	free(di->snapshots);
	free(di->top_guid);
	free(di->runtime->xml_fname);
	free(di->runtime);
	free(di);
}

static int find_image_by_name(struct ploop_disk_images_data *di, char *name)
{
	int i;
	char *n1, *n2;

	if ((n1 = strrchr(name, '/')) != NULL)
		n1++;
	else
		n1 = name;

	for (i = 0; i < di->nimages; i++) {
		if ((n2 = strrchr(di->images[i]->file, '/')) != NULL)
			n2++;
		else
			n2 = di->images[i]->file;
		if (strcmp(n1, n2) == 0)
			return i;
	}
	return -1;
}

static int find_image_idx_by_guid(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	for (i = 0; i < di->nimages; i++) {
		if (!strcmp(guid, di->images[i]->guid))
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
		if (strcmp(di->snapshots[i]->guid, guid) == 0)
			return i;
	return -1;
}

static void remove_data_from_array(void **array, int nelem, int id)
{
	int i;

	for (i = id; i < nelem -1; i++)
		array[i] = array[i+1];
}

int ploop_get_child_by_uuid(struct ploop_disk_images_data *di, const char *guid, char **child_guid)
{
	int i;

	for (i = 0; i < di->nsnapshots; i++) {
		if (strcmp(di->snapshots[i]->parent_guid, guid) == 0) {
			*child_guid = di->snapshots[i]->guid;
			return 0;
		}
	}
	return -1;
}

char *ploop_find_parent_by_guid(struct ploop_disk_images_data *di, const char *guid)
{
	int i;

	i = find_snapshot_by_guid(di, guid);
	if (i == -1)
		return NULL;
	if (strcmp(di->snapshots[i]->parent_guid, NONE_UUID) == 0)
		return NULL;
	return di->snapshots[i]->parent_guid;
}

int ploop_get_child_count_by_uuid(struct ploop_disk_images_data *di, const char *guid)
{
	int i, n = 0;

	for (i = 0; i < di->nsnapshots; i++)
		if (strcmp(di->snapshots[i]->parent_guid, guid) == 0)
			n++;
	return n;
}

int ploop_remove_images(struct ploop_disk_images_data *di, char **images, char ***images_out)
{
	int i, id;
	struct ploop_image_data *image;
	char **images2;

	images2 = calloc(di->nimages + 1, sizeof(char *));
	if (images2 == NULL)
		return SYSEXIT_MALLOC;
	*images_out = images2;

	for (i = 0; images[i] != NULL; i++) {
		id = find_image_by_name(di, images[i]);
		if (id == -1)
			continue;

		image = di->images[id];
		*images2++ = strdup(di->images[id]->file);

		remove_data_from_array((void**)di->images, di->nimages, id);
		di->nimages--;
		// update Snapshots
		id = find_snapshot_by_guid(di, image->guid);
		if (id != -1) {
			free_snapshot_data(di->snapshots[id]);
			remove_data_from_array((void**)di->snapshots, di->nsnapshots, id);
			di->nsnapshots--;
		}

		free_image_data(image);
	}
	free(di->top_guid);
	di->top_guid = NULL;

	return 0;
}

int ploop_di_remove_image(struct ploop_disk_images_data *di, const char *guid, char **fname)
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
	if (strcmp(snapshot->parent_guid, NONE_UUID) == 0) {
		ploop_err(0, "Unable to delete image %s: it is a base image",
				guid);
		return SYSEXIT_PARAM;
	}
	image = di->images[image_id];
	if (fname != NULL) {
		*fname = strdup(image->file);
		if (*fname == NULL)
			return SYSEXIT_NOMEM;
	}

	ploop_log(3, "del snapshot %s", guid);
	// update top uuid
	if (strcmp(guid, di->top_guid) == 0)
		strcpy(di->top_guid, snapshot->parent_guid);
	remove_data_from_array((void**)di->snapshots, di->nsnapshots, snap_id);
	di->nsnapshots--;
	remove_data_from_array((void**)di->images, di->nimages, image_id);
	di->nimages--;

	free_snapshot_data(snapshot);
	free_image_data(image);

	return 0;
}

int ploop_di_merge_image(struct ploop_disk_images_data *di, const char *guid, char **fname)
{
	int i, snap_id, image_id, nr_ch;
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
	nr_ch = ploop_get_child_count_by_uuid(di, snapshot->parent_guid);
	if (nr_ch > 1) {
		ploop_err(0, "Unable to merge snapshot %s: "
				"it has %d children",
				guid, nr_ch);
		return SYSEXIT_PARAM;
	}
	if (strcmp(snapshot->parent_guid, NONE_UUID) == 0) {
		ploop_err(0, "Unable to merge image %s: it is a base image",
				guid);
		return SYSEXIT_PARAM;
	}
	image = di->images[image_id];
	if (fname != NULL) {
		*fname = strdup(image->file);
		if (*fname == NULL)
			return SYSEXIT_NOMEM;
	}

	ploop_log(3, "merge snapshot %s -> %s",
			snapshot->guid, snapshot->parent_guid);
	/* Caller passed child_guid S2 to delete S1 (S1 <- S2 <- S3) (S2 <- S3)
	 * so it has merge S2 to S1 and we should update all S1 referrences to S2
	 */
	for (i = 0; i < di->nsnapshots; i++)
		if (strcmp(di->snapshots[i]->guid, snapshot->parent_guid) == 0)
			strcpy(di->snapshots[i]->guid, guid);
	for (i = 0; i < di->nimages; i++)
		if (strcmp(di->images[i]->guid, snapshot->parent_guid) == 0)
			strcpy(di->images[i]->guid, guid);
	remove_data_from_array((void**)di->snapshots, di->nsnapshots, snap_id);
	di->nsnapshots--;
	remove_data_from_array((void**)di->images, di->nimages, image_id);
	di->nimages--;

	free_snapshot_data(snapshot);
	free_image_data(image);

	return 0;
}
