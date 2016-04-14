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

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>
#include <errno.h>
#include <unistd.h>

#include "ploop.h"

static xmlNodePtr find_child_node(xmlNode *cur_node, const char *elem)
{
	xmlNodePtr child;

	for (child = cur_node->xmlChildrenNode; child != NULL; child = child->next) {
		if (!xmlStrcmp(child->name, (const xmlChar *) elem) &&
				child->type == XML_ELEMENT_NODE)
		{
			return child;
		}
	}
	return NULL;
}

static xmlNodePtr seek(xmlNodePtr root, const char *elem)
{
	xmlNodePtr childNode = root;
	const char *path, *p;
	char nodename[128];
	int last = 0;

	path = elem;
	if (path[0] == '/')
		path++;
	if (path[0] == 0)
		return NULL;
	while (!last) {
		if ((p = strchr(path, '/')) == NULL) {
			p = path + strlen(path);
			last = 1;
		}
		snprintf(nodename, p - path + 1, "%s", path);
		childNode = find_child_node(childNode, nodename);
		if (childNode == NULL)
			return NULL;
		path = ++p;
	}
	return childNode;
}

static const char *get_element_txt(xmlNode *node)
{
	xmlNode *child;

	for (child = node->xmlChildrenNode; child; child = child->next) {
		if (child->type == XML_TEXT_NODE)
			return (const char*)child->content;
	}
	return NULL;
}

static int parse_ul(const char *str, __u64 *val)
{
	char *endptr;

	if (str == NULL)
		return -1;

	*val = strtoul(str, &endptr, 0);
	if (endptr != NULL && *endptr != '\0')
		return -1;
	return 0;
}

#define ERR(var, name)							\
	do {								\
		if (var == NULL) {					\
			ploop_err(0, "Invalid disk descriptor file "	\
				"format: '" name "' node not found");	\
			return -1;					\
		}							\
	} while (0)

static int parse_xml(const char *basedir, xmlNode *root_node, struct ploop_disk_images_data *di)
{
	xmlNode *cur_node, *node;
	char image[PATH_MAX];
	const char *data = NULL;
	const char *file = NULL;
	const char *guid = NULL;
	const char *parent_guid = NULL;
	__u64 val;
	int is_preallocated = 0;
	int mode = PLOOP_EXPANDED_MODE;
	int n;

	cur_node = seek(root_node, "/Disk_Parameters");
	ERR(cur_node, "/Disk_Parameters");

	node = seek(cur_node, "Disk_size");
	if (node != NULL) {
		data = get_element_txt(node);
		if (parse_ul(data, &val) == 0)
			di->size = val;
	}

	node = seek(cur_node, "Max_delta_size");
	if (node != NULL) {
		data = get_element_txt(node);
		if (parse_ul(data, &val) == 0)
			di->max_delta_size = val;
	}

	node = seek(cur_node, "Cylinders");
	if (node != NULL) {
		data = get_element_txt(node);
		if (parse_ul(data, &val) == 0)
			di->cylinders = (unsigned)val;
	}

	node = seek(cur_node, "Heads");
	if (node != NULL) {
		data = get_element_txt(node);
		if (parse_ul(data, &val) == 0)
			di->heads = (unsigned)val;
	}
	node = seek(cur_node, "Sectors");
	if (node != NULL) {
		data = get_element_txt(node);
		if (parse_ul(data, &val) == 0)
			di->sectors= (unsigned)val;
	}
	cur_node = seek(root_node, "/StorageData/Storage");
	ERR(cur_node, "/StorageData/Storage");
	for (n = 0; cur_node; cur_node = cur_node->next, n++) {
		if (cur_node->type != XML_ELEMENT_NODE)
			continue;

		if (n > 0) {
			ploop_err(0, "Invalid disk descriptor file format:"
				" splitted disk is not supported");
			return -1;
		}

		node = seek(cur_node, "Blocksize");
		if (node != NULL) {
			data = get_element_txt(node);
			if (parse_ul(data, &val)) {
				ploop_err(0, "Invalid disk descriptor file format:"
						" Invalid Blocksize %s", data);
				return -1;
			}
			di->blocksize = (unsigned)val;
		}
		node = seek(cur_node, "Preallocated");
		if (node != NULL) {
			data = get_element_txt(node);
			if (parse_ul(data, &val) != 0 || val > 1) {
				ploop_err(0, "Invalid disk descriptor file format:"
						" Invalid Preallocated tag");
				return -1;
			}
			is_preallocated = val;
		}
	}

	cur_node = seek(root_node, "/StorageData/Storage/Image");
	ERR(cur_node, "/StorageData/Storage/Image");
	for (; cur_node; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE)
			continue;
		guid = NULL;
		node = seek(cur_node, "GUID");
		if (node != NULL) {
			guid = get_element_txt(node);
			if (guid == NULL)
				guid = "";
		}
		ERR(guid, "GUID");
		node = seek(cur_node, "Type");
		if (node != NULL) {
			data = get_element_txt(node);
			if (data != NULL && !strcmp(data, "Plain"))
				mode = PLOOP_RAW_MODE;
		}
		file = NULL;
		node = seek(cur_node, "File");
		if (node != NULL) {
			file = get_element_txt(node);
			if (file != NULL) {
				if (basedir[0] != 0 && file[0] != '/')
					snprintf(image, sizeof(image), "%s%s", basedir, file);
				else
					snprintf(image, sizeof(image), "%s", file);
			}
		}
		ERR(file, "File");

		if (ploop_add_image_entry(di, image, guid))
			return -1;
	}

	if (is_preallocated) {
		if (mode == PLOOP_RAW_MODE) {
			ploop_err(0, "Invalid disk descriptor file format:"
				" Preallocated is not compatible with Plain image");
			return -1;
		}
		di->mode = PLOOP_EXPANDED_PREALLOCATED_MODE;
	} else {
		di->mode = mode;
	}

	cur_node = seek(root_node, "/Snapshots");
	ERR(cur_node, "/Snapshots");

	node = seek(cur_node, "TopGUID");
	if (node != NULL) {
		data = get_element_txt(node);
		ERR(data, "TopGUID");
		di->top_guid = strdup(data);
	}

	cur_node = seek(root_node, "/Snapshots/Shot");
	if (cur_node != NULL) {
		for (; cur_node; cur_node = cur_node->next) {
			int temporary = 0;

			if (cur_node->type != XML_ELEMENT_NODE)
				continue;

			guid = NULL;
			node = seek(cur_node, "GUID");
			if (node != NULL)
				guid = get_element_txt(node);
			ERR(guid, "Snapshots GUID");

			parent_guid = NULL;
			node = seek(cur_node, "ParentGUID");
			if (node != NULL)
				parent_guid = get_element_txt(node);

			ERR(parent_guid, "ParentGUID");

			node = seek(cur_node, "Temporary");
			if (node != NULL)
				temporary = 1;

			if (ploop_add_snapshot_entry(di, guid, parent_guid, temporary))
				return -1;
		}
	}
	return 0;
}
#undef ERR

void get_basedir(const char *fname, char *out, int len)
{
	char *p;

	strncpy(out, fname, len);

	p = strrchr(out, '/');
	if (p != NULL)
		*(++p) = '\0';
	else
		out[0] = '\0';
}

/* Convert to new format with constant TopGUID */
static int convert_disk_descriptor(struct ploop_disk_images_data *di)
{
	if (di->top_guid == NULL) {
		ploop_err(0, "Invalid DiskDescriptor.xml: TopGUID not found");
		return -1;
	}
	if (!guidcmp(di->top_guid, TOPDELTA_UUID))
		return 0;

	ploop_log(0, "DiskDescriptor.xml is in old format: converting");

	if ((find_image_by_guid(di, TOPDELTA_UUID) != NULL) ||
			(find_snapshot_by_guid(di, TOPDELTA_UUID) != -1)) {
		ploop_err(0, "Can't convert: %s is in use",
				TOPDELTA_UUID);
		return -1;
	}

	ploop_log(0, "Changing %s to %s",
			di->top_guid, TOPDELTA_UUID);
	ploop_di_change_guid(di, di->top_guid, TOPDELTA_UUID);

	return 0;
}

static int validate_disk_descriptor(struct ploop_disk_images_data *di)
{
	if (di->nimages == 0) {
		ploop_err(0, "No images found in %s",
				di->runtime->xml_fname);
		return -1;
	}
	if (!is_valid_blocksize(di->blocksize)) {
		ploop_err(0, "Invalid block size %d", di->blocksize);
		return -1;
	}
	// FIXME: compatibility issue have to be removed before BETA
	if (di->nimages != di->nsnapshots) {
		int ret;

		ret = ploop_add_snapshot_entry(di, TOPDELTA_UUID, NONE_UUID, 0);
		if (ret)
			return ret;
		if (di->top_guid == NULL)
			di->top_guid = strdup(TOPDELTA_UUID);
	}
	if (di->top_guid == NULL && find_snapshot_by_guid(di, TOPDELTA_UUID) != -1) {
		/* Parallels VM compatibility.
		 * The top delta is hardcoded {5fbaabe3-6958-40ff-92a7-860e329aab41}
		 */
		di->top_guid = strdup(TOPDELTA_UUID);
	}


	if (!is_valid_guid(di->top_guid)) {
		ploop_err(0, "Validation of %s failed: invalid top delta %s",
				di->runtime->xml_fname, di->top_guid);
		return -1;
	}

	int i = find_snapshot_by_guid(di, di->top_guid);
	if (i == -1) {
		ploop_err(0, "Validation of %s failed: top delta %s is not found",
				di->runtime->xml_fname, di->top_guid);
		return -1;
	}

	if (di->snapshots[i]->temporary) {
		ploop_err(0, "Validation of %s failed: top delta %s is temporary",
				di->runtime->xml_fname, di->top_guid);
		return -1;
	}

	if (di->nimages != di->nsnapshots) {
		ploop_err(0, "Validation of %s failed: images(%d) != snapshots(%d)",
				di->runtime->xml_fname, di->nimages, di->nsnapshots);
		return -1;
	}
	return 0;
}

int ploop_read_dd(struct ploop_disk_images_data *di)
{
	int ret;
	char basedir[PATH_MAX];
	const char *fname;
	struct stat st;
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;

	LIBXML_TEST_VERSION

	if (!di || !di->runtime || !di->runtime->xml_fname) {
		ploop_err(0, "DiskDescriptor.xml is not opened");
		return -1;
	}
	ploop_clear_dd(di);

	fname = di->runtime->xml_fname;
	if (stat(fname, &st)) {
		ploop_err(errno, "Can't stat %s", fname);
		return -1;
	}

	/* workaround libxml2 SIGSEGV on empty document */
	if (st.st_size == 0) {
		ploop_err(0, "Can't parse %s", fname);
		return -1;
	}

	doc = xmlReadFile(fname, NULL, 0);
	if (doc == NULL) {
		ploop_err(0, "Can't parse %s", fname);
		return -1;
	}
	root_element = xmlDocGetRootElement(doc);

	get_basedir(fname, basedir, sizeof(basedir));
	ret = parse_xml(basedir, root_element, di);
	if (ret == 0)
		ret = validate_disk_descriptor(di);

	xmlFreeDoc(doc);

	return ret;
}

int ploop_read_disk_descr(struct ploop_disk_images_data **di, const char *file)
{
	int ret;

	ret = ploop_open_dd(di, file);
	if (ret)
		return ret;

	return ploop_read_dd(*di);
}

int normalize_image_name(const char *basedir, const char *image, char *out, int len)
{
	const char *p;
	int n;

	n = strlen(basedir);
	while (basedir[n-1] == '/')
		n--;
	p = image;
	if ((strncmp(image, basedir, n) == 0) && (image[n] == '/'))
		p += n + 1;

	snprintf(out, len, "%s", p);

	return 0;
}

int ploop_store_diskdescriptor(const char *fname, struct ploop_disk_images_data *di)
{
	int i, rc = -1;
	xmlTextWriterPtr writer = NULL;
	xmlDocPtr doc = NULL;
	char tmp[PATH_MAX];
	char basedir[PATH_MAX];
	FILE *fp = NULL;

	ploop_log(0, "Storing %s", fname);

	if (convert_disk_descriptor(di))
		return -1;

	if (di->runtime->xml_fname == NULL)
		di->runtime->xml_fname = strdup(fname);

	get_basedir(fname, tmp, sizeof(tmp));
	if (tmp[0] == '\0')
		strcpy(tmp, "./");

	if (realpath(tmp, basedir) == NULL) {
		ploop_err(errno, "Can't resolve %s", tmp);
		return -1;
	}

	doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
	if (doc == NULL) {
		ploop_err(0, "Error creating xml document tree");
		return -1;
	}

	/* Create a new XmlWriter for DOM tree, with no compression. */
	writer = xmlNewTextWriterTree(doc, NULL, 0);
	if (writer == NULL) {
		ploop_err(0, "Error creating xml writer");
		goto err;
	}

	/* Start the document with the xml default for the version,
	 * encoding ISO 8859-1 and the default for the standalone
	 * declaration. */
	rc = xmlTextWriterStartDocument(writer, NULL, NULL, NULL);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterStartDocument");
		goto err;
	}
	rc = xmlTextWriterStartElement(writer, BAD_CAST "Parallels_disk_image");
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterStartDocument");
		goto err;
	}
	/*********************************************
	 *	Disk_Parameters
	 ********************************************/
	rc = xmlTextWriterStartElement(writer, BAD_CAST "Disk_Parameters");
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Disk_Parameters");
		goto err;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Disk_size", "%llu", di->size);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Disk_size");
		goto err;
	}

	if (di->max_delta_size != 0) {
		rc = xmlTextWriterWriteFormatElement(writer,
				BAD_CAST "Max_delta_size", "%llu", di->max_delta_size);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter Max_delta_size");
			goto err;
		}
	}

	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Cylinders", "%u", di->cylinders);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Cylinders");
		goto err;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Heads", "%u", di->heads);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Heads");
		goto err;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Sectors", "%llu",
			di->size /(di->cylinders * di->heads));
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Sectors");
		goto err;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Padding", "%u", 0);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Padding");
		goto err;
	}

	/* Close   Disk_Parameters */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterEndElement");
		goto err;
	}
	/****************************************
	 * StorageData
	 ****************************************/
	rc = xmlTextWriterStartElement(writer, BAD_CAST "StorageData");
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter StorageData");
		goto err;
	}
	/* Start an element named "Storage" as child of StorageData. */
	rc = xmlTextWriterStartElement(writer, BAD_CAST "Storage");
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Storage");
		goto err;
	}
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "Start",  BAD_CAST "0");
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Start");
		goto err;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "End", "%llu", di->size);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter End");
		goto err;
	}
	rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Blocksize", "%d",
			di->blocksize);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Blocksize");
		goto err;
	}
	if (di->mode == PLOOP_EXPANDED_PREALLOCATED_MODE) {
		rc = xmlTextWriterWriteElement(writer, BAD_CAST "Preallocated",
				BAD_CAST "1");
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter Preallocated");
			goto err;
		}
	}
	/****************************************
	 *	Images
	 ****************************************/
	for (i = 0; i < di->nimages; i++) {
		rc = xmlTextWriterStartElement(writer, BAD_CAST "Image");
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter Image");
			goto err;
		}

		rc = xmlTextWriterWriteElement(writer, BAD_CAST "GUID",
				BAD_CAST di->images[i]->guid);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter GUID");
			goto err;
		}
		rc = xmlTextWriterWriteElement(writer, BAD_CAST "Type",
			BAD_CAST (di->mode == PLOOP_RAW_MODE ? "Plain" : "Compressed"));
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter Type");
			goto err;
		}

		normalize_image_name(basedir, di->images[i]->file, tmp, sizeof(tmp));
		rc = xmlTextWriterWriteElement(writer, BAD_CAST "File",
				BAD_CAST tmp);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter File");
			goto err;
		}

		/*  Close  Image */
		rc = xmlTextWriterEndElement(writer);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriterEndElement");
			goto err;
		}
	}

	/* Close Storage */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterEndElement");
		goto err;
	}
	/* Close StorageData. */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterEndElement");
		goto err;
	}
	/****************************************
	 *	Snapshots
	 ****************************************/
	rc = xmlTextWriterStartElement(writer, BAD_CAST "Snapshots");
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriter Snapshots");
		goto err;
	}

	if (di->top_guid != NULL) {
		rc = xmlTextWriterWriteElement(writer, BAD_CAST "TopGUID",
				BAD_CAST di->top_guid);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter TopGUID");
			goto err;
		}
	}

	/****************************************
	 *      Shot
	 ****************************************/
	for (i = 0; i < di->nsnapshots; i++) {
		rc = xmlTextWriterStartElement(writer, BAD_CAST "Shot");
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter Shot");
			goto err;
		}

		rc = xmlTextWriterWriteElement(writer, BAD_CAST "GUID",
				BAD_CAST di->snapshots[i]->guid);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriterWrite GUID");
			goto err;
		}
		rc = xmlTextWriterWriteElement(writer, BAD_CAST "ParentGUID",
				BAD_CAST di->snapshots[i]->parent_guid);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriter ParentGUID");
			goto err;
		}

		if (di->snapshots[i]->temporary) {
			rc = xmlTextWriterWriteElement(writer, BAD_CAST "Temporary",  BAD_CAST "");
			if (rc < 0) {
				ploop_err(0, "Error at xmlTextWriter Temporary");
				goto err;
			}
		}

		/*  Close Shot */
		rc = xmlTextWriterEndElement(writer);
		if (rc < 0) {
			ploop_err(0, "Error at xmlTextWriterEndElement");
			goto err;
		}
	}
	/* Close Snapshots */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterEndElement");
		goto err;
	}

	/* Close Parallels_disk_image */
	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) {
		ploop_err(0, "Error at xmlTextWriterEndElement");
		goto err;
	}
	xmlFreeTextWriter(writer);
	writer = NULL;

	snprintf(tmp, sizeof(tmp), "%s.tmp", fname);
	fp = fopen(tmp, "w+");
	if (fp == NULL) {
		ploop_err(errno, "Can't open %s", tmp);
		goto err;
	}

	rc = xmlDocFormatDump(fp, doc, 1);
	if (rc < 0) {
		ploop_err(0, "Error at xmlDocFormatDump %s", tmp);
		goto err;
	}

	rc = fsync(fileno(fp));
	if (rc) {
		ploop_err(errno, "Failed to sync %s", tmp);
		goto err;
	}
	fclose(fp);
	fp = NULL;

	rc = rename(tmp, fname);
	if (rc < 0) {
		ploop_err(errno, "Can't rename %s to %s", tmp, fname);
		goto err;
	}

	rc = 0;
err:
	if (fp)
		fclose(fp);

	if (writer)
		xmlFreeTextWriter(writer);
	if (doc)
		xmlFreeDoc(doc);
	if (rc)
		return SYSEXIT_DISKDESCR;

	return 0;
}
