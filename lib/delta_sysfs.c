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
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>

#include "ploop.h"

const char *get_full_devname(const char *devname, char *out, int size)
{
	if (devname[0] != '/')
		snprintf(out, size, "/dev/mapper/%s", devname);
	else
		snprintf(out, size, "%s", devname);
	return out;
}

const char *get_dm_name(const char *devname, char *out, int size)
{
	char b[512];

	snprintf(out, size, "/dev/%s", devname);

	snprintf(b, sizeof(b), "/sys/class/block/%s/dm/name", devname);
	if (access(b, F_OK) == 0 && read_line(b, b, sizeof(b)) == 0)
		get_full_devname(b, out, size);

	return out;
}

int get_dev_from_sys(const char *devname, const char *type, char *out,
		int len)
{
	char buf[PATH_MAX];
	struct stat st;
	char **devs = NULL;

	if (stat(get_full_devname(devname, buf, sizeof(buf)), &st) == -1) {
		ploop_err(errno, "Can not stat %s", devname);
		return -1;
	}

	snprintf(buf, sizeof(buf), "/sys/dev/block/%d:%d/%s",
			major(st.st_rdev), minor(st.st_rdev), type);
	if (get_dir_entry(buf, &devs)) {
		ploop_free_array(devs);
		return -1;
	}

	if (devs == NULL)
		return 1;

	get_dm_name(devs[0], out, len);

	ploop_free_array(devs);

	return 0;
}

int ploop_find_top_delta_name_and_format(const char *device, char *image,
		size_t image_size, char *format, size_t format_size)
{
	char *i = NULL;
	int f;
	int rc;

	rc = get_image_param_online(NULL, device, &i, NULL, NULL, &f, NULL);
	if (rc)
		return rc;

	snprintf(image, image_size, "%s", i);
	free(i);
	snprintf(format, format_size, "%d", f);

	return 0;
}

int ploop_get_names(const char *device, char **names[])
{
	int rc, i;
	char **n = NULL;
	const int D = 32;

	for (i = 0; i < 0xffff; i++) {
		if ((i % D) == 0) {
			char **t = realloc(n, (i + D + 2) * sizeof(char *));
			if (t == NULL)
				return SYSEXIT_MALLOC;
			n = t;
		}
		rc = dm_get_delta_name(device, i, &n[i]);
		if (rc == -1) {
			rc = SYSEXIT_SYS;
			goto err;
		} else if (rc == 1)
			break;

		n[i + 1] = NULL;
	}

	if (names)
		*names = n;
	else
		ploop_free_array(n);

	return 0;

err:
	ploop_free_array(n);
	return rc;
}

/* Finds a level for a given delta in a running ploop device.
 *
 * Parameters:
 *   device	ploop device
 *   delta	delta file name
 *   *level	pointer to store found level to
 *
 * Returns:
 *   0		found
 *   SYSEXIT_*	error (SYSEXIT_PARAM if not found)
 */
int find_level_by_delta(const char *device, const char *delta, int *level)
{
	int i, top_level;
	struct stat st1, st2;

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	if (stat(delta, &st1)) {
		ploop_err(errno, "Can't stat %s", delta);
		return SYSEXIT_FSTAT;
	}
	if (ploop_get_attr(device, "top", &top_level))
		return SYSEXIT_SYSFS;

	for (i = 0; i <= top_level; i++) {
		char nbuf[PATH_MAX];

		if (ploop_get_delta_attr_str(device, i, "image",
					nbuf, sizeof(nbuf)))
			return SYSEXIT_SYSFS;

		if (stat(nbuf, &st2)) {
			ploop_err(errno, "Can't stat %s", nbuf);
			return SYSEXIT_FSTAT;
		}

		if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
			*level = i;
			return 0;
		}
	}

	return SYSEXIT_PARAM; /* not found */
}

int ploop_get_attr(const char * device, const char * attr, int * res)
{
	char path[PATH_MAX];
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(path, sizeof(path), "/sys/block/%s/pstate/%s", device, attr);

	if (read_line(path, nbuf, sizeof(nbuf)))
		return -1;

	if (sscanf(nbuf, "%d", res) != 1) {
		ploop_err(0, "Unexpected format of %s: %s", path, nbuf);
		return -1;
	}
	return 0;
}

int ploop_get_delta_attr_str(const char *device, int level, const char *attr,
		char *out, int len)
{
	char path[PATH_MAX];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(path, sizeof(path), "/sys/block/%s/pdelta/%d/%s",
			device,	level, attr);

	if (read_line(path, out, len))
		return -1;

	return 0;
}

int ploop_get_delta_attr(const char *device, int level, const char *attr, int *res)
{
	char path[PATH_MAX];
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(path, sizeof(path), "/sys/block/%s/pdelta/%d/%s",
			device,	level, attr);

	if (read_line(path, nbuf, sizeof(nbuf)))
		return -1;

	if (sscanf(nbuf, "%d", res) != 1) {
		ploop_err(0, "Unexpected format of %s: %s", path, nbuf);
		return -1;
	}

	return 0;
}

int ploop_get_size(const char * device, off_t * res)
{
	int fd;

	fd = open(device, O_RDONLY|O_CLOEXEC, 0);
	if (fd == -1) {
		ploop_err(errno, "Can't open %s", device);
		return SYSEXIT_OPEN;
	}
	if (ioctl_device(fd, BLKGETSIZE64, res)) {
		close(fd);
		return SYSEXIT_DEVIOC;
	}
	*res >>= PLOOP1_SECTOR_LOG;
	close(fd);

	return 0;
}

static int get_dev_num(const char *path, dev_t *dev_num)
{
	char nbuf[4096];
	int maj, min;

	if (read_line(path, nbuf, sizeof(nbuf)))
		return -1;

	if (sscanf(nbuf, "%d:%d", &maj, &min) != 2) {
		ploop_err(0, "Unexpected format of %s: %s", path, nbuf);
		return -1;
	}
	*dev_num = makedev(maj, min);
	return 0;
}

int get_dev_by_name(const char *device, dev_t *dev)
{
	char nbuf[4096];

	snprintf(nbuf, sizeof(nbuf), "/sys/block/%s/dev", basename(device));

	return get_dev_num(nbuf, dev);
}

static int get_dev_start(const char *path, __u32 *start)
{
	char nbuf[4096];

	if (read_line(path, nbuf, sizeof(nbuf)))
		return -1;

	if (sscanf(nbuf, "%u", start) != 1) {
		ploop_err(0, "Unexpected format of %s: %s", path, nbuf);
		return -1;
	}

	return 0;
}

int append_array_entry(const char *entry, char **ar[], int nelem)
{
	char **t;

	if (nelem == 0)
		nelem++;
	t = realloc(*ar, (nelem+1) * sizeof(char *));
	if (t == NULL) {
		ploop_err(ENOMEM, "Memory allocation failed");
		goto err;
	}

	*ar = t;
	if ((t[nelem-1] = strdup(entry)) == NULL) {
		ploop_err(ENOMEM, "Memory allocation failed");
		goto err;
	}
	t[nelem++] = NULL;

	return nelem;

err:
	ploop_free_array(*ar);
	*ar = NULL;

	return -1;
}

int get_dir_entry(const char *path, char **out[])
{
	DIR *dp;
	struct stat st;
	char buf[PATH_MAX];
	struct dirent *de;
	int ret = 0;
	int nelem = 0;

	dp = opendir(path);
	if (dp == NULL) {
		if (errno == ENOENT)
			return 0;
		ploop_err(errno, "Can't opendir %s", path);
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		if (!strcmp(de->d_name, ".") ||
				!strcmp(de->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", path, de->d_name);
		if (stat(buf, &st)) {
			ploop_err(errno, "Can't stat %s", buf);
			ret = -1;
			break;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		nelem = append_array_entry(de->d_name, out, nelem);
		if (nelem == -1) {
			ret = -1;
			break;
		}
	}
	closedir(dp);

	if (ret) {
		ploop_free_array(*out);
		*out = NULL;
	}

	return ret;
}

static int get_dm_offset(dev_t dev, dev_t *parent, __u32 *offset)
{
	FILE *fp;
	char b[PATH_MAX];
	char *token, *savedptr = NULL;
	unsigned int found = 0, major, minor;
	char name[PATH_MAX];

	snprintf(b, sizeof(b), "/sys/dev/block/%d:%d/dm/name",
			major(dev), minor(dev));
	if (read_line(b, name, sizeof(name))) {
		ploop_err(0, "Cannot read dm name from %s", b);
		return -1;
	}

	snprintf(b, sizeof(b), "LANG=C dmsetup table %s", name);
	fp = popen(b, "r");
	if (fp == NULL) {
		ploop_err(0, "Failed %s", b);
		return SYSEXIT_SYS;
	}

	if (fgets(b, sizeof(b), fp) == NULL)
		goto err;

	if ((token = strtok_r(b, " ", &savedptr)) == NULL)
		goto err;

	do {
		if (found) {
			if (sscanf(token, "%u", offset) != 1)
				found = 0;
			break;
		}
		if (sscanf(token, "%u:%u", &major, &minor) == 2)
			found = 1;

	} while ((token = strtok_r(NULL, " ", &savedptr)) != NULL);

err:
	if (pclose(fp)) {
		ploop_err(0, "Failed to get dm table %s", name);
		return -1;
	}

	if (!found) {
		ploop_err(0, "Cannot to find start offset for %s", name);
		return -1;
	}

	*parent = makedev(major, minor);

	return 0;
}

int dev_num2dev_start(dev_t dev_num, __u32 *dev_start)
{
	int ret;
	char path[PATH_MAX];
	__u32 offset = 0;
	dev_t parent;

	snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/start",
			major(dev_num), minor(dev_num));
	/* ploopNp1 */
	if (access(path, F_OK) == 0)
		return get_dev_start(path, dev_start);

	snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/dm",
			major(dev_num), minor(dev_num));
	/* ploopN */
	if (access(path, F_OK)) {
		*dev_start = 0;
		return 0;
	}

	/* CRYPT-ploop */
	ret = get_dm_offset(dev_num, &parent, dev_start);
	if (ret)
		return ret;

	if (major(parent) == 182)
		ret = get_dev_start(path, &offset);
	else 
		ret = get_dm_offset(parent, &parent, &offset);

	*dev_start += offset;
	return ret;
}

int ploop_find_dev(const char *component_name, const char *delta,
		char *out, int size)
{
	return find_dev_by_delta(delta, out, size);
}

void ploop_free_array(char *array[])
{
	char **p;

	if (array == NULL)
		return;

	for (p = array; *p != NULL; p++)
		free(*p);
	free(array);
}

int get_part_devname_from_sys(const char *device, char *devname, int dsize,
		char *part, int psize)
{
	int rc, i = 0;
	char dev[PATH_MAX];

	snprintf(devname, dsize, "%s", device);
	snprintf(part, psize, "%s", device);
	snprintf(dev, sizeof(dev), "%s", device);

	while ((rc = get_dev_from_sys(dev, "holders", dev, sizeof(dev)) == 0)) {
		if (i++)
			snprintf(devname, dsize, "%s", part);
		get_full_devname(dev, part, psize);
	}

	return rc == -1 ? -1 : 0;
}
