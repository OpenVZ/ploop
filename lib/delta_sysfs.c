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

#include "ploop.h"

char *make_sysfs_dev_name(int minor, char *buf, int len)
{
	snprintf(buf, len, "ploop%d", minor >> 4);
	return buf;
}

int ploop_find_top_delta_name_and_format(
		const char *device,
		char *image,
		size_t image_size,
		char *format,
		size_t format_size)
{
	int top_level = 0;
	char *img;
	char *fmt;

	if (ploop_get_attr(device, "top", &top_level))
		return SYSEXIT_SYSFS;

	if (find_delta_names(device, top_level, top_level, &img, &fmt))
		return SYSEXIT_SYSFS;

	if (image)
		strncpy(image, img, image_size);
	free(img);
	if (format)
		strncpy(format, fmt, format_size);

	return 0;
}

static int read_image_info(const char *devname, int level,
		struct image_info *info)
{
	char buf[PATH_MAX];
	unsigned long major = 0, minor = 0;
	FILE *fp;

	snprintf(buf, sizeof(buf), "/sys/block/%s/pdelta/%d/image_info",
			devname, level);

	info->ino = 0;
	fp = fopen(buf, "rt");
	if (fp == NULL) {
		if (errno == ENOENT)
			return 0;
		ploop_err(errno, "Cannot open %s", buf);
		return SYSEXIT_OPEN;
	}

	/*   ino:254
	 *   sdev:0:38
	 */
	while (fgets(buf, sizeof(buf) - 1, fp)) {
		sscanf(buf, "ino:%lu\n", &info->ino);
		sscanf(buf, "sdev:%lu:%lu", &major, &minor);
	}
	fclose(fp);

	info->dev = makedev(major, minor);

	return 0;
}

int find_delta_info(const char *device, int start_level, int end_level,
		     char **names, struct image_info *info, char **format)
{
	int i, n;
	char path[PATH_MAX];
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	for (i = 0; i <= end_level - start_level; i++) {
		snprintf(path, sizeof(path), "/sys/block/%s/pdelta/%d/image",
			 device, start_level + i);

		if (read_line(path, nbuf, sizeof(nbuf)))
			return -1;

		n = (end_level-start_level)-i;
		if (names)
			names[n] = strdup(nbuf);

		if (info && read_image_info(device, start_level + i, &info[n]))
			return -1;

		if (i == 0 && format) {
			snprintf(path, sizeof(path), "/sys/block/%s/pdelta/%d/format",
				 device, start_level);

			if (read_line(path, nbuf, sizeof(nbuf)))
				return -1;

			if (strcmp(nbuf, "raw") == 0)
				*format = "raw";
			else if (strcmp(nbuf, "ploop1") == 0)
				*format = "ploop1";
			else
				*format = "unknown";
		}
	}
	return 0;
}

int find_delta_names(const char *device, int start_level, int end_level,
		char **names, char **format)
{
	return find_delta_info(device, start_level, end_level, names, NULL, format);
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

static int append_array_entry(const char *entry, char **ar[], int nelem)
{
	char **t;

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
	int nelem = 1;

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
	char name[64];

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

static int check_dev_by_name(const char *devname, const char *delta,
		const char *topdelta)
{
	char fname[PATH_MAX];
	char image[PATH_MAX];
	int err;

	snprintf(fname, sizeof(fname), "/sys/block/%s/pdelta/0/image",
			devname);
	err = read_line_quiet(fname, image, sizeof(image));
	if (err) {
		if (err == ENOENT || err == ENODEV)
			return 1;

		ploop_err(err, "Can't open or read %s", fname);
		return -1;
	}

	if (strcmp(image, delta))
		return 1;
		
	if (topdelta != NULL) {
		if (!(ploop_find_top_delta_name_and_format(
				devname, image, sizeof(image), NULL, 0) == 0 &&
				strcmp(image, topdelta) == 0))
			return 1;
	}

	return 0;
}

static int check_dev_by_info(const char *devname, struct stat *delta,
		struct stat *topdelta)
{
	struct image_info info;

	read_image_info(devname, 0, &info);
	if (info.ino != delta->st_ino || info.dev != delta->st_dev)
		return 1;

	if (topdelta) {
		int top_level;

		if (ploop_get_attr(devname, "top", &top_level))
			return 1;

		if (read_image_info(devname, top_level, &info))
			return 1;

		if (info.ino != topdelta->st_ino || info.dev != topdelta->st_dev)
			return 1;
	}

	return 0;
}

/* Find device(s) by base ( & top ) delta and return name(s)
 * in a NULL-terminated array pointed to by 'out'.
 * Note that
 *  - if 0 is returned, 'out' should be free'd using
 *    ploop_free_array()
 *  - when 'component_name' is not NULL,
 *    no more than one device will be returned
 * Return:
 *  -1 on error
 *   0 found
 *   1 not found
 */
int ploop_get_dev_by_delta(const char *delta, const char *topdelta,
		const char *component_name, char **out[])
{
	char fname[PATH_MAX];
	char delta_r[PATH_MAX];
	char topdelta_r[PATH_MAX];
	char dev[64];
	DIR *dp;
	struct dirent *de;
	int ret = -1;
	char cookie[PLOOP_COOKIE_SIZE];
	int lckfd;
	int nelem = 1;
	struct stat st_delta = {}, st_topdelta = {};
	int use_image_info = -1;

	*out = NULL;

	if (stat(delta, &st_delta) && errno == ENOENT)
		return 1;
	if (topdelta && stat(topdelta, &st_topdelta))
		ploop_err(errno, "Warning: can't stat %s", topdelta);	

	lckfd = ploop_global_lock();
	if (lckfd == -1)
		return -1;

	snprintf(fname, sizeof(fname) - 1, "/sys/block/");
	dp = opendir(fname);
	if (dp == NULL) {
		ploop_err(errno, "Can't opendir %s", fname);
		goto err;
	}

	while ((de = readdir(dp)) != NULL) {
		int err;

		if (strncmp("ploop", de->d_name, 5))
			continue;

		if (use_image_info == -1) {
			snprintf(fname, sizeof(fname), "/sys/block/%s/pdelta/0/image_info",
				de->d_name);
			use_image_info = access(fname, F_OK) == 0;

			if (!use_image_info) {
				if (realpath(delta, delta_r) == NULL) {
					ploop_err(errno, "Warning: can't resolve %s", delta);
					snprintf(delta_r, sizeof(delta_r), "%s", delta);
				}
				if (topdelta && realpath(topdelta, topdelta_r) == NULL) {
					ploop_err(errno, "Warning: can't resolve %s", topdelta);	
					snprintf(topdelta_r, sizeof(topdelta_r), "%s", topdelta);
				}
			}
		}
		if (use_image_info)
			err = check_dev_by_info(de->d_name, &st_delta,
					topdelta ? &st_topdelta : NULL);
		else
			err = check_dev_by_name(de->d_name, delta_r,
					topdelta ? topdelta_r : NULL);
		if (err == -1)
			goto err;
		else if (err == 1)
			continue;

		if (component_name) {
			snprintf(fname, sizeof(fname), "/sys/block/%s/pstate/cookie",
					de->d_name);
			err = read_line_quiet(fname, cookie, sizeof(cookie));
			if (err) {
				if (err == ENOENT || err == ENODEV)
					/* This is not an error, but a race between
					 * mount and umount: device is being removed
					 */
					continue;

				ploop_err(err, "Can't open or read %s", fname);
				if ((errno == ENOENT) && component_name)
					/* Using component_name on old kernel is bad */
					ploop_err(0, "ERROR: " PRODUCT_NAME_SHORT " kernel with ploop cookie support "
							"(i.e. 042stab061.1 or greater) is required");
				goto err;
			}

			if (strncmp(component_name, cookie, sizeof(cookie)))
				continue;
		}

		snprintf(dev, sizeof(dev), "/dev/%s", de->d_name);
		nelem = append_array_entry(dev, out, nelem);
		if (nelem == -1)
			goto err;

		if (component_name)
			break;
	}
	ret = 0;

err:
	if (dp)
		closedir(dp);
	close(lckfd);

	if (ret) {
		ploop_free_array(*out);
		*out = NULL;
		return ret;
	}

	return (nelem == 1);
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

int find_dev_by_delta(const char *component_name, const char *delta,
		const char *topdelta, char *out, int size)
{
	int ret;
	char **devs;

	if (delta == NULL) {
		ploop_err(0, "find_dev_by_delta: base delta image name is not specified");
		return SYSEXIT_PARAM;
	}

	ret = ploop_get_dev_by_delta(delta, topdelta,
			/* We only need one device, so
			 * always set component_name */
			component_name ? component_name : "",
			&devs);
	if (ret == 0)
		snprintf(out, size, "%s", devs[0]);
	ploop_free_array(devs);

	return ret;
}

int ploop_find_dev(const char *component_name, const char *delta,
		char *out, int size)
{
	return find_dev_by_delta(component_name, delta, NULL, out, size);
}

const char *get_dm_name(const char *devname, char *out, int size)
{
	char b[512];

	snprintf(out, size, "/dev/%s", devname);

	snprintf(b, sizeof(b), "/sys/class/block/%s/dm/name", devname);
	if (access(b, F_OK) == 0 && read_line(b, b, sizeof(b)) == 0)
		snprintf(out, size, "/dev/mapper/%s", b);

	return out;
}

int get_part_devname_from_sys(const char *device, char *devname, int dsize,
		char *partname, int psize)
{
	char path[PATH_MAX];
	char **dirs = NULL;
	char **p = NULL;
	int len;

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(path, sizeof(path), "/sys/block/%s", device);
	if (get_dir_entry(path, &dirs))
		return -1;

	if (dirs == NULL)
		return -1;

	len = strlen(device);
	for (p = dirs; *p != NULL; p++) {
		if (strncmp(device, *p, len) == 0)
			break;
	}


	snprintf(devname, dsize, "%s", device);
	/* ploopNp1 */
	snprintf(partname, psize, "/dev/%s", *p ? *p : device);

	snprintf(path, sizeof(path), "/sys/class/block/%s/holders",	
			get_basename(partname));
	ploop_free_array(dirs);
	dirs = NULL;

	/* crypto based schema
 	 * old
		ploopN                               disk
		└─ploopNp1                           part
		  └─CRYPT-ploopNp1                   crypt
	 * new
	 	ploopN                               disk
		└─CRYPT-ploopN                       crypt
		  └─CRYPT-ploopNp1                   part
	 */
	if (get_dir_entry(path, &dirs) == 0 && dirs != NULL) {
		snprintf(devname, dsize, "%s", partname);
		snprintf(partname, psize, "%s", get_dm_name(dirs[0], path, sizeof(path)));
		snprintf(path, sizeof(path), "/sys/class/block/%s/holders", dirs[0]);

		ploop_free_array(dirs);
		dirs = NULL;

		if (get_dir_entry(path, &dirs) == 0 && dirs != NULL) {
			snprintf(devname, dsize, "%s", partname);
			snprintf(partname, psize, "%s",  get_dm_name(dirs[0], path, sizeof(path)));
		}
	}

	ploop_free_array(dirs);

	return 0;
}
