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

int find_delta_names(const char * device, int start_level, int end_level,
		     char **names, char ** format)
{
	int i;
	char path[PATH_MAX];
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	for (i = 0; i <= end_level - start_level; i++) {
		snprintf(path, sizeof(path), "/sys/block/%s/pdelta/%d/image",
			 device, start_level + i);

		if (read_line(path, nbuf, sizeof(nbuf)))
			return -1;

		names[(end_level-start_level)-i] = strdup(nbuf);

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

	fd = open(device, O_RDONLY, 0);
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

int get_dev_start(const char *path, __u32 *start)
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

int dev_num2dev_start(const char *device, dev_t dev_num, __u32 *dev_start)
{
	char nbuf[4096];
	dev_t dev;
	DIR * dp;
	struct dirent *de;

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(nbuf, sizeof(nbuf) - 1, "/sys/block/%s/dev", device);

	if (get_dev_num(nbuf, &dev))
		return -1;
	if (dev == dev_num) {
		*dev_start = 0;
		return 0;
	}

	snprintf(nbuf, sizeof(nbuf) - 1, "/sys/block/%s", device);
	dp = opendir(nbuf);
	if (dp == NULL) {
		ploop_err(errno, "Can't opendir %s", nbuf);
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		struct stat st;

		if (strlen(de->d_name) <= strlen(device) + 1 ||
		    memcmp(de->d_name, device, strlen(device)) ||
		    de->d_name[strlen(device)] != 'p')
			continue;

		snprintf(nbuf, sizeof(nbuf) - 1, "/sys/block/%s/%s",
			 device, de->d_name);
		if (lstat(nbuf, &st)) {
			ploop_err(errno, "Can't lstat %s", nbuf);
			goto close_dir;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		snprintf(nbuf, sizeof(nbuf) - 1, "/sys/block/%s/%s/dev",
			 device, de->d_name);
		if (get_dev_num(nbuf, &dev))
			goto close_dir;

		if (dev == dev_num) {
			snprintf(nbuf, sizeof(nbuf) - 1,
				 "/sys/block/%s/%s/start",
				 device, de->d_name);
			closedir(dp);
			return get_dev_start(nbuf, dev_start);
		}
	}

	ploop_err(0, "Can't find entry under /sys/block/%s with dev=%llx",
		device, (unsigned long long)dev_num);
close_dir:
	closedir(dp);
	return -1;
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
	char image[PATH_MAX];
	char dev[64];
	DIR *dp;
	struct dirent *de;
	int ret = -1;
	char cookie[PLOOP_COOKIE_SIZE];
	int lckfd;
	int nelem = 1;

	*out = NULL;

	if (access(delta, F_OK) && errno == ENOENT)
		return 1;

	if (realpath(delta, delta_r) == NULL) {
		ploop_err(errno, "Can't resolve %s", delta);
		return -1;
	}

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
		char **t;

		if (strncmp("ploop", de->d_name, 5))
			continue;

		snprintf(fname, sizeof(fname), "/sys/block/%s/pdelta/0/image",
				de->d_name);
		err = read_line_quiet(fname, image, sizeof(image));
		if (err) {
			if (err == ENOENT || err == ENODEV)
				continue;

			ploop_err(err, "Can't open or read %s", fname);
			goto err;
		}

		if (strcmp(image, delta_r))
			continue;

		if (topdelta != NULL) {
			if (!(ploop_find_top_delta_name_and_format(
					de->d_name, image, sizeof(image), NULL, 0) == 0 &&
					strcmp(image, topdelta) == 0))
				continue;
		}

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
				ploop_err(0, "ERROR: OpenVZ kernel with ploop cookie support "
						"(i.e. 042stab061.1 or greater) is required");
			goto err;
		}

		if (component_name && strncmp(component_name, cookie, sizeof(cookie)))
			continue;

		snprintf(dev, sizeof(dev), "/dev/%s", de->d_name);
		t = realloc(*out, (nelem+1) * sizeof(char *));
		if (t == NULL) {
			ploop_err(ENOMEM, "Memory allocation failed");
			goto err;
		}
		*out = t;
		if ((t[nelem-1] = strdup(dev)) == NULL) {
			ploop_err(ENOMEM, "Memory allocation failed");
			goto err;
		}
		t[nelem++] = NULL;
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

int ploop_find_dev(const char *component_name, const char *delta,
		char *out, int size)
{
	int ret;
	char **devs;

	ret = ploop_get_dev_by_delta(delta, NULL,
			/* We only need one device, so
			 * always set component_name */
			component_name ? component_name : "",
			&devs);
	if (ret == 0)
		snprintf(out, size, "%s", devs[0]);
	ploop_free_array(devs);

	return ret;
}
