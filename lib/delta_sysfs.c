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

	if (ploop_get_attr(device, "top", &top_level)) {
		ploop_err(0, "Can't find top delta");
		return SYSEXIT_SYSFS;
	}

	if (find_delta_names(device, top_level, top_level,
			     &img, &fmt)) {
		ploop_err(errno, "find_delta_names");
		return(SYSEXIT_SYSFS);
	}
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
		return SYSEXIT_BLKDEV;
	}
	*res >>= 9;
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
	*dev_num = gnu_dev_makedev(maj, min);
	return 0;
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
		ploop_err(errno, "sysfs opendir");
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
			ploop_err(errno, "lstat");
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

static int is_cookie_supported(void)
{
	struct utsname buf;
	int major, minor;

	uname(&buf);
	// >= 2.6.32-042stab061.1
	if (sscanf(buf.release, "%*d.%*d.%*d-%dstab%d.%*d", &major, &minor) != 2) {
		ploop_err(0, "Can't parse kernel version %s", buf.release);
		return 0;
	}

	return (major > 42 || (major == 42 && minor >= 61));
}

/* Find device by base delta and return the name
 * return: -1 on error
 *	    0 found
 *	    1 not found
 */
int ploop_find_dev(const char *component_name, const char *delta,
		char *buf, int size)
{
	char fname[PATH_MAX];
	char delta_r[PATH_MAX];
	char image[PATH_MAX];
	DIR *dp;
	struct dirent *de;
	struct stat st;
	int ret = -1;
	char name[64];
	char cookie[PLOOP_COOKIE_SIZE];
	dev_t dev;
	int lckfd;

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
		ploop_err(errno, "opendir %s", fname);
		goto err;
	}

	while ((de = readdir(dp)) != NULL) {
		if (strncmp("ploop", de->d_name, 5))
			continue;

		snprintf(fname, sizeof(fname), "/sys/block/%s/pdelta/0/image",
				de->d_name);
		if (stat(fname, &st)) {
			if (errno == ENOENT)
				continue;
			ploop_err(errno, "Can't stat %s", fname);
			goto err;
		}
		if (read_line(fname, image, sizeof(image)))
			goto err;
		if (strcmp(image, delta_r))
			continue;

		snprintf(fname, sizeof(fname), "/sys/block/%s/pstate/cookie",
				de->d_name);
		if (stat(fname, &st) == 0) {
			if (read_line(fname, cookie, sizeof(cookie)))
				goto err;
			if (strncmp(component_name == NULL ? "" : component_name,
						cookie, sizeof(cookie)))
				continue;
		} else {
			if ((errno == ENOENT) && is_cookie_supported())
				/* This is not an error, but a race between
				 * mount and umount: device is being removed
				 */
				continue;
			ploop_err(errno, "Can't stat %s", fname);
			if ((errno == ENOENT) && component_name)
				/* Using component_name on old kernel is bad */
				ploop_err(0, "ERROR: OpenVZ kernel with ploop cookie support "
						"(i.e. 042stab061.1 or greater) is required");
			goto err;
		}

		snprintf(fname, sizeof(fname), "/sys/block/%s/dev",
				de->d_name);
		if (get_dev_num(fname, &dev))
			goto err;

		snprintf(buf, size, "/dev/%s",
				make_sysfs_dev_name(gnu_dev_minor(dev), name, sizeof(name)));
		if (stat(buf, &st) == 0 &&
				st.st_rdev != dev)
		{
			ploop_err(0, "Inconsistency in device number detected for %s sys_dev=%lu dev=%lu",
					buf, (unsigned long)dev, (unsigned long)st.st_rdev);
			goto err;
		}
		ret = 0;
		goto err;
	}
	ret = 1; /* not found */

err:
	if (dp)
		closedir(dp);
	close(lckfd);

	return ret;
}

int ploop_get_top_level(int devfd, const char *devname, int *top)
{
	char path[PATH_MAX];
	char name[64];
	struct stat st;
	char nbuf[4096];

	if (fstat(devfd, &st)) {
		ploop_err(errno, "fstat %s", devname);
		return -1;
	}

	snprintf(path, sizeof(path) - 1, "/sys/block/%s/pstate/top",
		 make_sysfs_dev_name(gnu_dev_minor(st.st_rdev), name, sizeof(name)));

	if (read_line(path, nbuf, sizeof(nbuf)))
		return -1;

	if (sscanf(nbuf, "%d", top) != 1) {
		ploop_err(0, "Unexpected format of %s: %s (%s)",
			  path, nbuf, devname);
		errno = ERANGE;
		return -1;
	}

	return 0;
}
