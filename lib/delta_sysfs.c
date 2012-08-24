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
	FILE * fp;
	int len;
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	for (i = 0; i <= end_level - start_level; i++) {
		snprintf(nbuf, sizeof(nbuf)-1, "/sys/block/%s/pdelta/%d/image",
			 device, start_level + i);

		fp = fopen(nbuf, "r");
		if (fp == NULL) {
			ploop_err(errno, "fopen sysfs image %s", nbuf);
			return -1;
		}
		if (fgets(nbuf, sizeof(nbuf), fp) == NULL) {
			ploop_err(errno, "read sysfs image");
			fclose(fp);
			return -1;
		}
		len = strlen(nbuf);
		if (len > 0 && nbuf[len-1] == '\n') {
			len--;
			nbuf[len] = 0;
		}
		names[(end_level-start_level)-i] = strdup(nbuf);
		fclose(fp);

		if (i == 0) {
			snprintf(nbuf, sizeof(nbuf)-1, "/sys/block/%s/pdelta/%d/format",
				 device, start_level);
			fp = fopen(nbuf, "r");
			if (fp == NULL) {
				ploop_err(errno, "fopen sysfs format %s", nbuf);
				return -1;
			}
			if (fgets(nbuf, sizeof(nbuf), fp) == NULL) {
				ploop_err(errno, "read sysfs format");
				fclose(fp);
				return -1;
			}
			len = strlen(nbuf);
			if (len > 0 && nbuf[len-1] == '\n') {
				len--;
				nbuf[len] = 0;
			}
			if (format) {
				if (strcmp(nbuf, "raw") == 0)
					*format = "raw";
				else if (strcmp(nbuf, "ploop1") == 0)
					*format = "ploop1";
				else
					*format = "unknown";
			}
			fclose(fp);
		}
	}
	return 0;
}

int ploop_get_attr(const char * device, const char * attr, int * res)
{
	FILE * fp;
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(nbuf, sizeof(nbuf)-1, "/sys/block/%s/pstate/%s", device, attr);

	fp = fopen(nbuf, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen %s", nbuf);
		return -1;
	}

	if (fgets(nbuf, sizeof(nbuf), fp) == NULL) {
		ploop_err(errno, "fgets");
		fclose(fp);
		return -1;
	}
	fclose(fp);

	if (sscanf(nbuf, "%d", res) != 1) {
		ploop_err(0, "Unexpected format of %s/pstate/%s %s",
			device, attr, nbuf);
		return -1;
	}
	return 0;
}

static int ploop_get_delta_attr_str(const char *device, int level, const char *attr,
		char *nbuf, int nbuf_len)
{
	FILE * fp;

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(nbuf, nbuf_len-1, "/sys/block/%s/pdelta/%d/%s",
			device,	level, attr);

	fp = fopen(nbuf, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen %s", nbuf);
		return -1;
	}

	if (fgets(nbuf, nbuf_len, fp) == NULL) {
		ploop_err(errno, "fgets /sys/block/%s/pdelta/%d/%s",
				device, level, attr);
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return 0;
}

int ploop_get_delta_attr(const char * device, int level, char * attr, int * res)
{
	char nbuf[4096];
	int err;

	if ((err = ploop_get_delta_attr_str(device, level, attr, nbuf, sizeof(nbuf))))
		return err;

	if (sscanf(nbuf, "%d", res) != 1) {
		ploop_err(0, "Unexpected format of %s/pdelta/%s %s",
			device, attr, nbuf);
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

int read_line(const char *path, char *nbuf, int len)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen %s", path);
		return -1;
	}
	if (fgets(nbuf, len, fp) == NULL) {
		ploop_err(errno, "read %s", path);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	len = strlen(nbuf);
	if (len > 0 && nbuf[len-1] == '\n') {
		nbuf[len-1] = 0;
	}
	return 0;
}

static int get_dev_num(char *path, dev_t *dev_num)
{
	char nbuf[4096];
	int maj, min;

	if (read_line(path, nbuf, sizeof(nbuf)))
		return-1;
	if (sscanf(nbuf, "%d:%d", &maj, &min) != 2) {
		ploop_err(0, "Unexpected format of /sys/.../dev: %s", nbuf);
		return -1;
	}
	*dev_num = gnu_dev_makedev(maj, min);
	return 0;
}

static int get_dev_start(char *path, __u32 *start)
{
	FILE * fp;
	int len;
	char nbuf[4096];

	fp = fopen(path, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen %s", path);
		return -1;
	}
	if (fgets(nbuf, sizeof(nbuf), fp) == NULL) {
		ploop_err(errno, "read sysfs start");
		fclose(fp);
		return -1;
	}
	len = strlen(nbuf);
	if (len > 0 && nbuf[len-1] == '\n') {
		len--;
		nbuf[len] = 0;
	}

	if (sscanf(nbuf, "%u", start) != 1) {
		ploop_err(0, "Unexpected format of /sys/.../start: %s", nbuf);
		fclose(fp);
		return -1;
	}
	fclose(fp);

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

int ploop_find_dev_by_delta(char *delta, char *buf, int size)
{
	char fname[PATH_MAX];
	char image[PATH_MAX];
	DIR *dp;
	struct dirent *de;
	struct stat st, st1;
	int ret = 1;
	char name[64];
	dev_t dev;

	if (stat(delta, &st)) {
		if (errno == ENOENT)
			return 1;
		ploop_err(errno, "ploop_find_dev_by_delta stat(%s)",
				delta);
		return -1;
	}

	snprintf(fname, sizeof(fname) - 1, "/sys/block/");
	dp = opendir(fname);
	if (dp == NULL) {
		ploop_err(errno, "opendir %s", fname);
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		if (strncmp("ploop", de->d_name, 5))
			continue;

		snprintf(fname, sizeof(fname), "/sys/block/%s/pdelta/0/image",
				de->d_name);
		if (stat(fname, &st1))
			continue;
		if (read_line(fname, image, sizeof(image)))
			continue;
		if (stat(image, &st1))
			continue;
		if (st.st_dev != st1.st_dev || st.st_ino != st1.st_ino)
			continue;

		snprintf(fname, sizeof(fname), "/sys/block/%s/dev",
				de->d_name);
		if (get_dev_num(fname, &dev) == 0) {
			snprintf(buf, size, "/dev/%s",
					make_sysfs_dev_name(gnu_dev_minor(dev), name, sizeof(name)));
			if (stat(buf, &st1) == 0 &&
					st1.st_rdev != dev)
			{
				ploop_err(0, "Inconsistency in device number detected for %s sys_dev=%lu dev=%lu",
						buf, (unsigned long)dev, (unsigned long)st1.st_rdev);
				ret = -1;
			} else
				ret = 0;
			break;
		}
	}
	closedir(dp);

	return ret;
}

int ploop_get_top_level(int devfd, const char *devname, int *top)
{
	char path[PATH_MAX];
	char name[64];
	struct stat st;
	FILE * fp;
	int len;
	char nbuf[4096];

	if (fstat(devfd, &st)) {
		ploop_err(errno, "fstat %s", devname);
		return -1;
	}

	snprintf(path, sizeof(path) - 1, "/sys/block/%s/pstate/top",
		 make_sysfs_dev_name(gnu_dev_minor(st.st_rdev), name, sizeof(name)));

	fp = fopen(path, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen %s (%s)", path, devname);
		return -1;
	}
	if (fgets(nbuf, sizeof(nbuf), fp) == NULL) {
		ploop_err(errno, "fgets from %s (%s)", path, devname);
		fclose(fp);
		return -1;
	}
	len = strlen(nbuf);
	if (len > 0 && nbuf[len-1] == '\n') {
		len--;
		nbuf[len] = 0;
	}

	if (sscanf(nbuf, "%d", top) != 1) {
		ploop_err(0, "Unexpected format of %s: %s (%s)",
			  path, nbuf, devname);
		fclose(fp);
		errno = ERANGE;
		return -1;
	}
	fclose(fp);

	return 0;
}
