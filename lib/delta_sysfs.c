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

char *get_loop_name(int minor, int full, char *buf, int len)
{
	snprintf(buf, len, "%sloop%d", full ? "/dev/" : "", minor);
	return buf;
}

int get_dev_from_sys(const char *devname, const char *type, char *out,
		int len)
{
	char buf[64];
	struct stat st;
	char **devs = NULL;

	if (devname[0] != '/')
		snprintf(buf, sizeof(buf), "/dev/mapper/%s", devname);
	else
		snprintf(buf, sizeof(buf), "%s", devname);
	if (stat(buf, &st) == -1) {
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

	snprintf(buf, sizeof(buf), "/sys/block/%s/dm/name", devs[0]);
	if (access(buf, F_OK) == 0) {
		if (read_line(buf, buf, sizeof(buf))) {
			ploop_free_array(devs);
			return -1;
		}
	} else
		snprintf(buf, sizeof(buf), "%s", devs[0]);

	snprintf(out, len, "/dev/%s", buf);
	if (access(out, F_OK))
		snprintf(out, len, "/dev/mapper/%s", buf);

	ploop_free_array(devs);

	return 0;
}

int ploop_find_top_delta_name_and_format(const char *device, char *image,
		size_t image_size, char *format, size_t format_size)
{
	char *i = NULL;
	const char *f;
	int blocksize, rc;

	rc = get_top_delta_name(device, &i, &f, &blocksize);
	if (rc)
		return rc;

	snprintf(image, image_size, "%s", i);
	free(i);
	snprintf(format, format_size, "%s", f);

	return 0;
}

int get_top_delta(const char*ldev, char *out, int size)
{
	int err;
	char f[PATH_MAX];

	snprintf(f, sizeof(f), "/sys/block/%s/loop/backing_file",
			get_basename(ldev));
	err = read_line_quiet(f, out, size);
	if (err) {
		if (err == ENOENT || err == ENODEV)
			return 1;

		ploop_err(err, "Can't open or read %s", f);
		return -1;
	}
	return 0;
}

int get_top_delta_name(const char *device, char **fname, const char **format,
		int *blocksize)
{
	int rc;
	char ldev[64];
	char buf[PATH_MAX];

	rc = get_dev_from_sys(device, "slaves", ldev, sizeof(ldev));
	if (rc) {
		if (rc == 1)
			ploop_err(0, "Can not find top delta fname by dev %s", device);
		return rc;
	}

	rc = get_top_delta(ldev, buf, sizeof(buf));
	if (rc)
		return rc;

	*fname = strdup(buf);
	if (fname == NULL)
		return SYSEXIT_MALLOC;

	if (format)
		*format = "ploop1";
	if (blocksize)
		*blocksize = 2048;

	return 0;
}

int ploop_get_names(const char *device, char **names[], const char **format,
		int *blocksize)
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
		if (rc == -1) 
			goto err;
		else if (rc)
			break;

		n[i + 1] = NULL;
	}

	rc = get_top_delta_name(device, &n[i++], format, blocksize);
	if (rc)
		goto err;
	n[i] = NULL;

	*names = n;

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

int dev_num2dev_start(dev_t dev_num, __u32 *dev_start, __u32 *start_offset)
{
	int ret;
	char path[PATH_MAX];
	__u32 offset = 0;

	snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/start",
			major(dev_num), minor(dev_num));
	if (access(path, F_OK)) {
		char **dirs = NULL;

		snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/slaves",
			major(dev_num), minor(dev_num));
		if (get_dir_entry(path, &dirs))
			return -1;

		if (dirs == NULL) {
			ploop_err(0, "No slaves found in %s", path);
			return -1;
		}

		snprintf(path, sizeof(path), "/sys/class/block/%s/start",
				dirs[0]);

		/* FIXME: get dm-crypt offset */
		offset = 4096;

		ploop_free_array(dirs);
	}

	ret = get_dev_start(path, dev_start);
	if (ret)
		return ret;

	*dev_start += offset;
	if (start_offset)
		*start_offset = offset;

	return 0;
}

static int check_dev_by_name(const char *ldev, const char *delta)
{
	int rc;
	char f[PATH_MAX];

	rc = get_top_delta(ldev, f, sizeof(f));
	if (rc)
		return rc;
	return strcmp(f, delta) == 0  ? 0 : 1;
}

int get_loop_by_delta(const char *delta, char **out[])
{
	char delta_r[PATH_MAX];
	char dev[64];
	DIR *dp;
	struct dirent *de;
	int err;
	int n = 0;

	*out = NULL;

	if (access(delta, F_OK ))
		return 1;

	if (realpath(delta, delta_r) == NULL) {
		ploop_err(errno, "Warning: can't resolve %s", delta);
		snprintf(delta_r, sizeof(delta_r), "%s", delta);
	}
	dp = opendir("/sys/block/");
	if (dp == NULL) {
		ploop_err(errno, "Can't opendir /sys/block");
		goto err;
	}
	while ((de = readdir(dp)) != NULL) {
		if (strncmp("loop", de->d_name, 4))
			continue;

		err = check_dev_by_name(de->d_name, delta_r);
		if (err == -1)
			goto err;
		else if (err == 1)
			continue;

		snprintf(dev, sizeof(dev), "/dev/%s", de->d_name);
		n = append_array_entry(dev, out, n);
		if (n == -1)
			goto err;
	}

	closedir(dp);
	return (n == 0);
err:
	if (dp)
		closedir(dp);
	ploop_free_array(*out);
	*out = NULL;
	return -1;
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

int get_part_devname_from_sys(const char *device, char *out, int size)
{
	int rc;

	rc = get_dev_from_sys(device, "holders", out, size);
	if (rc == -1)
		return rc;
	else if (rc)
		snprintf(out, size, "%s", device);

	return 0;
}
