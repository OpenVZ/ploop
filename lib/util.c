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

#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/vfs.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ploop.h"
#include "cleanup.h"

#define PLOOP_STATFS_FNAME	".statfs"

int get_statfs_info(const char *mnt, struct ploop_info *info)
{
	struct statfs fs;

	if (statfs(mnt, &fs)) {
		ploop_err(errno, "statfs(%s)", mnt);
		return -1;
	}

	info->fs_bsize = fs.f_bsize;
	info->fs_blocks = fs.f_blocks;
	info->fs_bfree = fs.f_bfree;
	info->fs_inodes = fs.f_files;
	info->fs_ifree = fs.f_ffree;

	return 0;
}

int store_statfs_info(const char *mnt, char *image)
{
	int fd, ret, err = 0;
	char fname[PATH_MAX];
	struct ploop_info info;

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, "/"PLOOP_STATFS_FNAME);

	if (get_statfs_info(mnt, &info))
		return -1;

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		ploop_err(errno, "Can't create file %s",
				fname);
		return -1;
	}
	ret = write(fd, &info, sizeof(info));
	if (ret != sizeof(struct ploop_info)) {
		ploop_err(ret == -1 ? errno : 0, "Can't write to %s",
				fname);
		err = -1;
	}
	close(fd);
	return err;
}

int read_statfs_info(const char *image, struct ploop_info *info)
{
	int fd, ret, err = 0;
	char fname[PATH_MAX];

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, "/"PLOOP_STATFS_FNAME);

	fd = open(fname, O_RDONLY, 0600);
	if (fd == -1) {
		if (errno != ENOENT)
			ploop_err(errno, "Can't open file %s",
					fname);
		return -1;
	}
	ret = read(fd, info, sizeof(struct ploop_info));
	if (ret != sizeof(struct ploop_info)) {
		ploop_err(ret == -1 ? errno : 0, "Can't read %s",
				fname);
		err = -1;
	}
	close(fd);
	return err;
}

int drop_statfs_info(const char *image)
{
	char fname[PATH_MAX];

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, "/"PLOOP_STATFS_FNAME);

	if (unlink(fname) < 0 && errno != ENOENT) {
		ploop_err(errno, "Can't delete file %s", fname);
		return -1;
	}

	return 0;
}

int is_valid_guid(const char *guid)
{
	int i;

	if (guid == NULL)
		return 0;
	if (strlen(guid) != 38)
		return 0;
	/* {5fbaabe3-6958-40FF-92a7-860e329aab41} */
	if (guid[0] != '{' || guid[37] != '}')
		return 0;
	guid++;
	for (i = 0; i < 36; i++)
		if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
			if (guid[i] != '-' )
				return 0;
		} else if (!isxdigit(guid[i]))
				return 0;
	return 1;
}

#define PLOOP_REG_DIR	"/dev/ploop/"
static void get_image_hash_name(const char *module, const char *image,
		char *buf, int size)
{
	char *p;
	int i, r;

	r = snprintf(buf, size, PLOOP_REG_DIR "%s",
			 module == NULL ? ":" : module);
	if (r > size)
		return;
	p = buf + r;
	size = size - r;
	for (i = 0; image[i] != '\0' && i < size - 1; i++, p++)
		*p = (image[i] == '/' ? ':' : image[i]);
	*p = '\0';
}

static int get_device_locked_state(const char *dev)
{
	char buf[64];
	char data[64];
	struct stat st;
	int ret;

	snprintf(buf, sizeof(buf), "/sys/block/%s/pstate/locked", dev);
	ret = stat(buf, &st);
	if (ret) {
		ploop_err(errno, "Can't stat %s", buf);
		return -1;
	}
	ret = read_line(buf, data, sizeof(data));
	if (ret)
		return -1;
	if (data[0] == '1')
		return 1;
	else if (data[0] == '0')
		return 0;

	ploop_err(0, "Unrecognized locked state '%s' for dev %s",
			data, dev);
	return -1;
}

static int is_registration_valid(const char *image, char *dev)
{
	char buf[64];
	char sysfname[PATH_MAX];
	struct stat st;
	int ret;

	ret = get_device_locked_state(dev);
	if (ret == -1)
		return -1;
	else if (ret == 1)
		return 1; /* registration in progress */

	snprintf(buf, sizeof(buf), "/sys/block/%s/pdelta/0/image", dev);
	ret = stat(buf, &st);
	if (ret == 0) {
		ret = read_line(buf, sysfname, sizeof(sysfname));
		if (ret == -1)
			return -1;
		ret = ploop_fname_cmp((char *)image, sysfname);
		if (ret == -1)
			return -1;
		if (ret == 0)
			return 1;
	} else if (errno != ENOENT) {
		ploop_err(errno, "Can't stat %s", buf);
		return -1;
	}
	return 0;
}

static int ploop_find_dev_locked(const char *component_name, const char *image,
		char *out, int size, const char *new_dev)
{
	char fname[PATH_MAX];
	char dev[64];
	struct stat st;
	int ret, n;

	get_image_hash_name(component_name, image, fname, sizeof(fname));
	ret = lstat(fname, &st);
	if (ret == 0) {
		n = readlink(fname, dev, sizeof(dev) - 1);
		if (n == -1) {
			ploop_err(errno, "Can't readlink %s", fname);
			return -1;
		}
		dev[n] = 0;
		ret = is_registration_valid(image, dev);
		if (ret == -1)
			return -1;
		else if (ret) {
			/* Special registration case
			 * new_dev is ours currently created dev
			 */
			if (new_dev != NULL) {
				const char *p = strrchr(new_dev, '/');
				if (p != NULL)
					p++;
				else
					p = new_dev;
				if (!strcmp(p, dev))
					return 1;
			}
			snprintf(out, size, "/dev/%s", dev);
			return 0;
		}
		ploop_err(0, "Removing stale registration %s %s",
				fname, dev);
		unlink(fname);
		return 1;
	} else if (errno != ENOENT) {
		ploop_err(errno, "Can't lstat %s", fname);
		return -1;
	}
	return 1;
}

int ploop_find_dev(const char *component_name, const char *image,
		char *out, int size)
{
	int ret, lckfd;

	lckfd = ploop_global_lock();
	if (lckfd == -1)
		return -1;

	ret = ploop_find_dev_locked(component_name, image, out, size, NULL);

	ploop_unlock(&lckfd);
	return ret;
}

static int remove_stale_device(const char *dev)
{
	char fname[PATH_MAX];
	char buf[64];
	DIR * dp;
	struct dirent *de;
	struct stat st;
	int n, ret;

	dp = opendir(PLOOP_REG_DIR);
	if (dp == NULL) {
		ploop_err(errno, "opendir " PLOOP_REG_DIR);
		return 0;
	}

	while ((de = readdir(dp)) != NULL) {
		snprintf(fname, sizeof(fname), PLOOP_REG_DIR"%s",
				de->d_name);
		if (lstat(fname, &st) != 0)
			continue;
		if (!S_ISLNK(st.st_mode))
			continue;
		n = readlink(fname, buf, sizeof(buf) -1);
		if (n == -1) {
			ploop_err(errno, "Can't readlink %s",
					de->d_name);
			continue;
		}
		buf[n] = 0;
		if (strcmp(dev, buf) != 0)
			continue;
		snprintf(fname, sizeof(fname),
				"/sys/block/%s/pdelta/0/image", dev);
		ret = stat(fname, &st);
		if (ret == -1 && errno == ENOENT) {
			snprintf(fname, sizeof(fname), PLOOP_REG_DIR"%s",
					de->d_name);

			ploop_log(0, "Removing stale registration %s %s",
					fname, dev);
			if (unlink(fname) == -1) {
				ploop_err(errno, "Can't unlink %s",
						fname);
				return -1;
			}
		} else if (ret == -1) {
			ploop_err(errno, "Can't stat %s",
					fname);
			return -1;
		} else {
			ploop_err(0, "Collision detected: device %s "
					"already used", dev);
			return -1;
		}
	}
	closedir(dp);
	return 0;
}

int register_ploop_dev(const char *component_name, const char *image,
		const char *dev)
{
	char fname[PATH_MAX];
	char buf[64];
	const char *device;
	int lckfd, ret;

	if (mkdir(PLOOP_REG_DIR, 0700) && errno != EEXIST) {
		ploop_err(0, "Can't create directory " PLOOP_REG_DIR);
		return -1;
	}
	lckfd = ploop_global_lock();
	if (lckfd == -1)
		return -1;

	ret = ploop_find_dev_locked(component_name, image, buf, sizeof(buf), dev);
	if (ret == -1)
		goto err;
	else if (ret == 0) {
		ploop_err(0, "Image %s already used by device %s",
				image, buf);
		goto err;
	}

	if (strncmp(dev, "/dev/", 5) == 0)
		device = dev + 5;
	else
		device = dev;

	if (remove_stale_device(device))
		goto err;
	get_image_hash_name(component_name, image, fname, sizeof(fname));
	if (symlink(device, fname)) {
		ploop_err(errno, "Can't create symlink %s -> %s",
				fname, device);
		goto err;
	}
	ploop_unlock(&lckfd);
	ploop_log(4, "register %s %s", fname, dev);
	return 0;

err:
	ploop_unlock(&lckfd);
	return -1;
}

void unregister_ploop_dev(const char *component_name, const char *image)
{
	int lckfd;
	char dev[64];
	char buf[512];
	char fname[PATH_MAX];
	struct stat st;
	int ret, n;

	lckfd = ploop_global_lock();
	if (lckfd == -1)
		return;

	get_image_hash_name(component_name, image, fname, sizeof(fname));
	n = readlink(fname, dev, sizeof(dev) -1);
	if (n == -1)
		goto out;
	dev[n] = 0;

	ret = get_device_locked_state(dev);
	/* error, or another registration in progress
	 * leave registration
	 */
	if (ret != 0)
		goto out;

	/* device were reused, leave registration */
	snprintf(buf, sizeof(buf), "/sys/block/%s/pdelta/0/image", dev);
	if (stat(buf, &st) == 0)
		goto out;

	ploop_log(4, "unregister %s", fname);
	if (unlink(fname))
		ploop_err(errno, "Can't unlink %s", fname);
out:
	ploop_unlock(&lckfd);
}

int is_valid_blocksize(__u32 blocksize)
{
	/* 32K <= blocksize <= 64M */
	if (blocksize < 64 ||
	    blocksize > B2S(64 * 1024 * 1024))
		return 0;
	if (blocksize != 1UL << (ffs(blocksize)-1))
		return 0;
	return 1;
}

int ploop_set_component_name(struct ploop_disk_images_data *di,
		const char *component_name)
{
	free(di->runtime->component_name);
	di->runtime->component_name = strdup(component_name);
	if (di->runtime->component_name == NULL)
		return SYSEXIT_NOMEM;
	return 0;
}

static void arg2str(char *const argv[], char *buf, int len)
{
	int i, r;
	char *sp = buf;
	char *ep = buf + len;

	for (i = 0; argv[i] != NULL; i++) {
		r = snprintf(sp, ep - sp, "%s ", argv[i]);
		if (r >= ep - sp)
			break;
		sp += r;
	}
}

static void cleanup_kill_process(void *data)
{
	int pid = *(int *) data;

	ploop_log(1, "Killing process %d", pid);
	kill(pid, SIGTERM);
}

int run_prg(char *const argv[])
{
	int pid, ret, status;
	char cmd[512];
	struct ploop_cleanup_hook *h;

	arg2str(argv, cmd, sizeof(cmd));
	ploop_log(1, "Running: %s", cmd);

	pid = fork();
	if (pid == 0) {
		int fd = open("/dev/null", O_RDONLY);
		dup2(fd, STDIN_FILENO);

		execvp(argv[0], argv);
	} else if (pid == -1) {
		ploop_err(errno, "Can't fork");
		return -1;
	}
	h = register_cleanup_hook(cleanup_kill_process, &pid);
	while ((ret = waitpid(pid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	unregister_cleanup_hook(h);
	if (ret == -1) {
		ploop_err(errno, "Can't waitpid %s", cmd);
		return -1;
	} else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret == 0)
			return 0;
		ploop_err(0, "Command %s exited with code %d", cmd, ret);
	} else if (WIFSIGNALED(status)) {
		ploop_err(0, "Command %s received signal %d",
				cmd, WTERMSIG(status));
	} else
		ploop_err(0, "Command %s died", cmd);

	return -1;
}
