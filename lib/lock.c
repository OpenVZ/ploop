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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/times.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

#include "ploop.h"

#define PLOOP_GLOBAL_LOCK_FILE	PLOOP_LOCK_DIR"/ploop.lck"
#define LOCK_TIMEOUT		60

static int create_file(char *fname)
{
	int fd;

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		ploop_err(errno, "Can't create file %s",
				fname);
		return -1;
	}
	if (fchmod(fd, 0644))
		ploop_err(errno, "Can't chmod(0644) on %s", fname);

	close(fd);
	return 0;
}

int do_open(const char *fname, int flags)
{
	useconds_t total = 0;
	useconds_t wait = 10000; // initial wait time 0.01s
	useconds_t maxwait = 5 * 1000000; // max wait time per iteration 5s
	useconds_t maxtotal = 60 * 1000000; // max total wait time 60s

	do {
		int fd = open(fname, flags);
		if (fd != -1)
			return fd;
		else if (errno != EBUSY)
			return -1;

		if (total > maxtotal)
			break;

		usleep(wait);
		total += wait;
		wait *= 2;
		if (wait > maxwait)
			wait = maxwait;
	} while (1);

	return -1;
}

#define LOCK_EXCL_BASE	200
#define LOCK_LEN	5

static int lock_fcntl(int fd, int cmd, off_t start, off_t len,
		short type, struct flock *out)
{
	int rc;
	struct flock fl = {
		.l_whence = SEEK_SET,
		.l_start = start,
		.l_len = len,
		.l_type = type,
	};

	rc = TEMP_FAILURE_RETRY(fcntl(fd, cmd, &fl));
	if (rc) {
		ploop_err(errno, "Can not lock");
		return rc;
	}

	if (out)
		memcpy(out, &fl, sizeof(struct flock));

	return 0;
}

static int lock_set(int fd, off_t start)
{
	return lock_fcntl(fd, F_SETLK, start, LOCK_LEN, F_RDLCK, NULL);
}

static int lock_test(int fd, off_t start, unsigned int tm)
{
	int rc;
	struct flock fl;

	do {
		rc = lock_fcntl(fd, F_GETLK, start, LOCK_LEN, F_WRLCK, &fl);
		if (rc)
			return rc;
		if (fl.l_type == F_UNLCK)
			return 0;
		if (tm)
			sleep(1);
	} while (tm--);

	ploop_err(0, "Already locked by pid %d", fl.l_pid);

	return -1;
}

static int lock_unlock(int fd, off_t start)
{
	return lock_fcntl(fd, F_SETLK, start, LOCK_LEN, F_UNLCK, NULL);
}

static int do_lock(const char *fname, unsigned int timeout)
{
	int fd, r;

	if ((fd = do_open(fname, O_RDONLY | O_CLOEXEC)) == -1) {
		ploop_err(errno, "Can not open %s", fname);
		return -1;
	}

	r = lock_test(fd, LOCK_EXCL_BASE, timeout);
	if (r)
		goto err;

	r = lock_set(fd, LOCK_EXCL_BASE);
	if (r)
		goto err_close;

	r = lock_test(fd, LOCK_EXCL_BASE, 0);
	if (r)
		goto err;

	return fd;

err:
	lock_unlock(fd, LOCK_EXCL_BASE);
err_close:
	close(fd);
	return -1;
}

void ploop_unlock(int *lckfd)
{
	if (*lckfd != -1) {
		lock_unlock(*lckfd, LOCK_EXCL_BASE);
		close(*lckfd);
		*lckfd = -1;
	}
}

void get_disk_descriptor_lock_fname(struct ploop_disk_images_data *di,
				    char *out, int size)
{
	get_disk_descriptor_fname(di, out, size);
	strcat(out, ".lck");
}

int ploop_lock_di(struct ploop_disk_images_data *di)
{
	char fname[PATH_MAX];

	if (di == NULL)
		return 0;
	if (di->runtime->image_type == QCOW_TYPE)
		return 0;
	get_disk_descriptor_lock_fname(di, fname, sizeof(fname));
	if (access(fname, F_OK)) {
		if (create_file(fname))
			return -1;
	}
	di->runtime->lckfd = do_lock(fname, LOCK_TIMEOUT);
	if (di->runtime->lckfd == -1)
		return -1;
	return 0;
}

void ploop_unlock_di(struct ploop_disk_images_data *di)
{
	if (di != NULL)
		ploop_unlock(&di->runtime->lckfd);
}

void ploop_unlock_dd(struct ploop_disk_images_data *di)
{
	return ploop_unlock_di(di);
}

int ploop_global_lock(void)
{
	if (access(PLOOP_GLOBAL_LOCK_FILE, F_OK)) {
		if (access(PLOOP_LOCK_DIR, F_OK) &&
				mkdir(PLOOP_LOCK_DIR, 0700) && errno != EEXIST) {
			ploop_err(errno, "Failed to create " PLOOP_LOCK_DIR);
			return -1;
		}
		if (create_file(PLOOP_GLOBAL_LOCK_FILE))
			return -1;
	}
	return do_lock(PLOOP_GLOBAL_LOCK_FILE, 0);
}
