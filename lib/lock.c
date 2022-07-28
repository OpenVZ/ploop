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

#define LOCK_EXCL_BASE	200
#define LOCK_LEN	5
#define LOCK_EXCL_LONG	300
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

static int do_lock_set(int fd, int long_op)
{
	int rc;

	if (long_op) {
		rc = lock_set(fd, LOCK_EXCL_LONG);
		if (rc)
			return rc;
	}
	return lock_set(fd, LOCK_EXCL_BASE);
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

static int do_lock_test(int fd, unsigned int timeout)
{
	int r;

	/* do not wait if long lock obtained */
	r = lock_test(fd, LOCK_EXCL_LONG, 0);
	if (r)
		return r;
	return lock_test(fd, LOCK_EXCL_BASE, timeout);
}

static int do_lock_unlock(int fd)
{
	int rc;

	rc = lock_fcntl(fd, F_SETLK, LOCK_EXCL_LONG, LOCK_LEN, F_UNLCK, NULL);
	rc |= lock_fcntl(fd, F_SETLK, LOCK_EXCL_BASE, LOCK_LEN, F_UNLCK, NULL);

	return rc;
}

int lock(const char *fname, int long_op, unsigned int timeout)
{
	int fd, r;

	if ((fd = do_open(fname, O_RDONLY | O_CLOEXEC)) == -1) {
		ploop_err(errno, "Can not open %s", fname);
		return -1;
	}

	r = do_lock_test(fd, timeout);
	if (r)
		goto err_close;

	r = do_lock_set(fd, long_op);
	if (r)
		goto err_close;

	r = do_lock_test(fd, 0);
	if (r)
		goto err;

	return fd;

err:
	do_lock_unlock(fd);
err_close:
	close(fd);
	return -1;
}

void ploop_unlock(int *lckfd)
{
	if (*lckfd != -1) {
		do_lock_unlock(*lckfd);
		close(*lckfd);
		*lckfd = -1;
	}
}

int ploop_lock_di(struct ploop_disk_images_data *di)
{
	char fname[PATH_MAX];

	if (di == NULL)
		return 0;

	if (di->runtime->image_fmt == QCOW_FMT) {
		snprintf(fname, sizeof(fname), "%s", di->runtime->xml_fname);
	} else {
		if (ploop_read_dd(di))
			return -1;

		if (get_delta_fname(di, get_base_delta_uuid(di), fname, sizeof(fname)))
			return -1;
	}

	di->runtime->lckfd = lock(fname, 0, LOCK_TIMEOUT);
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
	return lock(PLOOP_GLOBAL_LOCK_FILE, 0, LOCK_TIMEOUT);
}
