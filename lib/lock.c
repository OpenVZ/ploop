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

#include "ploop.h"

#define PLOOP_GLOBAL_LOCK_FILE	PLOOP_LOCK_DIR"/ploop.lck"
#define LOCK_TIMEOUT		60

static int create_file(char *fname)
{
	int fd;

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		ploop_err(errno, "Can't create file %s",
				fname);
		return -1;
	}
	close(fd);
	return 0;
}

static void timer_handler(int ino)
{
}

static int set_timer(timer_t *tid, unsigned int timeout)
{
	struct sigevent sigev = {};
	struct itimerspec it = {};

	sigev.sigev_notify = SIGEV_SIGNAL;
	sigev.sigev_signo = SIGRTMIN;
	sigev.sigev_value.sival_ptr = tid;

	if (timer_create(CLOCK_MONOTONIC, &sigev, tid)) {
		ploop_err(errno, "timer_create");
		return -1;
	}
	it.it_value.tv_sec = timeout;
	it.it_value.tv_nsec = 0;

	if (timer_settime(*tid, 0, &it, NULL)) {
		ploop_err(errno, "timer_settime");
		return -1;
	}
	return 0;
}

#define SEC_TO_NSEC(sec) ((clock_t)(sec) * 1000000000)
static clock_t get_cpu_time(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		ploop_err(errno, "clock_gettime");
		return (clock_t)-1;
	}
	return SEC_TO_NSEC(ts.tv_sec) + ts.tv_nsec;
}

static int do_lock(const char *fname, unsigned int timeout)
{
	int fd, r, _errno;
	timer_t tid;
	clock_t end = 0;
	struct sigaction osa;
	struct sigaction sa = {
			.sa_handler = timer_handler,
		};

	if ((fd = open(fname, O_RDWR)) == -1) {
		ploop_err(errno, "Can't open lock file %s", fname);
		return -1;
	}

	/* Set FD_CLOEXEC explicitly */
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	if (timeout) {
		end = get_cpu_time();
		if (end == (clock_t)-1)
			goto err;
		end += SEC_TO_NSEC(timeout);
		sigaction(SIGRTMIN, &sa, &osa);
		if (set_timer(&tid, timeout))
			goto err;
	}
	while ((r = flock(fd, LOCK_EX)) == -1) {
		_errno = errno;
		if (_errno != EINTR)
			break;
		if (timeout == 0 || get_cpu_time() < end)
			continue;
		_errno = EAGAIN;
		break;
	}
	if (timeout) {
		timer_delete(tid);
		sigaction(SIGRTMIN, &osa, NULL);
	}
	if (r != 0) {
		if (_errno == EAGAIN) {
			ploop_err(_errno, "The %s is locked", fname);
			goto err;
		} else {
			ploop_err(_errno, "Error in flock(%s)", fname);
			goto err;
		}
	}
	return fd;

err:
	close(fd);
	return -1;
}

void ploop_unlock(int *lckfd)
{
	if (*lckfd != -1) {
		if (flock(*lckfd, LOCK_UN))
			ploop_err(errno, "Can't flock(%d, LOCK_UN)",
					*lckfd);
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
