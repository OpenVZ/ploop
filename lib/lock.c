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
#include <fcntl.h>
#include <limits.h>

#include "ploop.h"

#define PLOOP_LOCK_DIR		"/var/lock/ploop"
#define PLOOP_GLOBAL_LOCK_FILE	PLOOP_LOCK_DIR"/ploop.lck"
#define LOCK_TIMEOUT		60*2

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

static int do_lock(const char *fname, int flags)
{
	int fd, r, retry = 0;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		ploop_err(errno, "Can't open lock file %s", fname);
		return -1;
	}
	while ((r = flock(fd, LOCK_EX | flags)) == -1 && retry < LOCK_TIMEOUT) {
		if (errno == EAGAIN) {
			retry++;
			usleep(500000);
		} else if (errno != EINTR)
			break;
	}

	if (r != 0) {
		if (errno == EAGAIN) {
			ploop_err(errno, "The %s is locked", fname);
			close(fd);
			return -1;
		} else {
			ploop_err(errno, "Error in flock(%s)", fname);
			close(fd);
			return -1;
		}
	}
	return fd;
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
	struct stat st;
	char fname[PATH_MAX];

	if (di == NULL)
		return 0;
	get_disk_descriptor_lock_fname(di, fname, sizeof(fname));
	if (stat(fname, &st)) {
		if (create_file(fname))
			return -1;
	}
	di->runtime->lckfd = do_lock(fname, LOCK_NB);
	if (di->runtime->lckfd == -1)
		return -1;
	return 0;
}

void ploop_unlock_di(struct ploop_disk_images_data *di)
{
	if (di != NULL)
		ploop_unlock(&di->runtime->lckfd);
}

int ploop_global_lock(void)
{
	struct stat st;

	if (stat(PLOOP_GLOBAL_LOCK_FILE, &st)) {
		if (create_file(PLOOP_GLOBAL_LOCK_FILE))
			return -1;
	}
	return do_lock(PLOOP_GLOBAL_LOCK_FILE, 0);
}
