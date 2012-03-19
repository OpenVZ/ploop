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

/* _XXX_ We should use AIO. ploopcopy cannot use cached reads and
 * has to use O_DIRECT, which introduces large read latencies.
 * AIO is necessary to transfer with maximal speed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"

#define CLUSTER DEF_CLUSTER

static int send_buf(int ofd, void *iobuf, int len, off_t pos)
{
	int n;

	if (len == 0)
		return 0;

	n = pwrite(ofd, iobuf, len, pos);
	if (n < 0)
		return n;
	if (n != len) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int get_image_info(const char *device, char **send_from_p, char **format_p)
{
	FILE *fp;
	int len;
	char nbuf[4096];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;

	snprintf(nbuf, sizeof(nbuf)-1, "/sys/block/%s/pdelta/0/image", device);
	fp = fopen(nbuf, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen sysfs image");
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
	*send_from_p = strdup(nbuf);
	fclose(fp);

	snprintf(nbuf, sizeof(nbuf)-1, "/sys/block/%s/pdelta/0/format", device);
	fp = fopen(nbuf, "r");
	if (fp == NULL) {
		ploop_err(errno, "fopen sysfs format");
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
	*format_p = strdup(nbuf);
	fclose(fp);
	return 0;
}

int send_process(const char *device, int ofd, const char *flush_cmd)
{
	struct delta idelta = { .fd = -1 };
	int tracker_on = 0;
	int devfd = -1;
	int ret = 0;
	char *send_from = NULL;
	char *format = NULL;
	void *iobuf = NULL;
	__u64 pos;
	__u64 iterpos;
	__u64 trackpos;
	__u64 trackend;
	__u64 xferred;
	int iter;
	struct ploop_track_extent e;

	if (posix_memalign(&iobuf, 4096, CLUSTER)) {
		ploop_err(errno, "posix_memalign");
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	devfd = open(device, O_RDONLY);
	if (devfd < 0) {
		ploop_err(errno, "open device");
		ret = SYSEXIT_DEVICE;
		goto done;
	}

	if (ioctl(devfd, PLOOP_IOC_TRACK_INIT, &e)) {
		ploop_err(errno, "PLOOP_IOC_TRACK_INIT");
		ret = SYSEXIT_DEVIOC;
		goto done;
	}
	tracker_on = 1;

	if (get_image_info(device, &send_from, &format)) {
		ret = SYSEXIT_OPEN;
		goto done;
	}

	if (open_delta_simple(&idelta, send_from, O_RDONLY|O_DIRECT, OD_NOFLAGS)) {
		ret = SYSEXIT_OPEN;
		goto done;
	}

	trackend = e.end;

	for (pos = 0; pos < trackend; ) {
		int n;

		trackpos = pos + CLUSTER;
		if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
			ploop_err(errno, "PLOOP_IOC_TRACK_INIT");
			ret = SYSEXIT_DEVIOC;
			goto done;
		}

		n = idelta.fops->pread(idelta.fd, iobuf, CLUSTER, pos);
		if (n < 0) {
			ploop_err(errno, "pread");
			ret = SYSEXIT_READ;
			goto done;
		}
		if (n == 0)
			break;

		if (send_buf(ofd, iobuf, n, pos)) {
			ploop_err(errno, "write");
			ret = SYSEXIT_WRITE;
			goto done;
		}

		pos += n;
	}
	/* First copy done */

	iter = 1;
	iterpos = 0;
	xferred = 0;

	for (;;) {
		int err;

		err = ioctl(devfd, PLOOP_IOC_TRACK_READ, &e);
		if (err == 0) {

			//fprintf(stderr, "TRACK %llu-%llu\n", e.start, e.end); fflush(stdout);

			if (e.end > trackend)
				trackend = e.end;

			if (e.start < iterpos)
				iter++;
			iterpos = e.end;
			xferred += e.end - e.start;

			for (pos = e.start; pos < e.end; ) {
				int n;
				int copy = e.end - pos;

				if (copy > CLUSTER)
					copy = CLUSTER;
				if (pos + copy > trackpos) {
					trackpos = pos + copy;
					if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
						ploop_err(errno, "PLOOP_IOC_TRACK_INIT");
						ret = SYSEXIT_DEVIOC;
						goto done;
					}
				}
				n = idelta.fops->pread(idelta.fd, iobuf, copy, pos);
				if (n < 0) {
					ploop_err(errno, "read2");
					ret = SYSEXIT_READ;
					goto done;
				}
				if (n == 0) {
					ploop_err(0, "unexpected EOF");
					ret = SYSEXIT_READ;
					goto done;
				}
				if (send_buf(ofd, iobuf, n, pos)) {
					ploop_err(errno, "write2");
					ret = SYSEXIT_WRITE;
					goto done;
				}
				pos += n;
			}
		} else {
			if (errno == EAGAIN)
				break;
			ploop_err(errno, "PLOOP_IOC_TRACK_READ");
			ret = SYSEXIT_DEVIOC;
			goto done;
		}

		if (iter > 10 || (iter > 1 && xferred > trackend))
			break;
	}

	/* Live iterative transfers are done. Either we transferred
	 * everything or iterations did not converge. In any case
	 * now we must suspend VE disk activity. Now it is just
	 * call of an external program (something sort of
	 * "killall -9 writetest; sleep 1; umount /mnt2"), actual
	 * implementation must be intergrated to vzctl/vzmigrate
	 * and suspend VE with subsequent fsyncing FS.
	 */

	if (flush_cmd)
		system(flush_cmd);

	if (ioctl(devfd, PLOOP_IOC_SYNC, 0)) {
		ploop_err(errno, "PLOOP_IOC_SYNC");
		ret = SYSEXIT_DEVIOC;
		goto done;
	}

	iter = 1;
	iterpos = 0;

	for (;;) {
		int err;
		struct ploop_track_extent e;

		err = ioctl(devfd, PLOOP_IOC_TRACK_READ, &e);
		if (err == 0) {
			__u64 pos;

			//fprintf(stderr, "TRACK %llu-%llu\n", e.start, e.end); fflush(stdout);

			if (e.end > trackend)
				trackend = e.end;
			if (e.start < iterpos)
				iter++;
			iterpos = e.end;

			for (pos = e.start; pos < e.end; ) {
				int n;
				int copy = e.end - pos;

				if (copy > CLUSTER)
					copy = CLUSTER;
				if (pos + copy > trackpos) {
					trackpos = pos + copy;
					if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
						ploop_err(errno, "PLOOP_IOC_TRACK_INIT");
						ret = SYSEXIT_DEVIOC;
						goto done;
					}
				}
				n = idelta.fops->pread(idelta.fd, iobuf, copy, pos);
				if (n < 0) {
					ploop_err(errno, "read3");
					ret = SYSEXIT_READ;
					goto done;
				}
				if (n == 0) {
					ploop_err(0, "unexpected EOF3");
					ret = SYSEXIT_READ;
					goto done;
				}
				if (send_buf(ofd, iobuf, n, pos)) {
					ploop_err(errno, "write3");
					ret = SYSEXIT_WRITE;
					goto done;
				}
				pos += n;
			}
		} else {
			if (errno == EAGAIN)
				break;

			ploop_err(errno, "PLOOP_IOC_TRACK_READ");
			ret = SYSEXIT_DEVIOC;
			goto done;
		}

		if (iter > 2) {
			ploop_err(0, "Too many iterations on frozen FS, aborting");
			goto done;
			ret = SYSEXIT_LOOP;
		}
	}

	/* Must clear dirty flag on ploop1 image. */
	if (strcmp(format, "ploop1") == 0) {
		int n;
		struct ploop_pvd_header *vh = (void*)iobuf;

		n = idelta.fops->pread(idelta.fd, iobuf, CLUSTER, 0);
		if (n != CLUSTER) {
			if (n < 0)
				ploop_err(errno, "read header");
			else
				ploop_err(0, "short read header");
			ret = SYSEXIT_READ;
			goto done;
		}

		vh->m_DiskInUse = 0;

		if (send_buf(ofd, iobuf, CLUSTER, 0)) {
			ploop_err(errno, "write3");
			ret = SYSEXIT_WRITE;
			goto done;
		}
	}

	if (ioctl(devfd, PLOOP_IOC_TRACK_STOP, 0)) {
		ploop_err(errno, "PLOOP_IOC_TRACK_STOP");
		ret = SYSEXIT_DEVIOC;
		goto done;
	}
	tracker_on = 0;

	if (send_buf(ofd, iobuf, 0, 0)) {
		ploop_err(errno, "write4");
		ret = SYSEXIT_WRITE;
		goto done;
	}

	if (fsync(ofd)) {
		ploop_err(errno, "fsync");
		ret = SYSEXIT_WRITE;
		goto done;
	}

done:
	if (tracker_on) {
		if (ioctl(devfd, PLOOP_IOC_TRACK_ABORT, 0))
			ploop_err(errno, "PLOOP_IOC_TRACK_ABORT");
	}
	if (iobuf)
		free(iobuf);
	if (devfd >=0)
		close(devfd);
	if (send_from)
		free(send_from);
	if (format)
		free(format);
	if (idelta.fd >= 0)
		close_delta(&idelta);

	return ret;
}
