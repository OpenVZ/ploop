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

int ofd = -1;

char * recv_to;
char * device;
char * flush_cmd;
int tracker_on;
int devfd;

void usage(void)
{
	fprintf(stderr, "Usage: ploop-copy -s DEVICE] [-d DESTINATION] [-F STOPCOMMAND]\n");
}

void atexit_cb(void)
{
	if (tracker_on) {
		if (ioctl(devfd, PLOOP_IOC_TRACK_ABORT, 0)) {
			perror("PLOOP_IOC_TRACK_ABORT");
		}
	}
	if (ofd >= 0) {
		close(ofd);
		ofd = -1;
		unlink(recv_to);
	}
}

static int nread(int fd, void * buf, int len)
{
	while (len) {
		int n;

		n = read(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		len -= n;
		buf += n;
	}

	if (len == 0)
		return 0;

	errno = EIO;
	return -1;
}

int receive_process(void)
{
	int ofd;
	unsigned long iobuf[CLUSTER/sizeof(unsigned long)];

	if (isatty(0) || errno == EBADF) {
		fprintf(stderr, "Invalid input stream: must be pipelined to a pipe or socket\n");
		return SYSEXIT_PARAM;
	}

	ofd = open(recv_to, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (ofd < 0) {
		perror("open");
		return SYSEXIT_CREAT;
	}
	atexit(atexit_cb);

	for (;;) {
		int n;
		struct xfer_desc desc;

		if (nread(0, &desc, sizeof(desc)) < 0) {
			perror("nread desc");
			return SYSEXIT_READ;
		}
		if (desc.marker != PLOOPCOPY_MARKER) {
			fprintf(stderr, "stream corrupted\n");
			return SYSEXIT_PROTOCOL;
		}
		if (desc.size > CLUSTER) {
			fprintf(stderr, "stream corrupted, too long chunk\n");
			return SYSEXIT_PROTOCOL;
		}
		if (desc.size == 0)
			break;

		if (nread(0, iobuf, desc.size)) {
			perror("nread data");
			return SYSEXIT_READ;
		}
		n = pwrite(ofd, iobuf, desc.size, desc.pos);
		if (n != desc.size) {
			if (n < 0)
				perror("pwrite");
			else
				fprintf(stderr, "short pwrite\n");
			return SYSEXIT_WRITE;
		}
	}

	if (fsync(ofd)) {
		perror("fsync");
		return SYSEXIT_WRITE;
	}
	if (close(ofd)) {
		perror("close");
		ofd = -1;
		return SYSEXIT_WRITE;
	}
	ofd = -1;
	return 0;
}

int main(int argc, char **argv)
{
	int i, ofd;

	while ((i = getopt(argc, argv, "F:s:d:")) != EOF) {
		switch (i) {
		case 'd':
			recv_to = optarg;
			break;
		case 's':
			device = optarg;
			break;
		case 'F':
			flush_cmd = optarg;
			break;
		default:
			usage();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		usage();
		return SYSEXIT_PARAM;
	}

	if (!device && !recv_to) {
		fprintf(stderr, "At least one of -s or -d is required\n");
		usage();
		return SYSEXIT_PARAM;
	}

	if (!device)
		return receive_process();

	ofd = open(recv_to, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (ofd < 0) {
		perror("open destination");
		return SYSEXIT_CREAT;
	}

	return send_process(device, ofd, flush_cmd);
}
