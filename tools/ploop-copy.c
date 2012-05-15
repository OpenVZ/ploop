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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "libploop.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ploop-copy -s DEVICE [-F STOPCOMMAND]\n"
			"       ploop-copy -d DESTINATION\n");
}

int main(int argc, char **argv)
{
	int i, ofd;
	const char *device;
	const char *recv_to;
	const char *flush_cmd;

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
		fprintf(stderr, "Either -s or -d is required\n");
		usage();
		return SYSEXIT_PARAM;
	}

	if (!device)
		return receive_process(recv_to);

	if (recv_to) {
		ofd = open(recv_to, O_WRONLY|O_CREAT|O_EXCL, 0600);
		if (ofd < 0) {
			perror("open destination");
			return SYSEXIT_CREAT;
		}
	}
	else {
		if (isatty(1) || errno == EBADF) {
			fprintf(stderr, "Invalid output stream: must be "
					"pipelined to a pipe or socket\n");
			return SYSEXIT_PARAM;
		}
		ofd = 1;
	}

	return send_process(device, ofd, flush_cmd);
}
