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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "libploop.h"
#include "ploop.h"
#include "common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ploop copy -s DEVICE -t FORMAT { [-d FILE] | [-o OFD] [-f FFD]}\n"
			"       ploop copy -d FILE [-i IFD]\n"
			"       DEVICE  := source ploop device, e.g. /dev/ploop0\n"
			"       FORMAT  := " USAGE_FORMATS "\n"
			"       FILE    := destination file name\n"
			"       OFD     := output file descriptor\n"
			"       IFD     := input file descriptor\n"
			"Action: effectively copy top ploop delta with write tracker\n"
			);
}

int plooptool_copy(int argc, char **argv)
{
	int i, ret;
	int niter = 3;
	struct ploop_copy_handle *h = NULL;
 	struct ploop_copy_stat stat;
 	struct ploop_copy_param s = {
		.ofd		=  1,	/* write to stdout by default */
	};
	struct ploop_copy_receive_param r = {
		.ifd		=  0,	/* read from stdin by default */
		.feedback_fd	= -1,	/* no feedback */
	};

	while ((i = getopt(argc, argv, "s:t:d:o:i:")) != EOF) {
		switch (i) {
		case 'd':
			r.file = optarg;
			break;
		case 's':
			s.device = optarg;
			break;
		case 'o':
			s.ofd = atoi(optarg);
			break;
		case 'i':
			r.ifd = atoi(optarg);
			break;
		case 't':
			s.image_fmt = parse_format_opt(optarg);
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

	if (!s.device && !r.file) {
		fprintf(stderr, "Either -s or -d is required\n");
		usage();
		return SYSEXIT_PARAM;
	}

	signal(SIGPIPE, SIG_IGN);

	if (!s.device)
		return ploop_copy_receiver(&r);

	if (r.file) {
		/* Write to a file, not pipe */
		s.ofd = open(r.file, O_WRONLY|O_CREAT|O_EXCL, 0600);
		if (s.ofd < 0) {
			fprintf(stderr, "Can't open %s: %m", r.file);
			return SYSEXIT_CREAT;
		}
	}

	if (s.ofd == 1)
		ploop_set_verbose_level(PLOOP_LOG_NOCONSOLE);

	ret = ploop_copy_init(NULL, &s, &h);
	if (ret)
		return ret;
	ret = ploop_copy_start(h, &stat);
	if (ret)
		goto err;
	
	for (i = 0; i < niter; i++) {
		ret = ploop_copy_next_iteration(h, &stat);
		if (ret)
			goto err;
	}

	ret = ploop_copy_stop(h, &stat);
	if (ret)
		goto err;
	
err:
	ploop_copy_deinit(h);
	if (r.file) {
		close(s.ofd);
		if (ret)
			unlink(r.file);
	}

	return ret;
}
