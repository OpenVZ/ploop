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
	fprintf(stderr, "Usage: ploop copy [-F STOPCMD] { [-d FILE] | [-o OFD] [-f FFD]} DiskDescriptor.xml\n"
	"       ploop copy -d FILE [-i IFD] [-f FFD] DiskDescriptor.xml\n"
	"       DEVICE  := source ploop device, e.g. /dev/ploop0\n"
	"       STOPCMD := a command to stop disk activity, e.g. \"vzctl chkpnt\"\n"
	"       FILE    := destination file name\n"
	"       OFD     := output file descriptor\n"
	"       IFD     := input file descriptor\n"
	"       FFD     := feedback file descriptor\n"
		"Action: effectively copy top ploop delta with write tracker\n"
);
}

int plooptool_copy(int argc, char **argv)
{
	int i, ret;
	struct ploop_copy_param s = {
		.ofd		=  1,	/* write to stdout by default */
	};
	struct ploop_copy_receive_param r = {
		.ifd		=  0,	/* read from stdin by default */
		.feedback_fd	= -1,	/* no feedback */
	};
	struct ploop_disk_images_data *di;
	struct ploop_copy_handle *h;
	struct ploop_copy_stat stat = {};

	while ((i = getopt(argc, argv, "F:d:o:i:f:")) != EOF) {
		switch (i) {
		case 'd':
			r.file = optarg;
			break;
			break;
		case 'F':
			//flush_cmd = optarg;
			break;
		case 'o':
			s.ofd = atoi(optarg);
			break;
		case 'i':
			r.ifd = atoi(optarg);
			break;
		case 'f':
			break;
		default:
			usage();
			return SYSEXIT_PARAM;
		}
	}

	argc -= optind;
	argv += optind;

	if (!r.file && !is_xml_fname(argv[0])) {
		fprintf(stderr, "Either -s or -d is required\n");
		usage();
		return SYSEXIT_PARAM;
	}

	signal(SIGPIPE, SIG_IGN);

	if (r.file)
		return ploop_copy_receiver(&r);

	ret = ploop_open_dd(&di, argv[0]);
	if (ret)
		return ret;

	ret = ploop_copy_init(di, &s, &h);
	if (ret)
		goto err;

	ret = ploop_copy_start(h, &stat);
	if (ret)
		goto err;

	for (i = 0; i < 3; i++) {
		
		ret = ploop_copy_next_iteration(h, &stat);
		if (ret)
			goto err;
	}

	ret = ploop_copy_stop(h, &stat);
	
err:
	ploop_copy_deinit(h);
	if (r.file) {
		close(s.ofd);
		if (ret)
			unlink(r.file);
	}
	ploop_close_dd(di);

	return ret;
}
