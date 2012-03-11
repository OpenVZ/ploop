#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"

int force;	/* try to repair non-fatal conditions */
int hard_force; /* try to repair even fatal conditions */
int check;	/* build bitmap and check for duplicate blocks */
int ro;		/* read-only access to image file */
int silent;	/* print messages only if errors detected */

static void usage(void)
{
	fprintf(stderr, "Usage: ploop fsck [-f|-F] [-c] [-r] [-s] DELTA\n"
			"	-f     - force fsck even if dirty flag is clear\n"
			"	-F     - -f and try to fix even fatal errors (dangerous)\n"
			"	-c     - check for duplicated blocks and holes\n"
			"	-r     - do not modify DELTA (read-only access)\n"
			"	-s     - be silent, report only errors\n"
		);
}

int main(int argc, char ** argv)
{
	int i;

	while ((i = getopt(argc, argv, "fFcrs")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
			break;
		case 'F':
			force = 1;
			hard_force = 1;
			break;
		case 'c':
			check = 1;
			break;
		case 'r':
			ro = 1;
			break;
		case 's':
			silent = 1;
			break;
		default:
			usage();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		return -1;
	}

	ploop_set_verbose_level(3);

	return ploop_fsck(argv[0], force, hard_force, check, ro, !silent);
}
