#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"

char  *mount_point;
int    force;	   /* do not flock hidden balloon */

char  *device;	   /* ploop device name (e.g. /dev/ploop0) */

struct delta delta;

void usage_summary(void)
{
	fprintf(stderr, "Usage: ploop-balloon { show | status | clear | change | complete | check | repair } ...\n"
			"Use \"ploop-balloon cmd\" to get more info about cmd\n"
		);
}

static void usage_show(void)
{
	fprintf(stderr, "Usage: ploop-balloon show [-f] -m MOUNT_POINT\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"	-f	    - do not flock hidden balloon\n"
			"Action: show current ploop balloon size\n"
		);
}

static int pb_show(int argc, char **argv)
{
	int i, ret;
	struct stat st;

	while ((i = getopt(argc, argv, "fm:")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_show();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || mount_point == NULL) {
		usage_show();
		return -1;
	}

	ret = get_balloon(mount_point, &st, NULL);
	if (ret)
		return ret;
	fprintf(stdout, "Current size of hidden balloon is %llu bytes",
		(unsigned long long) st.st_size);
	return 0;
}

static void usage_status(void)
{
	fprintf(stderr, "Usage: ploop-balloon status -d DEVICE -m MOUNT_POINT\n"
			"	ploop-balloon status -f -d DEVICE\n"
			"	DEVICE	    := ploop device, f.e. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"	-f	    - do not flock hidden balloon\n"
			"Action: inquire current in-kernel status of maintenance\n"
		);
}

static int pb_status(int argc, char **argv)
{
	int i, ret;
	__u32 state;

	while ((i = getopt(argc, argv, "fd:m:")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_status();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || device == NULL ||
	    (mount_point == NULL && !force) ||
	    (mount_point != NULL && force)) {
		usage_status();
		return -1;
	}

	ret = ploop_balloon_get_state(device, &state);
	if (ret)
		return ret;

	fprintf(stdout, "Current state of in-kernel maintenance: %s",
	       mntn2str(state));
	return 0;
}

static void usage_clear(void)
{
	fprintf(stderr, "Usage: ploop-balloon clear -d DEVICE -m MOUNT_POINT\n"
			"	DEVICE	    := ploop device, f.e. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: clear stale in-kernel \"BALLOON\" state of maintenance\n"
		);
}

static int pb_clear(int argc, char **argv)
{
	int i, ret;
	int fd2;

	while ((i = getopt(argc, argv, "d:m:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_clear();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || device == NULL || mount_point == NULL) {
		usage_clear();
		return -1;
	}

	ret = get_balloon(mount_point, NULL, &fd2);
	if (ret)
		return ret;

	ret = ploop_balloon_clear_state(device);
	if (ret)
		return ret;
	fprintf(stdout, "Current state of in-kernel maintenance is OFF now");
	return 0;
}

static void usage_change(void)
{
	fprintf(stderr, "Usage: ploop-balloon change -s SIZE -d DEVICE -m MOUNT_POINT\n"
			"	SIZE	    := NUMBER[kmg] (new size of balloon)\n"
			"	DEVICE	    := ploop device, f.e. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: inflate or truncate hidden balloon (dependently on new_size vs. old_size)\n"
		);
}

static int pb_change(int argc, char **argv)
{
	int    fd;
	int    i, ret;
	off_t  new_size = 0;
	int    new_size_set = 0;

	while ((i = getopt(argc, argv, "s:d:m:")) != EOF) {
		switch (i) {
		case 's':
			/* NB: currently, new_size is in 'sector' units */
			if (parse_size(optarg, &new_size)) {
				usage_change();
				return -1;
			}
			new_size_set++;
			break;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_change();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || !new_size_set ||
	    device == NULL || mount_point == NULL) {
		usage_change();
		return -1;
	}
	ret = get_balloon(mount_point, NULL, &fd);
	if (ret)
		return ret;

	return ploop_balloon_change_size(device, fd, new_size);
}

static void usage_complete(void)
{
	fprintf(stderr, "Usage: ploop-balloon complete -d DEVICE -m MOUNT_POINT\n"
			"	DEVICE	    := ploop device, f.e. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: complete previously interrupted balloon operation\n"
			"	 (sensible only if kernel is in \"FBLOAD\" or \"RELOC\"\n"
			"	  state of maintenance)\n"
		);
}

static int pb_complete(int argc, char **argv)
{
	int i, ret, fd;

	while ((i = getopt(argc, argv, "d:m:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			usage_complete();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || device == NULL || mount_point == NULL) {
		usage_complete();
		return -1;
	}

	ret = get_balloon(mount_point, NULL, &fd);
	if (ret)
		return ret;

	return ploop_baloon_complete(device);
}

static void usage_check(void)
{
	fprintf(stderr, "Usage: ploop-balloon check -d DEVICE -m MOUNT_POINT\n"
			"	DEVICE	    := ploop device, f.e. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: check whether hidden balloon has free blocks\n"
		);
}

static void usage_repair(void)
{
	fprintf(stderr, "Usage: ploop-balloon repair -d DEVICE -m MOUNT_POINT\n"
			"	DEVICE	    := ploop device, f.e. /dev/ploop0\n"
			"	MOUNT_POINT := path where fs living on ploop device mounted to\n"
			"Action: repair hidden balloon (i.e. relocate all free blocks\n"
			"	 present in hidden balloon (w/o inflate))\n"
		);
}

static int pb_check_and_repair(int argc, char **argv, int repair)
{
	int i;

	while ((i = getopt(argc, argv, "fd:m:")) != EOF) {
		switch (i) {
		case 'f':
			force = 1;
		case 'd':
			device = optarg;
			break;
		case 'm':
			mount_point = optarg;
			break;
		default:
			if (repair)
				usage_repair();
			else
				usage_check();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || device == NULL ||
	    (mount_point == NULL && !force) ||
	    (mount_point != NULL && force)) {
		if (repair)
			usage_repair();
		else
			usage_check();
		return -1;
	}

	return ploop_baloon_check_and_repair(device, mount_point, repair);

}

int main(int argc, char **argv)
{
	char *cmd;

	if (argc < 2) {
		usage_summary();
		return -1;
	}

	cmd = argv[1];
	argc--;
	argv++;

	ploop_set_verbose_level(3);

	if (strcmp(cmd, "show") == 0)
		return pb_show(argc, argv);
	if (strcmp(cmd, "status") == 0)
		return pb_status(argc, argv);
	if (strcmp(cmd, "clear") == 0)
		return pb_clear(argc, argv);
	if (strcmp(cmd, "change") == 0)
		return pb_change(argc, argv);
	if (strcmp(cmd, "complete") == 0)
		return pb_complete(argc, argv);
	if (strcmp(cmd, "check") == 0)
		return pb_check_and_repair(argc, argv, 0); /* check only */
	if (strcmp(cmd, "repair") == 0)
		return pb_check_and_repair(argc, argv, 1); /* check and repair */

	usage_summary();
	return -1;
}
