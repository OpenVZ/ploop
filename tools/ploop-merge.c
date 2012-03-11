#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <getopt.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"

void usage(void)
{
	fprintf(stderr, "Usage: ploop merge -d DEVICE [-l LEVEL[..TOP_LEVEL]]\n"
		        "       ploop merge [-f raw] DELTAS_TO_DELETE BASE_DELTA\n"
		        "       ploop merge [-t] DiskDescriptor.xml\n");
}

int main(int argc, char ** argv)
{
	int raw = 0;
	int start_level = 0;
	int end_level = 0;
	int merge_top = 0;
	char *device = NULL;
	char **names = NULL;
	int i, ret;
	struct ploop_merge_param param = {};

	while ((i = getopt(argc, argv, "f:d:l:u:A")) != EOF) {
		switch (i) {
		case 'f':
			if (strcmp(optarg, "raw") == 0)
				raw = 1;
			else if (strcmp(optarg, "direct") != 0) {
				usage();
				return -1;
			}
			break;
		case 'd':
			device = optarg;
			break;
		case 'l':
			if (sscanf(optarg, "%d..%d", &start_level, &end_level) != 2) {
				if (sscanf(optarg, "%d", &start_level) != 1) {
					usage();
					return -1;
				}
				end_level = start_level + 1;
			}
			if (start_level >= end_level || start_level < 0) {
				usage();
				return -1;
			}
			break;
		case 'u':
			param.guid = optarg;
			break;
		case 'A':
			param.merge_all = 1;
			break;
		default:
			usage();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	ploop_set_verbose_level(3);

	if (argc == 1 && strstr(argv[0], DISKDESCRIPTOR_XML)) {
		struct ploop_disk_images_data *di;

		di = ploop_alloc_diskdescriptor();
		ret = ploop_read_diskdescriptor(argv[0], di);
		if (ret == 0)
			ret = ploop_merge_snapshot(di, &param);
		ploop_free_diskdescriptor(di);
	} else {
		if (device == NULL) {
			if (argc < 2) {
				usage();
				return -1;
			}
			end_level = get_list_size(argv);
			names = argv;
		} else {
			struct merge_info info = {};

			if (argc || raw) {
				usage();
				return -1;
			}

			info.start_level = start_level;
			info.end_level = end_level;
			if ((ret = get_delta_info(device, param.merge_top_only, &info)))
				return ret;
			start_level = info.start_level;
			end_level = info.end_level;
			raw = info.raw;
			names = info.names;
			merge_top = info.merge_top;
		}

		ret = merge_image(device, start_level, end_level, raw, merge_top, names);
	}

	return ret;
}

