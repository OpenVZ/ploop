#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <getopt.h>
#include <linux/types.h>
#define le16_to_cpu(a) a
#define cpu_to_le16(a) a
#define BUG() do { } while(0)
#include <linux/ext3_fs.h>
#include <string.h>

#include "ploop.h"

char * device;
char * outfile;
int merge;
int raw;
int top_level = -1;

__u32 * bmap;
int bmap_size;

__u32 * rmap;
__u32 alloc_head;


struct delta_array da;

int ofd;

static void atexit_cb(void)
{
	if (ofd >= 0) {
		close(ofd);
		unlink(outfile);
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: ploop shrink [-f raw] [-d DEVICE -l LEVEL | [ TOP_DELTA... ] BASE_DELTA ]\n");
	fprintf(stderr, "       ploop shrink [-f raw] [-o OUTFILE [-m]] [-d DEVICE -l LEVEL | [ TOP_DELTA... ] BASE_DELTA ]\n");
}

#if 0

static int test_root(int a, int b)
{
	while (1) {
		if (a == 1)
			return 1;
		if (a % b)
			return 0;
		a = a / b;
	}
}

int has_super(int grp)
{
	if (!(sb.s_feature_ro_compat & EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER))
		return 1;

	if (grp == 0)
		return 1;

	if (test_root(grp, 3) || (test_root(grp, 5)) || test_root(grp, 7))
		return 1;

	return 0;
}
#endif

int collect_bitmap(struct delta_array * p)
{
	int i;
	int blocks_per_cluster;
	int groups_count;
	struct ext3_group_desc * descs;
	struct ext3_super_block sb;

	if (delta_read(p, &sb, sizeof(sb), 1024)) {
		perror("delta_read");
		return SYSEXIT_READ;
	}

	if (sb.s_magic != EXT3_SUPER_MAGIC) {
		fprintf(stderr, "Not ext3/ext2\n");
		return SYSEXIT_FS;
	}
	if (sb.s_feature_incompat & EXT3_FEATURE_INCOMPAT_META_BG) {
		fprintf(stderr, "Still no idea what is EXT2_FEATURE_INCOMPAT_META_BG\n");
		return SYSEXIT_FS;
	}
	if (sb.s_feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER) {
		fprintf(stderr, "Dirty EXT3 journal, cannot shrink\n");
		return SYSEXIT_FS;
	}
	if (sb.s_blocks_per_group != (1<<(sb.s_log_block_size+10+3))) {
		fprintf(stderr, "Hmm, funny group layout\n");
		return SYSEXIT_FS;
	}
	if ((sb.s_blocks_count << (sb.s_log_block_size + 1)) > p->bd_size) {
		fprintf(stderr, "File system does not fit to block device\n");
		return SYSEXIT_FS;
	}

	blocks_per_cluster = CLUSTER >> (sb.s_log_block_size + 10);

	bmap_size = (sb.s_blocks_count + blocks_per_cluster - 1) / blocks_per_cluster;
	bmap_size = (bmap_size + 31) / 8;
	bmap = calloc(bmap_size, 1);
	if (bmap == NULL) {
		perror("malloc");
		return SYSEXIT_MALLOC;
	}

 	groups_count = ((sb.s_blocks_count - sb.s_first_data_block - 1)
		/ sb.s_blocks_per_group) + 1;
	descs = malloc(sizeof(struct ext3_group_desc)*groups_count);
	if (descs == NULL) {
		perror("malloc");
		return SYSEXIT_MALLOC;
	}
	if (delta_read(p, descs, sizeof(struct ext3_group_desc)*groups_count,
		       (sb.s_first_data_block + 1)<<(sb.s_log_block_size+10))) {
		perror("delta_read");
		return SYSEXIT_READ;
	}

	for (i = 0; i < groups_count; i++) {
		__u32 map[1<<(sb.s_log_block_size+10-2)];
		__u32 cur = i*sb.s_blocks_per_group;
		__u32 maxb = sb.s_blocks_per_group;
#if 0
		int res_gdt_start = 0;
		int res_gdt_end = 0;

		if (has_super(i)) {
			res_gdt_start = groups_count*sizeof(struct ext3_group_desc);
			res_gdt_start += (1<<(sb.s_log_block_size+10)) - 1;
			res_gdt_start >>= sb.s_log_block_size+10;
			res_gdt_start++;

			res_gdt_end = res_gdt_start + sb.s_reserved_gdt_blocks;
		}
#endif

		if (cur + maxb > sb.s_blocks_count)
			maxb = sb.s_blocks_count - cur;

		maxb += cur;

		if (delta_read(p, map, sizeof(map), (off_t)descs[i].bg_block_bitmap<<(sb.s_log_block_size+10))) {
			perror("delta_read");
			return SYSEXIT_READ;
		}

		for ( ; cur < maxb; cur++) {
			int bit = cur % sb.s_blocks_per_group;
			if (map[bit / 32] & (1<<(bit % 32))) {
#if 0
				if (bit < res_gdt_end && bit >= res_gdt_start)
					continue;
#endif

				__u32 cl = cur / blocks_per_cluster;
				bmap[cl / 32] |= (1 << (cl % 32));
			}
		}
	}
	return 0;
}

void sync_index(struct delta * delta)
{
	if (delta->l2_cache >= 0 && delta->l2_dirty) {
		ssize_t res;

		res = pwrite(delta->fd, delta->l2, CLUSTER,
			     (off_t)delta->l1[delta->l2_cache]*CLUSTER);
		if (res != CLUSTER) {
			if (res >= 0)
				errno = EIO;
			perror("pwrite");
			exit(SYSEXIT_WRITE);
		}
		delta->l2_dirty = 0;
	}
}

int shrink_in_place(void)
{
	int i;
	ssize_t res;

	/* Build reversed mapping: file offset -> virtual cluster.
	 * Also, remove from bitmap clusters, which are not covered
	 * by top delta.
	 */

	alloc_head = da.delta_arr[0].dh->alloc_head;

	rmap = malloc(alloc_head*4);
	if (rmap == NULL) {
		perror("malloc");
		return SYSEXIT_MALLOC;
	}

	memset(rmap, -1, alloc_head*4);
	rmap[0] = -2;
	rmap[1] = -2;

	for (i = 0; i < CLUSTER/4; i++) {
		int k;

		if (da.delta_arr[0].l1[i] == 0) {
			for (k = 0; k < CLUSTER/4; k++) {
				__u32 cl = k + i*(CLUSTER/4);
				if (cl < bmap_size*8)
					bmap[cl / 32] &= ~(1 << (cl % 32));
			}
			continue;
		}
		if (da.delta_arr[0].l1[i] >= alloc_head) {
			fprintf(stderr, "corrupted: block beyond eof\n");
			return SYSEXIT_PLOOPFMT;
		}
		if (rmap[da.delta_arr[0].l1[i]] != ~0U) {
			fprintf(stderr, "corrupted: block used more than once\n");
			return SYSEXIT_PLOOPFMT;
		}
		rmap[da.delta_arr[0].l1[i]] = 0x80000000 | i;

		check_l2_cache(&da.delta_arr[0], i);

		for (k = 0; k < CLUSTER/4; k++) {
			__u32 cl = k + i*(CLUSTER/4);

			if (da.delta_arr[0].l2[k] == 0) {
				if (cl < bmap_size*8)
					bmap[cl / 32] &= ~(1 << (cl % 32));
				continue;
			}
			if (da.delta_arr[0].l2[k] >= alloc_head) {
				fprintf(stderr, "corrupted: block beyond eof\n");
				return SYSEXIT_PLOOPFMT;
			}
			if (rmap[da.delta_arr[0].l2[k]] != ~0U) {
				fprintf(stderr, "corrupted: block used more than once\n");
				return SYSEXIT_PLOOPFMT;
			}
			rmap[da.delta_arr[0].l2[k]] = cl;
		}
	}

	/* Count holes. */

	int holes = 0;
	for (i = 0; i < alloc_head; i++) {
		if (rmap[i] == ~0U) {
			holes++;
		} else if (!(rmap[i] & 0x80000000)) {
			__u32 cl = rmap[i];
			if (!(bmap[cl / 32] & (1 << (cl % 32))))
				holes++;
		}
	}

	if (holes == 0) {
		fprintf(stderr, "No holes - nothing to do\n");
		return 0;
	}

	if (dirty_delta(&da.delta_arr[0])) {
		perror("dirty_delta");
		return SYSEXIT_WRITE;
	}

	/* This position is going to be new end of file,
	 * everything after this position is to be relocated
	 */
	__u32 trim_to = alloc_head - holes;
	__u32 reloc_dst = 1;
	__u32 reloc_src;

	for (reloc_src = 2; reloc_src < alloc_head; reloc_src++) {
		__u32 cl;
		__u32 reloc_to;

		/* Real hole. This should not happen normally,
		 * but it is possible when machine crashes before
		 * index is synced to disk.
		 *
		 * Nothing to do.
		 */
		if (rmap[reloc_src] == ~0U)
			continue;

		/* This cluster corresponds to some virtual cluster,
		 * but it is not used by inner FS. Clear the index.
		 */
		cl = rmap[reloc_src];
		if (!(cl & 0x80000000) &&
		    !(bmap[cl / 32] & (1 << (cl % 32)))) {
			reloc_to = 0;
			goto update_index;
		}

		/* If cluster is before new EOF, we are done. */
		if (reloc_src < trim_to)
			continue;

		/* Otherwise, find a place before new EOF, where we
		 * can relocate this cluster to.
		 */
		for (reloc_dst++; reloc_dst < trim_to; reloc_dst++) {
			if (rmap[reloc_dst] == ~0U)
				break;
			cl = rmap[reloc_dst];
			if (!(cl & 0x80000000) &&
			    !(bmap[cl / 32] & (1 << (cl % 32))))
				break;
		}

		if (reloc_dst >= trim_to) {
			fprintf(stderr, "BUG: out of holes\n");
			return SYSEXIT_PLOOPFMT;
		}

		/* OK, now we are to relocate cluster at reloc_src
		 * to cluster at reloc_dst.
		 */
		if ((rmap[reloc_src] & 0x80000000) &&
		    da.delta_arr[0].l2_cache == (rmap[reloc_src] & ~0x80000000)) {
			__u32 idx = (rmap[reloc_src] & ~0x80000000);

			/* A little optimization: cluster could be index
			 * cluster and it could be in cache. We just update
			 * memory copy and we are done.
			 */
			da.delta_arr[0].l2_dirty = 1;
			da.delta_arr[0].l1[idx] = reloc_dst;
			da.delta_arr[0].l1_dirty = 1;
		} else {
			res = pread(da.delta_arr[0].fd, da.data_cache, CLUSTER,
				    (off_t)reloc_src*CLUSTER);
			if (res != CLUSTER) {
				if (res >= 0)
					errno = EIO;
				perror("pread");
				return SYSEXIT_READ;
			}
			res = pwrite(da.delta_arr[0].fd, da.data_cache, CLUSTER,
				     (off_t)reloc_dst*CLUSTER);
			if (res != CLUSTER) {
				if (res >= 0)
					errno = EIO;
				perror("pwrite");
				return SYSEXIT_WRITE;
			}

			if (rmap[reloc_src] & 0x80000000) {
				/* If it was index cluster, we just update
				 * memory copy of L1 index and that's all.
				 */
				__u32 l1_idx = rmap[reloc_src] & ~0x80000000;
				da.delta_arr[0].l1[l1_idx] = reloc_dst;
				da.delta_arr[0].l1_dirty = 1;
			} else {
				__u32 l1_idx;

				reloc_to = reloc_dst;

update_index:
				cl = rmap[reloc_src];
				l1_idx = cl / (CLUSTER/4);
				if (l1_idx != da.delta_arr[0].l2_cache) {
					sync_index(&da.delta_arr[0]);

					res = pread(da.delta_arr[0].fd,
						    da.delta_arr[0].l2,
						    CLUSTER,
						    (off_t)da.delta_arr[0].l1[l1_idx]*CLUSTER);
					if (res != CLUSTER) {
						if (res >= 0)
							errno = EIO;
						perror("pread index");
						return SYSEXIT_READ;
					}
					da.delta_arr[0].l2_dirty = 0;
					da.delta_arr[0].l2_cache = l1_idx;
				}
				if (da.delta_arr[0].l2[cl % (CLUSTER/4)] != reloc_to) {
					da.delta_arr[0].l2[cl % (CLUSTER/4)] = reloc_to;
					da.delta_arr[0].l2_dirty = 1;
				}
			}
		}
	}

	sync_index(&da.delta_arr[0]);

	if (da.delta_arr[0].l1_dirty) {
		res = pwrite(da.delta_arr[0].fd,  da.delta_arr[0].l1,
			     CLUSTER, (off_t)CLUSTER);
		if (res != CLUSTER) {
			if (res >= 0)
				errno = EIO;
			perror("pwrite");
			return SYSEXIT_WRITE;
		}
		da.delta_arr[0].l1_dirty = 0;
	}

	da.delta_arr[0].dh->dirty = 0;
	da.delta_arr[0].dh->alloc_head = trim_to;
	da.delta_arr[0].dh->generation++;
	res = pwrite(da.delta_arr[0].fd, da.delta_arr[0].dh,
		     512, (off_t)4*4096);
	if (res != 512) {
		if (res >= 0)
			errno = EIO;
		perror("pwrite");
		return SYSEXIT_WRITE;
	}

	if (fsync(da.delta_arr[0].fd)) {
		perror("fsync");
		return SYSEXIT_WRITE;
	}

	if (top_level >= 0) {
		int lfd;

		lfd = open(device, O_RDONLY);
		if (lfd < 0) {
			perror("open dev");
			return SYSEXIT_DEVICE;
		}

		struct ploop_truncate_ctl treq = {
			.fd = da.delta_arr[0].fd,
			.alloc_head = trim_to,
			.level = top_level,
		};
		if (ioctl(lfd, PLOOP_IOC_TRUNCATE, &treq)) {
			perror("PLOOP_IOC_TRUNCATE");
			return SYSEXIT_DEVIOC;
		}
	} else {
		if (ftruncate(da.delta_arr[0].fd, (off_t)trim_to*CLUSTER)) {
			perror("ftruncate");
			return SYSEXIT_WRITE;
		}
		if (fsync(da.delta_arr[0].fd)) {
			perror("fsync");
			return SYSEXIT_WRITE;
		}
	}
	return 0;
}

static int WRITE(int fd, void * buf, unsigned int size, off_t pos)
{
	ssize_t res;

	res = pwrite(fd, buf, size, pos);
	if (res == size)
		return 0;

	if (res < 0) {
		perror("write");
		exit(SYSEXIT_WRITE);
	}
	fprintf(stderr, "short write\n");
	exit(SYSEXIT_WRITE);
}

int full_rebuild(void)
{
	unsigned char hdr0[CLUSTER];
	__u32 l1[CLUSTER/4];
	__u32 l2[CLUSTER/4];
	__u32 buf[CLUSTER/4];
	int l2_cache = -1;
	struct ploop_img_header * ph = (void*)hdr0;
	struct ploop_img_dyn_header * dh = (void*)hdr0 + 4*4096;
	off_t pos;
	size_t res;
	int i, k;
	int level;

	memset(hdr0, 0, sizeof(hdr0));
	memset(l1, 0, sizeof(l1));

	ph->signature = PLOOP1_SIGNATURE;
	ph->magic = PLOOP1_MAGIC;
	ph->version = PLOOP1_VERSION;
	ph->sector_log = 9;
	ph->cluster_log = 8;
	ph->data_start = CLUSTER/512;
	ph->l1_offset = 1;
	ph->l1_size = CLUSTER;
	ph->dyn_offset = 4*4096/512;
	if (uuid_new((unsigned char*)ph->guid)) {
		perror("uuid_new");
		return SYSEXIT_SYS;
	}

	pos = CLUSTER*2;
	dh->alloc_head = pos / CLUSTER;
	dh->dirty = 1;
	dh->disk_size_lo = da.bd_size & 0xFFFFFFFFULL;
	dh->disk_size_hi = da.bd_size >> 32;

	WRITE(ofd, hdr0, sizeof(hdr0), 0);
	WRITE(ofd, l1, sizeof(l1), CLUSTER);

	for (i = 0; i < bmap_size*8; i++) {
		int l1_slot = i / (CLUSTER/4);

		if (!(bmap[i / 32] & (1<<(i % 32))))
			continue;

		if (!merge && da.delta_max) {
			if (da.delta_arr[0].l1[l1_slot] == 0)
				continue;
			if (da.delta_arr[0].l2_cache != l1_slot) {
				res = pread(da.delta_arr[0].fd, da.delta_arr[0].l2,
					    CLUSTER,
					    (off_t)da.delta_arr[0].l1[l1_slot] * CLUSTER);
				if (res != CLUSTER) {
					if (res >= 0)
						errno = EIO;
					perror("read");
					return SYSEXIT_READ;
				}
				da.delta_arr[0].l2_cache = l1_slot;
			}
			if (da.delta_arr[0].l2[i % (CLUSTER/4)] == 0)
				continue;
		}

		if (delta_read_2(&da, buf, CLUSTER, (off_t)i * CLUSTER, &level)) {
			perror("delta_read");
			return SYSEXIT_READ;
		}

		if (level < 0)
			continue;

		/* Detect and skip zero blocks */

		for (k = 0; k < CLUSTER/4; k++) {
			if (buf[k])
				break;
		}

		if (k == CLUSTER/4) {
			if (da.raw_fd >= 0) {
				/* If we have raw delta zero blocks are skipped
				 * only when it is read from raw delta.
				 */
				if (level >= da.delta_max)
					continue;
			} else {
				/* Otherwise, we scan delta list to be sure
				 * that zero cluster does not cover any
				 * cluster in lower deltas.
				 */
				for (k = level + 1; k < da.delta_max; k++) {
					if (da.delta_arr[k].l1[l1_slot] == 0)
						continue;
					if (da.delta_arr[k].l2_cache != l1_slot) {
						res = pread(da.delta_arr[k].fd,
							    da.delta_arr[k].l2,
							    CLUSTER,
							    (off_t)da.delta_arr[k].l1[l1_slot] * CLUSTER);
						if (res != CLUSTER) {
							if (res >= 0)
								errno = EIO;
							perror("read");
							return SYSEXIT_READ;
						}
						da.delta_arr[k].l2_cache = l1_slot;
					}
					if (da.delta_arr[k].l2[i % (CLUSTER/4)] == 0)
						continue;
				}
				if (k >= da.delta_max)
					continue;
			}
		}

		if (l1[l1_slot] == 0) {
			l1[l1_slot] = pos / CLUSTER;
			pos += CLUSTER;
		}
		if (l2_cache != l1_slot) {
			if (l2_cache >= 0) {
				WRITE(ofd, l2, sizeof(l2),
				      (off_t)(l1[l2_cache])*CLUSTER);
			}
			l2_cache = l1_slot;
			memset(l2, 0, sizeof(l2));
		}
		l2[i % (CLUSTER/4)] = pos / CLUSTER;
		WRITE(ofd, buf, sizeof(buf), pos);
		pos += CLUSTER;
	}

	if (l2_cache >= 0) {
		WRITE(ofd, l2, sizeof(l2),
		      (off_t)(l1[l2_cache])*CLUSTER);
	}

	dh->dirty = 0;
	dh->alloc_head = pos / CLUSTER;
	WRITE(ofd, hdr0, sizeof(hdr0), 0);
	WRITE(ofd, l1, sizeof(l1), CLUSTER);

	if (fsync(ofd)) {
		perror("fsync");
		return SYSEXIT_WRITE;
	}
	if (close(ofd)) {
		perror("close");
		return SYSEXIT_WRITE;
	}
	ofd = -1;
	return 0;
}

int main(int argc, char ** argv)
{
	int i;
	char **names;
	int ndelta;
	int running;

	while ((i = getopt(argc, argv, "d:l:o:mf:")) != EOF) {
		switch (i) {
		case 'd':
			device = optarg;
			break;
		case 'l':
			top_level = atoi(optarg);
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'f':
			if (strcmp(optarg, "raw") == 0)
				raw = 1;
			else if (strcmp(optarg, "ploop1") != 0) {
				usage();
				return -1;
			}
			break;
		case 'm':
			merge = 1;
			break;
		default:
			usage();
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (device) {
		if (top_level < 0 || argc) {
			usage();
			return -1;
		}
	} else {
		if (top_level >= 0 || !argc) {
			usage();
			return -1;
		}
	}

	if (merge && !outfile) {
		usage();
		return -1;
	}

	if (top_level >= 0) {
		char * fmt;

		names = calloc(top_level + 1, sizeof(char*));
		if (find_delta_names(device, 0, top_level, names, &fmt)) {
			perror("find_delta_names");
			return SYSEXIT_SYSFS;
		}

		raw = 0;
		if (strcmp(fmt, "raw") == 0)
			raw = 1;
		ndelta = top_level + 1;

		if (ploop_get_attr(device, "running", &running)) {
			fprintf(stderr, "Could not get running attr\n");
			return SYSEXIT_SYSFS;
		}

		if (running) {
			for (i = 0; i < ndelta; i++) {
				int ro;

				if (ploop_get_delta_attr(device, i, "ro", &ro)) {
					fprintf(stderr, "Could not get ro attr\n");
					return SYSEXIT_SYSFS;
				}
				if (!ro) {
					fprintf(stderr, "Delta is mounted\n");
					return SYSEXIT_PARAM;
				}
			}
		}
	} else {
		names = argv;
		ndelta = argc;
	}

	if (raw) {
		ndelta--;
	}

	init_delta_array(&da);

	if (raw) {
		if (ndelta == 0 && !outfile) {
			usage();
			return SYSEXIT_PARAM;
		}
		da.raw_fd = open(names[ndelta], O_RDONLY|O_DIRECT);
		if (da.raw_fd < 0) {
			perror("open");
			return SYSEXIT_OPEN;
		}
	}

	for (i = 0; i < ndelta; i++) {
		int oflag = O_RDONLY|O_DIRECT;

		if (i == 0 && !outfile)
			oflag = O_RDWR|O_DIRECT;

		if (extend_delta_array(&da, names[i], oflag)) {
			perror("extend_data_array");
			return SYSEXIT_OPEN;
		}
	}

	if (da.delta_max) {
		da.bd_size = delta_bd_size(&da.delta_arr[0]);
	} else {
		struct stat st;

		if (da.raw_fd < 0) {
			usage();
			return SYSEXIT_PARAM;
		}
		if (fstat(da.raw_fd, &st)) {
			perror("fstat");
			return SYSEXIT_OPEN;
		}

		if (S_ISREG(st.st_mode)) {
			da.bd_size = st.st_size >> 9;
		} else if (S_ISBLK(st.st_mode)) {
			if (ioctl(da.raw_fd, BLKGETSIZE64, &da.bd_size) < 0) {
				perror("ioctl(BLKGETSIZE)");
				return SYSEXIT_BLKDEV;
			}
			da.bd_size >>= 9;
		} else {
			fprintf(stderr, "Not a regular file, not a block device\n");
			return SYSEXIT_PARAM;
		}
	}

	if (outfile) {
		ofd = open(outfile, O_RDWR|O_EXCL|O_CREAT, 0600);
		if (ofd < 0) {
			perror("open");
			return SYSEXIT_CREAT;
		}
		atexit(atexit_cb);
	}

	/* Collect bitmap of used clusters */
	if (collect_bitmap(&da))
		return SYSEXIT_BLKDEV;

	if (!outfile)
		return shrink_in_place();
	else
		return full_rebuild();
}
