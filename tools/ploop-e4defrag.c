/*
 *  Copyright (c) 2021 Virtuozzo International GmbH. All rights reserved.
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

#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

/* A relatively new ioctl interface ... */
#ifndef EXT4_IOC_MOVE_EXT
#define EXT4_IOC_MOVE_EXT      _IOWR('f', 15, struct move_extent)
#endif

#if (!defined(EXT4_IOC_CLEAR_ES_CACHE) && defined(__linux__))
#define EXT4_IOC_CLEAR_ES_CACHE         _IO('f', 40)
#endif

/*
 * Borowed from e2fsprogs/misc/e4defrag.c. This should be increased,
 * since kernel allows (UINT_MAX / sizeof(struct fiemap_extent)).
 */
#define EXTENT_MAX_COUNT	512

/* Data type for filesystem-wide blocks number */
typedef unsigned long long ext4_fsblk_t;

struct fiemap_extent_data {
	__u64 len;                      /* blocks count */
	__u64 logical;          /* start logical block number */
	ext4_fsblk_t physical;          /* start physical block number */
	__u32 fe_flags;
};

unsigned int block_size = 4096; /* Kill this? */
unsigned int cluster_size = 1024 * 1024;

struct fiemap_extent_list {
 	struct fiemap_extent_list *prev;
	struct fiemap_extent_list *next;
	struct fiemap_extent_data data; /* extent belong to file */
};

struct move_extent {
	__s32 reserved; /* original file descriptor */
	__u32 donor_fd; /* donor file descriptor */
	__u64 orig_start;       /* logical start offset in block for orig */
	__u64 donor_start;      /* logical start offset in block for donor */
	__u64 len;      /* block length to be moved */
	__u64 moved_len;        /* moved block length */
};

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

/*
 * Insert a new extent into tail of extent list.
 * The new extent must be logically after current tail.
 */
static int insert_extent_by_logical_merge_tail(struct fiemap_extent_list *ext_list_head,
                        struct fiemap_extent_list *ext)
{
	struct fiemap_extent_list *tail;

	tail = ext_list_head->prev;
	if (tail != ext_list_head)
		assert(tail->data.logical < ext->data.logical);

	if (tail) {
		if (tail->data.logical + tail->data.len == ext->data.logical &&
		    tail->data.physical + tail->data.len == ext->data.physical) {
			tail->data.len += ext->data.len;
			free(ext);
			return 0;
		}
	}

	tail->next = ext;
	ext->prev = tail;
	ext->next = ext_list_head;
	ext_list_head->prev = ext;
	return 0;
}

static int get_file_extents(int fd, struct fiemap_extent_list *ext_list_head, __u64 *pos)
{
	__u32	i;
	int	ret;
	int	ext_buf_size, fie_buf_size;
	struct fiemap	*fiemap_buf = NULL;
	struct fiemap_extent	*ext_buf = NULL;
	struct fiemap_extent_list	*ext_list = NULL;

	/* Convert units, in bytes.
	 * Be careful : now, physical block number in extent is 48bit,
	 * and the maximum blocksize for ext4 is 4K(12bit),
	 * so there is no overflow, but in future it may be changed.
	 */

	/* Alloc space for fiemap */
	ext_buf_size = EXTENT_MAX_COUNT * sizeof(struct fiemap_extent);
	fie_buf_size = sizeof(struct fiemap) + ext_buf_size;

	fiemap_buf = malloc(fie_buf_size);
	if (fiemap_buf == NULL)
		return -1;

	ext_buf = fiemap_buf->fm_extents;
	memset(fiemap_buf, 0, fie_buf_size);
	fiemap_buf->fm_length = FIEMAP_MAX_OFFSET;
	fiemap_buf->fm_flags |= FIEMAP_FLAG_SYNC;
	fiemap_buf->fm_extent_count = EXTENT_MAX_COUNT;

	fiemap_buf->fm_start = *pos;
	memset(ext_buf, 0, ext_buf_size);
	ret = ioctl(fd, FS_IOC_FIEMAP, fiemap_buf);
	if (ret < 0 || fiemap_buf->fm_mapped_extents == 0)
		goto out;
	for (i = 0; i < fiemap_buf->fm_mapped_extents; i++) {
		ext_list = malloc(sizeof(struct fiemap_extent_list));
		if (ext_list == NULL) {
			fprintf(stderr, "malloc failed\n");
			goto out;
		}

		if (ext_buf[i].fe_logical < fiemap_buf->fm_start) {
			assert(!i);
			ext_buf[i].fe_length -= *pos - ext_buf[i].fe_logical;
			ext_buf[i].fe_logical = *pos;
		}

		ext_list->data.physical = ext_buf[i].fe_physical
					/ block_size;
		ext_list->data.logical = ext_buf[i].fe_logical
					/ block_size;
		ext_list->data.len = ext_buf[i].fe_length
					/ block_size;
		ext_list->data.fe_flags = ext_buf[i].fe_flags;

		ret = insert_extent_by_logical_merge_tail(
				ext_list_head, ext_list);
		if (ret < 0) {
			free(ext_list);
			goto out;
		}
	}
		/* Record file's logical offset this time */
	*pos = ext_buf[EXTENT_MAX_COUNT-1].fe_logical +
		ext_buf[EXTENT_MAX_COUNT-1].fe_length;

	if (fiemap_buf->fm_mapped_extents != EXTENT_MAX_COUNT ||
	    (ext_buf[EXTENT_MAX_COUNT-1].fe_flags
					& FIEMAP_EXTENT_LAST))
		*pos = ~(__u64)0;


	free(fiemap_buf);
	return 0;
out:
	fprintf(stderr, "get_file_extents() failed\n");
	free(fiemap_buf);
	return -1;
}

/*
 * Logical wants defrag in case of it is continuos logically but not physically.
 * This function consumes/deletes extents related to @cluster from @ext_list_head.
 */
static int cluster_logically_continuos(__u64 cluster, struct fiemap_extent_list *ext_list_head,
					int *ret_physical_gap)
{
	__u64 logical_start = cluster * cluster_size / block_size;
	__u64 logical_end = (cluster + 1) * cluster_size / block_size;
	__u64 phys_start = ULONG_MAX;
	__u64 delta;
	struct fiemap_extent_list *ext;
	int continuos = 1; /* Logically continous? */
	int physical_gap = 0; /* Has physical gap? */

	assert(ext_list_head->next);


	while ((ext = ext_list_head->next) != ext_list_head) {
		assert(ext->data.logical >= logical_start);

		if (ext->data.logical >= logical_end)
			break;

		if (!continuos)
			goto advance_or_del_extent;

		if (logical_start != ext->data.logical ||
		    ext->data.physical == 0 ||
		    (ext->data.fe_flags & FIEMAP_EXTENT_DELALLOC) != 0) {
			continuos = 0;
			goto advance_or_del_extent;
		}

		if (phys_start == ULONG_MAX)
			phys_start = ext->data.physical;
		else if (phys_start != ext->data.physical)
			physical_gap = 1;

advance_or_del_extent:

		delta = min(ext->data.logical + ext->data.len, logical_end) - ext->data.logical;
		logical_start += delta;
		phys_start += delta;

		if (delta < ext->data.len) {
			ext->data.len -= delta;
			ext->data.physical += delta;
			ext->data.logical += delta;
			break;
		}

		ext_list_head->next = ext->next;
		ext->next->prev = ext_list_head;
		free(ext);
	}

	*ret_physical_gap = physical_gap;
	return continuos && logical_start == logical_end;
}

/*
 * page_in_core() -	Get information on whether pages are in core.
 *
 * @fd:			defrag target file's descriptor.
 * @defrag_data:	data used for defrag.
 * @vec:		page state array.
 * @page_num:		page number.
 */
static int page_in_core(int fd, struct move_extent *defrag_data,
			unsigned char **vec, unsigned int *page_num)
{
	long	pagesize;
	void	*page = NULL;
	loff_t	offset, end_offset, length;

	if (vec == NULL || *vec != NULL)
		return -1;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0)
		return -1;
	/* In mmap, offset should be a multiple of the page size */
	offset = (loff_t)defrag_data->orig_start * block_size;
	length = (loff_t)defrag_data->len * block_size;
	end_offset = offset + length;
	/* Round the offset down to the nearest multiple of pagesize */
	offset = (offset / pagesize) * pagesize;
	length = end_offset - offset;

	page = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, offset);
	if (page == MAP_FAILED)
		return -1;

	*page_num = 0;
	*page_num = (length + pagesize - 1) / pagesize;
	*vec = (unsigned char *)calloc(*page_num, 1);
	if (*vec == NULL) {
		munmap(page, length);
		return -1;
	}

	/* Get information on whether pages are in core */
	if (mincore(page, (size_t)length, *vec) == -1 ||
		munmap(page, length) == -1) {
		free(*vec);
		return -1;
	}

	return 0;
}

/*
 * defrag_fadvise() -	Predeclare an access pattern for file data.
 *
 * @fd:			defrag target file's descriptor.
 * @defrag_data:	data used for defrag.
 * @vec:		page state array.
 * @page_num:		page number.
 */
static int defrag_fadvise(int fd, struct move_extent *defrag_data,
		   unsigned char *vec, unsigned int page_num)
{
	static int flag = 1;
	long	pagesize = sysconf(_SC_PAGESIZE);
	int	fadvise_flag = POSIX_FADV_DONTNEED;
	int	sync_flag = SYNC_FILE_RANGE_WAIT_BEFORE |
			    SYNC_FILE_RANGE_WRITE |
			    SYNC_FILE_RANGE_WAIT_AFTER;
	unsigned int	i;
	loff_t	offset;

	if (pagesize < 1)
		return -1;

	offset = (loff_t)defrag_data->orig_start * block_size;
	offset = (offset / pagesize) * pagesize;

	/* Sync file for fadvise process */
	if (sync_file_range(fd, offset,
		(loff_t)pagesize * page_num, sync_flag) < 0)
		return -1;

	/* Try to release buffer cache which this process used,
	 * then other process can use the released buffer
	 */
	for (i = 0; i < page_num; i++) {
		if ((vec[i] & 0x1) == 0) {
			offset += pagesize;
			continue;
		}
		if ((errno = posix_fadvise(fd, offset,
					   pagesize, fadvise_flag)) != 0) {
			if (flag) {
				perror("\tFailed to fadvise");
				flag = 0;
			}
		}
		offset += pagesize;
	}

	return 0;
}

static int call_defrag(int fd, int donor_fd, __u64 clu)
{
	int defraged_ret, defraged_errno, ret;
	struct move_extent move_data;
	unsigned char *vec = NULL;
	unsigned int page_num;

	move_data.orig_start = clu * cluster_size / block_size;
        move_data.donor_start = move_data.orig_start;
	move_data.len = cluster_size / block_size;
	move_data.donor_fd = donor_fd;
	move_data.moved_len = 0;
	move_data.reserved = 0;

	ret = page_in_core(fd, &move_data, &vec, &page_num);
	if (ret < 0) {
		fprintf(stderr, "Can't get pages related to extent\n");
		return ret;
	}

	defraged_ret = ioctl(fd, EXT4_IOC_MOVE_EXT, &move_data);
	defraged_errno = errno;

	if (defraged_ret < 0) {
		fprintf(stderr, "ioctl(EXT4_IOC_MOVE_EXT) failed: %s\n",
				strerror(defraged_errno));
		return -defraged_errno;
	}

	ret = defrag_fadvise(fd, &move_data, vec, page_num);
	if (vec)
		free(vec);

	return 0;
}

static int defrag_clusters(int fd, int donor_fd, __u64 clu_from, __u64 clu_to)
{
	struct fiemap_extent_list ext_list_head = {.next = &ext_list_head,
						   .prev = &ext_list_head};
	struct fiemap_extent_list *ext;
	__u64 pos = clu_from * cluster_size;
	size_t len = clu_to * cluster_size - pos;
	int physical_gap, ret = 0;
	__u64 clu;

	ret = fallocate(donor_fd, 0, pos, len);
	if (ret < 0) {
		fprintf(stderr, "Can't fallocate %llu %lu\n", pos, len);
		return ret;
	}

	for (clu = clu_from; clu < clu_to; clu++) {
		if (pos < (clu + 1) * cluster_size) {
			/* Refill extent buffer */
			if (pos < clu * cluster_size)
				pos = clu * cluster_size;
			/*
			 * In case of cluster discontinous physically,
			 * this may return only half of its extents.
			 * But cluster_logically_continuos() checks that
			 * extents covers all of the cluster, so it's OK.
			 */
			ret = get_file_extents(donor_fd, &ext_list_head, &pos);
			if (ret < 0)
				goto out;

		}
		if (!cluster_logically_continuos(clu, &ext_list_head, &physical_gap) ||
		    physical_gap) {
			continue;
		}

		ret = call_defrag(fd, donor_fd, clu);
		if (ret)
			goto out;
	}

out:
	while ((ext = ext_list_head.next) != &ext_list_head) {
		ext_list_head.next = ext->next;
		ext->next->prev = &ext_list_head;
		free(ext);
	}
	return ret;
}

static int defrag_file(int fd, int donor_fd)
{
	struct fiemap_extent_list ext_list_head = {.next = &ext_list_head,
						   .prev = &ext_list_head};
	struct fiemap_extent_list *ext;
	__u64 cluster = 0, batch_from = UINT_MAX, batch_to;
	int physical_gap, ret = 0;
	__u64 pos = 0;

	do {
		/* Populate extent cache for @cluster */
		while ((cluster + 1) * cluster_size > pos) {
			ret = get_file_extents(fd, &ext_list_head, &pos);
			if (ret < 0)
				goto out;
		}

		ext = ext_list_head.next;
		if (ext->data.logical * block_size >= (cluster + 1ULL) * cluster_size) {
			/*
			 * There is no an extent, that covers @cluster.
			 * Advance @cluster and try again (if not EOF).
			 */
			cluster = ext->data.logical * block_size / cluster_size;
			goto defrag_prev_batch;
		}

		/* Consumes extents related to @cluster */
		if (!cluster_logically_continuos(cluster, &ext_list_head, &physical_gap) ||
		    !physical_gap) {
			cluster++;
			goto defrag_prev_batch;
		}

		/* Set first cluster of next batch */
		if (batch_from == UINT_MAX)
			batch_from = cluster;
		batch_to = cluster + 1;

		cluster++;
		if (pos != ~(__u64)0 || ext_list_head.next != &ext_list_head)
			continue;

defrag_prev_batch:
		if (batch_from == UINT_MAX) {
			/* Nothing to defrag */
			continue;
		}

		printf("defrag: clu [%llu, %llu) -- blk [%llu, %llu)\n",
				batch_from, batch_to,
				batch_from * cluster_size / block_size,
				batch_to * cluster_size / block_size);
		ret = defrag_clusters(fd, donor_fd, batch_from, batch_to);
		if (ret < 0)
			goto out;

		batch_from = UINT_MAX;
	} while (pos != ~(__u64)0 || ext_list_head.next != &ext_list_head);

out:
	return ret;
}

int main(int argc, char *argv[])
{

	char donor_name[PATH_MAX + 8] = { 0 };
	int fd, donor_fd, ret;

	if (argc != 2) {
		fprintf(stderr, "Use %s <filename>\n", argv[0]);
		exit(1);
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s\n", argv[1]);
		exit(1);
	}

	snprintf(donor_name, PATH_MAX + 8, "%s.defrag", argv[1]);
        donor_fd = open(donor_name, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (donor_fd < 0) {
		ret = donor_fd;
		fprintf(stderr, "Can't open %s\n", donor_name);
		goto out_fd;
	}

	ret = unlink(donor_name);
	if (ret < 0) {
		fprintf(stderr, "Can't unlink %s\n", donor_name);
		goto out_donor;
	}

	assert(cluster_size % block_size == 0);

	ret = ioctl(fd, EXT4_IOC_CLEAR_ES_CACHE, 0);
	if (ret < 0)
		perror("Can't clear extent cache, defrag may run slower");

	ret = defrag_file(fd, donor_fd);

out_donor:
	close(donor_fd);
out_fd:
	close(fd);
	return ret;
}
