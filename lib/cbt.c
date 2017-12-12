/*
* Copyright (c) 2005-2017 Parallels International GmbH.
*
* This file is part of Virtuozzo Core Libraries. Virtuozzo Core
* Libraries is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as published
* by the Free Software Foundation; either version 2.1 of the License, or
* (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library.  If not, see
* <http://www.gnu.org/licenses/> or write to Free Software Foundation,
* 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
*
* Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
* Schaffhausen, Switzerland; http://www.parallels.com/.
*/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <openssl/md5.h>

#include "list.h"
#include "bit_ops.h"
#include "ploop.h"
#include "cbt.h"


static __u64 MIN(__u64 a, __u64 b)
{
	return a < b ? a : b;
}

static __u64 MAX(__u64 a, __u64 b)
{
	return a > b ? a : b;
}

struct blk_user_cbt_extent {
	__u64 ce_physical; /* physical offset in bytes for the start
						* of the extent from the beginning of the disk */
	__u64 ce_length;   /* length in bytes for this extent */
	__u64 ce_reserved64[1];
};

struct blk_user_cbt_info {
	__u8  ci_uuid[16];      /* Bitmap UUID */
	__u64 ci_start;         /* start phisical range of mapping which
							   userspace wants (in) */
	__u64 ci_length;        /* phisical length of mapping which
							 * userspace wants (in) */
	__u32 ci_blksize;       /* cbt logical block size */
	__u32 ci_flags;         /* FIEMAP_FLAG_* flags for request (in/out) */
	__u32 ci_mapped_extents;/* number of extents that were mapped (out) */
	__u32 ci_extent_count;  /* size of fm_extents array (in) */
	__u32 ci_reserved;
	struct blk_user_cbt_extent ci_extents[0]; /* array of mapped extents (out) */
};

enum CI_FLAGS
{
	CI_FLAG_ONCE = 1, /* BLKCBTGET will clear bits */
	CI_FLAG_NEW_UUID = 2 /* BLKCBTSET update uuid */
};

struct cbt_data {
	__u32 last_used_extent_ind;
	struct blk_user_cbt_info info;
};

#define BLKCBTSTART _IOR(0x12,200, struct blk_user_cbt_info)
#define BLKCBTSTOP _IO(0x12,201)
#define BLKCBTGET _IOWR(0x12,202, struct blk_user_cbt_info)
#define BLKCBTSET _IOR(0x12,203, struct blk_user_cbt_info)
#define BLKCBTCLR _IOR(0x12,204, struct blk_user_cbt_info)
#define CBT_MAX_EXTENTS 512

struct ext_block_entry
{
	list_elem_t list;
	__u64 offset;
};

struct ext_context
{
	list_head_t ext_blocks_head;
	struct ploop_pvd_dirty_bitmap_raw *raw;
};

static const char *uuid2str(const __u8 *u, char *buf)
{
	uuid_unparse(u, buf);

	return buf;
}

static int add_ext_block(struct ext_context *ctx, __u64 offset)
{
	struct ext_block_entry *b = malloc(sizeof(*b));
	if (b == NULL)
		return SYSEXIT_MALLOC;

	b->offset = offset;
	list_add_tail(&b->list, &ctx->ext_blocks_head);

	return 0;
}

struct ext_context *create_ext_context(void)
{
	struct ext_context *ctx = (struct ext_context *)malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	list_head_init(&ctx->ext_blocks_head);
	ctx->raw = NULL;
	return ctx;
}

void free_ext_context(struct ext_context *ctx)
{
	struct ext_block_entry *b_entry = NULL, *tmp;

	if (ctx == NULL)
		return;

	list_for_each_safe(b_entry, tmp, &ctx->ext_blocks_head, list) {
		free(b_entry);
	}

	free(ctx->raw);
	free(ctx);
}

static int truncate_ext_blocks(struct ext_context *ctx, struct delta *delta,
		size_t block_size)
{
	struct stat stat;
	__u64 size;
	int found;
	struct ext_block_entry *b_entry = NULL, *tmp;

	if (fstat(delta->fd, &stat)) {
		ploop_err(errno, "fstat");
		return SYSEXIT_READ;
	}

	size = stat.st_size;
	if (size % block_size != 0) {
		return SYSEXIT_PARAM;
	}

	do {
		found = 0;
		list_for_each(b_entry, &ctx->ext_blocks_head, list) {
			if (b_entry->offset == size - block_size) {
				list_del(&b_entry->list);
				free(b_entry);
				size -= block_size;
				found = 1;
				break;
			}
		}
	} while (found);

	list_for_each_safe(b_entry, tmp, &ctx->ext_blocks_head, list) {
		free(b_entry);
	}
	list_head_init(&ctx->ext_blocks_head);

	if (size < stat.st_size) {
		if (ftruncate(delta->fd, size)) {
			ploop_err(errno, "ftruncate to %llu", size);
			return SYSEXIT_FTRUNCATE;
		}
	}

	return 0;
}

static int is_const_bit(__u8 *data, ssize_t size, int *val)
{
	__u8 first8 = *data;
	if (first8 != 0 && first8 != 0xff)
		return 0;

	if (size > 8) {
		__u64 *p = (__u64 *)data;
		__u64 first64 = *p;

		if (first64 != 0 && first64 != ~0ULL)
			return 0;

		for ( ; size > 8; size -= 8)
			if (*p++ != first64)
				return 0;

		data = (__u8 *)p;
	}

	for ( ; size >= 0; size--)
		if (*data++ != first8)
			return 0;

	*val = (first8 == 0 ? 0 : 1);
	return 1;
}

int cbt_stop(int devfd)
{
	if (ioctl(devfd, BLKCBTSTOP)) {
		if (errno == EINVAL)
			return SYSEXIT_NOCBT;

		ploop_err(errno, "BLKCBTSTOP");
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

static int cbt_set_dirty_bitmap_part(int devfd, const __u8 *uuid, void *buf,
		__u64 size, __u64 offset, __u32 byte_granularity)
{
	int ret = 0;
	size_t s = sizeof(struct blk_user_cbt_info) + CBT_MAX_EXTENTS * sizeof(struct blk_user_cbt_extent);
	struct blk_user_cbt_info *info = (struct blk_user_cbt_info *)malloc(s);
	struct blk_user_cbt_extent *cur, *end;
	__s64 bit;
	if (info == NULL)
		return SYSEXIT_MALLOC;

	memset(info, 0, s);
	memcpy(info->ci_uuid, uuid, sizeof(info->ci_uuid));
	cur = info->ci_extents;
	end = info->ci_extents + CBT_MAX_EXTENTS;

	for (bit = BitFindNextSet64(buf, size, 0);
			bit != -1;
			bit = BitFindNextSet64(buf, size, bit + 1))
	{
		cur->ce_physical = (bit + offset) * byte_granularity;
		bit = BitFindNextClear64(buf, size, bit + 1);
		if (bit == -1)
			bit = size;
		cur->ce_length = (bit + offset) * byte_granularity - cur->ce_physical;

		info->ci_extent_count++;

		if (++cur == end) {
			info->ci_mapped_extents = info->ci_extent_count;
			if (ioctl(devfd, BLKCBTSET, info)) {
				ploop_err(errno, "BLKCBTSET");
				ret = SYSEXIT_DEVIOC;
				goto out;
			}
			info->ci_extent_count = 0;
			cur = info->ci_extents;
		}
	}

	if (info->ci_extent_count > 0) {
		info->ci_mapped_extents = info->ci_extent_count;
		if (ioctl(devfd, BLKCBTSET, info)) {
			ploop_err(errno, "BLKCBTSET");
			ret = SYSEXIT_DEVIOC;
			goto out;
		}
	}

out:
	free(info);
	return ret;
}

static int cbt_set_dirty_bitmap_const_part(int devfd, const __u8 *uuid, int val,
		__u64 size, __u64 offset, __u32 byte_granularity)
{
	int ret = 0;
	size_t s;
	struct blk_user_cbt_info *info;

	if (val == 0)
		return 0;

	s = sizeof(struct blk_user_cbt_info) + sizeof(struct blk_user_cbt_extent);
	info = (struct blk_user_cbt_info *)malloc(s);
	if (info == NULL)
		return SYSEXIT_MALLOC;
	memset(info, 0, s);

	memcpy(info->ci_uuid, uuid, sizeof(info->ci_uuid));
	info->ci_extent_count = 1;
	info->ci_mapped_extents = 1;
	info->ci_extents[0].ce_physical = offset * byte_granularity;
	info->ci_extents[0].ce_length = size * byte_granularity;

	if (ioctl(devfd, BLKCBTSET, info)) {
		ploop_err(errno, "BLKCBTSET");
		ret = SYSEXIT_DEVIOC;
	}

	free(info);

	return ret;
}

static int cbt_get_dirty_bitmap_part(int devfd, void *buf, __u64 size,
		__u64 offset, __u32 byte_granularity, void *or_data)
{
	int ret = 0;
	__u64 ci_end;
	size_t s = sizeof(struct blk_user_cbt_info) + CBT_MAX_EXTENTS * sizeof(struct blk_user_cbt_extent);
	struct blk_user_cbt_info *info = (struct blk_user_cbt_info *)malloc(s);
	struct blk_user_cbt_extent *cur, *end;
	struct cbt_data *or_cbt = (struct cbt_data *)or_data;

	if (info == NULL)
		return SYSEXIT_MALLOC;

	memset(info, 0, s);
	memset(buf, 0, size / 8);
	info->ci_extent_count = CBT_MAX_EXTENTS;
	info->ci_start = offset * byte_granularity;
	info->ci_length = size * byte_granularity;
	ci_end = info->ci_start + info->ci_length;

	do {
		struct blk_user_cbt_extent *last;
		info->ci_mapped_extents = 0;
		if (ioctl(devfd, BLKCBTGET, info)) {
			ploop_err(errno, "BLKCBTGET start=%llu length=%llu",
					info->ci_start, info->ci_length);
			ret = SYSEXIT_DEVIOC;
			goto out;
		}

		end = info->ci_extents + info->ci_mapped_extents;
		for (cur = info->ci_extents; cur != end; ++cur) {
			__u64 first = MAX(offset, cur->ce_physical / byte_granularity);
			__u64 last = MIN(offset + size - 1,
							 (cur->ce_physical + cur->ce_length - 1) / byte_granularity);
			BMAP_SET_BLOCK(buf, first - offset, last - first + 1);
		}

		last = end - 1;
		info->ci_start = last->ce_physical + last->ce_length;
		info->ci_length = ci_end - info->ci_start;
	} while (info->ci_mapped_extents == info->ci_extent_count);

	if (or_cbt != NULL) {
		cur = or_cbt->info.ci_extents;
		end = or_cbt->info.ci_extents + or_cbt->info.ci_mapped_extents;
		if (or_cbt->last_used_extent_ind > 0) {
			struct blk_user_cbt_extent *prev = or_cbt->info.ci_extents +
				or_cbt->last_used_extent_ind - 1;
			if (prev->ce_physical + prev->ce_length <= offset * byte_granularity)
				cur = prev + 1;
		}

		while (cur != end && cur->ce_physical + cur->ce_length <= offset * byte_granularity)
			++cur;

		for (; cur != end && cur->ce_physical < ci_end; ++cur) {
			__u64 first = MAX(offset, cur->ce_physical / byte_granularity);
			__u64 last = MIN(offset + size - 1,
							 (cur->ce_physical + cur->ce_length - 1) / byte_granularity);
			BMAP_SET_BLOCK(buf, first - offset, last - first + 1);
		}

		or_cbt->last_used_extent_ind = cur - or_cbt->info.ci_extents;
	}

out:
	free(info);

	return ret;
}

int cbt_get_and_clear(int devfd, void **data)
{
	size_t s = sizeof(struct cbt_data);
	struct cbt_data *cbt_data;
	struct blk_user_cbt_info *info, *info_kern;
	size_t s_kern = sizeof(struct blk_user_cbt_info) +
			CBT_MAX_EXTENTS * sizeof(struct blk_user_cbt_extent);

	cbt_data = (struct cbt_data *)calloc(1, s);
	if (cbt_data == NULL)
		return SYSEXIT_MALLOC;

	info_kern = (struct blk_user_cbt_info *)malloc(s_kern);
	if (info_kern == NULL) {
		free(cbt_data);
		return SYSEXIT_MALLOC;
	}

	memset(info_kern, 0, s_kern);
	info_kern->ci_extent_count = CBT_MAX_EXTENTS;
	info_kern->ci_length = -1;
	info_kern->ci_flags = CI_FLAG_ONCE;

	info = &cbt_data->info;
	info->ci_length = -1;
	info->ci_flags = CI_FLAG_ONCE;

	do {
		struct blk_user_cbt_extent *last;
		void *tmp = cbt_data;

		info->ci_extent_count += CBT_MAX_EXTENTS;
		s += CBT_MAX_EXTENTS * sizeof(struct blk_user_cbt_extent);
		cbt_data = (struct cbt_data *)realloc(cbt_data, s);
		if (cbt_data == NULL) {
			free(tmp);
			free(info_kern);
			return SYSEXIT_MALLOC;
		}
		info = &cbt_data->info;

		if (ioctl(devfd, BLKCBTGET, info_kern)) {
			free(cbt_data);
			free(info_kern);

			if (errno == EINVAL)
				return SYSEXIT_NOCBT;

			ploop_err(errno, "BLKCBTGET");
			return SYSEXIT_DEVIOC;
		}

		memcpy(&info->ci_extents[info->ci_mapped_extents], info_kern->ci_extents,
			   info_kern->ci_mapped_extents * sizeof(info_kern->ci_extents[0]));
		info->ci_mapped_extents += info_kern->ci_mapped_extents;

		last = info->ci_extents + info->ci_mapped_extents - 1;
		info->ci_start = last->ce_physical + last->ce_length;
		info->ci_length = -1 - info->ci_start;
		info_kern->ci_start = info->ci_start;
		info_kern->ci_length = info->ci_length;
		info_kern->ci_mapped_extents = 0;
	} while (info->ci_mapped_extents == info->ci_extent_count);

	free(info_kern);
	*data = cbt_data;
	return 0;
}

int cbt_get_dirty_bitmap_metadata(int devfd, __u8 *uuid, __u32 *blksize)
{
	struct blk_user_cbt_info info = {{0}};
	if (ioctl(devfd, BLKCBTGET, &info)) {
		if (errno  == EINVAL)
			return SYSEXIT_NOCBT;

		ploop_err(errno, "BLKCBTGET");
		return SYSEXIT_DEVIOC;
	}

	if (blksize != NULL)
		*blksize = info.ci_blksize;

	if (uuid != NULL)
		memcpy(uuid, info.ci_uuid, sizeof(info.ci_uuid));

	return 0;
}

int cbt_start(int devfd, const __u8 *uuid, __u32 blksize)
{
	struct blk_user_cbt_info info = {{0}};
	char buf[40];

	ploop_log(0, "Start CBT uuid=%s", uuid2str(uuid, buf));
	info.ci_blksize = blksize;
	memcpy(info.ci_uuid, uuid, sizeof(info.ci_uuid));

	if (ioctl(devfd, BLKCBTSTART, &info)) {
		ploop_err(errno, "BLKCBTSTART");
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

int cbt_set_uuid(int devfd, const __u8 *uuid)
{
	struct blk_user_cbt_info info = {{0}};

	info.ci_flags = CI_FLAG_NEW_UUID;
	memcpy(info.ci_uuid, uuid, sizeof(info.ci_uuid));

	if (ioctl(devfd, BLKCBTSET, &info)) {
		ploop_err(errno, "BLKCBTSET");
		return SYSEXIT_DEVIOC;
	}

	return 0;
}

int save_dirty_bitmap(int devfd, struct delta *delta, off_t offset,
		void *buf, __u32 *size, void *or_data, writer_fn wr,
		void *data)
{
	int ret = 0;
	struct ploop_pvd_header *vh;
	size_t block_size;
	__u64 bits, bytes, *p;
	__u32 byte_granularity;
	void *block;
	struct ploop_pvd_dirty_bitmap_raw *raw = (struct ploop_pvd_dirty_bitmap_raw *)buf;
	char x[50];

	vh = (struct ploop_pvd_header *)delta->hdr0;

	/* granularity and uuid */
	if ((ret = cbt_get_dirty_bitmap_metadata(devfd, raw->m_Id, &raw->m_Granularity)))
		return ret;
	raw->m_Granularity /= SECTOR_SIZE;

	block_size = vh->m_Sectors * SECTOR_SIZE;
	if (p_memalign((void **)&block, 4096, block_size))
		return SYSEXIT_MALLOC;

	raw->m_Size = vh->m_SizeInSectors_v2;

	byte_granularity = raw->m_Granularity * SECTOR_SIZE;
	bits = ((raw->m_Size + raw->m_Granularity - 1) / raw->m_Granularity);
	bytes = (bits + 7) >> 3;
	raw->m_L1Size = (bytes + block_size - 1) / block_size;

	ploop_log(3, "Store CBT uuid=%s L1Size=%d bytes=%llu blocksize=%llu offset=%llu",
		uuid2str(raw->m_Id, x), raw->m_L1Size, bytes,
		(unsigned long long)block_size, (unsigned long long)offset);
	for (p = raw->m_L1; p < raw->m_L1 + raw->m_L1Size; ++p) {
		__u64 cur_size = MIN(block_size, bytes);
		bytes -= cur_size;

		if ((ret = cbt_get_dirty_bitmap_part(
				devfd, block, cur_size * 8, (p - raw->m_L1) * block_size * 8, byte_granularity, or_data)))
			goto out;

		if (is_const_bit(block, cur_size, (int *)p))
			continue;

		*p = offset / SECTOR_SIZE;

		/// TODO: truncate instead of less write (blk size to cur_size)
		ret = wr ? wr(data, block, block_size, offset) :
				PWRITE(delta, block, block_size, offset);
		if (ret) {
			ploop_err(errno, "Can't write dirty_bitmap block");
			ret = SYSEXIT_WRITE;
			goto out;
		}
		offset += block_size;
	}

	*size = sizeof(*raw) + sizeof(raw->m_L1[0]) * raw->m_L1Size;

out:
	free(block);
	return ret;
}

static __u32 raw_size(struct ploop_pvd_dirty_bitmap_raw *raw)
{
	return sizeof(*raw) + sizeof(raw->m_L1[0]) * raw->m_L1Size;
}

static int save_dirty_bitmap_from_raw(struct ploop_pvd_dirty_bitmap_raw *in_raw,
		struct delta *delta, void *buf, __u32 *size)
{
	struct ploop_pvd_header *vh;
	size_t block_size;
	__u64 *p, *in_p;
	struct ploop_pvd_dirty_bitmap_raw *raw = (struct ploop_pvd_dirty_bitmap_raw *)buf;
	struct stat stat;
	__u64 offset;

	if (fstat(delta->fd, &stat)) {
		ploop_err(errno, "fstat");
		return SYSEXIT_READ;
	}
	offset = stat.st_size;

	/* copy raw */
	*size = raw_size(in_raw);
	memcpy(raw, in_raw, *size);

	/* WARNING: here we hope that block size in in_raw and in delta are the same */
	vh = (struct ploop_pvd_header *)delta->hdr0;
	block_size = vh->m_Sectors * SECTOR_SIZE;

	for (p = raw->m_L1, in_p = in_raw->m_L1; p < raw->m_L1 + raw->m_L1Size; ++p, ++in_p) {
		if (*in_p <= 1) {
			*p = *in_p;
		} else {
			*p = offset / SECTOR_SIZE;
			/// TODO: truncate instead of less write (blk size to cur_size)
			if (PWRITE(delta, (void *)*in_p, block_size, offset)) {
				ploop_err(errno, "Can't write dirty_bitmap block");
				return SYSEXIT_WRITE;
			}
			offset += block_size;
		}

	}

	return 0;
}

static int delta_save_optional_header(int devfd, struct delta *delta,
		void *or_data, struct ploop_pvd_dirty_bitmap_raw *raw)
{
	int ret = 0;
	struct ploop_pvd_header *vh;
	size_t block_size;
	struct ploop_pvd_ext_block_check *hc;
	struct ploop_pvd_ext_block_element_header *h;
	__u8 *block = NULL, *data;
	struct stat stat;

	/* save from device or from raw */
	if ((devfd == -1 ) == (raw == NULL))
		return SYSEXIT_PARAM;

	/* or_data may be used only when saving from device */
	if (raw != NULL && or_data != NULL)
		return SYSEXIT_PARAM;

	vh = (struct ploop_pvd_header *)delta->hdr0;

	block_size = vh->m_Sectors * SECTOR_SIZE;
	if (p_memalign((void **)&block, 4096, block_size))
		return SYSEXIT_MALLOC;

	memset(block, 0 , block_size);

	hc = (struct ploop_pvd_ext_block_check *)block;
	h = (struct ploop_pvd_ext_block_element_header *)(hc + 1);
	data = (__u8 *)(h + 1);

	h->magic = EXT_MAGIC_DIRTY_BITMAP;
	if (raw == NULL) {
		if (fstat(delta->fd, &stat)) {
			ploop_err(errno, "fstat");
			ret = SYSEXIT_READ;
			goto out;
		}

		ret = save_dirty_bitmap(devfd, delta, stat.st_size, data,
			&h->size, or_data, NULL, NULL);
		if (ret) {
			/* no we have no extensions except dirty bitmap extension, so, if
			 * there are no cbt it is the end (but not an error) */
			if (ret == SYSEXIT_NOCBT)
				ret = 0;
			goto out;
		}
	} else {
		if ((ret = save_dirty_bitmap_from_raw(raw, delta, data, &h->size))) {
			goto out;
		}
	}

	if (fstat(delta->fd, &stat)) {
		ploop_err(errno, "fstat");
		ret = SYSEXIT_READ;
		goto out;
	}

	vh->m_DiskInUse = SIGNATURE_DISK_CLOSED_V21;
	vh->m_FormatExtensionOffset = (stat.st_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
	if (PWRITE(delta, vh, sizeof(*vh), 0)) {
		ploop_err(errno, "Can't write header");
		ret = SYSEXIT_WRITE;
		goto out;
	}

	hc->m_Magic = FORMAT_EXTENSION_MAGIC;
	MD5((const unsigned char *)(hc + 1), block_size - sizeof(*hc), hc->m_Md5);

	if (PWRITE(delta, block, block_size, vh->m_FormatExtensionOffset * SECTOR_SIZE)) {
		ploop_err(errno, "Can't write optional header");
		ret = SYSEXIT_WRITE;
		goto out;
	}

out:
	free(block);
	return ret;
}

static int raw_move_to_memory(struct ext_context *ctx, struct delta *delta)
{
	__u64 bits, bytes, *p;
	struct ploop_pvd_header *vh = (struct ploop_pvd_header *)delta->hdr0;
	size_t block_size = vh->m_Sectors * SECTOR_SIZE;
	int ret;

	bits = ((ctx->raw->m_Size + ctx->raw->m_Granularity - 1) / ctx->raw->m_Granularity);
	bytes = (bits + 7) >> 3;
	for (p = ctx->raw->m_L1; p < ctx->raw->m_L1 + ctx->raw->m_L1Size; ++p) {
		__u64 cur_size = MIN(block_size, bytes);
		bytes -= cur_size;

		if (*p > 1) {
			void *block;
			if (p_memalign(&block, 4096, block_size))
				return SYSEXIT_MALLOC;

			if (PREAD(delta, block, cur_size, *p * SECTOR_SIZE)) {
				free(block);
				ploop_err(errno, "Can't read dirty_bitmap block");
				return SYSEXIT_READ;
			}

			if ((ret = add_ext_block(ctx, *p * SECTOR_SIZE))) {
				ploop_err(errno,  "add_ext_block failed");
				return ret;
			}

			*p = (__u64)block;
		}
	}

	return 0;
}

static int add_ext_blocks_from_raw(struct ext_context *ctx,
		struct ploop_pvd_dirty_bitmap_raw *raw)
{
	__u64 *p;
	int ret;

	if (ctx->raw == NULL)
		return 0;

	for (p = raw->m_L1; p < raw->m_L1 + raw->m_L1Size; ++p) {
		if (*p > 1) {
			if ((ret = add_ext_block(ctx, *p * SECTOR_SIZE))) {
				ploop_err(errno, "add_ext_block failed");
				return ret;
			}
		}
	}

	return 0;
}

static int read_size_in_sectors_from_image(const char *img_name, __u64 *size)
{
	struct delta delta = {};
	struct ploop_pvd_header *vh;

	if (open_delta(&delta, img_name, O_RDWR, OD_ALLOW_DIRTY))
		return SYSEXIT_OPEN;

	vh = (struct ploop_pvd_header *)delta.hdr0;
	*size = vh->m_SizeInSectors_v2;

	close_delta(&delta);

	return 0;
}

static int load_dirty_bitmap(struct ext_context *ctx, struct delta *delta,
		void *buf, __u32 size, int only_truncate)
{
	struct ploop_pvd_header *vh;
	struct ploop_pvd_dirty_bitmap_raw *raw = (struct ploop_pvd_dirty_bitmap_raw *)buf;

	vh = (struct ploop_pvd_header *)delta->hdr0;

	if (vh->m_FormatExtensionOffset == 0)
		return 0;

	if (raw->m_Size != vh->m_SizeInSectors_v2) {
		ploop_err(0, "Image size is not equal to dirty_bitmap size");
		return SYSEXIT_PROTOCOL;
	}

	if (size < sizeof(*raw) + sizeof(raw->m_L1[0]) * raw->m_L1Size) {
		ploop_err(0, "Spoiled bitmap extension data");
		return SYSEXIT_PROTOCOL;
	}

	if (only_truncate)
		return add_ext_blocks_from_raw(ctx, ctx->raw ?: raw);

	if (p_memalign((void **)&ctx->raw, 4096, size))
		return SYSEXIT_MALLOC;

	memcpy(ctx->raw, raw, size);
	return raw_move_to_memory(ctx, delta);
}

int send_dirty_bitmap_to_kernel(struct ext_context *ctx, int devfd,
		const char *img_name)
{
	int ret = 0;
	struct ploop_pvd_header *vh;
	size_t block_size;
	__u64 bits, bytes, *p;
	__u32 byte_granularity;
	struct ploop_pvd_dirty_bitmap_raw *raw = NULL;
	struct delta delta = {};

	if (ctx == NULL)
		return SYSEXIT_PARAM;
	raw = ctx->raw;

	if (raw == NULL)
		return 0;

	if (open_delta(&delta, img_name, O_RDWR, OD_ALLOW_DIRTY))
		return SYSEXIT_OPEN;

	vh = (struct ploop_pvd_header *)delta.hdr0;

	/* granularity and uuid */
	if ((ret = cbt_start(devfd, raw->m_Id, raw->m_Granularity * SECTOR_SIZE)))
		return ret;

	block_size = vh->m_Sectors * SECTOR_SIZE;

	byte_granularity = raw->m_Granularity * SECTOR_SIZE;
	bits = ((raw->m_Size + raw->m_Granularity - 1) / raw->m_Granularity);
	bytes = (bits + 7) >> 3;
	for (p = raw->m_L1; p < raw->m_L1 + raw->m_L1Size; ++p) {
		__u64 cur_size = MIN(block_size, bytes);
		__u64 offset = (p - raw->m_L1) * block_size;
		bytes -= cur_size;

		if (*p <= 1) {
			if ((ret = cbt_set_dirty_bitmap_const_part(
					devfd, raw->m_Id, *p, cur_size * 8, offset * 8, byte_granularity)))
				goto out;
		} else {
			if ((ret = cbt_set_dirty_bitmap_part(
					devfd, raw->m_Id, (void *)*p, cur_size * 8, offset * 8, byte_granularity)))
				goto out;
			free((void *)*p);
		}
	}

out:
	close_delta(&delta);
	return ret;
}

static int delta_load_optional_header(struct ext_context *ctx,
		struct delta *delta, int flags)
{
	int ret = 0;
	struct ploop_pvd_header *vh;
	size_t block_size;
	struct ploop_pvd_ext_block_check *hc;
	struct ploop_pvd_ext_block_element_header *h;
	unsigned char hash[16];
	__u8 *block, *end;

	vh = (struct ploop_pvd_header *)delta->hdr0;

	if (vh->m_FormatExtensionOffset == 0 ||
			vh->m_DiskInUse == SIGNATURE_DISK_CLOSED_V20)
		return 0;

	if (vh->m_DiskInUse != SIGNATURE_DISK_CLOSED_V21) {
		ploop_err(0, "Can't load dirty_bitmap, "
				  "because image was not successfully closed");
		return SYSEXIT_PROTOCOL;
	}

	block_size = vh->m_Sectors * SECTOR_SIZE;
	if (p_memalign((void **)&block, 4096, block_size))
		return SYSEXIT_MALLOC;
	end = block + block_size;

	if (PREAD(delta, block, block_size, vh->m_FormatExtensionOffset * SECTOR_SIZE)) {
		ploop_err(errno,  "Can't read optional header block, "
				  "offset: 0x%llx, size: 0x%lx",
				  vh->m_FormatExtensionOffset, block_size);
		ret = SYSEXIT_READ;
		goto drop_optional_hdr;
	}

	hc = (struct ploop_pvd_ext_block_check *)block;
	if (hc->m_Magic != FORMAT_EXTENSION_MAGIC) {
		ploop_err(0, "Wrong optional header magic");
		ret = SYSEXIT_PROTOCOL;
		goto drop_optional_hdr;
	}

	MD5((const unsigned char *)(hc + 1), block_size - sizeof(*hc), hash);
	if (memcmp(hash, hc->m_Md5, 16) != 0) {
		ploop_err(0, "Wrong optional header checksum");
		ret = SYSEXIT_PROTOCOL;
		goto drop_optional_hdr;
	}

	ret = add_ext_block(ctx, vh->m_FormatExtensionOffset * SECTOR_SIZE);
	if (ret) {
		ploop_err(errno, "add_ext_block failed");
		goto out;
	}

	h = (struct ploop_pvd_ext_block_element_header *)(hc + 1);
	while (1) {
		__u8 *data = (__u8 *)(h + 1);
		if ((__u8 *)(h + 1) > end || (data + h->size) > end) {
			ploop_err(0, "Spoiled optional header");
			ret = SYSEXIT_PROTOCOL;
			goto out;
		}

		if (h->magic == 0)
			break;

		if (h->magic == EXT_MAGIC_DIRTY_BITMAP)
			if ((ret = load_dirty_bitmap(ctx, delta, data, h->size,
					 flags & DIRTY_BITMAP_REMOVE)))
				goto out;

		h = (struct ploop_pvd_ext_block_element_header *)(data + h->size);
	}

	if (flags & (DIRTY_BITMAP_REMOVE | DIRTY_BITMAP_TRUNCATE)) {
		ret = truncate_ext_blocks(ctx, delta, block_size);
		if (ret) {
			ploop_err(errno, "Failed to truncate format extension blocks");
			goto out;
		}
	}
out:
	free(block);
	return ret;

drop_optional_hdr:
	if (flags & DIRTY_BITMAP_TRUNCATE) {
		ploop_err(0, "Drop optional header");
		vh->m_FormatExtensionOffset = 0;
		if (vh->m_DiskInUse == SIGNATURE_DISK_CLOSED_V21)
			vh->m_DiskInUse = SIGNATURE_DISK_CLOSED_V20;
		if (PWRITE(delta, vh, sizeof(*vh), 0))
			ploop_err(errno, "Can't write header");
	}

	goto out;
}

/* Be careful: this funciton creates ctx. It will be freed in send_dirty_bitmap_to_kernel(),
 * but you can also free it with free_ext_context(). Use it if you for some reason don't call
 * send_dirty_bitmap_to_kernel(). */
int read_optional_header_from_image(struct ext_context *ctx,
		const char *img_name, int flags)
{
	struct delta delta = {};
	int ret;

	if (open_delta(&delta, img_name, !flags ? O_RDONLY : O_RDWR,
				OD_ALLOW_DIRTY))
		return SYSEXIT_OPEN;

	ret = delta_load_optional_header(ctx, &delta, flags);
	close_delta(&delta);

	return ret;
}

static int remove_optional_header_from_image(const char *img_name)
{
	int ret;
	struct ext_context *ctx;

	if (img_name == NULL)
		return SYSEXIT_PARAM;

	ctx = create_ext_context();
	if (ctx == NULL)
		return SYSEXIT_MALLOC;

	ret = read_optional_header_from_image(ctx, img_name,	DIRTY_BITMAP_REMOVE);

	free_ext_context(ctx);

	return ret;
}

int write_optional_header_to_image(int devfd, const char *img_name,
		void *or_data)
{
	struct delta delta = {};
	int ret = 0;

	if (open_delta(&delta, img_name, O_RDWR, OD_NOFLAGS))
		return SYSEXIT_OPEN;

	ret = delta_save_optional_header(devfd, &delta, or_data, NULL);
	close_delta(&delta);

	return ret;
}

static int write_optional_header_to_image_from_raw(
		struct ploop_pvd_dirty_bitmap_raw *raw, const char *img_name)
{
	struct delta delta = {};
	int ret = 0;

	if (open_delta(&delta, img_name, O_RDWR, OD_NOFLAGS))
		return SYSEXIT_OPEN;

	ret = delta_save_optional_header(-1, &delta, NULL, raw);
	close_delta(&delta);

	return ret;
}

int write_empty_cbt_to_image(const char *fname, const char *prev_fname,
		const __u8 *cbt_u)
{
	int ret = 0;
	struct ploop_pvd_dirty_bitmap_raw new_cbt;
	char buf[50];

	ploop_log(0, "Write new CBT uuid=%s", uuid2str(cbt_u, buf));
	ret = read_size_in_sectors_from_image(prev_fname, &new_cbt.m_Size);
	if (ret)
		return ret;

	// TODO: it would be better to get granularity from prev_fname image
	new_cbt.m_Granularity = CBT_DEFAULT_BLKSIZE / SECTOR_SIZE;
	new_cbt.m_L1Size = 0;
	memcpy(&new_cbt.m_Id, cbt_u, sizeof(new_cbt.m_Id));
	if ((ret = write_optional_header_to_image_from_raw(&new_cbt, fname)))
		return ret;

	return 0;
}

void dunp_L1(__u64 *buf, __u64 size)
{
	__u64 *p;

	for (p = buf; p < (buf + size); ++p)
		printf("0x%lx ", (unsigned long) *p);
	printf("\n");
}

void dump_cbt_from_raw(struct ext_context *ctx)
{
	char buf[40];
	__u64 *p;
	unsigned i;
	__u64 bits, bytes, block_size;

	printf("Size: %lu\n", (unsigned long)ctx->raw->m_Size);
	printf("L1Size: %lu\n", (unsigned long)ctx->raw->m_L1Size);
	printf("uuid: %s\n", uuid2str(ctx->raw->m_Id, buf));
	printf("Granularity: %lu\n", (unsigned long)ctx->raw->m_Granularity);

	block_size = 2048 * SECTOR_SIZE;
	bits = ((ctx->raw->m_Size + ctx->raw->m_Granularity - 1) /
			ctx->raw->m_Granularity);
	bytes = (bits + 7) >> 3;
	for (p = ctx->raw->m_L1, i = 0;
			p < ctx->raw->m_L1 + ctx->raw->m_L1Size; ++p, ++i)
	{
		__u64 cur_size = MIN(block_size, bytes);
		bytes -= cur_size;

		if (*p == 0)
			continue;
		printf("<%u>	", i);
		if (*p == 1)
			printf("1\n");
		else
			dunp_L1((__u64 *)*p, cur_size / sizeof(__u64));
	}
}

static int read_optional_header_from_kernel(struct ext_context *ctx,
		const char *dev)
{
	int ret;
	int fd;
	__u64 block_size;
	__u64 *p, x, bits, bytes;
	__u32 blocksize, byte_granularity;
	int version;
	off_t dev_size;
	void *block = NULL;
	struct ploop_pvd_dirty_bitmap_raw *raw;

	fd = open(dev, O_RDONLY|O_CLOEXEC);
	if (fd == -1) {
		ploop_err(errno, "failed to open %s", dev);
		return -1;
	}

	ret = get_image_param_online(dev, &dev_size, &blocksize, &version);
	if (ret)
		goto out;

	block_size = blocksize * SECTOR_SIZE;

	x = block_size * sizeof(struct ploop_pvd_dirty_bitmap_raw);
	if (p_memalign((void **)&ctx->raw, 4096, x)) {
		ret = SYSEXIT_MALLOC;
		goto out;
	}
	memset(ctx->raw, 0, x);
	raw = ctx->raw;

	ret = cbt_get_dirty_bitmap_metadata(fd, raw->m_Id,
			&raw->m_Granularity);
	if (ret)
		goto out;

	byte_granularity = raw->m_Granularity;
	raw->m_Granularity /= SECTOR_SIZE;
	raw->m_Size = dev_size;

	bits = ((raw->m_Size + raw->m_Granularity - 1) / raw->m_Granularity);
	bytes = (bits + 7) >> 3;
	raw->m_L1Size = (bytes + block_size - 1) / block_size;
	for (p = raw->m_L1; p < raw->m_L1 + raw->m_L1Size; ++p) {
		__u64 cur_size = MIN(block_size, bytes);
		bytes -= cur_size;

		free(block);
		if (p_memalign((void **)&block, 4096, block_size)) {
			ret = SYSEXIT_MALLOC;
			goto out;
		}
		ret = cbt_get_dirty_bitmap_part(fd, block, cur_size * 8,
				(p - raw->m_L1) * block_size * 8,
				byte_granularity, NULL);
		if (ret)
			goto out;

		if (is_const_bit(block, cur_size, (int *)p))
			continue;

		*p = (__u64)block;
		block = NULL;
	 }

out:

	free(block);
	close(fd);

	return ret;
}

int cbt_snapshot_prepare(int lfd, const unsigned char *cbt_uuid,
		void **or_data)
{
	int ret;
	__u32 cbt_blksize = CBT_DEFAULT_BLKSIZE;

	if (cbt_uuid == NULL)
		return 0;

	ret = cbt_get_and_clear(lfd, or_data);
	if (ret == SYSEXIT_NOCBT) {
		ploop_log(0, "No cbt in kernel, starting a new one using default blksize: %u",
				cbt_blksize);

		if ((ret = cbt_start(lfd, cbt_uuid, cbt_blksize))) {
			ploop_err(errno, "Failed to start cbt: %d", ret);
			return ret;
		}

		return 0;
	}

	return ret;
}

int cbt_snapshot(int lfd, const unsigned char *cbt_uuid,
		const char *prev_delta, void *or_data)
{
	int ret;
	__u32 cbt_blksize = CBT_DEFAULT_BLKSIZE;
	__u8 uuid[16];

	if (cbt_uuid == NULL)
		return 0;

	ploop_log(0, "Saving cbt to img=%s and starting new cbt",
			prev_delta);

	if ((ret = cbt_get_dirty_bitmap_metadata(lfd, uuid, &cbt_blksize))) {
		ploop_err(errno, "Failed to get cbt metadata: %d", ret);
		return ret;
	}

	if (memcmp(uuid, cbt_uuid, sizeof(uuid)) == 0) {
		/* this means, that there was no cbt before cbt_snapshot_prepare. */
		return 0;
	}

	if ((ret = write_optional_header_to_image(lfd, prev_delta, or_data))) {
		ploop_err(0, "Error while writing optional header: %d", ret);
		return ret;
	}

	if ((ret = cbt_set_uuid(lfd, cbt_uuid))) {
		ploop_err(0, "Failed to set cbt uuid: %d", ret);
		return ret;
	}

	return 0;
}

int ploop_cbt_dump_info(struct ploop_disk_images_data *di)
{
	int ret;
	char dev[64];
	struct ext_context *ctx = NULL;
	const char *image;
	int online = 1;

	if (di == NULL) {
		return SYSEXIT_PARAM;
	}

	ret = ploop_lock_dd(di);
	if (ret)
		return ret;

	image = find_image_by_guid(di, di->top_guid);
	if (image == NULL) {
		ploop_err(0, "Unable to find image by uuid%s", di->top_guid);
		ret = SYSEXIT_PARAM;
		goto err;
	}

	ctx = create_ext_context();
	if (ctx == NULL) {
		ret = SYSEXIT_MALLOC;
		goto err;
	}

	ret = ploop_find_dev_by_cn(di, di->runtime->component_name, 0, dev,
			sizeof(dev));
	if (ret == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	} else if (ret != 0)
		online = 0;


	if (online)
		ret = read_optional_header_from_kernel(ctx, dev);
	else
		ret = read_optional_header_from_image(ctx, image, 0);

	if (ret)
		goto err;

	if (ctx->raw == NULL) {
		ret = 0;
		goto err;
	}

	dump_cbt_from_raw(ctx);

err:
	free_ext_context(ctx);

	ploop_unlock_dd(di);

	return ret;
}

int ploop_cbt_dump_info_from_image(const char *image)
{
	int ret;
	struct ext_context *ctx;

	ctx = create_ext_context();
	if (ctx == NULL)
		return SYSEXIT_MALLOC;

	ret = read_optional_header_from_image(ctx, image, 0);
	if (ret)
		goto err;

	if (ctx->raw == NULL) {
		ret = 0;
		goto err;
	}

	dump_cbt_from_raw(ctx);

err:
	free_ext_context(ctx);

	return ret;
}

int ploop_move_cbt(const char *dst, const char *src)
{
	int ret;
	struct ext_context *ctx;

	if (dst == NULL || src == NULL) {
		ploop_err(EINVAL, "Failed to move CBT");
		return SYSEXIT_PARAM;
	}

	ploop_log(0, "Move CBT %s -> %s", src, dst);
	ctx = create_ext_context();
	if (ctx == NULL)
		return SYSEXIT_MALLOC;

	ret = read_optional_header_from_image(ctx, src, 0);
	if (ret)
		goto err;

	if (ctx->raw == NULL) {
		ret = 0;
		goto err;
	}

	ret = remove_optional_header_from_image(dst);
	if (ret)
		goto err;

	ret = write_optional_header_to_image_from_raw(ctx->raw, dst);
	if (ret)
		goto err;

err:
	free_ext_context(ctx);

	return ret;
}

int cbt_dump(struct ploop_disk_images_data *di, const char *dev,
		const char *fname)
{
	int fd, ret;

	ploop_log(0, "Dump CBT to %s", fname);
	fd = open(dev, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open dev %s", dev);
		ret = SYSEXIT_DEVICE;
		goto err;
	}

	ret = cbt_get_dirty_bitmap_metadata(fd, NULL, NULL);
	if (ret) {
		if (ret == SYSEXIT_NOCBT)
			ret = 0;
		goto err;
	}

	ret = write_optional_header_to_image(fd, fname, NULL);

err:
	if (fd != -1)
		close(fd);

	return ret;
}

int ploop_dump_cbt(struct ploop_disk_images_data *di, const char *fname)
{
	int ret;
	char dev[64];

	ret = ploop_lock_dd(di);
	if (ret)
		return ret;

	ret = create_snapshot_delta(fname, di->blocksize, di->size,
			PLOOP_FMT_UNDEFINED);
	if (ret < 0) {
		ret = SYSEXIT_CREAT;
		goto err;
	}
	close(ret);

	ret = ploop_find_dev_by_cn(di, di->runtime->component_name, 0, dev,
			sizeof(dev));
	if (ret == -1) {
		ret = SYSEXIT_SYS;
	} else if (ret != 0) {
		ploop_err(0, "Image is not mounted");
		ret = SYSEXIT_DEV_NOT_MOUNTED;
	} else {
		ret = cbt_dump(di, dev, fname);
	}

err:
	if (ret)
		unlink(fname);
	ploop_unlock_dd(di);

	return ret;
}

int ploop_drop_cbt(struct ploop_disk_images_data *di)
{
	int ret;
	char dev[64];
	int lfd;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = ploop_find_dev_by_dd(di, dev, sizeof(dev));
	if (ret == -1) {
		ret = SYSEXIT_SYS;
		goto err;
	} else if (ret == 0) {
		/* online */
		ploop_log(0, "Drop CBT dev=%s", dev);
		lfd = open(dev, O_RDONLY|O_CLOEXEC);
		if (lfd < 0) {
			ploop_err(errno, "Can't open device %s", dev);
			ret = SYSEXIT_DEVICE;
			goto err;
		}

		ret = cbt_stop(lfd);
		if (ret == SYSEXIT_NOCBT)
			ret = 0;
		if (ret)
			ploop_err(errno, "Can't stop cbt on device %s", dev);

		close(lfd);
	} else {
		/* offline */
		const char *fname = find_image_by_guid(di, di->top_guid);

		ploop_log(0, "Drop CBT image=%s", fname);
		ret = remove_optional_header_from_image(fname);
	}

err:
	ploop_unlock_dd(di);

	return ret;
}

int ploop_clone_dd(struct ploop_disk_images_data *di, const char *guid,
		const char *target)
{
	int rc;
	int i, t;
	char fname[PATH_MAX];

	rc = ploop_read_dd(di);
	if (rc)
		return rc;

	i = find_snapshot_by_guid(di, guid);
	if (i == -1) {
		ploop_err(0, "Can't find snapshot by uuid %s",
				guid);
		return SYSEXIT_PARAM;
	}

	t = di->snapshots[i]->temporary;

	char *u = NULL;
	if (guid != NULL) {
		u = di->top_guid;
		di->top_guid = (char *)guid;
		di->snapshots[i]->temporary = 0;
	}

	get_ddxml_fname(target, fname, sizeof(fname));
	rc = store_diskdescriptor(fname, di, 1);

	if (u != NULL) {
		di->top_guid = u;
		di->snapshots[i]->temporary = t;
	}

	return rc;
}

struct ploop_bitmap *ploop_alloc_bitmap(__u64 size, __u64 cluster,
		__u32 granularity)
{
	struct ploop_bitmap *bmap;
	__u64 n;

	n = size / (cluster * granularity * 8);

	bmap = calloc(1, sizeof(struct ploop_bitmap) + (n * sizeof(__u64)));
	if (bmap == NULL) {
		ploop_err(ENOMEM, "ploop_alloc_bitmap()");
		return NULL;
	}

	bmap->l1_size = n;
	bmap->size_sec = size;
	bmap->cluster_sec = cluster;
	bmap->granularity_sec = granularity;

	return bmap;
}

void ploop_release_bitmap(struct ploop_bitmap *bmap)
{
	unsigned int i;

	if (bmap == NULL)
		return;

	for (i = 0; i < bmap->l1_size; ++i) {
		if (bmap->map[i] > 1)
			free((void *)bmap->map[i]);
	}

	free(bmap);
}

struct ploop_bitmap *ploop_get_used_bitmap_from_image(
		struct ploop_disk_images_data *di, const char *guid)
{
	__u32 n, clu, cluster, pid = 0;
	char *img;
	struct delta d = {};
	struct ploop_bitmap *bmap = NULL;
	__u8 *block = NULL;

	if (ploop_read_dd(di))
		return NULL;

	img = find_image_by_guid(di, guid ?: di->top_guid);
	if (img == NULL) {
		ploop_err(0, "Unable to find image by uuid %s", guid);
		return NULL;
	}

	if (open_delta(&d, img, O_RDONLY, OD_ALLOW_DIRTY))
		return NULL;

	cluster = d.blocksize;
	bmap = ploop_alloc_bitmap(d.l2_size * d.blocksize, 8, cluster);
	if (bmap == NULL)
		goto err;

	n = cluster / sizeof(__u32);

	__u64 clu_per_block = S2B(bmap->cluster_sec) * 8;

	for (clu = 0; clu < d.l1_size * n - PLOOP_MAP_OFFSET && clu < d.l2_size; clu++) {
		__u32 l2_cluster = (clu + PLOOP_MAP_OFFSET) / n;
		__u32 l2_slot = (clu + PLOOP_MAP_OFFSET) % n;

		if (d.l2_cache != l2_cluster) {
			if (read_safe(d.fd, d.l2, cluster,
						(off_t)l2_cluster * cluster, "read")) {
				goto err;
			}

			d.l2_cache = l2_cluster;
		}

		if (!((__u64)clu % clu_per_block)) {
			block = calloc(1, clu_per_block / 8);
			if (block == NULL) {
				ploop_err(ENOMEM, "ploop_get_used_bitmap_from_image()");
				goto err;
			}

			pid = clu / clu_per_block;
			bmap->map[pid] = (__u64)block;
			block = NULL;
		}

		if (d.l2[l2_slot] == 0)
			continue;

		__u32 x = clu % clu_per_block; 
		BMAP_SET((void *)bmap->map[pid], x);
	}

out:
	close_delta(&d);
	free(block);

	return bmap;

err:
	ploop_release_bitmap(bmap);
	bmap = NULL;

	goto out;
}


