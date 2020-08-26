#ifndef _PLOOP_H_
#define _PLOOP_H_ 1

#include <linux/types.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <assert.h>
#include <inttypes.h>

#include "ploop_if.h"
#include "ploop1_image.h"
#include "libploop.h"

#define PLOOP_UMOUNT_TIMEOUT	60
#define PLOOP_DEV_MAJOR 182

#define SNAP_TYPE_TEMPORARY     0x1
#define SNAP_TYPE_OFFLINE       0x2 

#ifndef __NR_fallocate
#if defined __i386__
#define __NR_fallocate	324
#elif defined __x86_64__
#define __NR_fallocate	285
#else
#error "No fallocate syscall known for this arch"
#endif
#endif /* ! __NR_fallocate */

#ifndef __NR_syncfs
#if defined __i386__
#define __NR_syncfs	344
#elif defined __x86_64__
#define __NR_syncfs	306
#else
#error "No syncfs syscall known for this arch"
#endif
#endif /* ! __NR_syncfs */

/* from linux/magic.h */
#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC	0xEF53
#endif

/* Compatibility: use this UUID to mark top delta */
#define TOPDELTA_UUID		"{5fbaabe3-6958-40ff-92a7-860e329aab41}"
#define NONE_UUID		"{00000000-0000-0000-0000-000000000000}"
#define UUID_SIZE		39	/* sizeof(TOPDELTA_UUID) for example */
#define DEFAULT_FSTYPE		"ext4"
#define BALLOON_FNAME		".balloon-c3a5ae3d-ce7f-43c4-a1ea-c61e2b4504e8"

/* od_flags for open_delta() */
#define OD_NOFLAGS	0x0
#define OD_ALLOW_DIRTY	0x1
#define OD_OFFLINE	0x2

/* flags for ploop_check() */
#define CHECK_FORCE	0x01
#define CHECK_HARDFORCE	0x02
#define CHECK_DROPINUSE	0x04
#define CHECK_DETAILED	0x08
#define CHECK_REPAIR_SPARSE	0x10
#define CHECK_READONLY		0x20	/* do a read-only check */
#define CHECK_TALKATIVE		0x40	/* be verbose, produce more output */
#define CHECK_RAW		0x80	/* delta is in raw format */
#define CHECK_DEFRAG		0x100
#define CHECK_SYNC_BAT		0x200

/* load/remove dirty bitmap flags */
#define DIRTY_BITMAP_REMOVE	0x01
#define DIRTY_BITMAP_TRUNCATE	0x02

#define S2B(sec) ((off_t)(sec) << PLOOP1_SECTOR_LOG)
#define B2S(sec) ((sec) >> PLOOP1_SECTOR_LOG)
#define ROUNDUP(size, blocksize) \
	(((off_t)size + blocksize - 1) / blocksize * blocksize)

#define PLOOP_LOCK_DIR	"/var/lock/ploop"

/* PATH used by the library */
#define DEF_PATH_ENV	"PATH=/sbin:/bin:/usr/sbin:/usr/bin:" \
			"/usr/local/sbin:/usr/local/bin"
#define DEF_PATH_LIST	{ "/sbin", "/bin", "/usr/sbin", "/usr/bin", \
			"/usr/local/sbin", "/usr/bin", NULL }

enum {
	CRYPT_NONE,
	CRYPT_V1,
	CRYPT_V2,
};

typedef int (*writer_fn) (void *h, const void *iobuf, int len, off_t pos);

struct delta
{
	int    fd;
	__u32 *hdr0;
	__u32 *l2;

	__u32  alloc_head;
	int    l1_dirty;
	int    l1_size;	  /* # CLUSTERs L2 table occupies */
	off_t  l2_size;	  /* # slots in L2 table */
	int    l2_dirty;
	int    l2_cache;
	int    dirtied;
	__u32  blocksize;
	int    version;	  /* ploop1 version */

	void *reserved1;
};

struct delta_array
{
	int		delta_max;
	struct delta	*delta_arr;
	__u32		data_cache_cluster;
	int		raw_fd;
	__u64		bd_size;
};

struct grow_maps
{
	struct ploop_index_update_ctl *ctl;
	__u32                         *zblks;
};

struct ploop_extent {
	__u64 pos;
	__u64 len;
};

struct pfiemap {
	int n_entries_alloced;
	int n_entries_used;
	struct ploop_extent extents[0];
};

struct ploop_free_cluster_extent {
	__u32 clu;
	__u32 iblk;
	__u32 len;
};

struct freemap {
	int n_entries_alloced;
	int n_entries_used;
	struct ploop_free_cluster_extent extents[0];
};

struct ploop_reloc_cluster_extent {
	__u32 clu;
	__u32 iblk;
	__u32 len;
	__u32 free; /* this extent is also present in freemap */
};

struct relocmap {
	int n_entries_alloced;
	int n_entries_used;
	struct ploop_reloc_cluster_extent extents[0];
};

struct image_info {
	unsigned long ino;
	dev_t dev;
};

struct merge_info {
	int start_level;
	int end_level;
	int raw;
	int top_level;
	int merge_top;
	char **names;
	struct image_info *info;
};

struct xfer_desc
{
	__u32	marker;
#define PLOOPCOPY_MARKER 0x4cc0ac3d
	__u32	size;
	__u64	pos;
};

struct ploop_disk_images_runtime_data {
	int lckfd;
	char *xml_fname;
	char *component_name;
	int umount_timeout;
};

struct dump2fs_data {
	uint64_t block_count;
	uint64_t block_free;
	uint32_t block_size;
};

struct conf_data {
	int use_kio;
};

/* Mark lib functions used by ploop tools */
#define PL_EXT __attribute__ ((visibility("default")))

/* For PLOOP_FMT_V1:, L[idx] is the offset of iblock in image file measured
 * in 512-bites sectors. For PLOOP_FMT_V2 - it's measured in cluster-blocks.
 */
static inline __u32 ploop_sec_to_ioff(off_t offSec, __u32 blocksize, int version)
{
	switch(version) {
	case PLOOP_FMT_V1:
		return offSec;
	case PLOOP_FMT_V2:
		return offSec / blocksize;
	default:
		assert(0);
	}

	// this unreachable code is here to satisfy broken compilers
	return 0;
}

static inline off_t ploop_ioff_to_sec(__u32 iblk, __u32 blocksize, int version)
{
	switch(version) {
	case PLOOP_FMT_V1:
		return iblk;
	case PLOOP_FMT_V2:
		return (off_t)iblk * blocksize;
	default:
		assert(0);
	}

	// this unreachable code is here to satisfy broken compilers
	return 0;
}

static inline int ploop_fmt_log(int version)
{
	switch(version) {
	case PLOOP_FMT_V1:
		return 11;
	case PLOOP_FMT_V2:
		return 0;
	default:
		assert(0);
		return 0;
	}
}

int gen_uuid_pair(char *uuid1, int len1, char *uuid2, int len2);
int find_delta_names(const char * device, int start_level, int end_level,
			    char **names, char ** format);
int find_delta_info(const char *device, int start_level, int end_level,
		char **names, struct image_info *info, char **format);
PL_EXT int find_level_by_delta(const char *device, const char *delta, int *level);
PL_EXT int ploop_get_attr(const char * device, const char * attr, int * res);
int ploop_get_delta_attr(const char * device, int level, const char * attr, int * res);
int ploop_get_delta_attr_str(const char *device, int level, const char *attr, char *out, int len);
int ploop_get_size(const char * device, off_t * res);
int get_dev_by_name(const char *name, dev_t *dev);
int dev_num2dev_start(dev_t dev_num, __u32 *dev_start);
void init_delta_array(struct delta_array *);
void deinit_delta_array(struct delta_array * p);
int extend_delta_array(struct delta_array * p, char * path, int rw, int od_flags);
void close_delta(struct delta *delta);
int open_delta(struct delta * delta, const char * path, int rw, int od_flags);
int open_delta_simple(struct delta * delta, const char * path, int rw, int od_flags);
int change_delta_version(struct delta *delta, int version);
int change_delta_flags(struct delta * delta, __u32 flags);
int dirty_delta(struct delta * delta);
int clear_delta(struct delta * delta);
int read_size_from_image(const char *img_name, int raw, off_t * res);
int grow_delta(struct delta *odelta, off_t bdsize, void *buf,
		struct grow_maps *gm);
int grow_raw_delta(const char *image, off_t append_size, int sparse);
PL_EXT int ploop_grow_image(struct ploop_disk_images_data *di, off_t size, int sparse);
PL_EXT int ploop_grow_device(const char *device, off_t new_size);
PL_EXT int ploop_grow_raw_delta_offline(const char *image, off_t new_size, int sparse);
PL_EXT int ploop_grow_delta_offline(const char *image, off_t new_size);

struct pfiemap *fiemap_alloc(int n);
int fiemap_get(int fd, __u64 off, __u64 start, off_t size, struct pfiemap **pfiemap_pp);
void fiemap_adjust(struct pfiemap *pfiemap, __u32 blocksize);
int fiemap_build_rmap(struct pfiemap *pfiemap, __u32 *rmap, __u32 rlen, struct delta *delta);

struct freemap *freemap_alloc(int n);
int rmap2freemap(__u32 *rmap, __u32 iblk_start, __u32 iblk_end,
		 struct freemap **freemap_pp, int *entries_used);
struct ploop_freeblks_ctl;
int freeblks_alloc(struct ploop_freeblks_ctl **freeblks_pp, int n);
int freemap2freeblks(struct freemap *freemap,
		int lvl, struct ploop_freeblks_ctl **freeblks_pp, __u32 *total);
int freeblks2freemap(struct ploop_freeblks_ctl *freeblks,
		struct freemap **freemap_pp, __u32 *total);

int range_build(__u32 a_h, __u32 n_free_blocks,
		__u32 *rmap, __u32 rlen,
		struct delta     *delta,
		struct freemap   *freemap,
		struct freemap  **rangemap_pp,
		struct relocmap **relocmap_pp);

struct relocmap *relocmap_alloc(int n);
struct ploop_relocblks_ctl;
int relocmap2relocblks(struct relocmap *relocmap, int lvl, __u32 a_h, __u32 n_scanned,
			struct ploop_relocblks_ctl **relocblks_pp);
PL_EXT int ploop_check(const char *img, int flags, __u32 *blocksize_p,
		int *cbt_allowed);
int check_deltas(struct ploop_disk_images_data *di, char **images,
		int raw, __u32 *blocksize, int *cbt_allowed, int flags);
PL_EXT int check_dd(struct ploop_disk_images_data *di, const char *uuid,
		int flags);
/* Logging */
#define LOG_BUF_SIZE	8192
int ploop_get_log_level(void);
void ploop_log(int level, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
void __ploop_err(int err_no, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#ifdef DEBUG
#define ploop_err(err, format, ...)					\
		__ploop_err(err, "Error in %s (%s:%d): " format,	\
				__func__, __FILE__, __LINE__,		\
				##__VA_ARGS__)
#else
#define ploop_err __ploop_err
#endif

#define ioctl_device(fd, req, arg)					\
	({								\
		int __ret = 0;						\
		if (ioctl(fd, req, arg)) {				\
			ploop_err(errno, "Error in ioctl(" #req ")");	\
			__ret = SYSEXIT_DEVIOC;				\
		}							\
		__ret;							\
	 })

char *make_sysfs_dev_name(int minor, char *buf, int len);
int mount_image(struct ploop_disk_images_data *di, struct ploop_mount_param *param);
PL_EXT int ploop_mount(struct ploop_disk_images_data *di, char **images,
		struct ploop_mount_param *param, int raw);
PL_EXT int replace_delta(const char *device, int level, const char *image, int raw, int flags);
PL_EXT int create_snapshot(const char *device, const char *delta, int syncfs,
		const __u8 *cbt_u, const char *prev_delta);
int get_list_size(char **list);
int normalize_image_name(const char *basedir, const char *image, char *out, int len);
int PWRITE(struct delta * delta, void * buf, unsigned int size, off_t off);
int PREAD(struct delta * delta, void *buf, unsigned int size, off_t off);
PL_EXT int ploop_getdevice(int *minor);
struct ploop_disk_images_data *alloc_diskdescriptor(void);
int ploop_store_diskdescriptor(const char *fname, struct ploop_disk_images_data *di);
PL_EXT int ploop_read_disk_descr(struct ploop_disk_images_data **di, const char *file);
void get_disk_descriptor_fname(struct ploop_disk_images_data *di, char *buf, int size);
void get_disk_descriptor_lock_fname(struct ploop_disk_images_data *di, char *out, int size);
int find_image_idx_by_guid(struct ploop_disk_images_data *di, const char *guid);
int find_image_idx_by_file(struct ploop_disk_images_data *di, const char *file);
int ploop_find_dev(const char *component_name, const char *image, char *out, int size);
int ploop_find_dev_by_cn(struct ploop_disk_images_data *di, const char *component_name,
		int check_state, char *out, int len);
int ploop_find_dev_by_dd(struct ploop_disk_images_data *di,
		char *out, int len);
int sys_fallocate(int fd, int mode, off_t offset, off_t len);
int sys_syncfs(int fd);
int create_snapshot_delta(const char *path, __u32 blocksize, off_t bdsize,
		int version);
int get_image_param_online(const char *device, off_t *size,
		__u32 *blocksize, int *version);
int get_image_param(struct ploop_disk_images_data *di, const char *guid,
		off_t *size, __u32 *blocksize, int *version);
int get_image_param_offline(struct ploop_disk_images_data *di, const char *guid,
                off_t *size, __u32 *blocksize, int *version);
PL_EXT char **make_images_list(struct ploop_disk_images_data *di, const char *guid, int reverse);

// manage struct ploop_disk_images_data
int ploop_di_add_image(struct ploop_disk_images_data *di, const char *fname,
		const char *guid, const char *parent_guid);
void ploop_di_set_temporary(struct ploop_disk_images_data *di, const char *guid);
int ploop_di_remove_image(struct ploop_disk_images_data *di, const char *guid,
		int renew_top_uuid, char **fname);
int ploop_di_merge_image(struct ploop_disk_images_data *di, const char *guid, char **fname);
void ploop_di_change_guid(struct ploop_disk_images_data *di, const char *guid, const char *new_guid);
PL_EXT char *find_image_by_guid(struct ploop_disk_images_data *di, const char *guid);
PL_EXT int find_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid);
int ploop_add_image_entry(struct ploop_disk_images_data *di, const char *fname, const char *guid);
int ploop_add_snapshot_entry(struct ploop_disk_images_data *di, const char *guid,
		const char *parent_guid, int temporary);

//balloon
PL_EXT char *mntn2str(int mntn_type);
PL_EXT int get_balloon(const char *mount_point, struct stat *st, int *outfd);
PL_EXT int ploop_balloon_change_size(const char *device, int balloonfd, off_t new_size);
PL_EXT int ploop_balloon_get_state(const char *device, __u32 *state);
PL_EXT int ploop_balloon_clear_state(const char *device);
PL_EXT int ploop_balloon_complete(const char *device);
PL_EXT int ploop_balloon_check_and_repair(const char *device, const char *mount_point, int repair);
PL_EXT int ploop_discard_get_stat_by_dev(const char *device, const char *mount_point,
		struct ploop_discard_stat *pd_stat);
PL_EXT int ploop_discard_by_dev(const char *device, const char *mount_point,
		__u64 minlen_b, __u64 to_free, const int *stop);
int ploop_blk_discard(const char* device, __u32 blocksize, off_t start, off_t end);

/* lock */
int ploop_lock_dd(struct ploop_disk_images_data *di);
void ploop_unlock_dd(struct ploop_disk_images_data *di);
void ploop_clear_dd(struct ploop_disk_images_data *di);
int ploop_lock_di(struct ploop_disk_images_data *di);
void ploop_unlock_di(struct ploop_disk_images_data *di);
int ploop_global_lock(void);
void ploop_unlock(int *lckfd);

// fs util
int get_partition_device_name(const char *device, char *out, int size);
int get_partition_device_name_by_num(const char *device, int part_num, char *out, int size);
int make_fs(const char *device, const char *fstype, unsigned int fsblocksize,
		unsigned int flags, const char *fslabel);
void tune_fs(int balloonfd, const char *device, unsigned long long size);
int resize_fs(const char *device, off_t blocks);
int dumpe2fs(const char *device, struct dump2fs_data *data);
int e2fsck(const char *device, int flags, int *rc);
int create_gpt_partition(const char *dev, off_t size, __u32 blocksize);
int resize_gpt_partition(const char *devname, const char *partname,
		__u64 new_size512, __u32 blocksize512);
int check_and_repair_gpt(const char *device, __u32 blocksize512);
int parted_mklabel_gpt(const char *device);
int sgdisk_resize_gpt(const char *device, int part_num, off_t part_start);
int sgdisk_mkpart(const char *device, int part_num,
		unsigned long long part_start, unsigned long long part_end);
int get_partition_range(const char *device, int part_num,
		unsigned long long *part_start, unsigned long long *part_end);
int get_last_partition_num(const char *device, int *part_num);
int reread_part(const char *device);
int partprobe(const char *device);
int is_device_from_devmapper(const char *device);

// misc
void get_basedir(const char *fname, char *out, int len);
__u32 ploop_crc32(const unsigned char *buf, unsigned long len);
int store_statfs_info(const char *mnt, char *image);
int drop_statfs_info(const char *image);
int read_statfs_info(const char *image, struct ploop_info *info);
int get_statfs_info(const char *mnt, struct ploop_info *info);
int ploop_get_child_count_by_uuid(struct ploop_disk_images_data *di, const char *guid);
const char* ploop_get_child_by_uuid(struct ploop_disk_images_data *di, const char *guid);
int fname_cmp(const char *p1, struct stat *st);
PL_EXT int is_valid_guid(const char *guid);
PL_EXT int read_line(const char *path, char *nbuf, int len);
int read_line_quiet(const char *path, char *nbuf, int len);
int is_valid_blocksize(__u32 blocksize);
int run_prg(char *const argv[]);
#define HIDE_STDOUT	1 << 0	/* hide process' stdout */
#define HIDE_STDERR	1 << 1	/* hide process' stderr */
int run_prg_rc(char *const argv[], char *const env[], int hide_mask, int *rc);
int p_memalign(void **memptr, size_t alignment, size_t size);
PL_EXT int guidcmp(const char *p1, const char *p2);
int auto_mount_image(struct ploop_disk_images_data *di,
		struct ploop_mount_param *param);
void free_mount_param(struct ploop_mount_param *param);
int check_and_restore_fmt_version(struct ploop_disk_images_data *di);
int check_blockdev_size(unsigned long long sectors, __u32 blocksize, int version);
int print_output(int level, const char *cmd, const char *arg);
PL_EXT int read_safe(int fd, void * buf, unsigned int size, off_t pos, char *msg);
int write_safe(int fd, void * buf, unsigned int size, off_t pos, char *msg);
const char *get_snap_str(int temporary);
PL_EXT int ploop_restore_descriptor(const char *dir, char *delta_path, int raw, int blocksize);
int is_device_inuse(const char *dev);
// merge
PL_EXT int get_delta_info(const char *device, struct merge_info *info);
PL_EXT int merge_image(const char *device, int start_level, int end_level, int raw, int merge_top,
		char **images, const char *new_delta);
int ploop_merge_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid, const char *new_delta);
int merge_temporary_snapshots(struct ploop_disk_images_data *di);

PL_EXT int ploop_change_fmt_version(struct ploop_disk_images_data *di,
		int new_version, int flags);
int ploop_get_dev_by_delta(const char *delta, const char *topdelta,
		const char *component_name, char **out[]);
int check_snapshot_mount(struct ploop_disk_images_data *di,
		const char *guid, const char *fname, int temp);
int create_image(const char *file, __u32 blocksize, off_t size_sec, int mode,
		int version, int flags);
int do_replace_delta(int devfd, int level, int imgfd, __u32 blocksize,
		const char *image, int raw, int flags);
int copy_delta(const char *src, const char *dst);

struct ploop_copy_handle;
PL_EXT int ploop_copy_init(struct ploop_disk_images_data *di, struct ploop_copy_param *param,
	struct ploop_copy_handle **h);
PL_EXT int ploop_copy_start(struct ploop_copy_handle *h, struct ploop_copy_stat *stat);
PL_EXT int ploop_copy_next_iteration(struct ploop_copy_handle *h, struct ploop_copy_stat *stat);
PL_EXT int ploop_copy_stop(struct ploop_copy_handle *h, struct ploop_copy_stat *stat);
PL_EXT void ploop_copy_deinit(struct ploop_copy_handle *h);
PL_EXT int ploop_copy_receiver(struct ploop_copy_receive_param *arg);
PL_EXT int ploop_create_snapshot_offline(struct ploop_disk_images_data *di,
		struct ploop_snapshot_param *param);
int complete_running_operation(struct ploop_disk_images_data *di,
		const char *device);
int set_encryption_keyid(struct ploop_disk_images_data *di, const char *keyid);
int store_encryption_keyid(struct ploop_disk_images_data *di,
		const char *keyid);
const char *crypt_get_device_name(const char *part, char *out, int len);
int crypt_init(const char *device, const char *keyid);
int crypt_open(const char *device, const char *keyid);
int crypt_close(const char *devname, const char *partname);
int crypt_resize(const char *part);
int get_crypt_layout(const char *devname, const char *partname);
int get_dir_entry(const char *path, char **out[]);
int get_part_devname_from_sys(const char *device, char *devname, int dsize,
		char *partname, int psize);
int ploop_create(const char *path, const char *ipath,
		struct ploop_create_param *param);
int do_create_snapshot(struct ploop_disk_images_data *di,
		const char *guid, const char *snap_dir,
		const char *cbt_uuid, int flags);
int get_delta_fname(struct ploop_disk_images_data *di, const char *guid,
		char *out, int len);
const char *get_base_delta_uuid(struct ploop_disk_images_data *di);
int do_delete_snapshot(struct ploop_disk_images_data *di, const char *guid);
const char *get_basename(const char *path);
const char *get_top_delta_guid(struct ploop_disk_images_data *di);
int find_dev_by_delta(const char *component_name, const char *delta,
		const char *topdelta, char *out, int size);
int read_dd(struct ploop_disk_images_data *di);
void normalize_path(const char *path, char *out);
int get_snap_file_name(struct ploop_disk_images_data *di, const char *snap_dir,
		const char *file_guid, char *out, int size);
int has_partition(const char *device, int *res);
int is_luks(const char *device, int *res);
void free_encryption_data(struct ploop_disk_images_data *di);
const char *get_ddxml_fname(const char *dir, char *buf, int size);
int store_diskdescriptor(const char *fname, struct ploop_disk_images_data *di,
		int skip_convert);
int ploop_get_mntn_state(int fd, int *state);
int is_native_discard(const char *device);
__u32 *alloc_reverse_map(__u32 len);
int range_build_rmap(__u32 iblk_start, __u32 iblk_end,
		__u32 *rmap, __u32 rlen, struct delta *delta,
		__u32 *out, __u32 *max);
int fsync_safe(int fd);
int build_hole_bitmap(struct delta *delta, __u64 **hole_bitmap,
		__u32 *hole_bitmap_size, int *nr_clusters);
int image_defrag(struct delta *delta);
int do_umount(const char *mnt, int tmo_sec);
int get_part_devname(struct ploop_disk_images_data *di,
		const char *device, char *devname, int dlen,
		char *partname, int plen);
int get_mount_dir(const char *device, int pid, char *out, int size);
int auto_mount_fs(struct ploop_disk_images_data *di, pid_t pid,
		const char *partname, struct ploop_mount_param *param);
int get_dev_and_mnt(struct ploop_disk_images_data *di, pid_t pid,
		int automount, char *dev, int dev_len, char *mnt,
		int mnt_len, int *mounted);
int umnt(struct ploop_disk_images_data *di, const char *dev,
		const char *mnt, int mounted);

PL_EXT int dump_bat(const char *image);
PL_EXT int ploop_image_shuffle(const char *image, int nr, int flags);
PL_EXT int ploop_check_bat(struct ploop_disk_images_data *di, const char *device,
		int flags);
int get_pctl_type(struct conf_data *conf, const char *image, __u32 *out);
int read_conf(struct conf_data *conf);
#endif
