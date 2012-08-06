#ifndef _PLOOP_H_
#define _PLOOP_H_ 1

#include <linux/types.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>

#include "ploop1_image.h"
#include "ploop_if.h"
#include "libploop.h"

#define PLOOP_DEV_MAJOR 182

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

#define DISKDESCRIPTOR_XML      "DiskDescriptor.xml"
/* Compatibility: Parallels use this UUID to mark top delta */
#define BASE_UUID		"{5fbaabe3-6958-40ff-92a7-860e329aab41}"
#define NONE_UUID		"{00000000-0000-0000-0000-000000000000}"
#define DEFAULT_FSTYPE		"ext4"
#define BALLOON_FNAME		".balloon-c3a5ae3d-ce7f-43c4-a1ea-c61e2b4504e8"

/* od_flags for open_delta() */
#define OD_NOFLAGS      0x0
#define OD_ALLOW_DIRTY  0x1
#define OD_OFFLINE      0x2

/* fsck mode flags */
#define FSCK_FORCE     0x01
#define FSCK_HARDFORCE 0x02
#define FSCK_DROPINUSE 0x04
#define FSCK_CHECK     0x08

#define S2B(sec) ((off_t)(sec) << PLOOP1_SECTOR_LOG)
#define B2S(sec) ((sec) >> PLOOP1_SECTOR_LOG)

struct delta_fops
{
	int		(*open)(char *pathname, int flags, mode_t mode);
	int		(*close)(int fd);
	int		(*pread)(int fd, void *buf, size_t count, off_t offset);
	int		(*pwrite)(int fd, void *buf, size_t count, off_t offset);
	int		(*fstat)(int fd, struct stat *buf);
	int		(*fsync)(int fd);
	int		(*update_size)(int fd, const char *pathname);
};

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

	struct delta_fops *fops;
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

struct merge_info {
	int start_level;
	int end_level;
	int raw;
	int top_level;
	int merge_top;
	char **names;
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
	int vm_compat;
	char *component_name;
};

enum {
	PLOOP_MERGE_WITH_CHILD = 0,
	PLOOP_MERGE_WITH_PARENT = 1,
};

/* Mark lib functions used by ploop tools */
#define PL_EXT __attribute__ ((visibility("default")))

int gen_uuid_pair(char *uuid1, int len1, char *uuid2, int len2);

int find_delta_names(const char * device, int start_level, int end_level,
			    char **names, char ** format);
PL_EXT int ploop_get_attr(const char * device, const char * attr, int * res);
int ploop_get_delta_attr(const char * device, int level, char * attr, int * res);
int ploop_get_size(const char * device, off_t * res);
int dev_num2dev_start(const char *device, dev_t dev_num, __u32 *dev_start);
int ploop_get_top_level(int devfd, const char *devname, int *top);

int init_delta_array(struct delta_array *);
void deinit_delta_array(struct delta_array * p);
int extend_delta_array(struct delta_array * p, char * path, int rw, int od_flags);
PL_EXT void close_delta(struct delta *delta);
PL_EXT int open_delta(struct delta * delta, const char * path, int rw, int od_flags);
PL_EXT int open_delta_simple(struct delta * delta, const char * path, int rw, int od_flags);
PL_EXT int dirty_delta(struct delta * delta);
PL_EXT int clear_delta(struct delta * delta);
PL_EXT int read_size_from_image(const char *img_name, int raw, off_t * res);
PL_EXT int grow_delta(struct delta *odelta, off_t bdsize, void *buf,
		       struct grow_maps *gm);
PL_EXT int grow_raw_delta(const char *image, off_t append_size);
PL_EXT int ploop_grow_device(const char *device, __u32 blocksize, off_t new_size);

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
PL_EXT int ploop_fsck(char *img, int flags, int ro, int verbose, __u32 *blocksize_p);
/* Logging */
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
PL_EXT int ploop_mount(struct ploop_disk_images_data *di, char **images,
		struct ploop_mount_param *param, int raw);
PL_EXT int create_snapshot(const char *device, const char *delta, __u32 blocksize, int syncfs);
int get_list_size(char **list);
void free_images_list(char **images);
int PWRITE(struct delta * delta, void * buf, unsigned int size, off_t off);
int PREAD(struct delta * delta, void *buf, unsigned int size, off_t off);
PL_EXT int ploop_getdevice(int *minor);
void get_disk_descriptor_fname(struct ploop_disk_images_data *di, char *buf, int size);
void get_disk_descriptor_lock_fname(struct ploop_disk_images_data *di, char *out, int size);
int ploop_find_dev_by_uuid(struct ploop_disk_images_data *di, int check_state, char *out, int len);
int sys_fallocate(int fd, int mode, off_t offset, off_t len);
int sys_syncfs(int fd);

// manage struct ploop_disk_images_data
int ploop_di_add_image(struct ploop_disk_images_data *di, const char *fname,
		const char *guid, const char *parent_guid);
int ploop_di_remove_image(struct ploop_disk_images_data *di, const char *guid, char **fname);
int ploop_di_merge_image(struct ploop_disk_images_data *di, const char *guid, char **fname);
void ploop_di_change_guid(struct ploop_disk_images_data *di, const char *guid, const char *new_guid);
char *find_image_by_guid(struct ploop_disk_images_data *di, const char *guid);
int find_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid);
int ploop_add_image_entry(struct ploop_disk_images_data *di, const char *fname, const char *guid);
int ploop_add_snapshot_entry(struct ploop_disk_images_data *di, const char *guid,
		const char *parent_guid);
int ploop_find_dev(const char *module, const char *image, char *out, int size);
int register_ploop_dev(const char *module, const char *image, const char *dev);
void unregister_ploop_dev(const char *module, const char *image);

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

/* lock */
int ploop_lock_di(struct ploop_disk_images_data *di);
void ploop_unlock_di(struct ploop_disk_images_data *di);
int ploop_global_lock(void);
void ploop_unlock(int *lckfd);

// fs util
int get_partition_device_name(const char *device, char *out, int size);
int make_fs(const char *device, const char *fstype);
void tune_fs(const char *target, const char *device, unsigned long long size);
int resize_fs(const char *device);
int create_gpt_partition(const char *dev, off_t size, __u32 blocksize);
int resize_gpt_partition(const char *devname);

// misc
void get_basedir(const char *fname, char *out, int len);
__u32 crc32(const unsigned char *buf, unsigned long len);
int store_statfs_info(const char *mnt, char *image);
int drop_statfs_info(const char *image);
int read_statfs_info(const char *image, struct ploop_info *info);
int get_statfs_info(const char *mnt, struct ploop_info *info);
int ploop_get_child_count_by_uuid(struct ploop_disk_images_data *di, const char *guid);
int ploop_get_child_by_uuid(struct ploop_disk_images_data *di, const char *guid,  char **child_guid);
int ploop_fname_cmp(const char *p1, const char *p2);
int is_valid_guid(const char *guid);
int read_line(const char *path, char *nbuf, int len);
int is_valid_blocksize(__u32 blocksize);
int run_prg(char *const argv[]);

// merge
PL_EXT int get_delta_info(const char *device, struct merge_info *info);
PL_EXT int merge_image(const char *device, int start_level, int end_level, int raw, int merge_top,
		char **images);
int ploop_merge_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid, int merge_mode);
int ploop_complete_running_operation(const char *device);

#endif
