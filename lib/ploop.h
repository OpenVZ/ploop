#ifndef _PLOOP_H_
#define _PLOOP_H_ 1

#include <linux/types.h>
#include <string.h>
#include <sys/stat.h>

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

/* mount flags */
#define PLOOP_MOUNT_SNAPSHOT   0x01

struct ploop_cancel_handle
{
	int flags;
};

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

	struct delta_fops *fops;
};

struct delta_array
{
	int		delta_max;
	struct delta	*delta_arr;
	__u32		data_cache_cluster;
	void		*data_cache;
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

extern int send_process(const char *device, int ofd, const char *flush_cmd);

extern int uuid_new(unsigned char * uuid);
int gen_uuid_pair(char *uuid1, int len1, char *uuid2, int len2);
extern const char *prl_uuid2str(unsigned char *in, char *out, int len);

extern int find_delta_names(const char * device, int start_level, int end_level,
			    char **names, char ** format);
extern int find_topdelta_name(const char *device, char **image);
extern int ploop_get_attr(const char * device, char * attr, int * res);
extern int ploop_get_delta_attr(const char * device, int level, char * attr, int * res);
extern int ploop_get_delta_attr_str(const char * device, int level, char * attr, char *nbuf, int nbuf_len);
extern int ploop_get_size(const char * device, off_t * res);
int dev_num2dev_start(const char *device, dev_t dev_num, __u32 *dev_start);
int ploop_get_top_level(int devfd, const char *devname, int *top);

extern int init_delta_array(struct delta_array *);
void deinit_delta_array(struct delta_array * p);
extern int extend_delta_array(struct delta_array * p, char * path, int rw, int od_flags);
extern void close_delta(struct delta *delta);
extern int open_delta(struct delta * delta, const char * path, int rw, int od_flags);
extern int open_delta_simple(struct delta * delta, const char * path, int rw, int od_flags);
extern int dirty_delta(struct delta * delta);
extern int clear_delta(struct delta * delta);
extern int parse_size(char * opt, off_t * sz);
extern int read_size_from_image(const char *img_name, int raw, off_t * res);
extern int grow_delta(struct delta *odelta, off_t bdsize, void *buf,
		       struct grow_maps *gm);
extern int grow_raw_delta(const char *image, off_t append_size);
int ploop_grow_device(const char *device, off_t new_size);

struct pfiemap *fiemap_alloc(int n);
int fiemap_add_extent(struct pfiemap **pfiemap_pp, __u64 pos, __u64 len);
int fiemap_get(int fd, __u64 off, __u64 start, off_t size, struct pfiemap **pfiemap_pp);
void fiemap_adjust(struct pfiemap *pfiemap);
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

int range_build_rmap(__u32 iblk_start, __u32 iblk_end,
		       __u32 *rmap, __u32 rlen, struct delta *delta, __u32 *out);
int range_build(__u32 a_h, __u32 n_free_blocks,
		__u32 *rmap, __u32 rlen,
		struct delta     *delta,
		struct freemap   *freemap,
		struct freemap  **rangemap_pp,
		struct relocmap **relocmap_pp);

void range_fix_gaps(struct freemap *freemap, __u32 iblk_start, __u32 iblk_end,
		    __u32 n_to_fix, __u32 *rmap);
int range_split(struct freemap *rangemap, struct freemap *freemap,
		 struct relocmap **relocmap_pp);

struct relocmap *relocmap_alloc(int n);
int relocmap_add_extent(struct relocmap **relocmap_pp,
			 __u32 clu, __u32 iblk, __u32 len, __u32 free);
struct ploop_relocblks_ctl;
int relocmap2relocblks(struct relocmap *relocmap, int lvl, __u32 a_h, __u32 n_scanned,
			struct ploop_relocblks_ctl **relocblks_pp);
int ploop_fsck(char *img, int force, int hard_force, int check, int ro, int verbose);
void ploop_log(int level, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
void ploop_err(int err_no, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
char *make_sysfs_dev_name(int minor, char *buf, int len);
int ploop_mount(struct ploop_disk_images_data *di, char **images,
		struct ploop_mount_param *param, int raw);
int create_snapshot(const char *device, const char *delta, int syncfs);
int get_list_size(char **list);
char **make_images_list(struct ploop_disk_images_data *di, char *guid, int reverse);
void free_images_list(char **images);
int PWRITE(struct delta * delta, void * buf, unsigned int size, off_t off);
int PREAD(struct delta * delta, void *buf, unsigned int size, off_t off);
int ploop_get_dev_by_mnt(const char *path, char *buf, int size);
int ploop_remove_images(struct ploop_disk_images_data *di, char **images, char ***images_out);
void get_disk_descriptor_fname(struct ploop_disk_images_data *di, char *buf, int size);
void get_disk_descriptor_lock_fname(struct ploop_disk_images_data *di, char *out, int size);
int ploop_find_dev_by_uuid(struct ploop_disk_images_data *di, int check_state, char *out, int len);
int sys_fallocate(int fd, int mode, off_t offset, off_t len);

int delete_deltas(int devfd, const char *devname);

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
char *mntn2str(int mntn_type);
int get_balloon(const char *mount_point, struct stat *st, int *outfd);
int ploop_balloon_change_size(const char *device, int balloonfd, off_t new_size);
int ploop_balloon_change_size_local(const char *device, int balloonfd, off_t new_size);
int ploop_balloon_get_state(const char *device, __u32 *state);
int ploop_balloon_clear_state(const char *device);
int ploop_baloon_complete(const char *device);
int ploop_baloon_check_and_repair(const char *device, char *mount_point, int repair);

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
int create_gpt_partition(const char *dev, off_t size);
int resize_gpt_partition(const char *devname);

// misc
int do_ioctl(int fd, int req);
void get_basedir(const char *fname, char *out, int len);
__u32 crc32(const unsigned char *buf, unsigned long len);
int ploop_is_on_nfs(const char *path);
int store_statfs_info(const char *mnt, char *image);
int read_statfs_info(const char *image, struct ploop_info *info);
int get_statfs_info(const char *mnt, struct ploop_info *info);
int ploop_get_child_count_by_uuid(struct ploop_disk_images_data *di, const char *guid);
int ploop_get_child_by_uuid(struct ploop_disk_images_data *di, const char *guid,  char **child_guid);
int ploop_fname_cmp(const char *p1, const char *p2);
int is_valid_guid(const char *guid);
int read_line(const char *path, char *nbuf, int len);

// merge
int get_delta_info(const char *device, int merge_top_only, struct merge_info *info);
int merge_image(const char *device, int start_level, int end_level, int raw, int merge_top,
		char **images);
int merge_image_local(const char *device, int start_level, int end_level, int raw, int merge_top,
		char **images);
int ploop_merge_snapshot_by_guid(struct ploop_disk_images_data *di, const char *guid, int merge_mode);

#endif
