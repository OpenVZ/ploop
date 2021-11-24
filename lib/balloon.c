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
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "ploop.h"
#include "ploop_if.h"
#include "cleanup.h"

#define EXT4_IOC_OPEN_BALLOON		_IO('f', 42)
#define XFS_IOC_OPEN_BALLOON		_IO('X', 255)

#define BIN_E4DEFRAG	"/usr/sbin/ploop-e4defrag"

char *mntn2str(int mntn_type)
{
	switch (mntn_type) {
	case PLOOP_MNTN_OFF:
		return "OFF";
	case PLOOP_MNTN_BALLOON:
		return "BALLOON";
	case PLOOP_MNTN_FBLOADED:
		return "FBLOADED";
	case PLOOP_MNTN_TRACK:
		return "TRACK";
	case PLOOP_MNTN_RELOC:
		return "RELOC";
	case PLOOP_MNTN_MERGE:
		return "MERGE";
	case PLOOP_MNTN_GROW:
		return "GROW";
	case PLOOP_MNTN_DISCARD:
		return "DISCARD";
	case PLOOP_MNTN_PUSH_BACKUP:
		return "PLOOP_MNTN_PUSH_BACKUP";
	}

	return "UNKNOWN";
}

static int fsync_balloon(int fd)
{
	if (fsync(fd)) {
		ploop_err(errno, "Can't fsync balloon");
		return(SYSEXIT_FSYNC);
	}
	return 0;
}

/*
 * Open, flock and stat balloon.
 *
 * Returns balloon fd.
 */
int get_balloon(const char *mount_point, struct stat *st, int *outfd)
{
	int fd, fd2;

	if (mount_point == NULL)
		return SYSEXIT_PARAM;

	fd = open(mount_point, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open mount point %s", mount_point);
		return(SYSEXIT_OPEN);
	}

	fd2 = ioctl(fd, XFS_IOC_OPEN_BALLOON, 0);
	if (fd2 == -1 && errno == ENOTTY)
		fd2 = ioctl(fd, EXT4_IOC_OPEN_BALLOON, 0);
	close(fd);

	if (fd2 < 0) {
		ploop_err(errno, "Cannot open balloon at %s", mount_point);
		return(SYSEXIT_DEVIOC);
	}

	if (outfd != NULL) {
		if (flock(fd2, LOCK_EX | LOCK_NB)) {
			close(fd2);
			if (errno == EWOULDBLOCK) {
				ploop_err(0, "Hidden balloon is in use "
					"by someone else!");
				return(SYSEXIT_EBUSY);
			}
			ploop_err(errno, "Can't flock balloon");
			return(SYSEXIT_FLOCK);
		}
		*outfd = fd2;
	}

	if (st != NULL && fstat(fd2, st)) {
		close(fd2);
		ploop_err(errno, "Can't stat balloon");
		return(SYSEXIT_FSTAT);
	}
	if (outfd == NULL)
		close(fd2);

	return 0;
}

__u32 *alloc_reverse_map(__u32 len)
{
	__u32 *reverse_map;

	reverse_map = malloc(len * sizeof(__u32));
	if (reverse_map == NULL) {
		ploop_err(errno, "Can't allocate reverse map");
		return NULL;
	}
	return reverse_map;
}

static int do_truncate(int fd, off_t old_size, off_t new_size)
{
	int ret;

	if (new_size == old_size) {
		ploop_log(0, "Nothing to do: new_size == old_size");
	} else if (ftruncate(fd, new_size)) {
		ploop_err(errno, "Can't truncate hidden balloon");
		fsync_balloon(fd);
		return(SYSEXIT_FTRUNCATE);
	} else {
		ret = fsync_balloon(fd);
		if (ret)
			return ret;
		ploop_log(0, "Successfully truncated balloon from %llu to %llu bytes",
			(unsigned long long)old_size, (unsigned long long)new_size);
	}
	return 0;
}

static int do_inflate(int fd, off_t old_size, off_t *new_size)
{
	struct stat st;
	int err;

	err = sys_fallocate(fd, 0, 0, *new_size);
	if (err)
		ploop_err(errno, "Can't fallocate balloon");

	if (fstat(fd, &st)) {
		ploop_err(errno, "Can't stat balloon (2)");
		if (ftruncate(fd, old_size))
			ploop_err(errno, "Can't revert old_size back");
		return(err ? SYSEXIT_FALLOCATE : SYSEXIT_FSTAT);
	}

	if (err) {
		if (st.st_size != old_size) {
			if (ftruncate(fd, old_size))
				ploop_err(errno, "Can't revert old_size back (2)");
		}
		return(SYSEXIT_FALLOCATE);
	}

	if (st.st_size < *new_size) {
		ploop_err(0, "Error: after fallocate(%d, 0, 0, %llu) fstat "
			"reported size == %llu", fd,
				(unsigned long long)*new_size, (unsigned long long)st.st_size);
		if (ftruncate(fd, old_size))
			ploop_err(errno, "Can't revert old_size back (3)");
		return(SYSEXIT_FALLOCATE);
	}
	*new_size = st.st_size;

	err = fsync_balloon(fd);
	if (err)
		return err;

	ploop_log(0, "Successfully inflated balloon from %llu to %llu bytes",
			(unsigned long long)old_size, (unsigned long long)*new_size);
	return 0;
}

int ploop_balloon_change_size(const char *device, int balloonfd, off_t new_size)
{
	int    ret;
	off_t  old_size;
	struct stat st;

	if (fstat(balloonfd, &st)) {
		ploop_err(errno, "Can't get balloon file size");
		return SYSEXIT_FSTAT;
	}

	old_size = st.st_size;
	new_size = (S2B(new_size) + st.st_blksize - 1) & ~(st.st_blksize - 1);

	ploop_log(0, "Changing balloon size old_size=%ld new_size=%ld",
			(long)old_size, (long)new_size);

	if (old_size >= new_size)
		ret = do_truncate(balloonfd, old_size, new_size);
	else
		ret = do_inflate(balloonfd, old_size, &new_size);

	return ret;
}


static volatile int trim_stop = 0;
static void stop_trim_handler(int sig)
{
	trim_stop = 1;
}

static int get_discard_granularity(struct ploop_disk_images_data *di,
		__u32 cluster, __u64 *granularity)
{
	int rc = 0;
	FILE *fp;
	struct stat st;
	char buf[128];
	const char *fname;

	if (di == NULL) {
		*granularity = cluster;
		return 0;
	}
		
	fname = find_image_by_guid(di, get_top_delta_guid(di));

	if (stat(fname, &st)) {
		ploop_err(errno, "Unable to stat %s", fname);
		return SYSEXIT_SYS;
	}

	snprintf(buf, sizeof(buf), "/sys/dev/block/%u:%u",
			major(st.st_dev), minor(st.st_dev));
	if (access(buf, F_OK)) {
		*granularity = cluster;
		return 0;
	}

	snprintf(buf, sizeof(buf), "/sys/dev/block/%u:%u/partition",
			major(st.st_dev), minor(st.st_dev));
	if (access(buf, F_OK) == 0) {
		char target[PATH_MAX];
		ssize_t n;

		snprintf(buf, sizeof(buf), "/sys/dev/block/%u:%u",
			major(st.st_dev), minor(st.st_dev));
		n = readlink(buf, target, sizeof(target) -1);
		if (n == -1) {
			ploop_err(errno, "Unable to readlink %s", buf);
			return SYSEXIT_OPEN;
		}
		target[n] = '\0';

		char *p = strrchr(target, '/');
		if (p == NULL) {
			ploop_err(errno, "Unable to get device name from %s", target);
			return SYSEXIT_OPEN;
		}
		*p = '\0';
		p = strrchr(target, '/');
		if (p == NULL)
			p = target;
		snprintf(buf, sizeof(buf), "/sys/block/%s/queue/discard_granularity",
				p);
	} else
		snprintf(buf, sizeof(buf), "/sys/dev/block/%u:%u/queue/discard_granularity",
				major(st.st_dev), minor(st.st_dev));
	fp = fopen(buf, "r");
	if (fp == NULL) {
		ploop_err(errno, "Unable to open %s", buf);
		return SYSEXIT_OPEN;
	}

	if (fscanf(fp, "%llu", granularity) != 1) {
		ploop_err(0, "Unable to parse %s", buf);
		rc = SYSEXIT_SYS;
	}

	fclose(fp);
	if (*granularity == 0)
		*granularity = cluster;
	return rc;
}


/* The fragmentation of such blocks doesn't affect the speed of w/r */
#define MAX_DISCARD_CLU 32

static int ploop_trim(struct ploop_disk_images_data *di,
		const char *devname, const char *mount_point, __u64 minlen_b)
{
	struct fstrim_range range = {};
	int fd, ret = -1, last = 0;
	off_t size;
	__u64 trim_minlen;
	__u64 discard_granularity;
	__u32 cluster;
	struct sigaction sa = {
		.sa_handler     = stop_trim_handler,
	};
	sigemptyset(&sa.sa_mask);

	ret = get_image_param_online(di, devname, NULL, &size, &cluster, NULL, NULL);
	if (ret)
		return ret;
	cluster = S2B(cluster);

	ret = get_discard_granularity(di, cluster, &discard_granularity);
	if (ret)
		return ret;

	if (sigaction(SIGUSR1, &sa, NULL)) {
		ploop_err(errno, "Can't set signal handler");
		return -1;
	}

	fd = open(mount_point, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open mount point %s", mount_point);
		return -1;
	}

	sys_syncfs(fd);

	if (minlen_b < cluster)
		minlen_b = cluster;
	else
		minlen_b = (minlen_b + cluster - 1) / cluster * cluster;

	if (minlen_b < discard_granularity)
		minlen_b = discard_granularity;
	range.minlen = MAX(MAX_DISCARD_CLU * cluster, minlen_b);

	for (; range.minlen >= minlen_b; range.minlen /= 2) {
		ploop_log(1, "Call FITRIM, for minlen=%" PRIu64, (uint64_t)range.minlen);

		/* range.len is reseted by FITRIM */
		range.len = ULLONG_MAX;
		trim_minlen = range.minlen;
		ret = ioctl(fd, FITRIM, &range);
		if (ret < 0) {
			if (trim_stop)
				ret = 0;
			else
				ploop_err(errno, "Can't trim file system");
			break;
		}

		if (last)
			break;

		if (range.minlen > trim_minlen)
			minlen_b = range.minlen;

		/* last iteration should go with range.minlen == minlen_b */
		if (range.minlen / 2 < minlen_b) {
			range.minlen = minlen_b * 2;
			last = 1;
		}
	}

	close(fd);

	return ret;
}

static int blk_discard(int fd, __u32 cluster, __u64 start, __u64 len)
{
	__u64 max_discard_len = S2B(B2S(UINT_MAX) / cluster * cluster);

	while (len > 0) {
		__u64 range[2];
		int ret;

		range[0] = start;
		range[1] = MIN(len, max_discard_len);

		if (start % S2B(cluster) && len > range[1])
			range[1] -= start % S2B(cluster);

		ploop_log(1, "Call BLKDISCARD start=%" PRIu64 " length=%" PRIu64, (uint64_t)range[0], (uint64_t)range[1]);
		ret = ioctl_device(fd, BLKDISCARD, range);
		if (ret)
			return ret;

		start += range[1];
		len -= range[1];
	}

	return 0;
}

int wait_pid(pid_t pid, const char *mes, const volatile int *stop)
{
	int err, status;
	int flags = stop != NULL ? WNOHANG : 0;

	while ((err = waitpid(pid, &status, flags)) <= 0) {
		if (stop && err == 0) {
			if (*stop) {
				kill(pid, SIGTERM);
				flags = 0;
			} else
				sleep(1);
		} else if (errno != EINTR)
			break;
	}
	if (err == -1) {
		if (errno != ECHILD)
			ploop_err(errno, "wait() failed");
	} else if (WIFEXITED(status)) {
		err = WEXITSTATUS(status);
		if (err) {
			ploop_err(0, "The %s process failed with code %d",
					mes, err);
			err = -1;
		}
	} else if (WIFSIGNALED(status)) {
		ploop_err(0, "The %s process killed by signal %d",
				mes, WTERMSIG(status));
		err = -1;
	} else {
		ploop_err(0, "The %s process died abnormally", mes);
		err = -1;
	}

	return err;
}

int ploop_blk_discard(const char* device, __u32 blocksize, off_t start, off_t end)
{
	int ret, fd;

	start = S2B(start);
	end = S2B(end);

	if (start >= end)
		return 0;

	fd = open(device, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		ploop_err(errno, "Can't open ploop device %s",
				device);
		return SYSEXIT_OPEN;
	}

	ret = blk_discard(fd, blocksize, start, end - start);
	close(fd);

	return ret;
}

int umnt(struct ploop_disk_images_data *di, const char *dev,
		const char *mnt, int mounted)
{
	if (mounted == 2)
		return ploop_umount(dev, di);
	else if (mounted == 1)
		return do_umount(mnt, PLOOP_UMOUNT_TIMEOUT);
	return 0;
}

int get_dev_and_mnt(struct ploop_disk_images_data *di, pid_t pid,
		int automount, char *dev, int dev_len, char *mnt,
		int mnt_len, int *mounted)
{
	int ret, r;        
	struct ploop_mount_param m = {};
	char partname[64]; 
	char devname[64]; 

	r = ploop_find_dev_by_dd(di, dev, dev_len);
	if (r == -1)
		return SYSEXIT_SYS;

	if (r == 0) {
		ret = get_part_devname(di, dev, devname, sizeof(devname),
				partname, sizeof(partname));
		if (ret)
			return ret;

		ret = get_mount_dir(partname, 0, mnt, mnt_len);
		if (ret < 0)
			return SYSEXIT_SYS;
		else if (ret == 0)
			return 0;
	}

	if (!automount) {
		ploop_err(0, "Unable to discard: image is not mounted");
		return SYSEXIT_PARAM;
	}

	if (r == 0) {
		ret = auto_mount_fs(di, pid, partname, &m);
		if (ret)
			goto err;
		*mounted = 1;
	} else {
		ret = auto_mount_image(di, &m);
		if (ret)
			goto err;
		snprintf(dev, dev_len, "%s", m.device);
		*mounted = 2;
	}
	snprintf(mnt, mnt_len, "%s", m.target);

err:
	free_mount_param(&m);

	return ret;
}

int ploop_discard_by_dev(const char *device, const char *mount_point,
		__u64 minlen_b, __u64 to_free, const volatile int *stop)
{
	return ploop_trim(NULL, device, mount_point, minlen_b);
}

static void defrag_pidfile(const char *dev, char *out, int size)
{
	char *p = strrchr(dev, '/');

	snprintf(out, size, PLOOP_LOCK_DIR "/%s.defrag.pid",
			p ? ++p : dev);
}

static void defrag_complete(const char *dev)
{
	char buf[PATH_MAX];
	char cmdline[64];
	pid_t pid;
	FILE *fp;
	char *cmd;

	defrag_pidfile(dev, buf, sizeof(buf));

	fp = fopen(buf, "r");
	if (fp == NULL) {
		if (errno != ENOENT)
			ploop_err(errno, "Can't open %s", buf);
		return;
	}

	if (fscanf(fp, "%d\n", &pid) != 1) {
		ploop_err(0, "Can't read PID from %s", buf);
		fclose(fp);
		return;
	}
	fclose(fp);

	snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);
	fp = fopen(cmdline, "r");
	if (fp == NULL) {
		// no process with such pidr, possible stale file
		goto stale;
	}

	if (fscanf(fp, "%ms", &cmd) != 1) {
		// the process just gone
		fclose(fp);
		return;
	}
	fclose(fp);

	if (strcmp(BIN_E4DEFRAG, cmd) != 0) {
		// some other process that happen to reuse our pid
		free(cmd);
		goto stale;
	}
	free(cmd);

	ploop_log(0, "Cancelling defrag dev=%s pid=%d", dev, pid);
	kill(pid, SIGTERM);
	return;

stale:
	if (access(buf, F_OK))
		ploop_log(0, "Warning: stale defrag pidfile %s", buf);

	return;
}

static int create_pidfile(const char *fname, pid_t pid)
{
	FILE *fp;

	fp = fopen(fname, "w");
	if (fp == NULL) {
		ploop_err(errno, "Cant't create %s", fname);
		return -1;
	}

	fprintf(fp, "%d\n", pid);

	fclose(fp);

	return 0;
}

static int get_num_clusters(const char *dev, char *img, int size, __u32 *out)
{
	int ret = 0;
	__u32 clu, cluster;
	struct ploop_pvd_header *hdr = NULL;
	struct delta d = {};

	ret = ploop_find_top_delta_name_and_format(dev, img, size, NULL, 0);
	if (ret)
		return ret;

	ret = open_delta(&d, img, O_RDONLY|O_DIRECT, OD_ALLOW_DIRTY);
	if (ret)
		return ret;

	hdr = (struct ploop_pvd_header *) d.hdr0;
	cluster = S2B(d.blocksize);

	for (clu = 0; clu < hdr->m_Size; clu++) {
		int l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		if (d.l2_cache != l2_cluster) {
			if (PREAD(&d, d.l2, cluster, (off_t)l2_cluster * cluster)) {
				ret = SYSEXIT_READ;
				goto err;
			}
			d.l2_cache = l2_cluster;
		}

		if (d.l2[l2_slot])
			(*out)++;
	}

err:
	close_delta(&d);

	return ret;
}

static int get_num_extents(const char *img, __u32 *out)
{
	char cmd[PATH_MAX];
	FILE *fp;
	int ret, fd;
	char *p;

	fd = open(img, O_RDONLY|O_CLOEXEC);
	if (fd == -1) {
		ploop_err(0, "Failed to open %s", img);
		return SYSEXIT_SYS;
	}
	clean_es_cache(fd);
	close(fd);

	snprintf(cmd, sizeof(cmd), "LANG=C /usr/sbin/filefrag %s", img);
	fp = popen(cmd, "r");
	if (fp == NULL) {
		ploop_err(0, "Failed %s", cmd);
		return SYSEXIT_SYS;
	}

	while (fgets(cmd, sizeof(cmd), fp) != NULL);

	p = strrchr(cmd, ':');
	if (p == NULL || sscanf(p + 1, "%d extent found", out) != 1) {
		ploop_err(0, "Can not parse the filefrag output: %s", cmd);
		ret = SYSEXIT_SYS;
	}

	if (pclose(fp)) {
		ploop_err(0, "Error in pclose() for %s", cmd);
		ret = SYSEXIT_SYS;
	}

	return ret;
}

static int do_kaio_ext4_defrag(const char *dev, struct ploop_discard_param *param)
{
	int ret;
	pid_t pid;
	char file[PATH_MAX];
	char *arg[] = {BIN_E4DEFRAG, file, NULL};
	__u32 num_clusters = 0, num_extents = 0, threshold = 0;

	if (access(arg[0], F_OK))
		return 0;

	ret = get_num_clusters(dev, file, sizeof(file), &num_clusters);
	if (ret)
		return ret;

	ret = get_num_extents(file, &num_extents);
	if (ret)
		return ret;
	if (num_clusters)
		threshold = num_extents / num_clusters;
	if (threshold <= param->image_defrag_threshold)
		return 0;

	ploop_log(0, "Start defrag threshold=%d %s %s",
			threshold, arg[0], arg[1]);

	pid = fork();
	if (pid < 0) {
		ploop_err(errno, "Can't fork");
		return -1;
	} else if (pid == 0) {
		execv(arg[0], arg);

		ploop_err(errno, "Can't exec %s", arg[0]);
		_exit(1);
	}

	defrag_pidfile(dev, file, sizeof(file));
	create_pidfile(file, pid);

	ret = wait_pid(pid, arg[0], param->stop);

	unlink(file);

	return ret;
}

int ploop_discard(struct ploop_disk_images_data *di,
		struct ploop_discard_param *param)
{
	int ret;
	char dev[64];
	char mnt[PATH_MAX];
	int mounted = 0;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = get_dev_and_mnt(di, 0, param->automount, dev, sizeof(dev),
			mnt, sizeof(mnt), &mounted);
	if (ret) {
		ploop_unlock_dd(di);
		return ret;
	}

	if (!mounted) {
		ret = check_deltas_live(di, dev);
		if (ret) {
			ploop_unlock_dd(di);
			return ret;
		}
	}

	ploop_unlock_dd(di);
	ret = ploop_trim(di, dev, mnt, 0);
	if (ret)
		goto out;

	if (param->defrag)
		do_kaio_ext4_defrag(dev, param);

out:
	if (ploop_lock_dd(di) == 0) {
		if (mounted) {
			umnt(di, dev, mnt, mounted);
		} else {
			int rc = check_deltas_live(di, dev);
			if (ret == 0)
				ret = rc;
		}
		ploop_unlock_dd(di);
	}

	return ret;
}

int ploop_complete_running_operation(const char *device)
{
	return 0;
}

int ploop_get_mntn_state(int fd, int *state)
{
	int ret;
	struct ploop_balloon_ctl ctl = {
		.keep_intact = 2
	};

	ret = ioctl(fd, PLOOP_IOC_BALLOON, &ctl);
	if (ret) {
		ploop_err(errno, "Unable to get in-kernel maintenance state");
		return SYSEXIT_DEVIOC;
	}

	*state = ctl.mntn_type;

	return 0;
}

int complete_running_operation(struct ploop_disk_images_data *di,
		const char *device)
{
	defrag_complete(device);

	return 0;
}

int ploop_discard_get_stat_by_dev(const char *device, const char *mount_point,
		struct ploop_discard_stat *pd_stat)
{
	int		err;
	struct statfs	stfs;
	struct stat	st, balloon_stat;
	off_t		ploop_size;
	char		image[PATH_MAX];

	err = get_balloon(mount_point, &balloon_stat, NULL);
	if (err)
		return err;

	err = statfs(mount_point, &stfs);
	if (err == -1) {
		ploop_err(errno, "statfs(%s) failed", mount_point);
		return 1;
	}

	err = ploop_get_size(device, &ploop_size);
	if (err)
		return 1;

	err = ploop_find_top_delta_name_and_format(device, image, sizeof(image), NULL, 0);
	if (err)
		return 1;

	err = stat(image, &st);
	if (err == -1) {
		ploop_err(errno, "stat(%s) failed", image);
		return 1;
	}

	pd_stat->ploop_size = S2B(ploop_size) - balloon_stat.st_size;
	pd_stat->image_size = st.st_blocks * 512;
	pd_stat->data_size = pd_stat->ploop_size - stfs.f_bfree * stfs.f_bsize;
	pd_stat->balloon_size = balloon_stat.st_size;
	pd_stat->native_discard = 1;

	return 0;
}

int ploop_discard_get_stat(struct ploop_disk_images_data *di,
		struct ploop_discard_stat *pd_stat)
{
	int ret;
	char dev[PATH_MAX];
	char mnt[PATH_MAX];
	int mounted = 0;

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	ret = get_dev_and_mnt(di, 0, 1, dev, sizeof(dev),
			mnt, sizeof(mnt), &mounted);
	if (ret)
		goto err;

	ret = ploop_discard_get_stat_by_dev(dev, mnt, pd_stat);
	umnt(di, dev, mnt, mounted);

err:
	ploop_unlock_dd(di);
	return ret;
}
