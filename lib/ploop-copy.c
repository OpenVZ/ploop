/*
 *  Copyright (C) 2008-2014, Parallels, Inc. All rights reserved.
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
#include <limits.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <string.h>
#include <pthread.h>

#include "ploop.h"
#include "cleanup.h"

#define ploop_dbg(level, format, ...)

typedef enum {
	PCOPY_PKT_DATA,
	PCOPY_PKT_CMD,
} pcopy_pkt_type_t;

typedef enum {
	PCOPY_CMD_SYNC,
} pcopy_cmd_t;

struct pcopy_pkt_desc
{
        __u32		marker;
#define PCOPY_MARKER 0x4cc0ac3e
	pcopy_pkt_type_t type;
        __u32		size;
        __u64		pos;
};

struct sender_data {
	void *buf;
	int len;
	off_t pos;
	int ret;
	int err_no;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_mutex_t wait_mutex;
	pthread_cond_t wait_cond;
};

struct ploop_copy_handle {
	struct sender_data sd;
	struct delta idelta;
	int devfd;
	int ofd;
	int is_remote;
	int mntfd;
	void *iobuf[2];
	int cur_iobuf;
	int niter;
	int cluster;
	__u64 trackpos;
	__u64 trackend;
	int tracker_on;
	int fs_frozen;
	int raw;
	pthread_t send_th;
	struct ploop_cleanup_hook *cl;
	int cancelled;
};

/* Check what a file descriptor refers to.
 * Return:
 *  0 - file
 *  1 - socket
 * -1 - none of the above
 */
static int is_fd_socket(int fd)
{
	struct stat st;

	if (fstat(fd, &st))
		return -1;

	if (S_ISREG(st.st_mode))
		return 0;

	if (S_ISSOCK(st.st_mode))
		return 1;

	return -1;
}

static int data_sync(int fd)
{
	if (fdatasync(fd)) {
		ploop_err(errno, "Error in fdatasync()");
		return SYSEXIT_WRITE;
	}
	return 0;
}

static int nwrite(int fd, const void *buf, int len)
{
	while (len) {
		int n;

		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		len -= n;
		buf += n;
	}

	if (len == 0)
		return 0;

	errno = EIO;
	return -1;
}

static int remote_write(int fd, pcopy_pkt_type_t type,
		const void *data, int len, off_t pos)
{
	int rc;
	struct pcopy_pkt_desc desc = {
		.marker = PCOPY_MARKER,
		.type = type,
	};

	/* Header */
	desc.size = len;
	desc.pos = pos;
	if (nwrite(fd, &desc, sizeof(desc)))
		return SYSEXIT_WRITE;

	/* Data */
	if (len && nwrite(fd, data, len))
		return SYSEXIT_WRITE;

	/* get reply */
	if (read(fd, &rc, sizeof(rc)) != sizeof(rc))
		return SYSEXIT_PROTOCOL;

	return 0;
}

static int local_write(int ofd, const void *iobuf, int len, off_t pos)
{
	int n;

	if (len == 0) { /* End of transfer */
		if (fsync(ofd)) {
			ploop_err(errno, "Error in fsync");
			return SYSEXIT_WRITE;
		}
		return 0;
	}

	n = pwrite(ofd, iobuf, len, pos);
	if (n < 0)
		return SYSEXIT_WRITE;
	if (n != len) {
		errno = EIO;
		return SYSEXIT_WRITE;
	}

	return 0;
}

static int send_cmd(struct ploop_copy_handle *h, pcopy_cmd_t cmd)
{
	if (h->is_remote)
		return remote_write(h->ofd, PCOPY_PKT_CMD, &cmd, sizeof(cmd), 0);
	else
		if (cmd == PCOPY_CMD_SYNC)
			return data_sync(h->ofd);

	return 0;
}

static int nread(int fd, void * buf, int len)
{
	while (len) {
		int n;

		n = read(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		len -= n;
		buf += n;
	}

	if (len == 0)
		return 0;

	errno = EIO;
	return -1;
}

static int get_image_info(const char *device, char **send_from_p,
		char **format_p, int *blocksize)
{
	int top_level;

	if (ploop_get_attr(device, "top", &top_level)) {
		ploop_err(0, "Can't find top delta");
		return SYSEXIT_SYSFS;
	}

	if (ploop_get_attr(device, "block_size", blocksize)) {
		ploop_err(0, "Can't find block size");
		return SYSEXIT_SYSFS;
	}

	if (find_delta_names(device, top_level, top_level,
				send_from_p, format_p)) {
		ploop_err(errno, "find_delta_names");
		return SYSEXIT_SYSFS;
	}

	return 0;
}

int ploop_copy_receiver(struct ploop_copy_receive_param *arg)
{
	int ofd, ret;
	__u64 cluster = 0;
	void *iobuf = NULL;
	int n;
	struct pcopy_pkt_desc desc;

	if (!arg)
		return SYSEXIT_PARAM;

	if (is_fd_socket(arg->ifd) != 1) {
		ploop_err(errno, "Invalid input fd %d: must be "
				"a pipe or a socket", arg->ifd);
		return SYSEXIT_PARAM;
	}

	ofd = open(arg->file, O_WRONLY|O_CREAT, 0600);
	if (ofd < 0) {
		ploop_err(errno, "Can't open %s", arg->file);
		return SYSEXIT_CREAT;
	}

	ploop_dbg(4, "RCV start %s", arg->file);
	for (;;) {
		if (nread(arg->ifd, &desc, sizeof(desc)) < 0) {
			ploop_err(errno, "Error in nread(desc)");
			ret = SYSEXIT_READ;
			goto out;
		}

		if (desc.marker != PCOPY_MARKER) {
			ploop_err(0, "Stream corrupted");
			ret = SYSEXIT_PROTOCOL;
			goto out;
		}

		if (desc.size > cluster) {
			free(iobuf);
			iobuf = NULL;
			cluster = desc.size;
			if (p_memalign(&iobuf, 4096, cluster)) {
				ret = SYSEXIT_MALLOC;
				goto out;
			}
		}

		if (desc.size == 0)
			break;

		if (nread(arg->ifd, iobuf, desc.size)) {
			ploop_err(errno, "Error in nread data");
			ret = SYSEXIT_READ;
			goto out;
		}

		ploop_log(3, "RCV type=%d len=%d pos=%" PRIu64,
				desc.type, desc.size, (uint64_t)desc.pos);
		switch (desc.type) {
		case PCOPY_PKT_DATA: {
			n = pwrite(ofd, iobuf, desc.size, desc.pos);
			if (n != desc.size) {
				if (n < 0)
					ploop_err(errno, "Error in pwrite");
				else
					ploop_err(0, "Error: short pwrite");
				ret = SYSEXIT_WRITE;
				goto out;
			}
			break;
		}
		case PCOPY_PKT_CMD: {
			unsigned int cmd = ((unsigned int *) iobuf)[0];
			switch(cmd) {
			case PCOPY_CMD_SYNC:
				ret = data_sync(ofd);
				if (ret)
					goto out;
				break;
			default:
				ploop_err(0, "ploop_copy_receiver: unsupported command %d",
						cmd);
				ret = SYSEXIT_PARAM;
				goto out;
			}
			break;
		}
		default:
			ploop_err(0, "ploop_copy_receiver: unsupported command type%d",
						desc.type);
			ret = SYSEXIT_PARAM;
			goto out;
		}

		/* send reply */
		ret = 0;
		if (nwrite(arg->ifd, &ret, sizeof(int))) {
			ret = SYSEXIT_WRITE;
			ploop_err(errno, "failed to send reply");
			goto out;
		}
	}

	ret = data_sync(ofd);
	if (ret)
		goto out;

	ploop_dbg(4, "RCV exited");
	/* send final reply */
	ret = 0;
	if (nwrite(arg->ifd, &ret, sizeof(int))) {
		ret = SYSEXIT_WRITE;
		ploop_err(errno, "failed to send reply");
		goto out;
	}

out:
	if (close(ofd)) {
		ploop_err(errno, "Error in close");
		if (!ret)
			ret = SYSEXIT_WRITE;
	}
	if (ret)
		unlink(arg->file);
	free(iobuf);

	return ret;
}

static void cancel_sender(void *data)
{
	struct ploop_copy_handle *h = (struct ploop_copy_handle *)data;

	h->cancelled = 1;
}

static void wait_sender(struct ploop_copy_handle *h)
{
	pthread_mutex_lock(&h->sd.mutex);
	pthread_mutex_unlock(&h->sd.mutex);
}

static void wakeup(pthread_mutex_t *m, pthread_cond_t *c)
{
	pthread_mutex_lock(m);
	pthread_cond_signal(c);
	pthread_mutex_unlock(m);
}

static int send_buf(struct ploop_copy_handle *h, const void *iobuf, int len, off_t pos)
{
	if (h->cancelled)
		return SYSEXIT_WRITE;

	if (h->is_remote)
		return remote_write(h->ofd, PCOPY_PKT_DATA, iobuf, len, pos);
	else
		return local_write(h->ofd, iobuf, len, pos);
}

static void *sender_thread(void *data)
{
	struct ploop_copy_handle *h = data;
	struct sender_data *sd = &h->sd;
	int done;

	pthread_mutex_lock(&sd->mutex);

	do {
		pthread_cond_wait(&sd->cond, &sd->mutex);

		wakeup(&sd->wait_mutex, &sd->wait_cond);

		sd->ret = send_buf(h, sd->buf, sd->len, sd->pos);
		if (sd->ret)
			sd->err_no = errno;
		done = (sd->len == 0 && sd->pos == 0);
	} while (!done);

	pthread_mutex_unlock(&sd->mutex);

	ploop_log(3, "send_thread exited ret=%d", sd->ret);
	return NULL;
}

static int send_async(struct ploop_copy_handle *h, void *data,
		__u64 size, __u64 pos)
{
	struct sender_data *sd = &h->sd;

	pthread_mutex_lock(&sd->mutex);

	if (sd->ret) {
		ploop_err(sd->err_no, "write error");
		pthread_mutex_unlock(&sd->mutex);
		return sd->ret;
	}

	sd->buf = data;
	sd->len = size;
	sd->pos = pos;

	pthread_mutex_unlock(&sd->mutex);
	pthread_cond_signal(&sd->cond);

	/* wait till sender start processing */
	pthread_cond_wait(&sd->wait_cond, &sd->wait_mutex);

	return 0;
}

static void *get_free_iobuf(struct ploop_copy_handle *h)
{
	h->cur_iobuf = !h->cur_iobuf;
	return h->iobuf[h->cur_iobuf];
}

static int send_image_block(struct ploop_copy_handle *h, __u64 size,
		__u64 pos, ssize_t *nread)
{
	struct delta *idelta = &h->idelta;
	void *iobuf = get_free_iobuf(h);

	ploop_dbg(4, "READ size=%llu pos=%llu", size, pos);
	*nread = pread(idelta->fd, iobuf, size, pos);
	if (*nread == 0)
		return 0;
	if (*nread < 0) {
		ploop_err(errno, "Error from read");
		return SYSEXIT_READ;
	}

	return send_async(h, iobuf, *nread, pos);
}

void ploop_copy_release(struct ploop_copy_handle *h)
{
	if (h == NULL)
		return;


	if (h->fs_frozen) {
		(void)ioctl_device(h->mntfd, FITHAW, 0);
		h->fs_frozen = 0;
	}

	if (h->tracker_on) {
		(void)ioctl_device(h->devfd, PLOOP_IOC_TRACK_ABORT, 0);
		h->tracker_on = 0;
	}

	if (h->mntfd != -1) {
		close(h->mntfd);
		h->mntfd = -1;
	}

	if (h->devfd != -1) {
		close(h->devfd);
		h->devfd = -1;
	}

	if (h->idelta.fd != -1)
		close_delta(&h->idelta);
}

void free_ploop_copy_handle(struct ploop_copy_handle *h)
{
	if (h == NULL)
		return;

	pthread_mutex_destroy(&h->sd.mutex);
	pthread_cond_destroy(&h->sd.cond);
	pthread_mutex_destroy(&h->sd.wait_mutex);
	pthread_cond_destroy(&h->sd.wait_cond);

	unregister_cleanup_hook(h->cl);

	free(h->iobuf[0]);
	free(h->iobuf[1]);

	free(h);
}

static struct ploop_copy_handle *alloc_ploop_copy_handle(int cluster)
{
	struct ploop_copy_handle *h;

	h = calloc(1, sizeof(struct ploop_copy_handle));
	if (h == NULL)
		return NULL;

	pthread_mutex_init(&h->sd.mutex, NULL);
	pthread_cond_init(&h->sd.cond, NULL);
	pthread_mutex_init(&h->sd.wait_mutex, NULL);
	pthread_cond_init(&h->sd.wait_cond, NULL);

	h->devfd = h->ofd = h->mntfd = h->idelta.fd = -1;
	h->cluster = cluster;

	if (p_memalign(&h->iobuf[0], 4096, cluster))
		goto err;

	if (p_memalign(&h->iobuf[1], 4096, cluster))
		goto err;

	return h;
err:
	free_ploop_copy_handle(h);
	return NULL;
}


int ploop_copy_init(struct ploop_disk_images_data *di,
		struct ploop_copy_param *param,
		struct ploop_copy_handle **h)
{
	int ret, err;
	int blocksize;
	char *image = NULL;
	char *format = NULL;
	char device[64];
	struct ploop_copy_handle  *_h = NULL;
	int is_remote;
	char mnt[PATH_MAX];

	is_remote = is_fd_socket(param->ofd);
	if (is_remote < 0) {
		ploop_err(0, "Invalid output fd %d: must be a file, "
				"a pipe or a socket", param->ofd);
		return SYSEXIT_PARAM;
	}

	if (param->ofd == STDOUT_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOSTDOUT);
	else if (param->ofd == STDERR_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOCONSOLE);

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	if (ploop_find_dev_by_dd(di, device, sizeof(device))) {
		ploop_err(0, "Can't find running ploop device");
		ret = SYSEXIT_SYS;
		goto err;
	}

	ret = get_image_info(device, &image, &format, &blocksize);
	if (ret)
		goto err;

	ploop_log(0, "Send image %s device=%s fmt=%s blocksize=%d local=%d",
			image, device, format, blocksize, !is_remote);

	_h = alloc_ploop_copy_handle(S2B(blocksize));
	if (_h == NULL) {
		ploop_err(0, "alloc_ploop_copy_handle");
		ret = SYSEXIT_MALLOC;
		goto err;
	}

	_h->raw = strcmp(format, "raw") == 0;
	_h->ofd = param->ofd;
	_h->is_remote = is_remote;

	_h->devfd = open(device, O_RDONLY);
	if (_h->devfd == -1) {
		ploop_err(errno, "Can't open device %s", device);
		ret = SYSEXIT_DEVICE;
		goto err;
	}
	fcntl(_h->devfd, F_SETFD, FD_CLOEXEC);

	ret = SYSEXIT_OPEN;
	err = ploop_get_mnt_by_dev(device, mnt, sizeof(mnt));
	if (err == -1)
		goto err;
	else if (ret == 0) {
		_h->mntfd = open(mnt, O_RDONLY);
		if (_h->mntfd < 0) {
			ploop_err(errno, "Can't open %s", mnt);
			goto err;
		}
	}

	if (open_delta_simple(&_h->idelta, image, O_RDONLY|O_DIRECT, OD_NOFLAGS)) {
		ret = SYSEXIT_OPEN;
		goto err;
	}

	ret = complete_running_operation(di, device);
	if (ret)
		goto err;

	_h->cl = register_cleanup_hook(cancel_sender, _h);

	pthread_mutex_lock(&_h->sd.wait_mutex);
err:
	if (ret) {
		ploop_copy_release(_h);
		free_ploop_copy_handle(_h);
	} else
		*h = _h;

	free(image);
	ploop_unlock_dd(di);

	return ret;
}

int ploop_copy_start(struct ploop_copy_handle *h,
		struct ploop_copy_stat *stat)
{
	int ret;
	struct ploop_track_extent e;
	ssize_t n;
	__u64 pos;

	ret = pthread_create(&h->send_th, NULL, sender_thread, h);
	if (ret) {
		ploop_err(ret, "Can't create send thread");
		ret = SYSEXIT_SYS;
		goto err;
	}

	ploop_dbg(4, "pcopy track init");
	ret = ioctl_device(h->devfd, PLOOP_IOC_TRACK_INIT, &e);
	if (ret)
		goto err;

	h->tracker_on = 1;
	h->trackend = e.end;
	ploop_log(3, "pcopy start e.end=%" PRIu64, (uint64_t)e.end);
	for (pos = 0; pos <= h->trackend; ) {
		h->trackpos = pos + h->cluster;
		ret = ioctl_device(h->devfd, PLOOP_IOC_TRACK_SETPOS, &h->trackpos);
		if (ret)
			goto err;

		ret = send_image_block(h, h->cluster, pos, &n);
		if (ret)
			goto err;
		if (n == 0) /* EOF */
			break;

		pos += n;
	}

	wait_sender(h);

	stat->xferred_total = stat->xferred = pos;

	ploop_dbg(3, "pcopy start finished");

	return 0;
err:
	ploop_copy_release(h);

	return ret;
}

int ploop_copy_next_iteration(struct ploop_copy_handle *h,
		struct ploop_copy_stat *stat)
{
	struct ploop_track_extent e;
	int ret = 0;
	int done = 0;
	__u64 pos;
	__u64 iterpos = 0;

	stat->xferred = 0;
	ploop_dbg(3, "pcopy iter %d", h->niter);
	do {
		if (ioctl(h->devfd, PLOOP_IOC_TRACK_READ, &e)) {
			if (errno == EAGAIN) /* no more dirty blocks */
				break;

			ploop_err(errno, "PLOOP_IOC_TRACK_READ");
			ret = SYSEXIT_DEVIOC;
			goto err;
		}

		if (e.end > h->trackend)
			h->trackend = e.end;

		if (e.start < iterpos)
			done = 1;

		iterpos = e.end;
		stat->xferred += e.end - e.start;

		for (pos = e.start; pos < e.end; ) {
			ssize_t n;
			int copy = e.end - pos;

			if (copy > h->cluster)
				copy = h->cluster;

			if (pos + copy > h->trackpos) {
				h->trackpos = pos + copy;
				if (ioctl(h->devfd, PLOOP_IOC_TRACK_SETPOS, &h->trackpos)) {
					ploop_err(errno, "PLOOP_IOC_TRACK_SETPOS");
					ret = SYSEXIT_DEVIOC;
					goto err;
				}
			}

			ret = send_image_block(h, copy, pos, &n);
			if (ret)
				goto err;
			if (n != copy) {
				ploop_err(errno, "Short read");
				ret = SYSEXIT_READ;
				goto err;
			}

			pos += n;
		}
	} while (!done);

	wait_sender(h);

	/* sync after each iteration */
	ret = send_cmd(h, PCOPY_CMD_SYNC);
	if (ret)
		goto err;

	stat->xferred_total += stat->xferred;

	ploop_log(3, "pcopy iter %d xferred=%" PRIu64,
			h->niter++, (uint64_t)stat->xferred);

	return 0;

err:
	ploop_copy_release(h);
	return ret;
}

static int freeze_fs(struct ploop_copy_handle *h)
{
	int ret;

	if (h->mntfd != -1) {
		/* Sync fs */
		ploop_dbg(4, "SYNCFS");
		if (sys_syncfs(h->mntfd)) {
			ploop_err(errno, "syncfs() failed");
			ret = SYSEXIT_FSYNC;
			goto err;
		}

		/* Flush journal and freeze fs (this also clears the fs dirty bit) */
		ploop_dbg(4, "FIFREEZE");
		ret = ioctl_device(h->mntfd, FIFREEZE, 0);
		if (ret)
			goto err;

		h->fs_frozen = 1;
	}

	ploop_dbg(4, "IOC_SYNC");
	ret = ioctl_device(h->devfd, PLOOP_IOC_SYNC, 0);
	if (ret)
		goto err;

	return 0;
err:
	ploop_copy_release(h);
	return ret;
}

int ploop_copy_stop(struct ploop_copy_handle *h)
{
	int ret;
	struct ploop_copy_stat stat = {};
	int iter;

	ploop_log(3, "pcopy last");

	ret = freeze_fs(h);
	if (ret)
		goto err;

	iter = 1;
	for (;;) {
		ret = ploop_copy_next_iteration(h, &stat);
		if (ret)
			goto err;
		else if (stat.xferred == 0)
			break;
		if (iter++ > 2) {
			ploop_err(0, "Too many iterations on frozen FS, aborting");
			return SYSEXIT_LOOP;
		}
	}

	/* Must clear dirty flag on ploop1 image. */
	if (!h->raw) {
		struct ploop_pvd_header *vh = get_free_iobuf(h);

		if (PREAD(&h->idelta, vh, 4096, 0)) {
			ret = SYSEXIT_READ;
			goto err;
		}

		vh->m_DiskInUse = 0;

		ploop_dbg(4, "Update header");

		ret = send_buf(h, vh, 4096, 0);
		if (ret)
			goto err;
	}

	ploop_dbg(4, "IOCTL TRACK_STOP");
	ret = ioctl(h->devfd, PLOOP_IOC_TRACK_STOP, 0);
	if (ret)
		goto err;

	h->tracker_on = 0;

	ploop_dbg(4, "SEND 0 0 (close)");
	send_async(h, NULL, 0, 0);

	pthread_join(h->send_th, NULL);
	h->send_th = 0;

	ploop_dbg(4, "pcopy stop done");

err:
	ploop_copy_release(h);

	return ret;
}


void ploop_copy_deinit(struct ploop_copy_handle *h)
{
	if (h == NULL)
		return;

	ploop_dbg(4, "pcopy deinit");

	pthread_mutex_unlock(&h->sd.wait_mutex);

	if (h->send_th) {
		pthread_cancel(h->send_th);
		pthread_join(h->send_th, NULL);
		h->send_th = 0;
	}

	ploop_copy_release(h);
	free_ploop_copy_handle(h);

	ploop_dbg(4, "pcopy deinit done");
}
