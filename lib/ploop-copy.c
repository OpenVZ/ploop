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
#include <limits.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <string.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <sys/queue.h>

#include "ploop.h"
#include "cleanup.h"
#include "cbt.h"

#define ploop_dbg(level, format, args...) ploop_log(level, format, ##args)

typedef enum {
	PCOPY_PKT_DATA,
	PCOPY_PKT_CMD,
	PCOPY_PKT_DATA_ASYNC,
} pcopy_pkt_type_t;

typedef enum {
	PCOPY_CMD_SYNC,
	PCOPY_CMD_FINISH,
} pcopy_cmd_t;

#define PCOPY_FEATURE_MD5SUM	0x01
#define PCOPY_SUP_FLAGS		PCOPY_FEATURE_MD5SUM

struct pcopy_pkt_desc
{
        __u32		marker;
#define PCOPY_MARKER 0x4cc0ac3e
	pcopy_pkt_type_t type;
        __u32		size;
        __u64		pos;
};

struct pcopy_pkt_desc_md5
{
	__u8            md5[16];
};

struct chunk {
	TAILQ_ENTRY(chunk) list;
	size_t size;
	void *data;
	off_t pos;
};

struct sender_data {
	TAILQ_HEAD(, chunk) queue;
	int queue_size;
	int ret;
	int err_no;
	pthread_mutex_t queue_mutex;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_mutex_t wait_mutex;
	pthread_cond_t wait_cond;
};

enum {
	PLOOP_COPY_START,
	PLOOP_COPY_ITER,
	PLOOP_COPY_FINISH,
};

struct ploop_copy_handle {
	struct sender_data sd;
	struct delta idelta;
	int devfd;
	int partfd;
	int ofd;
	int is_remote;
	int mntfd;
	int niter;
	int cluster;
	__u64 trackpos;
	__u64 trackend;
	int tracker_on;
	int fs_frozen;
	int dev_frozen;
	int raw;
	pthread_t send_th;
	struct ploop_cleanup_hook *cl;
	int cancelled;
	off_t eof_offset;
	int async;
	int stage;
	int remote_flags;
};

static struct chunk *alloc_chunk(size_t size, off_t pos)
{
	struct chunk *c;

	c = calloc(1, sizeof(struct chunk));
	if (c == NULL)
		return NULL;

	if (size != 0 && p_memalign(&c->data, 4096, size))
		goto err;

	c->pos = pos;
	c->size = size;

	return c;
err:
	ploop_err(ENOMEM, "Can not create chunk");
	free(c);
	return NULL;
}

static void free_chunk(struct chunk *chunk)
{
	if (chunk == NULL)
		return;
	free(chunk->data);
	free(chunk);
}

static struct chunk *q_get_first(struct sender_data *sd)
{
	struct chunk *c;

	pthread_mutex_lock(&sd->queue_mutex);
	if (TAILQ_EMPTY(&sd->queue)) {
		pthread_mutex_unlock(&sd->queue_mutex);
		return NULL;
	}
	c = TAILQ_FIRST(&sd->queue);
	pthread_mutex_unlock(&sd->queue_mutex);

	return c;
}

static void enqueue(struct sender_data *sd, struct chunk *chunk)
{
	pthread_mutex_lock(&sd->queue_mutex);
	TAILQ_INSERT_TAIL(&sd->queue, chunk, list);
	sd->queue_size++;
	pthread_mutex_unlock(&sd->queue_mutex);
}

static void dequeue(struct sender_data *sd, struct chunk *c)
{
	pthread_mutex_lock(&sd->queue_mutex);
	TAILQ_REMOVE(&sd->queue, c, list);
	sd->queue_size--;
	pthread_mutex_unlock(&sd->queue_mutex);
	free_chunk(c);
}

static int q_get_size(struct sender_data *sd)
{
	return sd->queue_size;
}

static int wait_sender(struct ploop_copy_handle *h)
{
	pthread_mutex_lock(&h->sd.wait_mutex);
	while ((q_get_size(&h->sd) > 0 && h->sd.ret == 0)) {
		pthread_cond_wait(&h->sd.wait_cond, &h->sd.wait_mutex);
	}
	pthread_mutex_unlock(&h->sd.wait_mutex);

	return h->sd.ret;
}

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
			ploop_err(errno, "Cannot write");
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

static const char *md52str(__u8 *m, char *buf)
{
	sprintf(buf, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]);
	return buf;
}

static int remote_write(struct ploop_copy_handle *h, pcopy_pkt_type_t type,
		const void *data, int len, off_t pos)
{
	int rc;
	struct pcopy_pkt_desc desc = {
		.marker = PCOPY_MARKER,
		.type = type,
		.size = len,
		.pos = pos,
	};

	/* Header */
	if (nwrite(h->ofd, &desc, sizeof(desc)))
		return SYSEXIT_WRITE;

	if (h->remote_flags & PCOPY_FEATURE_MD5SUM) {
		char s[34];
		struct pcopy_pkt_desc_md5 m;

		MD5(data, len, m.md5);
		ploop_log(3, "SEND type: %d size=%d pos: %lu md5: %s",
				desc.type, len, pos, md52str(m.md5, s));
		if (nwrite(h->ofd, &m, sizeof(m)))
			return SYSEXIT_WRITE;
	}

	/* Data */
	if (len && nwrite(h->ofd, data, len))
		return SYSEXIT_WRITE;

	/* get reply */
	if (type != PCOPY_PKT_DATA_ASYNC) {
		rc = TEMP_FAILURE_RETRY(read(h->ofd, &rc, sizeof(rc)));
		if (rc != sizeof(rc))
			return SYSEXIT_PROTOCOL;
	}

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

	n = TEMP_FAILURE_RETRY(pwrite(ofd, iobuf, len, pos));
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
	int ret;
	size_t size = cmd == PCOPY_CMD_FINISH ? 0 : sizeof(cmd);

	ret = wait_sender(h);
	if (ret)
		return ret;

	if (h->is_remote)
		return remote_write(h, PCOPY_PKT_CMD, &cmd, size, 0);
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

static int check_data(void *buf, struct pcopy_pkt_desc *desc,
		struct pcopy_pkt_desc_md5 *md5)
{
	__u8 m[16];
	char s[34];
	char d[34];

	MD5(buf, desc->size, m);
	if (memcmp(md5->md5, m, sizeof(m))) {
		ploop_err(0, "MD5 mismatch pos: %llu src: %s dst: %s",
				desc->pos, md52str(md5->md5, s), md52str(m, d));
		return SYSEXIT_WRITE;
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
	struct pcopy_pkt_desc_md5 md5;
	int remote_flags = 0;

	if (!arg)
		return SYSEXIT_PARAM;

	if (is_fd_socket(arg->ifd) != 1) {
		ploop_err(errno, "Invalid input fd %d: must be "
				"a pipe or a socket", arg->ifd);
		return SYSEXIT_PARAM;
	}

	ofd = open(arg->file, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (ofd < 0) {
		ploop_err(errno, "Can't open %s", arg->file);
		return SYSEXIT_CREAT;
	}

	ploop_dbg(3, "RCV start %s", arg->file);
	for (;;) {
		if (nread(arg->ifd, &desc, sizeof(desc)) < 0) {
			ploop_err(errno, "Error in nread(desc)");
			ret = SYSEXIT_READ;
			goto out;
		}

		if (desc.marker != PCOPY_MARKER) {
			ploop_err(0, "Stream corrupted: marker: %x type: %d size: %d pos: %llu",
				desc.marker, desc.type, desc.size, desc.pos);
			ret = SYSEXIT_PROTOCOL;
			goto out;
		}

		if (remote_flags & PCOPY_FEATURE_MD5SUM) {
			if (nread(arg->ifd, &md5, sizeof(md5))) {
				ploop_err(errno, "Error in nread(md5)");
				ret = SYSEXIT_READ;
				goto out;
			}
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
		ret = 0;
		switch (desc.type) {
		case PCOPY_PKT_DATA:
		case PCOPY_PKT_DATA_ASYNC: {
			if (remote_flags & PCOPY_FEATURE_MD5SUM) {
				ret = check_data(iobuf, &desc, &md5);
				if (ret)
					goto out;
			}
			n = TEMP_FAILURE_RETRY(pwrite(ofd, iobuf, desc.size, desc.pos));
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
				if (desc.pos != 0) {
					remote_flags = desc.pos;
					ploop_log(0, "handshake remote flags %x", remote_flags);
					ret = -PCOPY_SUP_FLAGS;
				} else {
					ret = fsync_safe(ofd);
					if (ret)
						goto out;
				}
				break;
			default:
				ploop_err(0, "ploop_copy_receiver: unsupported command %d",
						cmd);
				ret = SYSEXIT_PARAM;
			}
			break;
		}
		default:
			ploop_err(0, "ploop_copy_receiver: unsupported command type%d",
						desc.type);
			ret = SYSEXIT_PARAM;
			break;
		}

		/* send reply */
		if (desc.type != PCOPY_PKT_DATA_ASYNC &&
				nwrite(arg->ifd, &ret, sizeof(int))) {
			ret = SYSEXIT_WRITE;
			ploop_err(errno, "failed to send reply");
			goto out;
		}
	}

	ret = fsync_safe(ofd);
	if (ret)
		goto out;

	ploop_dbg(3, "RCV exited");
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

	ploop_dbg(3, "ploop_copy_receiver rc: %d", ret);
	return ret;
}

static void cancel_sender(void *data)
{
	struct ploop_copy_handle *h = (struct ploop_copy_handle *)data;

	h->cancelled = 1;
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
		return remote_write(h, h->async ? PCOPY_PKT_DATA_ASYNC : PCOPY_PKT_DATA, iobuf, len, pos);
	else
		return local_write(h->ofd, iobuf, len, pos);
}

static void *sender_thread(void *data)
{
	struct ploop_copy_handle *h = data;
	struct sender_data *sd = &h->sd;
	struct chunk *c;
	int ret;

	ploop_dbg(3, "start sender_thread");
	do {
		pthread_mutex_lock(&sd->mutex);
		c = q_get_first(sd);
		if (c == NULL) {
			pthread_cond_wait(&sd->cond, &sd->mutex);
			pthread_mutex_unlock(&sd->mutex);
			continue;
		}
		pthread_mutex_unlock(&sd->mutex);

		ret = send_buf(h, c->data, c->size, c->pos);
		if (ret) {
			sd->ret = ret;
			sd->err_no = errno;
		}
		dequeue(sd, c);
		wakeup(&sd->wait_mutex, &sd->wait_cond);
	} while (h->stage != PLOOP_COPY_FINISH);

	wakeup(&sd->wait_mutex, &sd->wait_cond);
	ploop_log(3, "send_thread exited ret=%d", sd->ret);
	return NULL;
}

static int send_async(struct ploop_copy_handle *h, struct chunk *chunk)
{
	struct sender_data *sd = &h->sd;

	if (sd->ret) {
		ploop_err(sd->err_no, "write error");
		free_chunk(chunk);
		return sd->ret;
	}

	if (q_get_size(sd) > 2)
		wait_sender(h);

	pthread_mutex_lock(&sd->mutex);
	enqueue(sd, chunk);
	pthread_cond_signal(&sd->cond);
	pthread_mutex_unlock(&sd->mutex);

	return 0;
}

static int is_zero_block(void *buf, __u64 size)
{
	return *(__u64 *)buf == 0 &&
		!memcmp(buf, buf + sizeof(__u64), size - sizeof(__u64));
}

static int send_image_block(struct ploop_copy_handle *h, __u64 size,
		__u64 pos, ssize_t *nread)
{
	int ret = 0;
	struct delta *idelta = &h->idelta;
	struct chunk *c;

	if (h->sd.ret) {
		ploop_err(h->sd.err_no, "write error");
		return h->sd.ret;
	}

	c = alloc_chunk(size, pos);
	if (c == NULL) {
		return SYSEXIT_MALLOC;
	}

	ploop_dbg(4, "READ size=%llu pos=%llu", size, pos);
	*nread = TEMP_FAILURE_RETRY(pread(idelta->fd, c->data, c->size, c->pos));
	if (*nread == 0)
		goto out;
	if (*nread < 0) {
		ploop_err(errno, "Error from pread() size=%llu pos=%llu",
				 size, pos);
		ret = SYSEXIT_READ;
		goto out;
	}
	c->size = *nread;

	if (h->stage == PLOOP_COPY_START &&
			(pos % (__u64)h->cluster) == 0 && (c->size % (size_t)h->cluster) == 0 &&
			is_zero_block(c->data, c->size)) {
		ploop_dbg(4, "Skip zero cluster block at offset %llu size %lu",
				pos, c->size);
		goto out;
	}

	return send_async(h, c);
out:
	free_chunk(c);
	return ret;
}

void ploop_copy_release(struct ploop_copy_handle *h)
{
	if (h == NULL)
		return;

	if (h->dev_frozen) {
		if (ioctl_device(h->partfd, PLOOP_IOC_THAW, 0))
			ploop_err(errno, "Failed to PLOOP_IOC_THAW");
		h->dev_frozen = 0;
	}

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

	if (h->partfd != -1) {
		close(h->partfd);
		h->partfd = -1;
	}

	if (h->idelta.fd != -1)
		close_delta(&h->idelta);
}

void free_ploop_copy_handle(struct ploop_copy_handle *h)
{
	if (h == NULL)
		return;

	pthread_mutex_destroy(&h->sd.queue_mutex);
	pthread_mutex_destroy(&h->sd.mutex);
	pthread_cond_destroy(&h->sd.cond);
	pthread_mutex_destroy(&h->sd.wait_mutex);
	pthread_cond_destroy(&h->sd.wait_cond);

	unregister_cleanup_hook(h->cl);

	free(h);
}

static struct ploop_copy_handle *alloc_ploop_copy_handle(int cluster)
{
	struct ploop_copy_handle *h;

	h = calloc(1, sizeof(struct ploop_copy_handle));
	if (h == NULL)
		return NULL;

	TAILQ_INIT(&h->sd.queue);
	pthread_mutex_init(&h->sd.queue_mutex, NULL);
	pthread_mutex_init(&h->sd.mutex, NULL);
	pthread_cond_init(&h->sd.cond, NULL);
	pthread_mutex_init(&h->sd.wait_mutex, NULL);
	pthread_cond_init(&h->sd.wait_cond, NULL);

	h->devfd = h->ofd = h->mntfd = h->idelta.fd = -1;
	h->cluster = cluster;

	return h;
}

static int handshake(struct ploop_copy_handle *h)
{
       int rc, f;
       int cmd = PCOPY_CMD_SYNC;
       struct pcopy_pkt_desc desc = {
               .marker = PCOPY_MARKER,
               .type = PCOPY_PKT_CMD,
               .size = sizeof(cmd),
               .pos = PCOPY_SUP_FLAGS,
       };

       ploop_log(0, "handshake");
       if (!h->is_remote) {
	       h->remote_flags = PCOPY_SUP_FLAGS;
	       return 0;
       }

       /* Header */
       if (nwrite(h->ofd, &desc, sizeof(desc)))
	       return SYSEXIT_WRITE;
       if (nwrite(h->ofd, &cmd, sizeof(cmd)))
	       return SYSEXIT_WRITE;

       /* get reply */
       rc = TEMP_FAILURE_RETRY(read(h->ofd, &f, sizeof(f)));
       if (rc != sizeof(rc)) {
	       ploop_err(errno, "handshake read()");
	       return SYSEXIT_PROTOCOL;
       }

       if (f > 0) {
	       ploop_err(0, "handshake failed: rc=%d", f);
	       return SYSEXIT_PROTOCOL;
       }

       h->remote_flags = -f;
       ploop_log(0, "remote proto ver: %x", h->remote_flags);

       return 0;
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
	char partdev[64];
	struct ploop_copy_handle  *_h = NULL;
	int is_remote;
	char mnt[PATH_MAX] = "";

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


	_h = alloc_ploop_copy_handle(S2B(blocksize));
	if (_h == NULL) {
		ploop_err(0, "alloc_ploop_copy_handle");
		ret = SYSEXIT_MALLOC;
		goto err;
	}

	_h->raw = strcmp(format, "raw") == 0;
	_h->ofd = param->ofd;
	_h->is_remote = is_remote;
	_h->async = param->async;

	_h->devfd = open(device, O_RDONLY|O_CLOEXEC);
	if (_h->devfd == -1) {
		ploop_err(errno, "Can't open device %s", device);
		ret = SYSEXIT_DEVICE;
		goto err;
	}

	ret = get_partition_device_name(device, partdev, sizeof(partdev));
	if (ret)
		goto err;

	_h->partfd = open(partdev, O_RDONLY|O_CLOEXEC);
	if (_h->partfd == -1) {
		ploop_err(errno, "Can't open device %s", partdev);
		ret = SYSEXIT_DEVICE;
		goto err;
	}

	ret = SYSEXIT_OPEN;
	err = ploop_get_mnt_by_dev(device, mnt, sizeof(mnt));
	if (err == -1)
		goto err;
	else if (err == 0) {
		_h->mntfd = open(mnt, O_RDONLY|O_NONBLOCK|O_DIRECTORY);
		if (_h->mntfd < 0) {
			ploop_err(errno, "Can't open %s", mnt);
			goto err;
		}
	}

	ploop_log(0, "Send image %s dev=%s mnt=%s fmt=%s blocksize=%d local=%d",
			image, device, mnt, format, blocksize, !is_remote);

	if (open_delta(&_h->idelta, image, O_RDONLY|O_DIRECT, OD_ALLOW_DIRTY)) {
		ret = SYSEXIT_OPEN;
		goto err;
	}

	ret = complete_running_operation(di, device);
	if (ret)
		goto err;

	_h->cl = register_cleanup_hook(cancel_sender, _h);

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

	ret = handshake(h);
	if (ret)
		goto err;

	h->stage = PLOOP_COPY_START;
	ret = pthread_create(&h->send_th, NULL, sender_thread, h);
	if (ret) {
		ploop_err(ret, "Can't create send thread");
		ret = SYSEXIT_SYS;
		goto err;
	}

	ploop_dbg(3, "pcopy track init");
	ret = ioctl_device(h->devfd, PLOOP_IOC_TRACK_INIT, &e);
	if (ret)
		goto err;

	h->tracker_on = 1;
	h->trackend = e.end;
	ploop_log(3, "pcopy start %s e.end=%" PRIu64,
			h->async ? "async" : "", (uint64_t)e.end);
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
		if (pos > h->eof_offset)
			h->eof_offset = pos;
	}

	stat->xferred_total = stat->xferred = pos;
	ret = send_cmd(h, PCOPY_CMD_SYNC);
	if (ret)
		goto err;
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

	h->stage = PLOOP_COPY_ITER;
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
			__u64 copy = e.end - pos;

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
			if (pos > h->eof_offset)
				h->eof_offset = pos;
		}
	} while (!done);

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
		ploop_log(0, "Freezing fs...");
		if (sys_syncfs(h->mntfd)) {
			ploop_err(errno, "syncfs() failed");
			return SYSEXIT_FSYNC;
		}

		/* Flush journal and freeze fs (this also clears the fs dirty bit) */
		ploop_dbg(3, "FIFREEZE");
		ret = ioctl_device(h->mntfd, FIFREEZE, 0);
		if (ret)
			return ret;

		h->fs_frozen = 1;
	}

	return 0;
}

static int freeze(struct ploop_copy_handle *h)
{
	int ret;

	ret = ioctl(h->partfd, PLOOP_IOC_FREEZE);
	if (ret) {
		if (errno == EINVAL)
			ret = freeze_fs(h);
		else
			ploop_err(errno, "Failed to freeze device");
		if (ret)
			goto err;

	} else {
		ploop_log(0, "Freezing device...");
		h->dev_frozen = 1;
	}

	ploop_dbg(3, "IOC_SYNC");
	ret = ioctl_device(h->devfd, PLOOP_IOC_SYNC, 0);
	if (ret)
		goto err;

	return 0;
err:
	ploop_copy_release(h);
	return ret;
}

static int cbt_writer(void *data, const void *buf, int len, off_t pos)
{
	struct ploop_copy_handle *h = (struct ploop_copy_handle *)data;

	h->eof_offset += len;

	return send_buf(h, buf, len, pos);
}

static int send_optional_header(struct ploop_copy_handle *copy_h)
{
	int ret;
	struct ploop_pvd_header *vh;
	size_t block_size;
	struct ploop_pvd_ext_block_check *hc;
	struct ploop_pvd_ext_block_element_header *h;
	__u8 *block = NULL, *data;

	vh = (struct ploop_pvd_header *)copy_h->idelta.hdr0;
	block_size = vh->m_Sectors * SECTOR_SIZE;
	if (p_memalign((void **)&block, 4096, block_size))
		return SYSEXIT_MALLOC;

	hc = (struct ploop_pvd_ext_block_check *)block;
	h = (struct ploop_pvd_ext_block_element_header *)(hc + 1);
	data = (__u8 *)(h + 1);
	h->magic = EXT_MAGIC_DIRTY_BITMAP;

	ret = save_dirty_bitmap(copy_h->devfd, &copy_h->idelta,
			copy_h->eof_offset, data, &h->size,
			NULL, cbt_writer, copy_h);
	if (ret) {
		if (ret == SYSEXIT_NOCBT)
			ret = 0;
		goto out;
	}

	vh->m_DiskInUse = SIGNATURE_DISK_CLOSED_V21;
	vh->m_FormatExtensionOffset = (copy_h->eof_offset + SECTOR_SIZE - 1) / SECTOR_SIZE;
	if (send_buf(copy_h, vh, sizeof(*vh), 0)) {
		ploop_err(errno, "Can't write header");
		ret = SYSEXIT_WRITE;
		goto out;
	}
	ploop_log(3, "Send extension header offset=%llu size=%d",
			vh->m_FormatExtensionOffset * SECTOR_SIZE, h->size);
	hc->m_Magic = FORMAT_EXTENSION_MAGIC;
	MD5((const unsigned char *)(hc + 1), block_size - sizeof(*hc), hc->m_Md5);

	if (send_buf(copy_h, block, block_size, vh->m_FormatExtensionOffset * SECTOR_SIZE)) {
		ploop_err(errno, "Can't write optional header");
		ret = SYSEXIT_WRITE;
		goto out;
	}

out:
	free(block);

	return ret;
}

int ploop_copy_stop(struct ploop_copy_handle *h,
		struct ploop_copy_stat *stat)
{
	int ret;
	int iter;
	void *buf = NULL;

	ploop_log(3, "pcopy last");

	ret = freeze(h);
	if (ret)
		goto err;

	iter = 1;
	for (;;) {
		ret = ploop_copy_next_iteration(h, stat);
		if (ret)
			goto err;
		else if (stat->xferred == 0)
			break;
		if (iter++ > 2) {
			ploop_err(0, "Too many iterations on frozen FS, aborting");
			return SYSEXIT_LOOP;
		}
	}

	if (!h->raw) {
		/* Must clear dirty flag on ploop1 image. */
		struct ploop_pvd_header *vh;

		if (p_memalign(&buf, 4096, 4096)) {
			ret = SYSEXIT_MALLOC;
	               	goto err;
		}

		if (PREAD(&h->idelta, buf, 4096, 0)) {
			ret = SYSEXIT_READ;
			goto err;
		}

		vh = (struct ploop_pvd_header *)buf;
		vh->m_DiskInUse = 0;

		ploop_dbg(3, "Update header");

		ret = send_buf(h, vh, 4096, 0);
		if (ret)
			goto err;

		ret = send_optional_header(h);
		if (ret)
			goto err;
	}

	ploop_dbg(4, "IOCTL TRACK_STOP");
	ret = ioctl(h->devfd, PLOOP_IOC_TRACK_STOP, 0);
	if (ret)
		goto err;

	h->tracker_on = 0;

	send_cmd(h, PCOPY_CMD_FINISH);
	h->stage = PLOOP_COPY_FINISH;
	wakeup(&h->sd.mutex, &h->sd.cond);

	pthread_join(h->send_th, NULL);
	h->send_th = 0;

	ploop_dbg(3, "pcopy stop done");

err:
	free(buf);
	ploop_copy_release(h);

	return ret;
}

void ploop_copy_deinit(struct ploop_copy_handle *h)
{
	struct chunk *c;

	if (h == NULL)
		return;

	ploop_dbg(4, "pcopy deinit");
	while ((c = q_get_first(&h->sd)))
		dequeue(&h->sd, c);

	if (h->send_th) {
		pthread_cancel(h->send_th);
		pthread_join(h->send_th, NULL);
		h->send_th = 0;
	}

	ploop_copy_release(h);
	free_ploop_copy_handle(h);

	ploop_dbg(3, "pcopy deinit done");
}
