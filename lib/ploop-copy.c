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
#include <sys/queue.h>

#include "ploop.h"
#include "cleanup.h"
#include "cbt.h"
#include "bit_ops.h"

#define TG_NAME	"tracking"
#define ploop_dbg(level, format, args...) ploop_log(level, format, ##args)

typedef enum {
	PCOPY_PKT_DATA,
	PCOPY_PKT_CMD,
	PCOPY_PKT_DATA_ASYNC,
	PCOPY_PKT_DATA_DEVICE,
} pcopy_pkt_type_t;

typedef enum {
	PCOPY_CMD_SYNC,
	PCOPY_CMD_FINISH,
	PCOPY_CMD_INIT_PLOOP,
	PCOPY_CMD_INIT_QCOW,
	PCOPY_CMD_MOUNT,
	PCOPY_CMD_UMOUNT,
} pcopy_cmd_t;

#define PCOPY_FEATURE_MD5SUM	0x01
#define PCOPY_FEATURE_COPY_DEVICE	0x02
#define PCOPY_SUP_FLAGS		PCOPY_FEATURE_MD5SUM|PCOPY_FEATURE_COPY_DEVICE

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
	int type;
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
	char devname[64];
	char devploop[64];
	char part[64];
	int devfd;
	int devploopfd; 
	int ofd;
	int qcowfd;
	int is_remote;
	int niter;
	int cluster;
	__u64 trackpos;
	__u64 trackend;
	int tracker_on;
	int dev_frozen;
	int raw;
	pthread_t send_th;
	struct ploop_cleanup_hook *cl;
	int cancelled;
	off_t eof_offset;
	int async;
	int stage;
	int remote_flags;
	struct ploop_tg_data tg;
	int image_fmt;
	off_t size;
	char *image;
};

struct ploop_receiver_data {
	const char *file;
	int ifd;
	int ofd;
	int devfd;
	void *iobuf;
	char device[64];
	int remote_flags;
};

static struct chunk *alloc_chunk(int type, size_t size, off_t pos)
{
	struct chunk *c;

	c = calloc(1, sizeof(struct chunk));
	if (c == NULL)
		return NULL;

	if (size != 0 && p_memalign(&c->data, 4096, size))
		goto err;
	c->type = type;
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
	int rc, n;
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

		md5sum(data, len, m.md5);
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
		n = TEMP_FAILURE_RETRY(read(h->ofd, &rc, sizeof(rc)));
		if (n != sizeof(rc))
			return SYSEXIT_PROTOCOL;
		if (type == PCOPY_PKT_CMD && rc != 0) {
			ploop_err(0, "Command %d exited with error %d", *(int*) data, rc);
			return rc;
		}
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

static int send_cmd_ex(struct ploop_copy_handle *h, pcopy_cmd_t cmd, __u32 size, off_t off)
{
	int ret;

	ret = wait_sender(h);
	if (ret)
		return ret;
	ploop_log(3, "pcopy: send cmd %d", cmd);
	if (h->is_remote)
		return remote_write(h, PCOPY_PKT_CMD, &cmd, size, off);
	else
		if (cmd == PCOPY_CMD_SYNC)
			return data_sync(h->ofd);

	return 0;
}

static int send_init_cmd(struct ploop_copy_handle *h)
{
	return send_cmd_ex(h, h->image_fmt == QCOW_FMT ?
			PCOPY_CMD_INIT_QCOW : PCOPY_CMD_INIT_PLOOP,
			B2S(h->cluster), h->size);
}

static int send_cmd(struct ploop_copy_handle *h, pcopy_cmd_t cmd)
{
	return send_cmd_ex(h, cmd, cmd == PCOPY_CMD_FINISH ? 0 : sizeof(cmd), 0);
}

static int nread(int fd, void *buf, int len)
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

static int check_data(void *buf, struct pcopy_pkt_desc *desc,
		struct pcopy_pkt_desc_md5 *md5)
{
	__u8 m[16];
	char s[34];
	char d[34];

	md5sum(buf, desc->size, m);
	if (memcmp(md5->md5, m, sizeof(m))) {
		ploop_err(0, "MD5 mismatch pos: %llu src: %s dst: %s",
				desc->pos, md52str(md5->md5, s), md52str(m, d));
		return SYSEXIT_WRITE;
	}
	return 0;
}

static int receiver_process_init(struct ploop_receiver_data *data,
		struct pcopy_pkt_desc *desc, int image_fmt)
{
	int rc;
	struct ploop_mount_param m = {};
	struct ploop_disk_images_data *di;
	struct ploop_create_param p = {
		.blocksize = desc->size,
		.size = desc->pos,
	};

	ploop_log(3, "pcopy_receiver: init image %s size: %llu blocksize: %u",
			data->file, p.size, p.blocksize);

	if (image_fmt == PLOOP_FMT)
		rc = create_image(data->file, p.blocksize, p.size, PLOOP_EXPANDED_MODE,
			PLOOP_FMT_UNDEFINED, 0);
	else
		rc = qcow_create(data->file, &p);
	if (rc)
		return rc;

	ploop_log(3, "pcopy_receiver: mount %s", data->file);
	di = alloc_diskdescriptor();
	di->size = p.size;
	di->runtime->image_fmt = image_fmt;
	rc = ploop_di_add_image(di, data->file, TOPDELTA_UUID, NONE_UUID);
	if (rc) {
		ploop_close_dd(di);
		return rc;
	}

	rc = ploop_mount(di, NULL, &m, 0);
	ploop_close_dd(di);
	if (rc)
		return rc;

	data->devfd = open(m.device, O_WRONLY|O_DIRECT|O_CLOEXEC);
	if (data->devfd == -1) {
		ploop_err(errno, "pcopy_receiver: cannot open %s", m.device);
		return SYSEXIT_OPEN;
	}
	snprintf(data->device, sizeof(data->device), "%s", m.device);

	return 0;
}

static int receiver_process(struct ploop_receiver_data *data,
		struct pcopy_pkt_desc *desc, int *rc)
{
	int ret, n;

	switch (desc->type) {
	case PCOPY_PKT_DATA:
	case PCOPY_PKT_DATA_ASYNC:
		if (data->ofd == -1) {
			data->ofd = open(data->file, O_WRONLY|O_CREAT|O_CLOEXEC, 0600);
			if (data->ofd < 0) {
				ploop_err(errno, "pcopy_receiver: cannot open %s", data->file);
				return SYSEXIT_CREAT;
			}
		}

		n = TEMP_FAILURE_RETRY(pwrite(data->ofd, data->iobuf, desc->size, desc->pos));
		if (n != desc->size) {
			if (n < 0)
				ploop_err(errno, "pcopy_receiver: error in pwrite size: %u pos: %llu",
						desc->size, desc->pos);
			else
				ploop_err(0, "pcopy_receiver: short pwrite");
			return SYSEXIT_WRITE;
		}
		break;
	case PCOPY_PKT_DATA_DEVICE:
		n = TEMP_FAILURE_RETRY(pwrite(data->devfd, data->iobuf, desc->size, desc->pos));
		if (n != desc->size) {
			if (n < 0)
				ploop_err(errno, "pcopy_receiver: error in pwrite");
			else
				ploop_err(0, "pcopy_receiver: short pwrite");
			return SYSEXIT_WRITE;
		}
		break;
	case PCOPY_PKT_CMD: {
		unsigned int cmd = ((unsigned int *) data->iobuf)[0];

		ploop_log(3, "pcopy_receiver: process cmd %d", cmd);
		switch (cmd) {
		case PCOPY_CMD_SYNC:
			if (desc->pos != 0) {
				data->remote_flags = desc->pos;
				ploop_log(0, "handshake remote flags %x", data->remote_flags);
				*rc = -PCOPY_SUP_FLAGS;
				return 0;
			} else if (data->ofd != -1) {
				ret = fsync_safe(data->ofd);
				if (ret)
					return ret;
			}
			break;
		case PCOPY_CMD_INIT_PLOOP:
		case PCOPY_CMD_INIT_QCOW:
			ret = receiver_process_init(data, desc,
				cmd == PCOPY_CMD_INIT_QCOW ? QCOW_FMT : PLOOP_FMT);
			if (ret) {
				ploop_err(0, "failed receiver_process_init");
				return ret;
			}
			break;
		case PCOPY_CMD_UMOUNT:
			close(data->devfd);
			data->devfd = -1;
			ploop_log(3, "pcopy_receiver: umount %s", data->device);
			ret = ploop_umount(data->device, NULL);
			if (ret)
				return ret;
			break;
		default:
			ploop_err(0, "pcopy_receiver: unsupported command %d",
					cmd);
			return SYSEXIT_PARAM;
		}
		break;
	}
	default:
		ploop_err(0, "pcopy_receiver: unsupported command type%d",
					desc->type);
		return SYSEXIT_PARAM;
	}

	*rc = 0;
	return 0;
}

int ploop_copy_receiver(struct ploop_copy_receive_param *arg)
{
	int ret, rc;
	__u64 cluster = 0;
	struct pcopy_pkt_desc_md5 md5;
	struct pcopy_pkt_desc desc;
	struct ploop_receiver_data data = {
		.ifd = arg->ifd,
		.file = arg->file,
		.ofd = -1,
		.devfd = -1,
	};

	if (!arg)
		return SYSEXIT_PARAM;

	if (is_fd_socket(arg->ifd) != 1) {
		ploop_err(errno, "Invalid input fd %d: must be "
				"a pipe or a socket", arg->ifd);
		return SYSEXIT_PARAM;
	}

	ploop_dbg(3, "pcopy_receiver: start %s", arg->file);
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

		if (data.remote_flags & PCOPY_FEATURE_MD5SUM) {
			if (nread(arg->ifd, &md5, sizeof(md5))) {
				ploop_err(errno, "Error in nread(md5)");
				ret = SYSEXIT_READ;
				goto out;
			}
		}

		if (desc.size > cluster) {
			free(data.iobuf);
			data.iobuf = NULL;
			cluster = desc.size;
			if (p_memalign(&data.iobuf, 4096, cluster)) {
				ret = SYSEXIT_MALLOC;
				goto out;
			}
		}

		if (desc.size == 0)
			break;

		if (nread(arg->ifd, data.iobuf, desc.size)) {
			ploop_err(errno, "Error in nread data");
			ret = SYSEXIT_READ;
			goto out;
		}

		if (data.remote_flags & PCOPY_FEATURE_MD5SUM) {
			ret = check_data(data.iobuf, &desc, &md5);
			if (ret)
				break;
		}

		ret = receiver_process(&data, &desc, &rc);

		/* send reply */
		if (desc.type != PCOPY_PKT_DATA_ASYNC) {
			int r = ret ? ret : rc;
			ploop_log(3, "pcopy_receiver: type %d reply %d", desc.type, r);
			if (nwrite(arg->ifd, &r, sizeof(int))) {
				ploop_err(errno, "failed to send reply");
				ret = SYSEXIT_WRITE;
			}
		}
		if (ret)
			goto out;
	}

	if (data.ofd != -1) {
		ret = fsync_safe(data.ofd);
		if (ret)
			goto out;
	}

	ploop_dbg(3, "pcopy_receiver: exited");
	/* send final reply */
	ret = 0;
	if (nwrite(arg->ifd, &ret, sizeof(int))) {
		ret = SYSEXIT_WRITE;
		ploop_err(errno, "pcopy_receiver: failed to send reply");
		goto out;
	}

out:
	if (data.ofd != -1 && close(data.ofd)) {
		ploop_err(errno, "pcopy_receiver: Error in close");
		if (!ret)
			ret = SYSEXIT_WRITE;
	}
	if (data.devfd != -1) {
		close(data.devfd);
		ploop_umount(data.device, NULL);
	}

	if (ret)
		unlink(arg->file);
	free(data.iobuf);

	ploop_dbg(3, "pcopy_receiver: rc %d", ret);
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

static int send_buf(struct ploop_copy_handle *h, int type, const void *iobuf, int len, off_t pos)
{
	if (h->cancelled)
		return SYSEXIT_WRITE;

	if (h->is_remote)
		return remote_write(h, type, iobuf, len, pos);
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

		ret = send_buf(h, c->type, c->data, c->size, c->pos);
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

static int send_image_block(struct ploop_copy_handle *h, int type, __u64 size, __u64 pos)
{
	int ret = 0, fd;
	size_t nread;
	struct chunk *c;

	if (h->sd.ret) {
		ploop_err(h->sd.err_no, "write error");
		return h->sd.ret;
	}

	c = alloc_chunk(type, size, pos);
	if (c == NULL) {
		return SYSEXIT_MALLOC;
	}

	ploop_dbg(3, "READ type=%d size=%llu pos=%llu", type, size, pos);
	fd = type == PCOPY_PKT_DATA_DEVICE ? h->devploopfd :
		(h->image_fmt == QCOW_FMT ? h->qcowfd : h->idelta.fd);
	nread = TEMP_FAILURE_RETRY(pread(fd, c->data, c->size, c->pos));
	if (nread == 0)
		goto out;
	if (nread < 0) {
		ploop_err(errno, "Error from pread() size=%llu pos=%llu",
				 size, pos);
		ret = SYSEXIT_READ;
		goto out;
	}
	c->size = nread;

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

static int resume(struct ploop_copy_handle *h)
{
	int rc;

	if (!h->dev_frozen)
		return 0;
	rc = dm_resume(h->devname);
	rc |= dm_resume(h->part);
	h->dev_frozen = 0;

	return rc;
}

static int suspend(struct ploop_copy_handle *h)
{
	int rc;

	rc = dm_suspend(h->part);
	if (rc)
		return rc;
	rc = dm_suspend(h->devname);
	if (rc)
		goto err;
	h->dev_frozen = 1;

	return 0;
err:
	resume(h);
	return rc;
}

void ploop_copy_release(struct ploop_copy_handle *h)
{
	if (h == NULL)
		return;

	ploop_log(3, "ploop_copy_release %s", h->devname);
	if (resume(h))
		ploop_err(errno, "Failed to resume %s", h->devname);

	if (h->tracker_on) {
		dm_tracking_stop(h->devname);
		h->tracker_on = 0;
	}

	if (h->devfd != -1) {
		close(h->devfd);
		h->devfd = -1;
	}
	if (h->devploopfd != -1) {
		close(h->devploopfd);
		h->devploopfd = -1;
	}

	if (h->idelta.fd != -1) {
		close_delta(&h->idelta);
		h->idelta.fd = -1;
	}

	if (h->qcowfd != -1) {
		close(h->qcowfd);
		h->qcowfd = -1;
	}

	if (h->send_th) {
		pthread_cancel(h->send_th);
		pthread_join(h->send_th, NULL);
		h->send_th = 0;
	}

	free(h->image);
	h->image = NULL;
	ploop_tg_deinit(h->devploop, &h->tg);
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

	h->devfd = h->ofd = h->idelta.fd = h->qcowfd = -1;

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
	int ret;
	__u32 blocksize;
	int fmt;
	char device[64];
	struct ploop_copy_handle  *_h = NULL;
	int is_remote;

	ploop_log(3, "ploop_copy_init");
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

	if (di) {
		ret = ploop_read_dd(di);
		if (ret)
			return ret;

		if (ploop_find_dev_by_dd(di, device, sizeof(device))) {
			ploop_err(0, "Can't find running ploop device");
			ret = SYSEXIT_SYS;
			goto err;
		}
	} else if (param->device) {
		snprintf(device, sizeof(device), "%s", param->device);
	} else {
		return SYSEXIT_PARAM;
	}

	_h = alloc_ploop_copy_handle(S2B(blocksize));
	if (_h == NULL) {
		ploop_err(0, "alloc_ploop_copy_handle");
		return SYSEXIT_MALLOC;
	}

	ret = ploop_tg_init(device, TG_NAME, &_h->tg);
	if (ret)
		goto err;

	_h->raw = fmt == PLOOP_FMT_UNDEFINED;
	_h->ofd = param->ofd;
	_h->is_remote = is_remote;
	_h->async = param->async;
	_h->image_fmt = di->runtime->image_fmt;
	snprintf(_h->devploop, sizeof(_h->devname), "%s", _h->tg.devname);
	snprintf(_h->devname, sizeof(_h->devname), "%s", _h->tg.devtg);
	snprintf(_h->part, sizeof(_h->part), "%s", _h->tg.part);
	_h->devfd = open(_h->devname, O_RDONLY|O_CLOEXEC);
	if (_h->devfd == -1) {
		ploop_err(errno, "Can't open device %s", _h->devname);
		ret = SYSEXIT_DEVICE;
		goto err;
	}
	ret = get_image_param_online(di, _h->devploop, &_h->image, &_h->size, &blocksize, &fmt, NULL);
	if (ret)
		goto err;
	_h->cluster = S2B(blocksize);
	_h->devploopfd = open(_h->devploop, O_RDONLY|O_CLOEXEC|O_DIRECT);
	if (_h->devploopfd == -1) {
		ploop_err(errno, "Can't open device %s", _h->devploop);
		ret = SYSEXIT_DEVICE;
		goto err;
	}
	if (_h->image_fmt == QCOW_FMT) {
		_h->qcowfd = open(_h->image, O_RDONLY|O_CLOEXEC|O_DIRECT);
		if (_h->qcowfd == -1) {
			ploop_err(errno, "Can't open qcow2 image %s", _h->image);
			ret = SYSEXIT_OPEN;
			goto err;
		}
	} else {
		if (open_delta(&_h->idelta, _h->image, O_RDONLY|O_DIRECT, OD_ALLOW_DIRTY)) {
			ret = SYSEXIT_OPEN;
			goto err;
		}
	}
	ploop_log(0, "Send %s image %s dev=%s fmt=%d blocksize=%d local=%d",
			_h->image_fmt == QCOW_FMT ? "qcow2" : "ploop",
			_h->image, device, fmt, blocksize, !is_remote);
	ret = complete_running_operation(di, device);
	if (ret)
		goto err;

	_h->cl = register_cleanup_hook(cancel_sender, _h);

err:
	if (ret) {
		ploop_tg_deinit(_h->devploop, &_h->tg);
		ploop_copy_release(_h);
		free_ploop_copy_handle(_h);
	} else
		*h = _h;

	return ret;
}


static int process_start(struct ploop_copy_handle *h, struct ploop_copy_stat *stat)
{
	int rc, nr_clusters;
	__u64 n = 0, *map = NULL;
	__u32 map_size;

	ploop_log(3, "pcopy start %s %s", h->devname, h->async ? "async" : "");
	rc = suspend(h);
	if (rc)
		return rc;
	rc = dm_tracking_start(h->devname);
	if (rc)
		goto err;
	h->tracker_on = 1;
	if (h->image_fmt != QCOW_FMT) {
		rc = build_alloc_bitmap(&h->idelta, &map, &map_size, &nr_clusters);
		if (rc)
			goto err;
	}
	rc = resume(h);
	if (rc) 
		goto err;
	rc = send_init_cmd(h);
	if (rc)
		goto err;

	if (h->image_fmt != QCOW_FMT) {
		while ((n = BitFindNextSet64(map, map_size, n)) != -1) {
			rc = send_image_block(h, PCOPY_PKT_DATA_DEVICE, h->cluster, n * h->cluster);
	 		if (rc)
				break;
			rc = dm_tracking_clear(h->devname, n);
	 		if (rc)
				break;
	 		stat->xferred_total += h->cluster;
			n++;
		}
	} else {
		off_t off;

		for (off = 0; off < h->size; off += h->cluster) {
			rc = send_image_block(h, PCOPY_PKT_DATA_DEVICE, h->cluster, off);
			if (rc)
				break;
			rc = dm_tracking_clear(h->devname, off / h->cluster);
			if (rc)
				break;
			stat->xferred_total += h->cluster;
		}
	}
err:
	resume(h);
	free(map);
	return rc;
}

static int process_next(struct ploop_copy_handle *h, struct ploop_copy_stat *stat)
{
	int rc;
	__u64 p, c = 0;

	stat->xferred = 0;
	do {
		p = c;
		rc = dm_tracking_get_next(h->devname, &c);
		if (rc) {
			if (errno == EAGAIN)
				rc = 0;
			break;
		}
		rc = send_image_block(h, PCOPY_PKT_DATA_DEVICE, h->cluster, c * h->cluster);
		if (rc)
			break;
		stat->xferred += h->cluster;
	} while (p < c);
	
        wait_sender(h);

        /* sync after each iteration */
        rc = send_cmd(h, PCOPY_CMD_SYNC);
        if (rc)
                return rc;

	stat->xferred_total += stat->xferred;
	ploop_log(3, "process_next: %llu/%llu", stat->xferred_total, stat->xferred);

	return 0;
}

int ploop_copy_start(struct ploop_copy_handle *h,
		struct ploop_copy_stat *stat)
{
	int ret;

	ret = handshake(h);
	if (ret)
		goto err;

	h->stage = PLOOP_COPY_START;
	if (pthread_create(&h->send_th, NULL, sender_thread, h)) {
		ploop_err(errno, "Can't create send thread");
		ret = SYSEXIT_SYS;
		goto err;
	}

	ret = process_start(h, stat);
	if (ret)
		goto err;
	ploop_dbg(3, "pcopy start finished %s", h->devname);

	return 0;
err:
	ploop_copy_release(h);
	ploop_err(0, "Cannot start pcopy");

	return ret;
}

int ploop_copy_next_iteration(struct ploop_copy_handle *h,
		struct ploop_copy_stat *stat)
{
	int ret;

	ploop_dbg(3, "pcopy %s iter %d", h->devname, h->niter);

	h->stage = PLOOP_COPY_ITER;
	ret = process_next(h, stat);
	if (ret) {
		ploop_copy_release(h);
		return ret;
	}
	ploop_log(3, "pcopy %s iter %d xferred=%" PRIu64,
			h->devname, h->niter++, (uint64_t)stat->xferred);
	return 0;
}

static int cbt_writer(void *data, const void *buf, int len, off_t pos)
{
	struct ploop_copy_handle *h = (struct ploop_copy_handle *)data;
	off_t eof = pos + len;

	if (h->eof_offset < eof)
		h->eof_offset = eof;
	return send_buf(h, PCOPY_PKT_DATA, buf, len, pos);
}

static int send_optional_header(struct ploop_copy_handle *copy_h)
{
	int ret;
	struct ploop_pvd_header *vh;
	struct ploop_pvd_ext_block_check *hc;
	struct ploop_pvd_ext_block_element_header *h;
	__u8 *block = NULL, *data;
	struct stat st;

	if (fstat(copy_h->idelta.fd, &st)) {
		ploop_err(errno, "send_optional_header: fstat");
		return SYSEXIT_READ;
	}

	vh = (struct ploop_pvd_header *)copy_h->idelta.hdr0;
	if (p_memalign((void **)&block, 4096, copy_h->cluster))
		return SYSEXIT_MALLOC;
	bzero(block, copy_h->cluster);
	hc = (struct ploop_pvd_ext_block_check *)block;
	h = (struct ploop_pvd_ext_block_element_header *)(hc + 1);
	data = (__u8 *)(h + 1);
	h->magic = EXT_MAGIC_DIRTY_BITMAP;

	ret = save_dirty_bitmap(copy_h->devfd, &copy_h->idelta,
			st.st_size, data, &h->size,
			NULL, cbt_writer, copy_h);
	if (ret) {
		if (ret == SYSEXIT_NOCBT)
			ret = 0;
		goto out;
	}

	vh->m_DiskInUse = SIGNATURE_DISK_CLOSED_V21;
	vh->m_FormatExtensionOffset = (copy_h->eof_offset + SECTOR_SIZE - 1) / SECTOR_SIZE;
	ploop_log(3, "Send extension header offset=%llu size=%d",
			vh->m_FormatExtensionOffset * SECTOR_SIZE, h->size);

	if (send_buf(copy_h, PCOPY_PKT_DATA, vh, sizeof(*vh), 0)) {
		ploop_err(errno, "Can't write header");
		ret = SYSEXIT_WRITE;
		goto out;
	}

	hc->m_Magic = FORMAT_EXTENSION_MAGIC;
	md5sum((const unsigned char *)(hc + 1), copy_h->cluster - sizeof(*hc), hc->m_Md5);

	if (send_buf(copy_h, PCOPY_PKT_DATA, block, copy_h->cluster, vh->m_FormatExtensionOffset * SECTOR_SIZE)) {
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

	ploop_log(3, "pcopy final %s", h->devname);

	ret = suspend(h);
	if (ret)
		goto err;

	iter = 1;
	for (;;) {
		ret = process_next(h, stat);
		if (ret)
			goto err;
		else if (stat->xferred == 0)
			break;
		if (iter++ > 2) {
			ploop_err(0, "Too many iterations on frozen FS, aborting");
			ret =  SYSEXIT_LOOP;
			goto err;
		}
	}

	ret = send_cmd(h, PCOPY_CMD_UMOUNT);
	if (ret)
		goto err;
	if (!h->raw && h->image_fmt != QCOW_FMT) {
		ret = send_optional_header(h);
		if (ret)
			goto err;
	}

	ret = dm_tracking_stop(h->devname);
	if (ret)
		goto err;

	h->tracker_on = 0;

	send_cmd(h, PCOPY_CMD_FINISH);
	h->stage = PLOOP_COPY_FINISH;
	wakeup(&h->sd.mutex, &h->sd.cond);

	pthread_join(h->send_th, NULL);
	h->send_th = 0;

	ploop_dbg(3, "pcopy stop done %s", h->devname);

err:
	ploop_copy_release(h);

	return ret;
}

void ploop_copy_deinit(struct ploop_copy_handle *h)
{
	struct chunk *c;

	if (h == NULL)
		return;

	ploop_log(4, "pcopy deinit");
	while ((c = q_get_first(&h->sd)))
		dequeue(&h->sd, c);

	ploop_copy_release(h);
	free_ploop_copy_handle(h);

	ploop_dbg(3, "pcopy deinit done");
}

/* Deprecated */
int ploop_copy_receive(struct ploop_copy_receive_param *arg)
{
	return SYSEXIT_PARAM;
}

int ploop_send(const char *device, int ofd, const char *flush_cmd,
                int is_pipe)
{
	return SYSEXIT_PARAM;
}

int ploop_receive(const char *dst) 
{

	return SYSEXIT_PARAM;
}
