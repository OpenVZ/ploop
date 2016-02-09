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

#define SYNC_MARK	4

#define STATUS_OK	"SUCCESS\n"
#define STATUS_FAIL	"FAILURE\n"
#define LEN_STATUS	8

/* Check what a file descriptor refers to.
 * Return:
 *  0 - file
 *  1 - pipe or socket
 * -1 - none of the above
 */
static int is_fd_pipe(int fd) {
	struct stat st;

	if (fstat(fd, &st))
		return -1;

	if (S_ISREG(st.st_mode))
		return 0;

	if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))
		return 1;

	return -1;
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

static int remote_write(int ofd, const void *iobuf, int len, off_t pos)
{
	struct xfer_desc desc = { .marker = PLOOPCOPY_MARKER };

	/* Header */
	desc.size = len;
	desc.pos = pos;
	if (nwrite(ofd, &desc, sizeof(desc)))
		return SYSEXIT_WRITE;

	/* Data */
	if (len && nwrite(ofd, iobuf, len))
		return SYSEXIT_WRITE;

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

static int send_buf(int ofd, const void *iobuf, int len, off_t pos,
		int is_pipe)
{
	if (is_pipe)
		return remote_write(ofd, iobuf, len, pos);
	else
		return local_write(ofd, iobuf, len, pos);
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

int ploop_copy_receive(struct ploop_copy_receive_param *arg)
{
	int ofd, ret;
	__u64 cluster = 0;
	void *iobuf = NULL;

	if (!arg)
		return SYSEXIT_PARAM;

	if (is_fd_pipe(arg->ifd) != 1) {
		ploop_err(errno, "Invalid input fd %d: must be "
				"a pipe or a socket", arg->ifd);
		return SYSEXIT_PARAM;
	}

	if (arg->feedback_fd >= 0 && is_fd_pipe(arg->feedback_fd) != 1) {
		ploop_err(errno, "Invalid feedback fd %d: must be "
				"a pipe or a socket", arg->feedback_fd);
		return SYSEXIT_PARAM;
	}

	/* If feedback is to be send to stdout or stderr,
	 * we have to disable logging to appropriate fd.
	 *
	 * As currently there's no way to disable just stderr,
	 * so in this case we have to disable stdout as well.
	 */
	if (arg->feedback_fd == STDOUT_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOSTDOUT);
	else if (arg->feedback_fd == STDERR_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOCONSOLE);

	ofd = open(arg->file, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (ofd < 0) {
		ploop_err(errno, "Can't open %s", arg->file);
		return SYSEXIT_CREAT;
	}

	/* Read data */
	for (;;) {
		int n;
		struct xfer_desc desc;

		if (nread(arg->ifd, &desc, sizeof(desc)) < 0) {
			ploop_err(errno, "Error in nread(desc)");
			ret = SYSEXIT_READ;
			goto out;
		}
		if (desc.marker != PLOOPCOPY_MARKER) {
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
		if (desc.size == SYNC_MARK) {
			int st;
			/* ignore received data, instead do sync */
			st = fdatasync(ofd);
			if (arg->feedback_fd >= 0) {
				/* Tell the sending side how it went */
				int w;

				w = write(arg->feedback_fd,
					st ? STATUS_FAIL : STATUS_OK,
					LEN_STATUS);
				/* check write error only if no error yet */
				if (!st && w != LEN_STATUS) {
					ploop_err(errno, "Error in write(%d)",
							arg->feedback_fd);
					ret = SYSEXIT_WRITE;
					goto out;
				}
			}
			if (st) {
				ploop_err(errno, "Error in fdatasync()");
				ret = SYSEXIT_WRITE;
				goto out;
			}
			continue;
		}
		n = pwrite(ofd, iobuf, desc.size, desc.pos);
		if (n != desc.size) {
			if (n < 0)
				ploop_err(errno, "Error in pwrite");
			else
				ploop_err(0, "Error: short pwrite");
			ret = SYSEXIT_WRITE;
			goto out;
		}
	}

	if (fdatasync(ofd)) {
		ploop_err(errno, "Error in fdatasync");
		ret = SYSEXIT_WRITE;
		goto out;
	}

	ret = 0;

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

/* Deprecated, use ploop_copy_receive() instead */
int ploop_receive(const char *dst) {
	struct ploop_copy_receive_param r = {
		.file = dst,
	};

	return ploop_copy_receive(&r);
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

static int run_cmd(const char *cmd)
{
	int st;

	if (!cmd)
		return 0;

	st = system(cmd);
	if (!st)
		return 0;

	if (st == -1)
		ploop_err(errno, "Can't execute %s", cmd);
	else if (WIFEXITED(st))
		ploop_err(0, "Command %s failed with code %d", cmd, WEXITSTATUS(st));
	else if (WIFSIGNALED(st))
		ploop_err(0, "Command %s killed by signal %d", cmd, WTERMSIG(st));
	else
		ploop_err(0, "Command %s died abnormally", cmd);

	return SYSEXIT_SYS;
}

static int open_mount_point(const char *device)
{
	int fd;
	char mnt[PATH_MAX];

	if (ploop_get_mnt_by_dev(device, mnt, sizeof(mnt))) {
		ploop_err(0, "Can't find mount point for %s", device);
		return -1;
	}

	fd = open(mnt, O_RDONLY);
	if (fd < 0) {
		ploop_err(errno, "Can't open %s", mnt);
		return -1;
	}

	return fd;
}

/* If you want to see critical ploop_send() timings:
 *
 * 1) Compile with DEBUG_TIMES defined
 * 2) Use "ploop -vvvv copy" to set verbosity to (at least) 4
 * 3) Use either -d FILE or -o OUTFD (to keep stdout free for logging)
 */
#ifdef DEBUG_TIMES
#define TS(...) ploop_log(4, "psend: " __VA_ARGS__)
#else
#define TS(...)
#endif

struct send_data {
	int fd;
	void *buf;
	int len;
	off_t pos;
	int is_pipe;
	int ret;
	int err_no;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_cond_t cond_sent;
	int has_data;
};

static void *send_thread(void *data) {
	struct send_data *sd = data;
	int done;

	pthread_mutex_lock(&sd->mutex);
	do {
		while (!sd->has_data) {
			pthread_cond_wait(&sd->cond, &sd->mutex);
		}
		sd->ret = send_buf(sd->fd, sd->buf,
				sd->len, sd->pos, sd->is_pipe);
		if (sd->ret)
			sd->err_no = errno;
		done = (sd->len == 0 && sd->pos == 0);
		sd->has_data = 0;
		pthread_cond_signal(&sd->cond_sent);
	} while (!done);
	pthread_mutex_unlock(&sd->mutex);

	return NULL;
}

#define async_send(length, position)			\
do {							\
	pthread_mutex_lock(&sd.mutex);			\
	while (sd.has_data) {				\
		pthread_cond_wait(&sd.cond_sent, &sd.mutex);	\
	}						\
	if (sd.ret) {					\
		ploop_err(sd.err_no, "write error");	\
		ret = sd.ret;				\
		goto done;				\
	}						\
	sd.buf = iobuf[i];				\
	sd.len = (length);				\
	sd.pos = (position);				\
	sd.has_data = 1;				\
	pthread_cond_signal(&sd.cond);			\
	pthread_mutex_unlock(&sd.mutex);		\
} while (0)

#define do_pread(length, position)			\
({							\
	int __ret;					\
							\
	i = !i;						\
	__ret = pread(idelta.fd, iobuf[i],		\
			(length), (position));		\
	if (__ret < 0) {				\
		ploop_err(errno, "Error from read");	\
		ret = SYSEXIT_READ;			\
		goto done;				\
	}						\
							\
	__ret;						\
})

int ploop_copy_send(struct ploop_copy_send_param *arg)
{
	struct delta idelta = { .fd = -1 };
	int tracker_on = 0;
	int fs_frozen = 0;
	int devfd = -1;
	int mntfd = -1;
	int ret = 0;
	char *send_from = NULL;
	char *format = NULL;
	void *iobuf[2] = {};
	int blocksize;
	__u64 cluster;
	__u64 pos;
	__u64 iterpos;
	__u64 trackpos;
	__u64 trackend;
	__u64 xferred;
	int iter;
	struct ploop_track_extent e;
	int i;
	pthread_t send_th = 0;
	struct send_data sd = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
		.cond_sent = PTHREAD_COND_INITIALIZER,
	};

	if (!arg)
		return SYSEXIT_PARAM;

	sd.fd = arg->ofd;
	sd.is_pipe = is_fd_pipe(arg->ofd);
	if (sd.is_pipe < 0) {
		ploop_err(0, "Invalid output fd %d: must be a file, "
				"a pipe or a socket", arg->ofd);
		return SYSEXIT_PARAM;
	}

	if (arg->feedback_fd >= 0 && is_fd_pipe(arg->feedback_fd) != 1) {
		ploop_err(errno, "Invalid feedback fd %d: must be "
				"a pipe or a socket", arg->feedback_fd);
		return SYSEXIT_PARAM;
	}

	/* If data is to be send to stdout or stderr,
	 * we have to disable logging to appropriate fd.
	 *
	 * As currently there's no way to disable just stderr,
	 * so in this case we have to disable stdout as well.
	 */
	if (arg->ofd == STDOUT_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOSTDOUT);
	else if (arg->ofd == STDERR_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOCONSOLE);

	devfd = open(arg->device, O_RDONLY);
	if (devfd < 0) {
		ploop_err(errno, "Can't open device %s", arg->device);
		ret = SYSEXIT_DEVICE;
		goto done;
	}

	mntfd = open_mount_point(arg->device);
	if (mntfd < 0) {
		/* Error is printed by open_mount_point() */
		ret = SYSEXIT_OPEN;
		goto done;
	}

	ret = get_image_info(arg->device, &send_from, &format, &blocksize);
	if (ret)
		goto done;
	cluster = S2B(blocksize);

	ret = SYSEXIT_MALLOC;
	for (i = 0; i < 2; i++)
		if (p_memalign(&iobuf[i], 4096, cluster))
			goto done;

	ret = complete_running_operation(NULL, arg->device);
	if (ret)
		goto done;

	ret = ioctl_device(devfd, PLOOP_IOC_TRACK_INIT, &e);
	if (ret)
		goto done;
	tracker_on = 1;

	if (open_delta_simple(&idelta, send_from, O_RDONLY|O_DIRECT, OD_NOFLAGS)) {
		ret = SYSEXIT_OPEN;
		goto done;
	}

	ret = pthread_create(&send_th, NULL, send_thread, &sd);
	if (ret) {
		ploop_err(ret, "Can't create send thread");
		ret = SYSEXIT_SYS;
		goto done;
	}

	ploop_log(-1, "Sending %s", send_from);

	trackend = e.end;
	for (pos = 0; pos < trackend; ) {
		int n;

		trackpos = pos + cluster;
		ret = ioctl_device(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos);
		if (ret)
			goto done;

		n = do_pread(cluster, pos);
		if (n == 0) /* EOF */
			break;

		async_send(n, pos);
		pos += n;
	}
	/* First copy done */

	iter = 1;
	iterpos = 0;
	xferred = 0;

	for (;;) {
		int err;

		err = ioctl(devfd, PLOOP_IOC_TRACK_READ, &e);
		if (err == 0) {

			//fprintf(stderr, "TRACK %llu-%llu\n", e.start, e.end); fflush(stdout);

			if (e.end > trackend)
				trackend = e.end;

			if (e.start < iterpos)
				iter++;
			iterpos = e.end;
			xferred += e.end - e.start;

			for (pos = e.start; pos < e.end; ) {
				int n;
				int copy = e.end - pos;

				if (copy > cluster)
					copy = cluster;
				if (pos + copy > trackpos) {
					trackpos = pos + copy;
					if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
						ploop_err(errno, "PLOOP_IOC_TRACK_SETPOS");
						ret = SYSEXIT_DEVIOC;
						goto done;
					}
				}
				n = do_pread(copy, pos);
				if (n == 0) {
					ploop_err(0, "Unexpected EOF");
					ret = SYSEXIT_READ;
					goto done;
				}
				async_send(n, pos);
				pos += n;
			}
		} else {
			if (errno == EAGAIN) /* no more dirty blocks */
				break;
			ploop_err(errno, "PLOOP_IOC_TRACK_READ");
			ret = SYSEXIT_DEVIOC;
			goto done;
		}

		if (iter > 10 || (iter > 1 && xferred > trackend))
			break;
	}

	/* Live iterative transfers are done. Either we transferred
	 * everything or iterations did not converge. In any case
	 * now we must suspend VE disk activity. Now it is just
	 * call of an external program (something sort of
	 * "killall -9 writetest; sleep 1; umount /mnt2"), actual
	 * implementation must be intergrated to vzctl/vzmigrate
	 * and suspend VE with subsequent fsyncing FS.
	 */

	/* Send the sync command to receiving side. Since older ploop
	 * might be present on the other side, we need to not break the
	 * backward compatibility, so just send the first few (SYNC_MARK)
	 * bytes of delta file contents. New ploop_receive() interprets
	 * this as "sync me" command, while the old one just writes those
	 * bytes which is useless but harmless.
	 */
	if (sd.is_pipe) {
		char buf[LEN_STATUS + 1] = {};

		ret = do_pread(4096, 0);
		if (ret < SYNC_MARK) {
			ploop_err(errno, "Short read");
			ret = SYSEXIT_READ;
			goto done;
		}
		TS("SEND 0 %d (sync)", SYNC_MARK);
		async_send(SYNC_MARK, 0);

		/* Now we should wait for the other side to finish syncing
		 * before freezing the container, to optimize CT frozen time.
		 */
		if (arg->feedback_fd < 0) {
			/* No descriptor to receive a response back is given.
			 * As ugly as it looks, let's just sleep for some time
			 * hoping the other side will finish sync.
			 */
			TS("SLEEP 5");
			sleep(5);
			goto sync_done;
		}

		/* Wait for feedback from the receiving side */

		/* FIXME: use select/poll with a timeout */
		if (read(arg->feedback_fd, buf, LEN_STATUS)
				!= LEN_STATUS) {
			ploop_err(errno, "Can't read feedback");
			ret = SYSEXIT_PROTOCOL;
			goto done;
		}

		if (strncmp(buf, STATUS_OK, LEN_STATUS) == 0) {
			goto sync_done;
		}
		else if (strncmp(buf, STATUS_FAIL, LEN_STATUS) == 0) {
			ploop_err(0, "Remote side reported sync failure");
			ret = SYSEXIT_FSYNC;
			goto done;
		}
		else {
			ploop_err(0, "Got back feedback: %s", buf);
			ret = SYSEXIT_PROTOCOL;
			goto done;
		}
	} else {
		/* Writing to local file */
		fdatasync(arg->ofd);
	}

sync_done:
	/* Freeze the container */
	TS("FLUSH");
	ret = run_cmd(arg->flush_cmd);
	if (ret)
		goto done;

	/* Sync fs */
	TS("SYNCFS");
	if (sys_syncfs(mntfd)) {
		ploop_err(errno, "syncfs() failed");
		ret = SYSEXIT_FSYNC;
		goto done;
	}

	/* Flush journal and freeze fs (this also clears the fs dirty bit) */
	TS("FIFREEZE");
	ret = ioctl_device(mntfd, FIFREEZE, 0);
	if (ret)
		goto done;
	fs_frozen = 1;

	TS("IOC_SYNC");
	ret = ioctl_device(devfd, PLOOP_IOC_SYNC, 0);
	if (ret)
		goto done;

	iter = 1;
	iterpos = 0;

	for (;;) {
		int err;
		struct ploop_track_extent e;

		err = ioctl(devfd, PLOOP_IOC_TRACK_READ, &e);
		if (err == 0) {
			__u64 pos;

			//fprintf(stderr, "TRACK %llu-%llu\n", e.start, e.end); fflush(stdout);

			if (e.end > trackend)
				trackend = e.end;
			if (e.start < iterpos)
				iter++;
			iterpos = e.end;

			for (pos = e.start; pos < e.end; ) {
				int n;
				int copy = e.end - pos;

				if (copy > cluster)
					copy = cluster;
				if (pos + copy > trackpos) {
					trackpos = pos + copy;
					ret = ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos);
					if (ret)
						goto done;
				}
				TS("READ %llu %d", pos, copy);
				n = do_pread(copy, pos);
				if (n == 0) {
					ploop_err(0, "Unexpected EOF");
					ret = SYSEXIT_READ;
					goto done;
				}
				TS("SEND %llu %d", pos, n);
				async_send(n, pos);
				pos += n;
			}
		} else {
			if (errno == EAGAIN)
				break;

			ploop_err(errno, "PLOOP_IOC_TRACK_READ");
			ret = SYSEXIT_DEVIOC;
			goto done;
		}

		if (iter > 2) {
			ploop_err(0, "Too many iterations on frozen FS, aborting");
			ret = SYSEXIT_LOOP;
			goto done;
		}
	}

	/* Must clear dirty flag on ploop1 image. */
	if (strcmp(format, "ploop1") == 0) {
		int n;
		struct ploop_pvd_header *vh;

		TS("READ 0 4096");
		n = do_pread(4096, 0);
		if (n < SECTOR_SIZE) {
			ploop_err(errno, "Short read");
			ret = SYSEXIT_READ;
			goto done;
		}

		vh = iobuf[i];
		vh->m_DiskInUse = 0;

		TS("SEND 0 %d (1st sector)", SECTOR_SIZE);
		async_send(SECTOR_SIZE, 0);
	}

	TS("IOCTL TRACK_STOP");
	ret = ioctl(devfd, PLOOP_IOC_TRACK_STOP, 0);
	if (ret)
		goto done;
	tracker_on = 0;

	TS("SEND 0 0 (close)");
	async_send(0, 0);
	pthread_join(send_th, NULL);
	send_th = 0;

done:
	if (send_th)
		pthread_cancel(send_th);
	if (fs_frozen)
		(void)ioctl_device(mntfd, FITHAW, 0);
	if (tracker_on)
		(void)ioctl_device(devfd, PLOOP_IOC_TRACK_ABORT, 0);
	free(iobuf[0]);
	free(iobuf[1]);
	if (devfd >=0)
		close(devfd);
	if (mntfd >=0)
		close(mntfd);
	free(send_from);
	if (idelta.fd >= 0)
		close_delta(&idelta);

	TS("DONE");
	return ret;
}
#undef do_pread
#undef async_send

/* Deprecated, please use ploop_copy_send() instead */
int ploop_send(const char *device, int ofd, const char *flush_cmd,
		int is_pipe)
{
	struct ploop_copy_send_param s = {
		.device		= device,
		.ofd		= ofd,
		.flush_cmd	= flush_cmd,
	};

	return ploop_copy_send(&s);
}
