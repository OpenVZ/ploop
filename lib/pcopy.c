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

/* _XXX_ We should use AIO. ploopcopy cannot use cached reads and
 * has to use O_DIRECT, which introduces large read latencies.
 * AIO is necessary to transfer with maximal speed.
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

#include "ploop.h"

#define SYNC_MARK	4

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

	if (isatty(0) || errno == EBADF) {
		ploop_err(errno, "Invalid input stream: must be pipelined "
				"to a pipe or a socket");
		return SYSEXIT_PARAM;
	}

	ofd = open(arg->file, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (ofd < 0) {
		ploop_err(errno, "Can't open %s", arg->file);
		return SYSEXIT_CREAT;
	}

	/* Read data */
	for (;;) {
		int n;
		struct xfer_desc desc;

		if (nread(0, &desc, sizeof(desc)) < 0) {
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

		if (nread(0, iobuf, desc.size)) {
			ploop_err(errno, "Error in nread data");
			ret = SYSEXIT_READ;
			goto out;
		}
		if (desc.size == SYNC_MARK) {
			/* ignore received data, instead do sync */
			ploop_log(4, "%s: fdatasync()", __func__);
			if (fdatasync(ofd)) {
				ploop_err(errno, "Error in fdatasync()");
				ret = SYSEXIT_WRITE;
				goto out;
			}
			ploop_log(4, "%s: fdatasync() complete", __func__);
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
	int ret;
	int fd;
	char mnt[PATH_MAX];

	ret = ploop_get_mnt_by_dev(device, mnt, sizeof(mnt));
	if (ret == -1) {
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

int ploop_copy_send(struct ploop_copy_send_param *arg)
{
	const char *device = arg->device;
	int ofd = arg->ofd;
	int is_pipe = arg->ofd_is_pipe;
	struct delta idelta = { .fd = -1 };
	int tracker_on = 0;
	int fs_frozen = 0;
	int devfd = -1;
	int mntfd = -1;
	int ret = 0;
	char *send_from = NULL;
	char *format = NULL;
	void *iobuf = NULL;
	int blocksize;
	__u64 cluster;
	__u64 pos;
	__u64 iterpos;
	__u64 trackpos;
	__u64 trackend;
	__u64 xferred;
	int iter;
	struct ploop_track_extent e;

	// Do not print anything on stdout, since we use it to send delta
	if (is_pipe && ofd == STDOUT_FILENO)
		ploop_set_verbose_level(PLOOP_LOG_NOSTDOUT);

	devfd = open(device, O_RDONLY);
	if (devfd < 0) {
		ploop_err(errno, "Can't open device %s", device);
		ret = SYSEXIT_DEVICE;
		goto done;
	}

	mntfd = open_mount_point(device);
	if (mntfd < 0) {
		/* Error is printed by open_mount_point() */
		ret = SYSEXIT_OPEN;
		goto done;
	}

	ret = get_image_info(device, &send_from, &format, &blocksize);
	if (ret)
		goto done;
	cluster = S2B(blocksize);

	if (p_memalign(&iobuf, 4096, cluster)) {
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	ret = ploop_complete_running_operation(device);
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

	ploop_log(-1, "Sending %s", send_from);

	trackend = e.end;
	for (pos = 0; pos < trackend; ) {
		int n;

		trackpos = pos + cluster;
		ret = ioctl_device(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos);
		if (ret)
			goto done;

		n = idelta.fops->pread(idelta.fd, iobuf, cluster, pos);
		if (n < 0) {
			ploop_err(errno, "pread");
			ret = SYSEXIT_READ;
			goto done;
		}
		if (n == 0)
			break;

		ret = send_buf(ofd, iobuf, n, pos, is_pipe);
		if (ret) {
			ploop_err(errno, "write");
			goto done;
		}

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
				n = idelta.fops->pread(idelta.fd, iobuf, copy, pos);
				if (n < 0) {
					ploop_err(errno, "read2");
					ret = SYSEXIT_READ;
					goto done;
				}
				if (n == 0) {
					ploop_err(0, "unexpected EOF");
					ret = SYSEXIT_READ;
					goto done;
				}
				ret = send_buf(ofd, iobuf, n, pos, is_pipe);
				if (ret) {
					ploop_err(errno, "write2");
					goto done;
				}
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
	if (is_pipe) {
		ret = idelta.fops->pread(idelta.fd, iobuf, 4096, 0);
		if (ret != 4096) {
			ploop_err(errno, "pread");
			ret = SYSEXIT_READ;
			goto done;
		}
		TS("SEND 0 %d (sync)", SYNC_MARK);
		ret = send_buf(ofd, iobuf, SYNC_MARK, 0, is_pipe);
		if (ret) {
			ploop_err(errno, "write");
			goto done;
		}
		/* Now we should wait for the other side to finish syncing
		 * before freezing the container. This is done in order to
		 * optimize CT frozen time. Unfortunately the protocol is
		 * one-way so there is no way to receive anything from the
		 * other side. As ugly as it is, let's just sleep for some time.
		 */
		sleep(5);
	} else {
		/* Writing to local file */
		fdatasync(ofd);
	}

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
				n = idelta.fops->pread(idelta.fd, iobuf, copy, pos);
				if (n < 0) {
					ploop_err(errno, "read3");
					ret = SYSEXIT_READ;
					goto done;
				}
				if (n == 0) {
					ploop_err(0, "unexpected EOF3");
					ret = SYSEXIT_READ;
					goto done;
				}
				TS("SEND %llu %d", pos, n);
				ret = send_buf(ofd, iobuf, n, pos, is_pipe);
				if (ret) {
					ploop_err(errno, "write3");
					goto done;
				}
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
		struct ploop_pvd_header *vh = (void*)iobuf;

		TS("READ 0 4096");
		n = idelta.fops->pread(idelta.fd, iobuf, 4096, 0);
		if (n != 4096) {
			ploop_err(errno, "Error reading 1st sector of %s", send_from);
			ret = SYSEXIT_READ;
			goto done;
		}

		vh->m_DiskInUse = 0;

		TS("SEND 0 %d (1st sector)", SECTOR_SIZE);
		ret = send_buf(ofd, vh, SECTOR_SIZE, 0, is_pipe);
		if (ret) {
			ploop_err(errno, "write3");
			goto done;
		}
	}

	TS("IOCTL TRACK_STOP");
	ret = ioctl(devfd, PLOOP_IOC_TRACK_STOP, 0);
	if (ret)
		goto done;
	tracker_on = 0;

	TS("SEND 0 0 (close)");
	ret = send_buf(ofd, iobuf, 0, 0, is_pipe);
	if (ret) {
		ploop_err(errno, "write4");
		goto done;
	}

done:
	if (fs_frozen)
		(void)ioctl_device(mntfd, FITHAW, 0);
	if (tracker_on)
		(void)ioctl_device(devfd, PLOOP_IOC_TRACK_ABORT, 0);
	free(iobuf);
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

/* Deprecated, please use ploop_copy_send() instead */
int ploop_send(const char *device, int ofd, const char *flush_cmd,
		int is_pipe)
{
	struct ploop_copy_send_param s = {
		.device		= device,
		.ofd		= ofd,
		.flush_cmd	= flush_cmd,
		.ofd_is_pipe	= is_pipe,
	};

	return ploop_copy_send(&s);
}
