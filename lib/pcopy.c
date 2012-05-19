/*
 *  Copyright (C) 2008-2012, Parallels, Inc. All rights reserved.
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <string.h>

#include "ploop.h"

struct xfer_header {
	__u64 magic;
#define XFER_HDR_MAGIC 0x726678706f6f6c70ULL
	__u32 version;
	__u32 blocksize;
	__u32 padding[32-4];
};

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


static int send_header(int ofd, __u32 blocksize) {
	struct xfer_header hdr = {
		.magic		= XFER_HDR_MAGIC,
		.version	= 1,
	};

	hdr.blocksize = blocksize;

	if (nwrite(ofd, &hdr, sizeof(hdr)))
		return SYSEXIT_WRITE;

	return 0;
}

static int send_buf(int ofd, void *iobuf, int len, off_t pos)
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

int receive_process(const char *dst)
{
	int ofd, ret;
	struct xfer_header hdr;
	__u64 cluster;
	void *iobuf;

	if (isatty(0) || errno == EBADF) {
		ploop_err(errno, "Invalid input stream: must be pipelined "
				"to a pipe or a socket");
		return SYSEXIT_PARAM;
	}

	ofd = open(dst, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (ofd < 0) {
		ploop_err(errno, "Can't open %s", dst);
		return SYSEXIT_CREAT;
	}

	/* Read header */
	if (nread(0, &hdr, sizeof(hdr)) < 0) {
		ploop_err(0, "Error in nread(hdr)");
		ret = SYSEXIT_READ;
		goto out;
	}
	if (hdr.magic != XFER_HDR_MAGIC) {
		ploop_err(0, "Stream corrupted, bad xfer header magic");
		ret = SYSEXIT_PROTOCOL;
		goto out;
	}
	if (hdr.version != 1) {
		ploop_err(0, "Unknown/unsupported stream version (%d)",
				hdr.version);
		ret = SYSEXIT_PROTOCOL;
		goto out;
	}
	cluster = S2B(hdr.blocksize);

	if (posix_memalign(&iobuf, 4096, cluster)) {
		ploop_err(errno, "posix_memalign");
		ret = SYSEXIT_MALLOC;
		goto out;
	}

	/* Read data */
	for (;;) {
		int n;
		struct xfer_desc desc;

		if (nread(0, &desc, sizeof(desc)) < 0) {
			ploop_err(0, "Error in nread(desc)");
			ret = SYSEXIT_READ;
			goto out;
		}
		if (desc.marker != PLOOPCOPY_MARKER) {
			ploop_err(0, "Stream corrupted");
			ret = SYSEXIT_PROTOCOL;
			goto out;
		}
		if (desc.size > cluster) {
			ploop_err(0, "Stream corrupted, too long chunk");
			ret = SYSEXIT_PROTOCOL;
			goto out;
		}
		if (desc.size == 0)
			break;

		if (nread(0, iobuf, desc.size)) {
			ploop_err(errno, "Error in nread data");
			ret = SYSEXIT_READ;
			goto out;
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

	if (fsync(ofd)) {
		ploop_err(errno, "Error in fsync");
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
		unlink(dst);

	return ret;
}

static int get_image_info(const char *device, char **send_from_p, char **format_p)
{
	int top_level;

	if (ploop_get_attr(device, "top", &top_level)) {
		ploop_err(0, "Can't find top delta");
		return SYSEXIT_SYSFS;
	}

	if (find_delta_names(device, top_level, top_level,
				send_from_p, format_p)) {
		ploop_err(errno, "find_delta_names");
		return SYSEXIT_SYSFS;
	}

	return 0;
}

int send_process(const char *device, int ofd, const char *flush_cmd)
{
	struct delta idelta = { .fd = -1 };
	int tracker_on = 0;
	int devfd = -1;
	int ret = 0;
	char *send_from = NULL;
	char *format = NULL;
	void *iobuf = NULL;
	int res;
	struct ploop_pvd_header *vh = NULL;
	__u64 cluster;
	__u64 pos;
	__u64 iterpos;
	__u64 trackpos;
	__u64 trackend;
	__u64 xferred;
	int iter;
	struct ploop_track_extent e;

	// Do not print anything on stdout, since we use it to send delta
	ploop_set_verbose_level(-1);

	devfd = open(device, O_RDONLY);
	if (devfd < 0) {
		ploop_err(errno, "open device");
		ret = SYSEXIT_DEVICE;
		goto done;
	}

	if (ioctl(devfd, PLOOP_IOC_TRACK_INIT, &e)) {
		ploop_err(errno, "PLOOP_IOC_TRACK_INIT");
		ret = SYSEXIT_DEVIOC;
		goto done;
	}
	tracker_on = 1;

	ret = get_image_info(device, &send_from, &format);
	if (ret)
		goto done;

	if (open_delta_simple(&idelta, send_from, O_RDONLY|O_DIRECT, OD_NOFLAGS)) {
		ret = SYSEXIT_OPEN;
		goto done;
	}

	/* Get blocksize */
	if (posix_memalign((void **)&vh, 4096, SECTOR_SIZE)) {
		ploop_err(errno, "posix_memalign");
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	res = idelta.fops->pread(idelta.fd, vh, SECTOR_SIZE, 0);
	if (res != SECTOR_SIZE) {
		ploop_err(errno, "Error reading 1st sector of %s", send_from);
		ret = SYSEXIT_READ;
		goto done;
	}
	cluster = S2B(vh->m_Sectors);

	if (posix_memalign(&iobuf, 4096, cluster)) {
		ploop_err(errno, "posix_memalign");
		ret = SYSEXIT_MALLOC;
		goto done;
	}

	ploop_log(-1, "Sending %s", send_from);

	ret = send_header(ofd, vh->m_Sectors);
	if (ret) {
		ploop_err(errno, "Error sending pcopy header");
		goto done;
	}

	trackend = e.end;
	for (pos = 0; pos < trackend; ) {
		int n;

		trackpos = pos + cluster;
		if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
			ploop_err(errno, "PLOOP_IOC_TRACK_SETPOS");
			ret = SYSEXIT_DEVIOC;
			goto done;
		}

		n = idelta.fops->pread(idelta.fd, iobuf, cluster, pos);
		if (n < 0) {
			ploop_err(errno, "pread");
			ret = SYSEXIT_READ;
			goto done;
		}
		if (n == 0)
			break;

		if (send_buf(ofd, iobuf, n, pos)) {
			ploop_err(errno, "write");
			ret = SYSEXIT_WRITE;
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
				if (send_buf(ofd, iobuf, n, pos)) {
					ploop_err(errno, "write2");
					ret = SYSEXIT_WRITE;
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

	if (flush_cmd)
		system(flush_cmd);

	if (ioctl(devfd, PLOOP_IOC_SYNC, 0)) {
		ploop_err(errno, "PLOOP_IOC_SYNC");
		ret = SYSEXIT_DEVIOC;
		goto done;
	}

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
					if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
						ploop_err(errno, "PLOOP_IOC_TRACK_SETPOS");
						ret = SYSEXIT_DEVIOC;
						goto done;
					}
				}
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
				if (send_buf(ofd, iobuf, n, pos)) {
					ploop_err(errno, "write3");
					ret = SYSEXIT_WRITE;
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
			goto done;
			ret = SYSEXIT_LOOP;
		}
	}

	/* Must clear dirty flag on ploop1 image. */
	if (strcmp(format, "ploop1") == 0) {
		vh->m_DiskInUse = 0;

		if (send_buf(ofd, vh, SECTOR_SIZE, 0)) {
			ploop_err(errno, "write3");
			ret = SYSEXIT_WRITE;
			goto done;
		}
	}

	if (ioctl(devfd, PLOOP_IOC_TRACK_STOP, 0)) {
		ploop_err(errno, "PLOOP_IOC_TRACK_STOP");
		ret = SYSEXIT_DEVIOC;
		goto done;
	}
	tracker_on = 0;

	if (send_buf(ofd, iobuf, 0, 0)) {
		ploop_err(errno, "write4");
		ret = SYSEXIT_WRITE;
		goto done;
	}

done:
	if (tracker_on) {
		if (ioctl(devfd, PLOOP_IOC_TRACK_ABORT, 0))
			ploop_err(errno, "PLOOP_IOC_TRACK_ABORT");
	}
	if (iobuf)
		free(iobuf);
	if (devfd >=0)
		close(devfd);
	if (send_from)
		free(send_from);
	if (idelta.fd >= 0)
		close_delta(&idelta);
	if (vh)
		free(vh);

	return ret;
}
