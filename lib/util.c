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

#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/vfs.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "ploop.h"
#include "cleanup.h"

#define PLOOP_STATFS_FNAME	".statfs"

int get_statfs_info(const char *mnt, struct ploop_info *info)
{
	struct statfs fs;

	if (statfs(mnt, &fs)) {
		ploop_err(errno, "statfs(%s)", mnt);
		return SYSEXIT_FSTAT;
	}

	info->fs_bsize = fs.f_bsize;
	info->fs_blocks = fs.f_blocks;
	info->fs_bfree = fs.f_bfree;
	info->fs_inodes = fs.f_files;
	info->fs_ifree = fs.f_ffree;

	return 0;
}

int store_statfs_info(const char *mnt, char *image)
{
	int fd, ret, err = 0;
	char fname[PATH_MAX];
	struct ploop_info info;

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, PLOOP_STATFS_FNAME);

	if (get_statfs_info(mnt, &info))
		return -1;

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		ploop_err(errno, "Can't create file %s",
				fname);
		return -1;
	}
	if (fchmod(fd, 0644))
		ploop_err(errno, "Cant't chmod(644) on %s", fname);

	ret = write(fd, &info, sizeof(info));
	if (ret != sizeof(struct ploop_info)) {
		ploop_err(ret == -1 ? errno : 0, "Can't write to %s",
				fname);
		err = -1;
	}
	close(fd);
	return err;
}

int read_statfs_info(const char *image, struct ploop_info *info)
{
	int fd, ret, err = 0;
	char fname[PATH_MAX];

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, PLOOP_STATFS_FNAME);

	fd = open(fname, O_RDONLY, 0600);
	if (fd == -1) {
		if (errno != ENOENT)
			ploop_err(errno, "Can't open file %s",
					fname);
		return -1;
	}
	ret = read(fd, info, sizeof(struct ploop_info));
	if (ret != sizeof(struct ploop_info)) {
		ploop_err(ret == -1 ? errno : 0, "Can't read %s",
				fname);
		err = -1;
	}
	close(fd);
	return err;
}

int drop_statfs_info(const char *image)
{
	char fname[PATH_MAX];

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, PLOOP_STATFS_FNAME);

	if (unlink(fname) < 0 && errno != ENOENT) {
		ploop_err(errno, "Can't delete file %s", fname);
		return -1;
	}

	return 0;
}

int read_line_quiet(const char *path, char *nbuf, int len)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (fp == NULL)
		return errno;
	if (fgets(nbuf, len, fp) == NULL) {
		int err = errno;
		fclose(fp);
		return err;
	}
	fclose(fp);
	len = strlen(nbuf);
	if (len > 0 && nbuf[len-1] == '\n')
		nbuf[len-1] = 0;

	return 0;
}

int read_line(const char *path, char *nbuf, int len)
{
	int err;

	err = read_line_quiet(path, nbuf, len);
	if (err) {
		ploop_err(err, "Can't open or read %s", path);
		return -1;
	}
	return 0;
}

int is_valid_guid(const char *guid)
{
	int i;

	if (guid == NULL)
		return 0;
	if (strlen(guid) != 38)
		return 0;
	/* {5fbaabe3-6958-40FF-92a7-860e329aab41} */
	if (guid[0] != '{' || guid[37] != '}')
		return 0;
	guid++;
	for (i = 0; i < 36; i++)
		if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
			if (guid[i] != '-' )
				return 0;
		} else if (!isxdigit(guid[i]))
				return 0;
	return 1;
}

int is_valid_blocksize(__u32 blocksize)
{
	/* 32K <= blocksize <= 64M */
	if (blocksize < 64 ||
	    blocksize > B2S(64 * 1024 * 1024))
		return 0;
	if (blocksize != 1UL << (ffs(blocksize)-1))
		return 0;
	return 1;
}

int ploop_find_dev_by_dd(struct ploop_disk_images_data *di, char *out,
		int len)
{
	return find_dev(di, out, len);
}

int ploop_set_component_name(struct ploop_disk_images_data *di,
		const char *component_name)
{
	free(di->runtime->component_name);
	di->runtime->component_name = strdup(component_name);
	if (di->runtime->component_name == NULL)
		return SYSEXIT_MALLOC;
	return 0;
}

void ploop_set_umount_timeout(struct ploop_disk_images_data *di, int timeout)
{
	di->runtime->umount_timeout = timeout;
}

static void arg2str(char *const argv[], char *buf, int len)
{
	int i, r;
	char *sp = buf;
	char *ep = buf + len;

	for (i = 0; argv[i] != NULL; i++) {
		r = snprintf(sp, ep - sp, "%s ", argv[i]);
		if (r >= ep - sp)
			break;
		sp += r;
	}
}

static void cleanup_kill_process(void *data)
{
	int pid = *(int *) data;

	ploop_log(1, "Killing process %d", pid);
	kill(pid, SIGTERM);
}

static int ploop_execvp(char *const argv[], char *const env[])
{
	char *const paths[] = DEF_PATH_LIST;
	int i, ret;

	if (*(argv[0]) == '/')
		return env ? execvpe(argv[0], argv, env) : execv(argv[0], argv);

	for (i = 0; paths[i] != NULL; i++) {
		char cmd[PATH_MAX];

		snprintf(cmd, sizeof(cmd), "%s/%s", paths[i], argv[0]);

		ret = env ? execvpe(cmd, argv, env) : execv(cmd, argv);
	}

	return ret;
}

int run_prg_rc(char *const argv[], char *const env[], int hide_mask, int *rc)
{
	int pid, ret, status;
	char cmd[PATH_MAX];
	struct ploop_cleanup_hook *h;

	arg2str(argv, cmd, sizeof(cmd));
	ploop_log(1, "Running: %s", cmd);

	pid = fork();
	if (pid == 0) {
		int fd = open("/dev/null", O_RDONLY);
		if (fd >= 0) {
			dup2(fd, STDIN_FILENO);

			if (hide_mask & HIDE_STDOUT)
				 dup2(fd, STDOUT_FILENO);

			if (hide_mask & HIDE_STDERR)
				 dup2(fd, STDERR_FILENO);

			close(fd);
		} else {
			ploop_err(errno, "Can't open /dev/null");
			return -1;
		}

		ploop_execvp(argv, env);

		ploop_err(errno, "Can't exec %s", argv[0]);
		return 127;
	} else if (pid == -1) {
		ploop_err(errno, "Can't fork");
		return -1;
	}
	h = register_cleanup_hook(cleanup_kill_process, &pid);
	while ((ret = waitpid(pid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	unregister_cleanup_hook(h);
	if (ret == -1) {
		ploop_err(errno, "Can't waitpid %s", cmd);
		return -1;
	} else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (rc) {
			*rc = ret;
			return 0;
		}
		if (ret == 0)
			return 0;
		ploop_err(0, "Command %s exited with code %d", cmd, ret);
	} else if (WIFSIGNALED(status)) {
		ploop_err(0, "Command %s received signal %d",
				cmd, WTERMSIG(status));
	} else
		ploop_err(0, "Command %s died", cmd);

	return -1;
}

int run_prg(char *const argv[])
{
	char *env[] = {"PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};

	return run_prg_rc(argv, env, 0, NULL);
}

int p_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;

	ret = posix_memalign(memptr, alignment, size);
	if (ret)
		ploop_err(ret, "Memory allocation failed, posix_memalign");

	return ret;
}

const char *get_snap_str(int temporary)
{
	return temporary ? "temporary snapshot" : "snapshot";
}

int dump_bat(const char *image)
{
	int ret;
	__u32 clu, cluster, n = 0, m = 0;
	struct delta delta = {};
	struct ploop_pvd_header *hdr;

	ret = open_delta(&delta, image, O_RDONLY|O_DIRECT, OD_ALLOW_DIRTY); 
	if (ret)
		return ret;

	hdr = (struct ploop_pvd_header *) delta.hdr0;

	cluster = S2B(delta.blocksize);
	ploop_log(0, "Image %s", image);
	ploop_log(0, "Size %u blocks", hdr->m_Size);
	ploop_log(0, "FirstBlockOffset %u", hdr->m_FirstBlockOffset);
	ploop_log(0, "Cluster %u sectors", hdr->m_Sectors);
	ploop_log(0, "Fmt %d", ploop1_version(hdr));
	
	for (clu = 0; clu < hdr->m_Size; clu++) {
		int l2_cluster = (clu + PLOOP_MAP_OFFSET) / (cluster / sizeof(__u32));
		__u32 l2_slot  = (clu + PLOOP_MAP_OFFSET) % (cluster / sizeof(__u32));
		if (delta.l2_cache != l2_cluster) {
			if (PREAD(&delta, delta.l2, cluster, (off_t)l2_cluster * cluster))
				return SYSEXIT_READ;
			delta.l2_cache = l2_cluster;
		}

		if (delta.l2[l2_slot] == 0)
			continue;
		if (m < delta.l2[l2_slot])
			m = delta.l2[l2_slot];
		n++;	
		ploop_log(0, "%d -> %d", clu, delta.l2[l2_slot]);
	}

	ploop_log(0, "Allocated: %u  Max: %u", n, m);

	close_delta(&delta);
	return 0;
}

#ifndef EXT4_IOC_CLEAR_ES_CACHE
#define EXT4_IOC_CLEAR_ES_CACHE _IO('f', 40)
#endif

void clean_es_cache(int fd)
{
	if (ioctl(fd, EXT4_IOC_CLEAR_ES_CACHE) && errno != ENOTTY)
		ploop_err(errno, "Warning: ioctl(EXT4_IOC_CLEAR_ES_CACHE)");
}
