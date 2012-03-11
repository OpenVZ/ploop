#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/vfs.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>

#include "ploop.h"

#define PLOOP_STATFS_FNAME	".statfs"
#define NFS_SUPER_MAGIC		0x6969

static int check_fs_type(const char *path, long magic)
{
	struct statfs st;

	if (statfs(path, &st) != 0) {
		ploop_err(errno, "statfs(%s)", path);
		return -1;
	}
	if (st.f_type == magic)
		return 1;
	return 0;
}

int ploop_is_on_nfs(const char *path)
{
	return check_fs_type(path, NFS_SUPER_MAGIC);
}

int get_statfs_info(const char *mnt, struct ploop_info *info)
{
	struct statfs fs;

	if (statfs(mnt, &fs)) {
		ploop_err(errno, "statfs(%s)", mnt);
		return -1;
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
	char fname[MAXPATHLEN];
	struct ploop_info info;

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, "/"PLOOP_STATFS_FNAME);

	if (get_statfs_info(mnt, &info))
		return -1;

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		ploop_err(errno, "Can't create file %s",
				fname);
		return -1;
	}
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
	char fname[MAXPATHLEN];

	get_basedir(image, fname, sizeof(fname)-sizeof(PLOOP_STATFS_FNAME));
	strcat(fname, "/"PLOOP_STATFS_FNAME);

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

int is_magic_fname(const char *fname)
{
	char *p = strrchr(fname, '.');

	if (p != NULL && strcmp(p + 1, BASE_UUID_MAGIC) == 0)
		return 1;
	return 0;
}
