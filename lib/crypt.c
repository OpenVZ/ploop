/*
 *  Copyright (c) 2005-2017 Parallels International GmbH.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "libploop.h"
#include "ploop.h"

#define CRYPT_BIN	"/usr/libexec/ploop/crypthelper"
#define CRYPT_PREFIX	"CRYPT-"

const char *get_basename(const char *path)
{
	char *x = strrchr(path, '/');

	return x ? ++x : path;
}

const char *crypt_get_device_name(const char *part, char *out, int len)
{
	snprintf(out, len, "/dev/mapper/"CRYPT_PREFIX"%s", get_basename(part));

	return out;
}

int get_crypt_layout(const char *devname, const char *partname)
{
	if (strstr(devname, CRYPT_PREFIX))
		return CRYPT_V2;
	if (strstr(partname, CRYPT_PREFIX))
		return CRYPT_V1;
	return CRYPT_NONE;
}

static char **get_param(const char *devname, const char *partname,
		const char *keyid)
{
	char x[256];
	int i = 0;
	char **env = (char **)malloc(sizeof(char *)* 4);

	if (env == NULL)
		return NULL;

	if (devname) {
		snprintf(x, sizeof(x), "DEVICE=%s", devname);
		env[i++] = strdup(x);
	}

	if (partname) {
		snprintf(x, sizeof(x), "DEVICE_NAME=%s", partname);
		env[i++] = strdup(x);
	}
	if (keyid) {
		snprintf(x, sizeof(x), "KEYID=%s", keyid);
		env[i++] = strdup(x);
	}
	env[i] = NULL;

	return env;

}

static int do_crypt(const char *action, const char *devname,
		const char *partname, const char *keyid)
{
	int ret = 0, rc = 0;
	char *const arg[] = {CRYPT_BIN,(char *) action, NULL};
	char **env = get_param(devname, partname, keyid);

	ploop_log(0, "Crypt %s dev=%s part=%s",
			action, devname ?: "", partname ?: "");
	if (run_prg_rc(arg, env, 0, &rc))
		ret = SYSEXIT_CRYPT;

	if (rc) {
		ploop_err(0, "Command %s %s exited with code %d",
				arg[0], arg[1], rc);
		ret = SYSEXIT_CRYPT;
	}
	ploop_free_array(env);

	return ret;
}

int crypt_init(const char *device, const char *keyid)
{
	return do_crypt("init", device, NULL, keyid);
}

int crypt_open(const char *device, const char *keyid)
{
	int rc, luks;
	char cryptdev[64];
	char name[64];

	rc = is_luks(device, &luks);
	if (rc)
		return rc;

	snprintf(cryptdev, sizeof(cryptdev), "%s", device);
	if (!luks) {
		int gpt;

		rc = has_partition(device, &gpt);
		if (rc)
			return rc;

		if (gpt)
			snprintf(cryptdev, sizeof(cryptdev), "%sp1", device);
	}

	crypt_get_device_name(cryptdev, name, sizeof(name));
	rc = do_crypt("open", cryptdev, get_basename(name), keyid);
	if (rc)
		return rc;

	if (luks)
		reread_part(name);

	return 0;
}

static int crypt_close_v1(const char *devname)
{
	return do_crypt("close", NULL, devname, NULL);
}

static int crypt_close_v2(const char *devname, const char *partname)
{
	int ret = dm_remove(partname, PLOOP_UMOUNT_TIMEOUT);
	if (ret)
		return ret;

	return do_crypt("close", NULL, devname, NULL);
}

int crypt_close(const char *devname, const char *partname)
{
	if (get_crypt_layout(devname, partname) == CRYPT_V2)
		return crypt_close_v2(devname, partname);

	return crypt_close_v1(partname);
}

int crypt_resize(const char *part)
{
	return do_crypt("resize", NULL, part, NULL);
}

int crypt_changekey(const char *device, const char *keyid,
		const char *new_keyid)
{
	return do_crypt("changekey", device, new_keyid, keyid);
}

static int do_copy(char *src, char *dst)
{
	char s[PATH_MAX];
	char *arg[] = {"rsync", "-a", "--acls", "--xattrs", "--hard-links",
			s, dst, NULL};

	snprintf(s, sizeof(s), "%s/", src);

	return run_prg(arg);
}

static int encrypt_image(struct ploop_disk_images_data *di,
		struct ploop_encrypt_param *param)
{
	int ret;
	char dir[PATH_MAX];
	char ddxml[PATH_MAX];
	char image[PATH_MAX];
	char bak[PATH_MAX] = "";
	const char *keyid = param->keyid && param->keyid[0] != '\0' ?
			param->keyid : NULL;
	struct ploop_mount_param m = {
		.mount_data = (char *)param->mnt_opts,
	};
	struct ploop_mount_param m_enc = {
		.mount_data = (char *)param->mnt_opts,
	};
	struct ploop_disk_images_data *di_enc = NULL;
	struct ploop_create_param c_enc = {
		.size = di->size,
		.image = image,
		.blocksize = di->blocksize,
		.keyid = keyid,
		.fstype = "",
	};
	int wipe = param->flags & PLOOP_ENC_WIPE;


	if (ploop_is_mounted(di)) {
		ploop_err(0, "Encryption of mounted disk image is prohibited");
		return SYSEXIT_PARAM;
	}

	ploop_log(0, "Encrypt ploop image %s", di->images[0]->file);
	get_basedir(di->images[0]->file, dir, sizeof(dir) - 4);
	strcat(dir, "enc");
	if (mkdir(dir, 0755 ) && errno != EEXIST) {
		ploop_err(errno, "mkdir %s", dir);
		ploop_unlock_dd(di);
		return SYSEXIT_MKDIR;
	}

	snprintf(image, sizeof(image), "%s/%s", dir,
			get_basename(di->images[0]->file));
	ret = ploop_create_image(&c_enc);
	if (ret)
		goto err;

	snprintf(ddxml, sizeof(ddxml), "%s/" DISKDESCRIPTOR_XML, dir);
	ret = ploop_open_dd(&di_enc, ddxml);
	if (ret)
		goto err;

	ret = ploop_read_dd(di_enc);
	if (ret)
		goto err;

	ret = auto_mount_image(di_enc, &m_enc);
	if (ret)
		goto err;

	ret = auto_mount_image(di, &m);
	if (ret)
		goto err;

	ret = do_copy(m.target, m_enc.target);
	if (ret)
		goto err;

	ret = ploop_umount(m.device, di);
	if (ret)
		goto err;

	ret = ploop_umount(m_enc.device, di_enc);
	if (ret)
		goto err;

	if (wipe && di->enc == NULL && keyid != NULL) {
		snprintf(bak, sizeof(bak), "%s.orig", di->images[0]->file);
		if (rename(di->images[0]->file, bak)) {
			ploop_err(errno, "Can't rename %s to %s",
					di->images[0]->file, bak);
			ret = SYSEXIT_RENAME;
			goto err;
		}
	}

	if (rename(image, di->images[0]->file)) {
		ploop_err(errno, "Can't rename %s to %s",
				image, di->images[0]->file);
		ret = SYSEXIT_RENAME;
		goto err;
	}

	if (rename(ddxml, di->runtime->xml_fname)) {
		ploop_err(errno, "Can't rename %s to %s",
				ddxml, di->runtime->xml_fname);
		ret = SYSEXIT_RENAME;
		goto err;
	}

	if (bak[0] != '\0') {
		char *cmd[] = {"shred", "-n1", bak, NULL};
		run_prg(cmd);
		if (unlink(bak))
			ploop_err(errno, "Can't unlink %s", bak);
	}

	ploop_log(0, "Ploop image %s has been successfully encrypted",
				di->images[0]->file);

	free_mount_param(&m);
	free_mount_param(&m_enc);
	if (di_enc)
		ploop_close_dd(di_enc);

	ploop_unlock_dd(di);

	return 0;

err:
	if (m.device[0] != '\0')
		ploop_umount(m.device, di);
	if (m_enc.device[0] != '\0')
		ploop_umount(m_enc.device, di_enc);

	if (wipe && di->enc != NULL && keyid == NULL ) {
		char *cmd[] = {"shred", "-n1", image, NULL};
		run_prg(cmd);
	}

	char *cmd[] = {"rm", "-rf", dir, NULL};
	run_prg(cmd);

	free_mount_param(&m);
	free_mount_param(&m_enc);
	if (di_enc)
		ploop_close_dd(di_enc);


	return ret;
}

static int change_key(struct ploop_disk_images_data *di,
		struct ploop_encrypt_param *param)
{
	int ret, rc;
	char ddxml[PATH_MAX];
	char tmp[PATH_MAX];
	char devname[64];
	int was_mounted = 0;
	struct ploop_mount_param m = {};
	char *keyid;

	if (di->enc == NULL || param->keyid[0] == '\0')
		return encrypt_image(di, param);

	keyid = strdupa(di->enc->keyid);

	ploop_log(0, "Change encryption key %s -> %s",
			keyid, param->keyid);
	rc = ploop_find_dev_by_dd(di, m.device, sizeof(m.device));
	if (rc == -1) {
		ret = SYSEXIT_SYS;
	} else if (rc != 0) {
		ret = ploop_mount(di, NULL, &m, (di->mode == PLOOP_RAW_MODE));
		if (ret)
			return ret;
		was_mounted = 1;
	}

	ret = get_partition_device_name(m.device, devname, sizeof(devname));
	if (ret)
		goto err;

	get_disk_descriptor_fname(di, ddxml, sizeof(ddxml));
	snprintf(tmp, sizeof(tmp), "%s.tmp", ddxml);
	ret = set_encryption_keyid(di, param->keyid);
	if (ret)
		goto err;
	ret = ploop_store_diskdescriptor(tmp, di);
	if (ret)
		goto err;

	ret = crypt_changekey(devname, keyid, param->keyid);
	if (ret)
		goto err;

	if (rename(tmp, ddxml)) {
		ploop_err(errno, "Cannot rename %s -> %s", tmp, ddxml);
		ret = SYSEXIT_RENAME;
		goto err;
	}

	ret = 0;
err:
	if (was_mounted)
		ploop_umount(m.device, di);
	unlink(tmp);

	return ret;
}

int ploop_encrypt_image(struct ploop_disk_images_data *di,
		struct ploop_encrypt_param *param)
{
	int ret;

	if (param->keyid == NULL) {
		ploop_err(9, "Keyid is not specified");
		return SYSEXIT_PARAM;
	}

	if (ploop_lock_dd(di))
		return SYSEXIT_LOCK;

	if (di->images == NULL) {
		ploop_unlock_dd(di);
		return SYSEXIT_PARAM;
	}

	if (param->flags & PLOOP_ENC_REENCRYPT)
		ret = encrypt_image(di, param);
	else
		ret = change_key(di, param);

	ploop_unlock_dd(di);
	return ret;
}
