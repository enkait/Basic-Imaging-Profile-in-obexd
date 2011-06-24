/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <wait.h>

#include <glib.h>
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>
#include "wand/MagickWand.h"

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imgattpull.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
	0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
	0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static const char * att_suf = "_att";

static char *get_att_dir(const char *image_path) {
	GString *att_path = g_string_new(image_path);
	att_path = g_string_append(att_path, att_suf);
	return g_string_free(att_path, FALSE);
}

static char *verify_attachment(const char *image_path, const char *name) {
	struct dirent *file;
	struct stat file_stat;
	char *att_dir_path = get_att_dir(image_path);
	DIR *att_dir = opendir(att_dir_path);
	char *ret = NULL;

	printf("%s\n", att_dir_path);

	if (att_dir == NULL)
		goto done;
	
	while ((file = readdir(att_dir)) != NULL) {
		char *path = g_build_filename(att_dir_path, file->d_name, NULL);
		printf("path: %s\n", path);
		lstat(path, &file_stat);
		
		printf("%d\n", file_stat.st_mode);

		if (!S_ISREG(file_stat.st_mode)) {
			printf("nie baldzo: %s\n", path);
			g_free(path);
			continue;
		}

		printf("porownojemy: %s %s\n", file->d_name, name);

		if (g_strcmp0(file->d_name, name) == 0) {
			printf("attachment path: %s\n", path);
			ret = path;
			goto done;
		}
		g_free(path);
	}
	printf("attachment not found\n");

done:
	g_free(att_dir_path);
	return ret;
}

static void *imgattpull_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	char *att_path;
	int handle;
	struct img_listing *il;
	int fd = -1;

	if (err)
		*err = 0;
	
	printf("imgattpull_open\n");
	printf("name: %s\n", name);

	handle = get_handle(session->handle_hdr, session->handle_hdr_len);

	if (handle == -1)
		goto enoent;

	printf("handle = %d\n", handle);

	if ((il = get_listing(session, handle)) == NULL)
		goto enoent;

	if ((att_path = verify_attachment(il->image, name)) == NULL)
		goto enoent;

	printf("path: %s\n", att_path);

	fd = open(att_path, oflag, mode);
	g_free(att_path);
	printf("fd = %d\n", fd);

	if (fd == -1)
		goto enoent;

	return GINT_TO_POINTER(fd);
enoent:
	if (err)
		*err = -ENOENT;
	return NULL;
}

static ssize_t imgattpull_read(void *object, void *buf, size_t count,
		uint8_t *hi)
{
	ssize_t ret;
	
	printf("imgattpull_read %p %p %u\n", object, buf, count);

	ret = read(GPOINTER_TO_INT(object), buf, count);
	printf("read %u\n", ret);
	if (ret < 0)
		return -errno;

	*hi = OBEX_HDR_BODY;

	return ret;
}

static int imgattpull_close(void *object)
{
	if (close(GPOINTER_TO_INT(object)) < 0)
		return -errno;

	return 0;
}

static struct obex_mime_type_driver imgattpull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-attachment",
	.open = imgattpull_open,
	.close = imgattpull_close,
	.read = imgattpull_read,
};


static int imgattpull_init(void)
{
	return obex_mime_type_driver_register(&imgattpull);
}

static void imgattpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgattpull);
}

OBEX_PLUGIN_DEFINE(imgattpull, imgattpull_init, imgattpull_exit)