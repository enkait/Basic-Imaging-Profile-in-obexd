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

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imgattpull.h"
#include "imglisting.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"

struct imgattpull_data {
	struct image_pull_session *context;
	int handle, fd;
	const char *name;
};

static char *get_att_path(const char *image_path, const char *name, int *err) {
	struct dirent *file;
	struct stat file_stat;
	char *att_dir_path = get_att_dir(image_path);
	DIR *att_dir = opendir(att_dir_path);
	char *ret = NULL;

	printf("%s\n", att_dir_path);

	if (att_dir == NULL) {
		if (err == NULL)
			*err = -ENOENT;
		goto done;
	}
	
	while ((file = readdir(att_dir)) != NULL) {
		char *path = g_build_filename(att_dir_path, file->d_name, NULL);
		printf("path: %s\n", path);
		if (lstat(path, &file_stat) < 0) {
			g_free(path);
			continue;
		}
		
		printf("%d\n", file_stat.st_mode);

		if (!S_ISREG(file_stat.st_mode)) {
			g_free(path);
			continue;
		}

		printf("porownojemy: %s %s\n", file->d_name, name);

		if (g_str_equal(file->d_name, name)) {
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
	struct imgattpull_data *data = g_new0(struct imgattpull_data, 1);

	data->handle = -1;
	data->fd = -1;
	data->context = context;
	data->name = name;

	if (err)
		*err = 0;

	return data;
}

static int feed_next_header(void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgattpull_data *data = object;
	struct image_pull_session *session = data->context;
	struct img_listing *il;
	int err, handle;

	if (data == NULL)
		return -EBADR;
	printf("feed_next_header\n");

	if (hi == IMG_HANDLE_HDR) {
		unsigned int hdr_len;
		char *header;

		if (!parse_bip_header(&header, &hdr_len, hi, hv.bs, hv_size))
			return -EBADR;
		handle = parse_handle(header, hdr_len);

		if (handle < 0)
			return -EBADR;

		data->handle = handle;
	}
	else if (hi == OBEX_HDR_EMPTY) {
		char *att_path = NULL;
		const char *name = data->name;
		handle = data->handle;

		if (handle == -1)
			return -ENOENT;

		if ((il = get_listing(session->image_list, handle, &err))
								== NULL)
			return err;

		if ((att_path = get_att_path(il->image, name, &err)) == NULL)
			return err;

		data->fd = open(att_path, O_RDONLY, 0);
		g_free(att_path);

		if (data->fd < 0)
			return -errno;
	}
	return 0;
}

static ssize_t imgattpull_read(void *object, void *buf, size_t count)
{
	ssize_t ret;
	
	printf("imgattpull_read %p %p %u\n", object, buf, count);

	ret = read(GPOINTER_TO_INT(object), buf, count);
	printf("read %u\n", ret);
	if (ret < 0)
		return -errno;

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
	.feed_next_header = feed_next_header,
};

static struct obex_mime_type_driver imgattpull_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-attachment",
	.open = imgattpull_open,
	.close = imgattpull_close,
	.read = imgattpull_read,
	.feed_next_header = feed_next_header,
};

static int imgattpull_init(void)
{
	int ret;
	if ((ret = obex_mime_type_driver_register(&imgattpull)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imgattpull_aos);
}

static void imgattpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgattpull_aos);
	obex_mime_type_driver_unregister(&imgattpull);
}

OBEX_PLUGIN_DEFINE(imgattpull, imgattpull_init, imgattpull_exit)
