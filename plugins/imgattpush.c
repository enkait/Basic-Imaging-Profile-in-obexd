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

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imgattpush.h"
#include "image_push.h"
#include "filesystem.h"
#include "bip_util.h"

#define EOL_CHARS "\n"

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

struct imgattpush_data {
	int fd;
	struct image_push_session *context;
	char *path, *att_path, *name;
	int handle;
};

struct att_desc {
	char *name;
};

static void att_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	char **desc = user_data;
	gchar **key;

	printf("element: %s\n", element);
	printf("names\n");

	if (g_str_equal(element, "attachment") != TRUE)
		return;

	printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++) {
		printf("key: %s\n", *key);
		if (g_str_equal(*key, "name")) {
			*desc = g_strdup(*values);
			printf("name: %s\n", *desc);
		}
	}
}

static const GMarkupParser handles_desc_parser = {
	att_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static char *parse_att_desc(const char *data, unsigned int length)
{
	char *desc = NULL;
	GMarkupParseContext *ctxt = g_markup_parse_context_new(&handles_desc_parser,
			0, &desc, NULL);
	g_markup_parse_context_parse(ctxt, data, length, NULL);
	g_markup_parse_context_free(ctxt);
	return desc;
}

static void *imgattpush_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgattpush_data *data = NULL;
	printf("imgattpush_open\n");

	if (err != NULL)
		*err = 0;
	
	data = g_new0(struct imgattpush_data, 1);
	data->context = context;
	data->handle = -1;

	return data;
}

static int feed_next_header(void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgattpush_data *data = object;
	struct image_push_session *session = data->context;
	int handle;

	if (data == NULL)
		return -EBADR;

	if (hi == IMG_HANDLE_HDR) {
		unsigned int hdr_len;
		char *header;

		header = decode_img_handle(hv.bs, hv_size, &hdr_len);

		if (header == NULL)
			return -EBADR;

		handle = parse_handle(header);

		if (handle < 0)
			return -EBADR;

		data->handle = handle;
	}
	else if (hi == IMG_DESC_HDR) {
		if (data->name != NULL)
			return -EBADR;

		data->name = parse_att_desc((char *) hv.bs, hv_size);

		if (data->name == NULL)
			return -EBADR;
	}
	else if (hi == OBEX_HDR_EMPTY) {
		struct pushed_image *pi;
		if (data->handle < 0)
			return -EBADR;

		if ((pi = get_pushed_image(session->pushed_images,
						data->handle)) == NULL)
			return -ENOENT;

		data->att_path = get_att_dir(pi->image);
		free_pushed_image(pi);

		if (data->att_path == NULL)
			return -ENOMEM;

		data->fd = g_file_open_tmp(NULL, &data->path, NULL);

		if (data->fd < 0)
			return -errno;
	}
	return 0;
}

static int imgattpush_flush(void *object) {
	struct imgattpush_data *data = object;
	struct stat file_stat;
	char *new_path;
	int err;

	if (mkdir(data->att_path, 0700) < 0) {
		if (-errno != EEXIST)
			return -errno;
		if (lstat(data->att_path, &file_stat) < 0)
			return -errno;
		if (!S_ISDIR(file_stat.st_mode))
			return -EBADR;
	}

	if ((new_path = safe_rename(data->name, data->att_path, data->path,
							&err)) == NULL) {
		return -EBADR;
	}
	g_free(new_path);
	return 0;
}

static int imgattpush_close(void *object)
{
	struct imgattpush_data *data = object;
	if (data->fd >= 0 && close(data->fd) < 0)
		return -errno;
	printf("imgattpush_close\n");
	return 0;
}

static ssize_t imgattpush_write(void *object, const void *buf, size_t count)
{
	struct imgattpush_data *data = object;
	ssize_t ret = write(data->fd, buf, count);
	printf("imgattpush_write\n");
	if (ret < 0)
		return -errno;
	return ret;
}

static struct obex_mime_type_driver imgattpush = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-attachment",
	.open = imgattpush_open,
	.close = imgattpush_close,
	.write = imgattpush_write,
	.flush = imgattpush_flush,
	.feed_next_header = feed_next_header,
};

static int imgattpush_init(void)
{
	return obex_mime_type_driver_register(&imgattpush);
}

static void imgattpush_exit(void)
{
	obex_mime_type_driver_unregister(&imgattpush);
}

OBEX_PLUGIN_DEFINE(imgattpush, imgattpush_init, imgattpush_exit)
