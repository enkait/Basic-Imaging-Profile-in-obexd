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

#include "obex-priv.h"
#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imgimg.h"
#include "image_push.h"
#include "filesystem.h"
#include "bip_util.h"

#define HANDLE_LIMIT 10000000

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

struct imgthm_data {
	int fd;
	void *context;
	char *path;
	int handle;
	int (*finished_cb) (void *context, char *path, int handle);
	gboolean handle_sent;
};

static struct imgthm_data *imgthm_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err)
{
	struct imgthm_data *data = g_new0(struct imgthm_data, 1);
	printf("imgthm_open\n");
	data->context = context;
	data->handle = -1;

	if (!name) {
		if (err != NULL)
			*err = -errno;
		return NULL;
	}

	data->fd = g_file_open_tmp(NULL, &data->path, NULL);

	if (data->fd < 0) {
		if (err != NULL)
			*err = -errno;
		return NULL;
	}

	return data;
}

static int thmpushcb(void *context, char *path, int handle) {
	struct image_push_session *session = context;
	char *new_path = NULL, *name = NULL;
	GString *thmname = NULL;
	struct pushed_image *img = NULL;

	if (handle < 0)
		return -EBADR;
	img = get_pushed_image(ips, handle);

	if (img == NULL)
		return -EEXIST;

	printf("path: %s\n", img->image);
	name = g_path_get_basename(img->image);
	thmname = g_string_new(name);
	thmname = g_string_append(thmname, "_thm");
	g_free(name);

	if ((new_path = safe_rename(thmname->str, bip_root, ips->file_path))
								== NULL) {
		g_string_free(thmname, TRUE);
		return -errno;
	}
	g_string_free(thmname, TRUE);
	printf("newpath: %s\n", new_path);
	return 0;
}

static void *image_push_thm_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgthm_data *data =
			imgthm_open(name, oflag, mode, context, size, err);
	data->finished_cb = thmpushcb;
	return data;
}

static int imgthm_flush(void *object)
{
	struct imgthm_data *data = object;
	int err;
	printf("imgthm_flush\n");
	if (data->finished_cb != NULL)
		if ((err = data->finished_cb(data->context, data->path,
							data->handle)) < 0)
			return err;
	return 0;
}

int (*feed_next_header) (void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgthm_data *data = object;
	char *handle_hr;
	unsigned int handle_hdr_len;

	if (hi == IMG_HANDLE_HDR) {
		if (data->handle != -1)
			return -EBADR;
		if (!parse_bip_header(&handle_hdr, &handle_hdr_len, hi, hv.bs,
								hv_size))
			return -EBADR;
		data->handle = parse_handle(handle_hdr, handle_hdr_len);
		g_free(handle_hdr);

		if (data->handle < 0)
			return -EBADR;
	}
	return 0;
}

static struct obex_mime_type_driver imgthm = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = image_push_thm_open,
	.close = imgimg_close,
	.write = imgimg_write,
	.flush = imgthm_flush,
	.feed_next_header = imgthm_feed_next_header,
};

static int imgthm_init(void)
{
	return obex_mime_type_driver_register(&imgthm);
}

static void imgthm_exit(void)
{
	obex_mime_type_driver_unregister(&imgthm);
}

OBEX_PLUGIN_DEFINE(imgthm, imgthm_init, imgthm_exit)
