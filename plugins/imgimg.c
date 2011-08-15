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
#include "imglisting.h"
#include "image_push.h"
#include "remote_display.h"
#include "filesystem.h"
#include "bip_util.h"

#define EOL_CHARS "\n"

#define CAPABILITIES_BEGIN "<imaging-capabilities version=\"1.0\">" EOL_CHARS

#define IMAGE_FORMATS "<image-formats encoding=\"JPEG\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"GIF\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"WBMP\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"PNG\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"JPEG2000\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"BMP\" pixel=\"0*0-65535*65535\">" EOL_CHARS \

#define CAPABILITIES_END "</imaging-capabilities>" EOL_CHARS

#define HANDLE_LIMIT 10000000

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

struct imgimg_data {
	int fd;
	void *context;
	char *path;
	int handle;
	int (*finished_cb) (void *context, char *path, int *handle);
	gboolean handle_sent;
};

static struct imgimg_data *imgimg_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimg_data *data = g_new0(struct imgimg_data, 1);
	printf("imgimg_open\n");
	data->context = context;
	data->handle = -1;

	DBG("");

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

static int pushcb(void *context, char *path, int *handle_out) {
	struct image_push_session *session = context;
	struct pushed_image *img = NULL;
	char *new_path = NULL;
	int err;

	DBG("");

	if ((new_path = safe_rename(session->os->name, session->bip_root,
							path, &err)) == NULL)
		return err;
	img = g_new0(struct pushed_image, 1);
	img->handle = get_new_handle(session);

	if (img->handle < 0) {
		g_free(img);
		g_free(new_path);
		return -EBADR;
	}
	img->image = new_path;
	session->pushed_images = g_slist_append(session->pushed_images, img);
	*handle_out = img->handle;
	return 0;
}

static void *image_push_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimg_data *data;

	DBG("");

	data = imgimg_open(name, oflag, mode, context, size, err);
	data->finished_cb = pushcb;
	return data;
}

static int remote_display_cb(void *context, char *path, int *handle_out) {
	struct remote_display_session *session = context;
	struct img_listing *il = NULL;
	int err = 0, handle;

	DBG("");

	handle = get_new_handle_rd(session);

	if (handle < 0) {
		err = -EBADR;
		goto cleanup;
	}

	il = get_img_listing(path, handle, &err);

	if (il == NULL) {
		err = -EBADR;
		goto cleanup;
	}
	session->image_list = g_slist_append(session->image_list, il);
	*handle_out = il->handle;
cleanup:
	return err;
}

static void *remote_display_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimg_data *data;

	DBG("");

	data = imgimg_open(name, oflag, mode, context, size, err);
	data->finished_cb = remote_display_cb;
	return data;
}

static ssize_t imgimg_get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct imgimg_data *data = object;
	ssize_t len;
	int err, handle;

	DBG("");

	if (data->handle_sent) {
		*hi = OBEX_HDR_EMPTY;
		return 0;
	}

	g_assert(data->finished_cb != NULL);

	if ((err = data->finished_cb(data->context, data->path, &handle)) < 0)
		return err;
	data->handle = handle;

	if ((len = add_reply_handle(buf, mtu, hi, data->handle)) < 0) {
		return len;
	}
	data->handle_sent = TRUE;
	return len;
}

int imgimg_close(void *object)
{
	struct imgimg_data *data = object;

	DBG("");

	printf("imgimg_close\n");

	if (close(data->fd) < 0)
		return -errno;

	return 0;
}

ssize_t imgimg_write(void *object, const void *buf, size_t count)
{
	struct imgimg_data *data = object;
	ssize_t ret;

	DBG("");

	ret = write(data->fd, buf, count);
	printf("imgimg_write\n");
	if (ret < 0)
		return -errno;
	return ret;
}

static struct obex_mime_type_driver imgimg = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = image_push_open,
	.close = imgimg_close,
	.write = imgimg_write,
	.get_next_header = imgimg_get_next_header,
};

static struct obex_mime_type_driver imgimg_rd = {
	.target = REMOTE_DISPLAY_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = remote_display_open,
	.close = imgimg_close,
	.write = imgimg_write,
	.get_next_header = imgimg_get_next_header,
};

void *img_capabilities_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	GString *capabilities;

	DBG("");

	capabilities = g_string_new(CAPABILITIES_BEGIN);
	capabilities = g_string_append(capabilities, IMAGE_FORMATS);
	capabilities = g_string_append(capabilities, CAPABILITIES_END);

	if (err)
		*err = 0;

	return capabilities;
}

ssize_t img_capabilities_read(void *object, void *buf, size_t count)
{
	DBG("");
	return string_read(object, buf, count);
}

static struct obex_mime_type_driver img_capabilities = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-capabilities",
	.open = img_capabilities_open,
	.close = string_free,
	.read = img_capabilities_read,
};

static int imgimg_init(void)
{
	int res;
	if ((res = obex_mime_type_driver_register(&img_capabilities)) < 0) {
		return res;
	}

	if ((res = obex_mime_type_driver_register(&imgimg_rd)) < 0) {
		return res;
	}

	return obex_mime_type_driver_register(&imgimg);
}

static void imgimg_exit(void)
{
	obex_mime_type_driver_unregister(&imgimg);
	obex_mime_type_driver_unregister(&imgimg_rd);
	obex_mime_type_driver_unregister(&img_capabilities);
}

OBEX_PLUGIN_DEFINE(imgimg, imgimg_init, imgimg_exit)
