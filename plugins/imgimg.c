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
	printf("pushcb %p %s\n", context, path);

	if ((new_path = safe_rename(session->os->name, session->bip_root,
								path)) == NULL)
		return -errno;
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
	struct imgimg_data *data =
		imgimg_open(name, oflag, mode, context, size, err);
	data->finished_cb = pushcb;
	return data;
}

//static int thmpushcb(void *context, char *path) {
	/*
	int handle = parse_handle(ips->handle_hdr, ips->handle_hdr_len);
	char *new_path, *name;
	GString *thmname = NULL;

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

	struct image_push_session *session = context;
	struct pushed_image *img = NULL;
	char *new_path = NULL;
	printf("pushcb %p %s\n", context, path);
	if ((new_path = safe_rename(session->os->name, session->bip_root, path)) == NULL)
		return -errno;
	img = g_new0(struct pushed_image, 1);
	img->handle = get_new_handle(session);
	if (img->handle < 0) {
		g_free(img);
		g_free(new_path);
		return -EBADR;
	}
	img->image = new_path;
	session->pushed_images = g_slist_append(session->pushed_images, img);
	return 0;
	*/
//	return 0;
//}

static void *image_push_thm_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimg_data *data =
		imgimg_open(name, oflag, mode, context, size, err);
//	data->finished_cb = thmpushcb;
	return data;
}

static ssize_t add_reply_handle(void *buf, size_t mtu, uint8_t *hi, int handle)
{
	GString *handle_str = g_string_new("");
	uint8_t *handle_hdr;
	unsigned int handle_hdr_len;

	if (handle < 0 || handle >= HANDLE_LIMIT) {
		g_string_free(handle_str, TRUE);
		return -EBADR;
	}
	g_string_append_printf(handle_str, "%07d", handle);
	handle_hdr = encode_img_handle(handle_str->str, handle_str->len,
							&handle_hdr_len);
	g_string_free(handle_str, TRUE);

	if (handle_hdr == NULL)
		return -ENOMEM;

	*hi = IMG_HANDLE_HDR;

	if (handle_hdr_len > mtu) {
		g_free(handle_hdr);
		return -ENOMEM;
	}
	printf("%p %p %d\n", buf, handle_hdr, handle_hdr_len);
	g_memmove(buf, handle_hdr, handle_hdr_len);
	g_free(handle_hdr);
	return handle_hdr_len;
}

static ssize_t imgimg_get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi) {
	struct imgimg_data *data = object;
	ssize_t len;
	printf("imgimg_get_next_header\n");
	if (data->handle_sent)
		return 0;
	if ((len = add_reply_handle(buf, mtu, hi, data->handle)) < 0)
		return len;
	data->handle_sent = TRUE;
	return len;
}

static int imgimg_flush(void *object)
{
	struct imgimg_data *data = object;
	int err, handle;
	printf("imgimg_flush\n");
	if (data->finished_cb != NULL)
		if ((err = data->finished_cb(data->context, data->path,
								&handle)) < 0)
			return err;
	data->handle = handle;
	return 0;
}

static int imgimg_close(void *object)
{
	struct imgimg_data *data = object;
	printf("imgimg_close\n");

	if (close(data->fd) < 0)
		return -errno;

	return 0;
}

static ssize_t imgimg_write(void *object, const void *buf, size_t count)
{
	struct imgimg_data *data = object;
	ssize_t ret = write(data->fd, buf, count);
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
	.flush = imgimg_flush,
	.get_next_header = imgimg_get_next_header,
};

static struct obex_mime_type_driver imgimgthm = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = image_push_thm_open,
	.close = imgimg_close,
	.write = imgimg_write,
};

void *img_capabilities_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	GString *capabilities = g_string_new(CAPABILITIES_BEGIN);
	capabilities = g_string_append(capabilities, IMAGE_FORMATS);
	capabilities = g_string_append(capabilities, CAPABILITIES_END);

	if (err)
		*err = 0;

	return capabilities;
}

ssize_t img_capabilities_read(void *object, void *buf, size_t count)
{
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

	if ((res = obex_mime_type_driver_register(&imgimgthm)) < 0) {
		return res;
	}
	return obex_mime_type_driver_register(&imgimg);
}

static void imgimg_exit(void)
{
	obex_mime_type_driver_unregister(&imgimg);
	obex_mime_type_driver_unregister(&imgimgthm);
	obex_mime_type_driver_unregister(&img_capabilities);
}

OBEX_PLUGIN_DEFINE(imgimg, imgimg_init, imgimg_exit)
