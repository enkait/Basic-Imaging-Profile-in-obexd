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
#include "imgthmpull.h"
#include "imglisting.h"
#include "image_pull.h"
#include "remote_camera.h"
#include "filesystem.h"
#include "bip_util.h"

struct imgthmpull_data {
	void *context;
	char * (*get_image_path) (void *context, int handle);
	int fd, handle;
};

static int get_thumbnail_fd(char *image_path, int *err)
{
	char *thm_path;
	int fd = g_file_open_tmp(NULL, &thm_path, NULL);

	DBG("");

	if (fd < 0) {
		if (err != NULL)
			*err = -errno;
		return -1;
	}

	if (!make_thumbnail(image_path, thm_path, err)) {
		close(fd);
		return -1;
	}
	
	unlink(thm_path);
	return fd;
}

static struct imgthmpull_data *imgthmpull_open(const char *name, int oflag,
		mode_t mode, void *context, size_t *size, int *err)
{
	struct imgthmpull_data *data = g_new0(struct imgthmpull_data, 1);

	DBG("");

	data->fd = -1;
	data->handle = -1;
	data->context = context;
	return data;
}

static char *image_pull_cb(void *context, int handle)
{
	int err = 0;
	struct image_pull_session *session = context;
	struct img_listing *il = NULL;

	DBG("");

	if (session == NULL)
		return NULL;

	il = get_listing(session->image_list, handle, &err);

	if (il == NULL)
		return NULL;

	return g_strdup(il->image);
}

static void *image_pull_open(const char *name, int oflag,
		mode_t mode, void *context, size_t *size, int *err)
{
	struct imgthmpull_data *data = imgthmpull_open(name, oflag, mode,
							context, size, err);

	DBG("");

	data->get_image_path = image_pull_cb;
	return data;
}

static char *remote_camera_cb(void *context, int handle)
{
	int err = 0;
	struct remote_camera_session *session = context;
	struct img_listing *il = NULL;

	DBG("");

	if (session == NULL)
		return NULL;

	il = get_listing(session->image_list, handle, &err);

	if (il == NULL)
		return NULL;

	return g_strdup(il->image);
}

static void *remote_camera_open(const char *name, int oflag,
		mode_t mode, void *context, size_t *size, int *err)
{
	struct imgthmpull_data *data = imgthmpull_open(name, oflag, mode,
							context, size, err);

	DBG("");

	data->get_image_path = remote_camera_cb;
	return data;
}

static int feed_next_header(void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgthmpull_data *data = object;
	char *header;
	unsigned int hdr_len;
	int err, handle;
	if (data == NULL)
		return -EBADR;

	DBG("");

	if (hi == IMG_HANDLE_HDR) {
		header = decode_img_handle(hv.bs, hv_size, &hdr_len);

		if (header == NULL)
			return -EBADR;

		handle = parse_handle(header);

		if (handle < 0)
			return -EBADR;

		data->handle = handle;
	}
	else if (hi == OBEX_HDR_EMPTY) {
		char *image_path;

		if (data->handle < 0)
			return -EBADR;

		image_path = data->get_image_path(data->context, data->handle);

		if (image_path == NULL)
			return -EBADR;

		data->fd = get_thumbnail_fd(image_path, &err);

		if (data->fd == -1)
			return -EBADR;
	}
	return 0;
}

static ssize_t imgthmpull_read(void *object, void *buf, size_t count)
{
	struct imgthmpull_data *data = object;
	ssize_t ret;

	DBG("");

	ret = read(data->fd, buf, count);
	if (ret < 0)
		return -errno;

	return ret;
}

static int imgthmpull_close(void *object)
{
	struct imgthmpull_data *data = object;

	DBG("");

	if (close(data->fd) < 0)
		return -errno;

	return 0;
}

static struct obex_mime_type_driver imgthmpull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = image_pull_open,
	.close = imgthmpull_close,
	.read = imgthmpull_read,
	.feed_next_header = feed_next_header,
};

static struct obex_mime_type_driver imgthmpull_rc = {
	.target = REMOTE_CAMERA_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = remote_camera_open,
	.close = imgthmpull_close,
	.read = imgthmpull_read,
	.feed_next_header = feed_next_header,
};

static struct obex_mime_type_driver imgthmpull_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = image_pull_open,
	.close = imgthmpull_close,
	.read = imgthmpull_read,
	.feed_next_header = feed_next_header,
};

static int imgthmpull_init(void)
{
	int ret;
	if ((ret = obex_mime_type_driver_register(&imgthmpull)) < 0)
		return ret;

	if ((ret = obex_mime_type_driver_register(&imgthmpull_rc)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imgthmpull_aos);
}

static void imgthmpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgthmpull_aos);
	obex_mime_type_driver_unregister(&imgthmpull_rc);
	obex_mime_type_driver_unregister(&imgthmpull);
}

OBEX_PLUGIN_DEFINE(imgthmpull, imgthmpull_init, imgthmpull_exit)
