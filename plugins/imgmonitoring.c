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
#include "imglisting.h"
#include "image_pull.h"
#include "remote_camera.h"
#include "filesystem.h"
#include "bip_util.h"

#define STOREFLAG_TAG 0x0A
#define STOREFLAG_LEN 0x01

struct imgmonitoring_data {
	gboolean storeflag, gotaparam, transfering, handle_sent;
	struct remote_camera_session *context;
	char *image, *monit_image;
	int fd, handle;
};

struct imgmonitoring_aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

static int parse_aparam(const uint8_t *buffer, uint32_t hlen,
							gboolean *storeflag)
{
	struct imgmonitoring_aparam_header *hdr;
	uint32_t len = 0;

	while (len < hlen) {
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
			case STOREFLAG_TAG:
				if (hdr->len != STOREFLAG_LEN)
					return -EBADR;
				*storeflag = hdr->val[0];
				break;

			default:
				return -EBADR;
		}

		len += hdr->len + sizeof(struct imgmonitoring_aparam_header);
	}

	DBG("sf %x", *storeflag);

	return 0;
}

static void *imgmonitoring_open(const char *name, int oflag,
			mode_t mode, void *context, size_t *size, int *err)
{
	struct imgmonitoring_data *data = g_new0(struct imgmonitoring_data, 1);
	printf("imgmonitoring_open\n");
	data->context = context;
	data->handle = -1;
	return data;
}

static int feed_next_header(void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgmonitoring_data *data = object;
	if (data == NULL)
		return -EBADR;
	printf("feed_next_header\n");

	if (hi == OBEX_HDR_APPARAM) {
		if (parse_aparam(hv.bs, hv_size, &data->storeflag) < 0)
			return -EBADR;
		data->gotaparam = TRUE;
	}
	else if (hi == OBEX_HDR_EMPTY) {
		if (!data->gotaparam)
			return -EBADR;
	}
	return 0;
}

static void get_monitoring_image_cb(void *user_data, char *monit_image,
							char *image, int err)
{
	struct imgmonitoring_data *data = user_data;
	struct img_listing *il = NULL;
	struct remote_camera_session *context = data->context;

	printf("get_monitoring_image_cb\n");

	if (err < 0) {
		obex_object_set_io_flags(user_data, G_IO_ERR, err);
		return;
	}
	err = 0;

	data->monit_image = monit_image;
	data->image = image;
	data->fd = open(data->monit_image, O_RDONLY, 0);

	if (data->fd < 0) {
		obex_object_set_io_flags(user_data, G_IO_ERR, -errno);
		return;
	}

	data->transfering = TRUE;

	if (!data->storeflag) {
		obex_object_set_io_flags(user_data, G_IO_IN, 0);
		return;
	}

	data->handle = get_new_handle_rc(data->context);

	if (data->handle < 0) {
		obex_object_set_io_flags(user_data, G_IO_ERR, -EBADR);
		return;
	}

	il = get_img_listing(data->image, data->handle, &err);

	if (il == NULL) {
		obex_object_set_io_flags(user_data, G_IO_ERR, err);
		return;
	}

	context->image_list = g_slist_append(context->image_list, il);

	obex_object_set_io_flags(user_data, G_IO_IN, 0);
}

static ssize_t imgmonitoring_get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct imgmonitoring_data *data = object;
	int ret = 0;
	printf("imgimg_get_next_header\n");

	if (data == NULL) {
		return -EBADR;
	}

	if (!data->transfering) {
		if ((ret = get_monitoring_image(data->storeflag,
					get_monitoring_image_cb, data)) < 0)
			return ret;
		printf("EAGAIN\n");
		return -EAGAIN;
	}

	if (!data->handle_sent) {
		ssize_t len = 0;
		if ((len = add_reply_handle(buf, mtu, hi, data->handle)) < 0) {
			printf("LEN = %d\n", len);
			return len;
		}
		data->handle_sent = TRUE;
		return len;
	}
	*hi = OBEX_HDR_EMPTY;
	return 0;
}

static ssize_t imgmonitoring_read(void *object, void *buf, size_t count)
{
	struct imgmonitoring_data *data = object;
	int ret;
	printf("imgmonitoring_read\n");
	if (data == NULL)
		return -EBADR;

	ret = read(data->fd, buf, count);
	if (ret < 0)
		return -errno;
	return ret;
}

static int imgmonitoring_close(void *object)
{
	return 0;
}

static struct obex_mime_type_driver imgmonitoring = {
	.target = REMOTE_CAMERA_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-monitoring",
	.open = imgmonitoring_open,
	.close = imgmonitoring_close,
	.feed_next_header = feed_next_header,
	.get_next_header = imgmonitoring_get_next_header,
	.read = imgmonitoring_read,
};

static int imgmonitoring_init(void)
{
	return obex_mime_type_driver_register(&imgmonitoring);
}

static void imgmonitoring_exit(void)
{
	obex_mime_type_driver_unregister(&imgmonitoring);
}

OBEX_PLUGIN_DEFINE(imgmonitoring, imgmonitoring_init, imgmonitoring_exit)
