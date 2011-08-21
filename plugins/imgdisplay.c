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
#include "imgimgpush.h"
#include "imglisting.h"
#include "remote_display.h"
#include "filesystem.h"
#include "bip_util.h"

#define HANDLE_LIMIT 10000000

#define RD_TAG 0x08
#define RD_LEN 0x01
#define RD_OP_NEXT 0x01
#define RD_OP_PREVIOUS 0x02
#define RD_OP_SELECT 0x03
#define RD_OP_CURRENT 0x04

struct imgdisplay_data {
	void *context;
	int handle;
	int rd;

	gboolean handle_sent;
};

static void *imgdisplay_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err)
{
	struct imgdisplay_data *data = g_new0(struct imgdisplay_data, 1);
	data->context = context;
	data->handle = -1;

	return data;
}

struct aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

static int parse_aparam(const uint8_t *buffer, uint32_t hlen)
{
	struct aparam_header *hdr;
	uint32_t len = 0;
	int ret = -EBADR;

	while (len < hlen) {
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
		case RD_TAG:
			if (hdr->len != RD_LEN)
				goto failed;
			memcpy(&ret, hdr->val, sizeof(ret));
			ret = hdr->val[0];
			break;
		default:
			goto failed;
		}

		len += hdr->len + sizeof(struct aparam_header);
	}

	DBG("rd %x", ret);

	return ret;

failed:
	return -EBADR;
}

static int feed_next_header(void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgdisplay_data *data = object;
	char *header;
	unsigned int hdr_len;
	int err = 0;
	printf("feed_next_header %x\n", hi);

	if (hi == IMG_HANDLE_HDR) {
		if (data->handle != -1)
			return -EBADR;

		header = decode_img_handle(hv.bs, hv_size, &hdr_len);

		// czy to tu ma byc
		if (header == NULL)
			return -EBADR;

		data->handle = parse_handle(header);
		g_free(header);
	}
	else if (hi == OBEX_HDR_APPARAM) {
		int rd = parse_aparam(hv.bs, hv_size);
		printf("apparam header\n");

		if (rd < 0)
			return err;

		data->rd = rd;
	}
	return 0;
}

static int imgdisplay_close(void *object)
{
	return 0;
}

static ssize_t get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct imgdisplay_data *data = object;
	struct remote_display_session *session = data->context;
	ssize_t len;
	printf("imgdisplay_get_next_header\n");

	if (data == NULL)
		return -EBADR;

	if (data->handle_sent) {
		*hi = OBEX_HDR_EMPTY;
		return 0;
	}

	if ((len = add_reply_handle(buf, mtu, hi, session->displayed_handle)) < 0) {
		return len;
	}
	printf("LEN = %d\n", len);

	data->handle_sent = TRUE;
	return len;
}

static int get_max_handle(GSList *image_list) {
	int handle = -1;
	while (image_list != NULL) {
		struct img_listing *il = image_list->data;
		handle = (il->handle > handle) ? (il->handle) : (handle);
		image_list = g_slist_next(image_list);
	}
	return handle;
}

static int imgdisplay_flush(void *object)
{
	struct imgdisplay_data *data = object;
	struct remote_display_session *session = data->context;
	struct img_listing *il = NULL;
	int new_handle = -1, err;

	if (data == NULL)
		return -EBADR;

	printf("flush\n");

	printf("old image displayed: %d\n", session->displayed_handle);
	switch (data->rd) {
	case RD_OP_NEXT:
		new_handle = session->displayed_handle + 1;
		il = get_listing(session->image_list, new_handle, &err);

		if (il == NULL)
			new_handle = 0;
		il = get_listing(session->image_list, new_handle, &err);

		if (il == NULL)
			new_handle = -1;
		break;
	case RD_OP_PREVIOUS:
		new_handle = session->displayed_handle - 1;
		il = get_listing(session->image_list, new_handle, &err);

		if (il == NULL)
			new_handle = get_max_handle(session->image_list);
		break;
	case RD_OP_SELECT:
		new_handle = data->handle;
		il = get_listing(session->image_list, new_handle, &err);

		if (il == NULL)
			return -EBADR;
		break;
	case RD_OP_CURRENT:
		new_handle = session->displayed_handle;
	}
	printf("IMGDISPLAY ------------------------------------------------------------\n");
	printf("next displayed handle: %d\n", new_handle);
	if (new_handle != -1) {
		il = get_listing(session->image_list, new_handle, &err);
		if ((err = display_image(session->os->cid, il->image)) < 0) {
			return err;
		}
		session->displayed_handle = new_handle;
	}
	printf("displaying %d\n", session->displayed_handle);
	return 0;
}

static struct obex_mime_type_driver imgdisplay = {
	.target = REMOTE_DISPLAY_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-display",
	.open = imgdisplay_open,
	.close = imgdisplay_close,
	.get_next_header = get_next_header,
	.flush = imgdisplay_flush,
	.feed_next_header = feed_next_header,
};

static int imgdisplay_init(void)
{
	return obex_mime_type_driver_register(&imgdisplay);
}

static void imgdisplay_exit(void)
{
	obex_mime_type_driver_unregister(&imgdisplay);
}

OBEX_PLUGIN_DEFINE(imgdisplay, imgdisplay_init, imgdisplay_exit)
