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
#include "imgimgpull.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"

#define EOL_CHARS "\n"

#define IMG_LISTING_BEGIN "<images-listing version=\"1.0\">" EOL_CHARS

#define IMG_LISTING_ELEMENT "<image handle=\"%s\" created=\"%s\" modified=\"%s\">" EOL_CHARS

#define IMG_LISTING_END "</images-listing>" EOL_CHARS

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
	0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
	0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

struct image_desc {
	char *encoding;
	unsigned int lower[2], upper[2];
	gboolean fixed_ratio;
	unsigned int maxsize;
	char *transform;
};

static struct image_desc *new_image_desc() {
	struct image_desc *desc = g_try_new0(struct image_desc, 1);
	desc->upper[0] = desc->upper[1] = -1;
	desc->maxsize = -1;
	return desc;
}

static void free_image_desc(struct image_desc *desc) {
	g_free(desc->encoding);
	g_free(desc->transform);
	g_free(desc);
}

static void image_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	struct image_desc *desc = user_data;
	gchar **key;

	printf("element: %s\n", element);
	printf("names\n");

	if (g_str_equal(element, "image") != TRUE)
		return;

	printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++) {
		printf("key: %s\n", *key);
		if (g_str_equal(*key, "maxsize")) {
			sscanf(*values, "%u", &desc->maxsize);
			printf("maxsize: %u\n", desc->maxsize);
		}
		else if (g_str_equal(*key, "encoding")) {
			desc->encoding = g_strdup(*values);
			printf("encoding: %s\n", desc->encoding);
		}
		else if (g_str_equal(*key, "transformation")) {
			desc->transform = g_strdup(*values);
			printf("transform: %s\n", desc->transform);
		}
		else if (g_str_equal(*key, "pixel")) {
			parse_pixel_range(*values, desc->lower, desc->upper, &desc->fixed_ratio);
			printf("pixel: %u %u %u %u %d\n", desc->lower[0], desc->lower[1], desc->upper[0], desc->upper[1], desc->fixed_ratio);
		}
	}
}


static const GMarkupParser image_desc_parser = {
	image_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static struct image_desc *parse_image_desc(char *data, unsigned int length)
{
	struct image_desc *desc = new_image_desc();
	GMarkupParseContext *ctxt = g_markup_parse_context_new(&image_desc_parser,
			0, desc, NULL);
	g_markup_parse_context_parse(ctxt, data, length, NULL);
	g_markup_parse_context_free(ctxt);
	return desc;
}

static int get_handle(char *data, unsigned int length)
{
	int handle;
	sscanf(data, "%d", &handle);
	return handle;
}

static int get_image_fd(char *image_path, struct image_desc *desc) {
	int fd;
	GString *new_image_path = g_string_new(image_path);
	struct image_attributes attr;
	new_image_path = g_string_append(new_image_path, "XXXXXX");
	
	if ((fd = mkstemp(new_image_path->str)) < 0)
		return -1;

	attr.format = desc->encoding;
	attr.width = desc->upper[0];
	attr.height = desc->upper[1];
	if (make_modified_image(image_path, new_image_path->str, &attr,
				desc->transform) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void *imgimgpull_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	struct image_desc *desc;
	int handle;
	GSList *images = session->image_list;
	int fd = -1;

	if (err)
		*err = 0;

	desc = parse_image_desc(session->desc_hdr, session->desc_hdr_len);
	handle = get_handle(session->handle_hdr, session->handle_hdr_len);

	while (images != NULL) {
		struct img_listing *il = images->data;
		if (il->handle == handle) {
			fd = get_image_fd(il->image, desc);
			break;
		}
		images = g_slist_next(images);
	}

	if (fd == -1)

	printf("imglisting_open\n");

	free_image_desc(desc);
	return GINT_TO_POINTER(fd);
}

static ssize_t imgimgpull_read(void *object, void *buf, size_t count,
		uint8_t *hi)
{
	ssize_t ret;

	ret = read(GPOINTER_TO_INT(object), buf, count);
	if (ret < 0)
		return -errno;

	*hi = OBEX_HDR_BODY;

	return ret;
}

static int imgimgpull_close(void *object)
{
	if (close(GPOINTER_TO_INT(object)) < 0)
		return -errno;

	return 0;
}

static struct obex_mime_type_driver imgimgpull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = imgimgpull_open,
	.close = imgimgpull_close,
	.read = imgimgpull_read,
};


static int imgimgpull_init(void)
{
	return obex_mime_type_driver_register(&imgimgpull);
}

static void imgimgpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgimgpull);
}

OBEX_PLUGIN_DEFINE(imgimgpull, imgimgpull_init, imgimgpull_exit)
