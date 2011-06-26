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
#include "imglisting.h"
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

struct image_handles_desc *new_hdesc()
{
	struct image_handles_desc *hdesc = g_new0(struct image_handles_desc, 1);
	hdesc->upper[0] = -1;
	hdesc->upper[1] = -1;
	hdesc->ctime_bounded[0] = FALSE;
	hdesc->ctime_bounded[1] = FALSE;
	hdesc->mtime_bounded[0] = FALSE;
	hdesc->mtime_bounded[1] = FALSE;
	return hdesc;
}

static void free_image_handles_desc(struct image_handles_desc *hdesc)
{
	g_free(hdesc->encoding);
	g_free(hdesc);
}

static gboolean filter_image(struct img_listing *il, const struct image_handles_desc *hdesc) {

	printf("hdesc = %p\n", hdesc);

	printf("hdesc %ld %ld\n", hdesc->ctime[0], hdesc->ctime[1]);

	if (!hdesc)
		return TRUE;

	printf("image: %s\n", il->image);

	printf("PASS: %s %d %d\n", il->image, hdesc->ctime_bounded[0], hdesc->ctime_bounded[1]);

	if (hdesc->ctime_bounded[0] && il->ctime < hdesc->ctime[0])
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->ctime_bounded[1] && il->ctime > hdesc->ctime[1])
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->mtime_bounded[0] && il->mtime < hdesc->mtime[0])
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->mtime_bounded[1] && il->mtime > hdesc->mtime[1])
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->encoding != NULL && g_strcmp0(hdesc->encoding, il->attr->format) != 0)
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->lower[0] > il->attr->width || hdesc->lower[1] > il->attr->height)
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->upper[0] < il->attr->width || hdesc->upper[1] < il->attr->height)
		return FALSE;
	printf("PASS: %s\n", il->image);

	if (hdesc->fixed_ratio && hdesc->upper[1]*il->attr->width != hdesc->upper[0]*il->attr->height)
		return FALSE;
	printf("PASS: %s\n", il->image);

	return TRUE;
}

static GString *create_images_listing(struct image_pull_session *session, int count, int offset, int *res_count, int *err, const struct image_handles_desc *hdesc) {
	GSList *images = NULL;
	GString *listing_obj = g_string_new(IMG_LISTING_BEGIN);
	char mtime[18], ctime[18];
	char handle_str[8];

	images = session->image_list;

	if (res_count != NULL)
		*res_count = 0;
	while (images != NULL && count > 0) {
		struct img_listing *listing = images->data;
		printf("filtering: %s\n", listing->image);
		printf("%p\n", filter_image);
		if (!filter_image(listing, hdesc)) {
			images = g_slist_next(images);
			continue;
		}
		
		if (offset == 0) {
			strftime(mtime, 17, "%Y%m%dT%H%M%SZ", gmtime(&listing->mtime));
			strftime(ctime, 17, "%Y%m%dT%H%M%SZ", gmtime(&listing->ctime));
			snprintf(handle_str, 8, "%07d", listing->handle);
			g_string_append_printf(listing_obj, IMG_LISTING_ELEMENT, handle_str, ctime, mtime);
			if (res_count != NULL)
				(*res_count)++;
			count--;
		}
		else
			offset--;
		
		images = g_slist_next(images);
	}
	listing_obj = g_string_append(listing_obj, IMG_LISTING_END);
	return listing_obj;
}

static gboolean parse_time_range(const gchar *range, time_t *res, gboolean *bounded) {
	gchar **arr = g_strsplit(range, "-", 2);
	gchar **pos = arr;
	int i;
	for(i=0;i<2;i++) {
		int len = strlen(*pos);

		if (range[i] == '*')
			bounded[i] = FALSE;
		else
			bounded[i] = TRUE;

		res[i] = parse_iso8601_bip(*pos, len);
		if (res[i] == -1)
			return FALSE;
		pos++;
	}
	printf("time_range: %lu %lu %d %d\n", res[0], res[1], bounded[0], bounded[1]);
	g_strfreev(arr);
	return TRUE;
}

static void handles_listing_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	struct image_handles_desc *desc = user_data;
	gchar **key;

	printf("element: %s\n", element);
	printf("names\n");

	if (g_str_equal(element, "filtering-parameters") != TRUE)
		return;

	printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++) {
		printf("key: %s\n", *key);
		if (g_str_equal(*key, "created")) {
			parse_time_range(*values, desc->ctime, desc->ctime_bounded);
		}
		else if (g_str_equal(*key, "modified")) {
			parse_time_range(*values, desc->mtime, desc->mtime_bounded);
		}
		else if (g_str_equal(*key, "encoding")) {
			desc->encoding = g_strdup(*values);
			printf("encoding: %s\n", desc->encoding);
		}
		else if (g_str_equal(*key, "pixel")) {
			parse_pixel_range(*values, desc->lower, desc->upper, &desc->fixed_ratio);
			printf("pixel: %u %u %u %u %d\n", desc->lower[0], desc->lower[1], desc->upper[0], desc->upper[1], desc->fixed_ratio);
		}
	}
}

static const GMarkupParser handles_desc_parser = {
	handles_listing_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static struct image_handles_desc *parse_handles_desc(char *data,
		unsigned int length)
{
	struct image_handles_desc *desc = new_hdesc();
	GMarkupParseContext *ctxt = g_markup_parse_context_new(&handles_desc_parser,
			0, desc, NULL);
	g_markup_parse_context_parse(ctxt, data, length, NULL);
	g_markup_parse_context_free(ctxt);
	return desc;
}

static void *imglisting_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	int res_count, count=0, offset=0;
	struct image_handles_desc *desc;
	GString *body = NULL;

	if(session->aparam) {
		printf("using aparams\n");
		count = session->aparam->nbreturnedhandles;
		offset = session->aparam->liststartoffset;
	}

	if (err)
		*err = 0;

	printf("object: %s\n", session->desc_hdr);

	desc = parse_handles_desc(session->desc_hdr, session->desc_hdr_len);

	printf("imglisting_open\n");

	body = create_images_listing(session, count, offset, &res_count, err, desc);
	free_image_handles_desc(desc);
	return body;
}

static ssize_t imglisting_read(void *object, void *buf, size_t count,
		uint8_t *hi)
{
	*hi = OBEX_HDR_BODY;
	printf("imglisting_read\n");
	return string_read(object, buf, count);
}

static struct obex_mime_type_driver imglisting = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-listing",
	.open = imglisting_open,
	.close = string_free,
	.read = imglisting_read,
};


static int imglisting_init(void)
{
	return obex_mime_type_driver_register(&imglisting);
}

static void imglisting_exit(void)
{
	obex_mime_type_driver_unregister(&imglisting);
}

OBEX_PLUGIN_DEFINE(imglisting, imglisting_init, imglisting_exit)
