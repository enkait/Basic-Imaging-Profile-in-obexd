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

#define IMG_LISTING_ELEMENT "<image handle=\"%s\" created=\"%s\" modified=\"%s\"/>" EOL_CHARS

#define IMG_LISTING_END "</images-listing>" EOL_CHARS

#define NBRETURNEDHANDLES_TAG 0x01
#define NBRETURNEDHANDLES_LEN 0x02
#define LISTSTARTOFFSET_TAG 0x02
#define LISTSTARTOFFSET_LEN 0x02
#define LATESTCAPTUREDIMAGES_TAG 0x03
#define LATESTCAPTUREDIMAGES_LEN 0x01

struct img_hdesc {
    time_t ctime[2];
    gboolean ctime_bounded[2];
    time_t mtime[2];
    gboolean mtime_bounded[2];
    char *encoding;
    unsigned int lower[2], upper[2];
    gboolean fixed_ratio;
};

static struct img_hdesc *get_hdesc()
{
	struct img_hdesc *hdesc = g_new0(struct img_hdesc, 1);
	hdesc->upper[0] = -1;
	hdesc->upper[1] = -1;
	hdesc->ctime_bounded[0] = FALSE;
	hdesc->ctime_bounded[1] = FALSE;
	hdesc->mtime_bounded[0] = FALSE;
	hdesc->mtime_bounded[1] = FALSE;
	return hdesc;
}

static void free_img_hdesc(struct img_hdesc *hdesc)
{
	g_free(hdesc->encoding);
	g_free(hdesc);
}

static gboolean filter_image(struct img_listing *il, const struct img_hdesc *hdesc)
{
	if (!hdesc)
		return TRUE;

	if (hdesc->ctime_bounded[0] && il->ctime < hdesc->ctime[0])
		return FALSE;

	if (hdesc->ctime_bounded[1] && il->ctime > hdesc->ctime[1])
		return FALSE;

	if (hdesc->mtime_bounded[0] && il->mtime < hdesc->mtime[0])
		return FALSE;

	if (hdesc->mtime_bounded[1] && il->mtime > hdesc->mtime[1])
		return FALSE;

	if (hdesc->encoding != NULL && g_strcmp0(hdesc->encoding,
							il->attr->encoding) != 0)
		return FALSE;

	if (hdesc->lower[0] > il->attr->width ||
					hdesc->lower[1] > il->attr->height)
		return FALSE;

	if (hdesc->upper[0] < il->attr->width ||
					hdesc->upper[1] < il->attr->height)
		return FALSE;

	if (hdesc->fixed_ratio && hdesc->upper[1]*il->attr->width !=
					hdesc->upper[0]*il->attr->height)
		return FALSE;

	return TRUE;
}

static GString *create_images_listing(struct image_pull_session *session,
					int count, int offset,
					int *res_count,
					const struct img_hdesc *hdesc)
{
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
		
		if (!filter_image(listing, hdesc)) {
			images = g_slist_next(images);
			continue;
		}
		
		if (offset == 0) {
			strftime(mtime, 17, "%Y%m%dT%H%M%SZ",
					gmtime(&listing->mtime));
			strftime(ctime, 17, "%Y%m%dT%H%M%SZ",
					gmtime(&listing->ctime));
			snprintf(handle_str, 8, "%07d", listing->handle);
			g_string_append_printf(listing_obj,
						IMG_LISTING_ELEMENT,
						handle_str, ctime, mtime);

			if (res_count != NULL)
				(*res_count)++;
			count--;
		}
		else {
			offset--;
		}
		
		images = g_slist_next(images);
	}
	listing_obj = g_string_append(listing_obj, IMG_LISTING_END);
	return listing_obj;
}

static gboolean parse_time_range(const gchar *range, time_t *res,
					gboolean *bounded) {
	gchar **arr = g_strsplit(range, "-", 0);
	gchar **pos = arr;
	int i;
	for (i = 0; arr[i] != NULL; i++);

	if (i != 2)
		return FALSE;

	for (i = 0; i < 2; i++) {
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

static gboolean parse_attr(struct img_hdesc *desc, const gchar *key,
					const gchar *value, GError **gerr)
{
	printf("key: %s\n", key);
	if (g_str_equal(key, "created")) {
		if (!parse_time_range(value, desc->ctime, desc->ctime_bounded))
			goto invalid;
	}
	else if (g_str_equal(key, "modified")) {
		if (!parse_time_range(value, desc->mtime, desc->mtime_bounded))
			goto invalid;
	}
	else if (g_str_equal(key, "encoding")) {
		desc->encoding = g_strdup(convBIP2IM(value));
		if (desc->encoding == NULL)
			goto invalid;
		printf("encoding: %s\n", desc->encoding);
	}
	else if (g_str_equal(key, "pixel")) {
		if (!parse_pixel_range(value, desc->lower, desc->upper,
							&desc->fixed_ratio))
			goto invalid;
		printf("pixel: %u %u %u %u %d\n",
				desc->lower[0], desc->lower[1],
				desc->upper[0], desc->upper[1],
				desc->fixed_ratio);
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
	return FALSE;
}

static void handles_listing_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	struct img_hdesc *desc = user_data;
	gchar **key;

	printf("element: %s\n", element);
	printf("names\n");

	if (g_str_equal(element, "filtering-parameters") != TRUE) {
		g_set_error(gerr, G_MARKUP_ERROR,
					G_MARKUP_ERROR_UNKNOWN_ELEMENT, NULL);
		return;
	}

	printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++)
		if (!parse_attr(desc, *key, *values, gerr))
			return;
}

static const GMarkupParser handles_desc_parser = {
	handles_listing_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static struct img_hdesc *parse_handles_desc(char *data,
						unsigned int length, int *err)
{
	struct img_hdesc *desc = get_hdesc();
	if (length > 0) {
		gboolean status;
		GMarkupParseContext *ctxt = g_markup_parse_context_new(
				&handles_desc_parser, 0, desc, NULL);
		if (err != NULL)
			*err = 0;
		status = g_markup_parse_context_parse(ctxt, data, length, NULL);
		g_markup_parse_context_free(ctxt);
		if (!status) {
			if (err != NULL)
				*err = -EINVAL;
			free_img_hdesc(desc);
			desc = NULL;
		}
	}
	return desc;
}

struct imglisting_aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

struct imglisting_aparam {
	uint16_t nbreturnedhandles;
	uint16_t liststartoffset;
	uint8_t latestcapturedimages;
};

static struct imglisting_aparam *parse_aparam(const uint8_t *buffer, uint32_t hlen, int *err)
{
	struct imglisting_aparam *param;
	struct imglisting_aparam_header *hdr;
	uint32_t len = 0;
	uint16_t val16;
	gboolean fields[3];
	int i;
	for (i = 0; i < 3; i++)
		fields[i] = FALSE;

	param = g_new0(struct imglisting_aparam, 1);

	while (len < hlen) {
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
			case NBRETURNEDHANDLES_TAG:
				if (hdr->len != NBRETURNEDHANDLES_LEN)
					goto failed;
				memcpy(&val16, hdr->val, sizeof(val16));
				param->nbreturnedhandles = GUINT16_FROM_BE(val16);
				fields[0] = TRUE;
				break;

			case LISTSTARTOFFSET_TAG:
				if (hdr->len != LISTSTARTOFFSET_LEN)
					goto failed;
				memcpy(&val16, hdr->val, sizeof(val16));
				param->liststartoffset = GUINT16_FROM_BE(val16);
				fields[1] = TRUE;
				break;

			case LATESTCAPTUREDIMAGES_TAG:
				if (hdr->len != LATESTCAPTUREDIMAGES_LEN)
					goto failed;
				param->latestcapturedimages = hdr->val[0];
				fields[2] = TRUE;
				break;

			default:
				goto failed;
		}

		len += hdr->len + sizeof(struct imglisting_aparam_header);
	}

	for (i = 0; i < 3; i++)
		if (!fields[i])
			goto failed;

	DBG("nb %x ls %x lc %x",
			param->nbreturnedhandles, param->liststartoffset,
			param->latestcapturedimages);

	return param;

failed:
	g_free(param);

	if (err != NULL)
		*err = -EBADR;

	return NULL;
}

struct imglist_aparam_r {
	uint8_t nbtag;
	uint8_t nblen;
	uint16_t nbval;
} __attribute__ ((packed));

static GString *cr_imglist_aparam_r(uint16_t nbval)
{
	struct imglist_aparam_r *ia = g_new0(struct imglist_aparam_r, 1);
	ia->nbtag = NBRETURNEDHANDLES_TAG;
	ia->nblen = NBRETURNEDHANDLES_LEN;
	ia->nbval = GUINT16_TO_BE(nbval);
	return g_string_new_len((gchar *) ia, sizeof(struct imglist_aparam_r));
}

static GString *create_hdesc_hdr(const char *data, unsigned int length)
{
	unsigned int encdata_len;
	uint8_t *encdata = encode_img_descriptor(data, length, &encdata_len);
	return g_string_new_len((gchar *) encdata, encdata_len);
}

struct imglist_resp {
	GString *aparam, *hdesc, *body;
};

static void *imglisting_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	int res_count, count=0, offset=0;
	struct img_hdesc *desc;
	struct imglisting_aparam *aparam;
	struct imglist_resp *resp;

	if (err != NULL)
		*err = 0;

	if (session->aparam_data == NULL) {
		if (err != NULL)
			*err = -EBADR;
		return NULL;
	}

	aparam = parse_aparam(session->aparam_data, session->aparam_data_len,
			err);

	if (aparam == NULL)
		return NULL;

	count = aparam->nbreturnedhandles;
	offset = aparam->liststartoffset;

	printf("object: %s\n", session->desc_hdr);

	desc = parse_handles_desc(session->desc_hdr, session->desc_hdr_len,
			err);

	if (desc == NULL) {
		g_free(aparam);
		if (err != NULL)
			*err = -EBADR;
		return NULL;
	}
	printf("desc = %p\n", desc);

	printf("imglisting_open\n");

	resp = g_new0(struct imglist_resp, 1);
	resp->body = create_images_listing(session, count, offset, &res_count,
			desc);
	resp->aparam = cr_imglist_aparam_r(res_count);
	resp->hdesc = create_hdesc_hdr(session->desc_hdr, session->desc_hdr_len);

	printf("response: %u %u %u\n", resp->body->len, resp->aparam->len,
			resp->hdesc->len);

	free_img_hdesc(desc);
	g_free(aparam);
	return resp;
}

static ssize_t imglisting_read(void *object, void *buf, size_t count,
		uint8_t *hi)
{
	struct imglist_resp *resp = object;
	GString *data;
	if (resp->aparam->len > 0) {
		data = resp->aparam;
		*hi = OBEX_HDR_APPARAM;
	}
	else if (resp->hdesc->len > 0) {
		data = resp->hdesc;
		*hi = IMG_DESC_HDR;
	}
	else {
		data = resp->body;
		*hi = OBEX_HDR_BODY;
	}
	printf("imglisting_read\n");
	return string_read(data, buf, count);
}

static int imglisting_close(void *object)
{
	struct imglist_resp *resp = object;

	g_string_free(resp->aparam, TRUE);
	g_string_free(resp->hdesc, TRUE);
	g_string_free(resp->body, TRUE);

	return 0;
}

static struct obex_mime_type_driver imglisting = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-listing",
	.open = imglisting_open,
	.close = imglisting_close,
	.read = imglisting_read,
};

static struct obex_mime_type_driver imglisting_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-listing",
	.open = imglisting_open,
	.close = imglisting_close,
	.read = imglisting_read,
};

static int imglisting_init(void)
{
	int ret;
	if ((ret = obex_mime_type_driver_register(&imglisting)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imglisting_aos);
}

static void imglisting_exit(void)
{
	obex_mime_type_driver_unregister(&imglisting_aos);
	obex_mime_type_driver_unregister(&imglisting);
}

OBEX_PLUGIN_DEFINE(imglisting, imglisting_init, imglisting_exit)
