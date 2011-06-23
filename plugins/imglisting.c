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

static const char * bip_dir = "/tmp/bip/";

struct img_listing {
	int handle;
	char * image;
	time_t ctime;
	time_t mtime;
};

struct image_handles_desc *new_hdesc()
{
	struct image_handles_desc *hdesc = g_new0(struct image_handles_desc, 1);
	hdesc->upper[0] = hdesc->upper[1] = -1;
	return hdesc;
}

static void free_image_handles_desc(struct image_handles_desc *hdesc)
{
	g_free(hdesc->encoding);
	g_free(hdesc);
}

static void img_listing_free(struct img_listing *listing)
{
	g_free(listing->image);
	g_free(listing);
}

static gint ctime_compare(gconstpointer a, gconstpointer b)
{
	const struct img_listing *ail = a, *bil = b;
	if(ail->ctime < bil->ctime) return -1;
	else if(ail->ctime > bil->ctime) return 1;
	return g_strcmp0(ail->image, bil->image);
}

static gboolean verify_image(const gchar *image_file) {
	struct stat file_stat;
	struct image_attributes attr;
	lstat(image_file, &file_stat);

	if (!(file_stat.st_mode & S_IFREG)) {
		return FALSE;
	}

	if (get_image_attributes(image_file, &attr) < 0)
		return FALSE;

	return TRUE;
}

static gboolean filter_image(const gchar *image_file, const struct image_handles_desc *hdesc) {
	struct stat file_stat;
	struct image_attributes attr;
	lstat(image_file, &file_stat);

	if (!(file_stat.st_mode & S_IFREG)) {
		return FALSE;
	}

	if (!hdesc)
		return TRUE;

	printf("image: %s\n", image_file);

	if (hdesc->ctime_bounded[0] && file_stat.st_ctime<hdesc->ctime[0])
		return FALSE;

	if (hdesc->ctime_bounded[1] && file_stat.st_ctime>hdesc->ctime[1])
		return FALSE;

	if (hdesc->mtime_bounded[0] && file_stat.st_mtime<hdesc->mtime[0])
		return FALSE;

	if (hdesc->mtime_bounded[1] && file_stat.st_mtime>hdesc->mtime[1])
		return FALSE;

	if (get_image_attributes(image_file, &attr) < 0)
		return FALSE;

	if (hdesc->encoding != NULL && g_strcmp0(hdesc->encoding,attr.format) != 0)
		return FALSE;

	if (hdesc->lower[0] > attr.width || hdesc->lower[1] > attr.height)
		return FALSE;

	if (hdesc->upper[0] < attr.width || hdesc->upper[1] < attr.height)
		return FALSE;

	if (hdesc->fixed_ratio && hdesc->upper[1]*attr.width != hdesc->upper[0]*attr.height)
		return FALSE;

	return TRUE;
}

static GString *create_images_listing(int count, int offset, int *res_count, int *err, const struct image_handles_desc *hdesc) {
	GString *listing_obj = g_string_new(IMG_LISTING_BEGIN);
	struct dirent* file;
	struct stat file_stat;
	GSList *images = NULL;
	struct img_listing *il = NULL;
	char *handle_str = g_try_malloc(8);
	char ctime[18], mtime[18];
	int handle = 0;
	DIR *img_dir = opendir(bip_dir);

	if (!img_dir) {
		if (err)
			*err = -errno;
		return NULL;
	}

	while ((file = readdir(img_dir))) {
		GString *str = g_string_new(bip_dir);
		str = g_string_append(str, file->d_name);

		lstat(str->str, &file_stat);

		if (!verify_image(str->str)) {
			g_string_free(str, TRUE);
			continue;
		}

		printf("passed verification: %s\n", str->str);

		il = g_try_malloc(sizeof(struct img_listing));
		il->image = g_string_free(str, FALSE);
		il->mtime = file_stat.st_mtime;
		il->ctime = file_stat.st_ctime;
		images = g_slist_append(images, il);
	}
	images = g_slist_sort(images, ctime_compare);

	while (offset) {
		images = g_slist_next(images);
		offset--;
	}

	*res_count = 0;
	while (images && count) {
		struct img_listing *listing = images->data;
		listing->handle = handle++;
		printf("filtering: %s\n", listing->image);
		printf("%p\n", filter_image);
		if (!filter_image(listing->image, hdesc)) {
			img_listing_free(listing);
			images = g_slist_next(images);
			continue;
		}
		strftime(mtime, 17, "%Y%m%dT%H%M%SZ", gmtime(&listing->mtime));
		strftime(ctime, 17, "%Y%m%dT%H%M%SZ", gmtime(&listing->ctime));
		snprintf(handle_str, 8, "%07d", listing->handle);
		g_string_append_printf(listing_obj, IMG_LISTING_ELEMENT, handle_str, ctime, mtime);
		img_listing_free(listing);
		images = g_slist_next(images);
		(*res_count)++;
		count--;
	}
	g_slist_free(images);
	listing_obj = g_string_append(listing_obj, IMG_LISTING_END);
	g_free(handle_str);
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

		res[i] = parse_iso8601(*pos, len);
		if (res[i] == -1)
			return FALSE;
		pos++;
	}
	printf("time_range: %lu %lu %d %d\n", res[0], res[1], bounded[0], bounded[1]);
	g_strfreev(arr);
	return TRUE;
}

static gboolean parse_pixel_range(const gchar *dim, unsigned int *lower, unsigned int *upper, gboolean *fixed_ratio)
{
	static regex_t no_range;
	static regex_t range;
	static regex_t range_fixed;
	static int regex_initialized = 0;
	if (!regex_initialized) {
		regcomp(&no_range, "^([[:digit:]]+)\\*([[:digit:]]+)$", REG_EXTENDED);
		regcomp(&range, "^([[:digit:]]+)\\*([[:digit:]]+)-([[:digit:]]+)\\*([[:digit:]]+)$", REG_EXTENDED);
		regcomp(&range_fixed, "^([[:digit:]]+)\\*\\*-([[:digit:]]+)\\*([[:digit:]]+)$", REG_EXTENDED);
		regex_initialized = 1;
	}
	printf("dim=%s\n", dim);
	if (regexec(&no_range, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u*%u", &lower[0], &lower[1]);
		upper[0] = lower[0];
		upper[1] = lower[1];
		*fixed_ratio = FALSE;
	}
	else if (regexec(&range, dim, 0, NULL, 0) == 0) {
		printf("range\n");
		sscanf(dim, "%u*%u-%u*%u", &lower[0], &lower[1], &upper[0], &upper[1]);
		*fixed_ratio = FALSE;
	}
	else if (regexec(&range_fixed, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u**-%u*%u", &lower[0], &upper[0], &upper[1]);
		lower[1] = 0;
		*fixed_ratio = TRUE;
	}
	if (lower[0] > 65535 || lower[1] > 65535 || upper[0] > 65535 || upper[1] > 65535)
		return FALSE;
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

	desc = parse_handles_desc(session->handle_hdr, session->handle_hdr_len);

	printf("imglisting_open\n");

	body = create_images_listing(count, offset, &res_count, err, desc);
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
