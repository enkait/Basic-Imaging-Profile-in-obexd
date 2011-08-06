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
#include "imglisting.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"
#include "imgimg.h"

#define EOL_CHARS "\n"
#define CAPABILITIES_BEGIN "<imaging-capabilities version=\"1.0\">" EOL_CHARS

#define IMAGE_FORMATS "<image-formats encoding=\"JPEG\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"GIF\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"WBMP\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"PNG\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"JPEG2000\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"BMP\" pixel=\"0*0-65535*65535\">" EOL_CHARS \

#define CAPABILITIES_END "</imaging-capabilities>" EOL_CHARS

struct image_desc {
	char *encoding;
	unsigned int lower[2], upper[2];
	gboolean fixed_ratio;
	unsigned int maxsize;
	char *transform;
};

static struct image_desc *create_image_desc() {
	struct image_desc *desc = g_new0(struct image_desc, 1);
	desc->upper[0] = desc->upper[1] = -1;
	desc->maxsize = -1;
	return desc;
}

static void free_image_desc(struct image_desc *desc) {
	g_free(desc->encoding);
	g_free(desc->transform);
	g_free(desc);
}

static gboolean parse_attr(struct image_desc *desc, const gchar *key,
					const gchar *value, GError **gerr)
{
	printf("key: %s\n", key);
	if (g_str_equal(key, "maxsize")) {
		if (sscanf(value, "%u", &desc->maxsize) < 1)
			goto invalid;
		printf("maxsize: %u\n", desc->maxsize);
	}
	else if (g_str_equal(key, "encoding")) {
		if (strlen(value) == 0)
			goto ok;
		desc->encoding = g_strdup(convBIP2IM(value));
		if (desc->encoding == NULL)
			goto invalid;
		printf("encoding: %s\n", desc->encoding);
	}
	else if (g_str_equal(key, "transformation")) {
		printf("value: %s\n", value);
		if (!verify_transform(value))
			goto invalid;
		desc->transform = g_strdup(value);
		printf("transform: %s\n", desc->transform);
	}
	else if (g_str_equal(key, "pixel")) {
		if (strlen(value) == 0)
			goto ok;
		if (!parse_pixel_range(value, desc->lower, desc->upper,
							&desc->fixed_ratio))
			goto invalid;
		printf("pixel: %u %u %u %u %d\n", desc->lower[0],
				desc->lower[1], desc->upper[0], desc->upper[1],
							desc->fixed_ratio);
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
ok:
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
									NULL);
	return FALSE;
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
	for (key = (gchar **) names; *key; key++, values++)
		if (!parse_attr(desc, *key, *values, gerr))
			return;
}


static const GMarkupParser image_desc_parser = {
	image_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static struct image_desc *parse_image_desc(char *data, unsigned int length,
								int *err)
{
	struct image_desc *desc = create_image_desc();
	GMarkupParseContext *ctxt = g_markup_parse_context_new(
					&image_desc_parser, 0, desc, NULL);
	if (err != NULL)
		*err = 0;
	if (!g_markup_parse_context_parse(ctxt, data, length, NULL)) {
		if (err != NULL)
			*err = -EINVAL;
		free_image_desc(desc);
		desc = NULL;
	}
	g_markup_parse_context_free(ctxt);
	return desc;
}

static gboolean get_file_size(int fd, unsigned int *size, int *err) {
	struct stat st;
	if (fstat(fd, &st) < 0) {
		if (err != NULL)
			*err = -EBADR;
		return FALSE;
	}
	*size = st.st_size;
	if (err != NULL)
		*err = 0;
	return TRUE;
}

static int get_image_fd(char *image_path, struct image_desc *desc, int *err)
{
	int fd;
	struct image_attributes *attr, *orig;
	char *new_image_path;
	gboolean res;
	GError *gerr;

	if ((fd = g_file_open_tmp(NULL, &new_image_path, &gerr)) < 0) {
		if (err != NULL)
			*err = gerr->code;
		return -1;
	}

	printf("fd = %d\n", fd);
	
	attr = g_new0(struct image_attributes, 1);
	attr->encoding = g_strdup(desc->encoding);

	orig = get_image_attributes(image_path, err);
	if (orig == NULL) {
		close(fd);
		return -1;
	}

	if (orig->width >= desc->lower[0] && orig->height >= desc->lower[1] &&
						orig->width <= desc->upper[0] &&
						orig->height <= desc->upper[1]) {
		attr->width = orig->width;
		attr->height = orig->height;
	}
	else {
		attr->width = desc->upper[0];
		attr->height = desc->upper[1];
	}
	printf("width: %u height: %u\n", attr->width, attr->height);
	free_image_attributes(orig);
	res = make_modified_image(image_path, new_image_path, attr,
						desc->transform, err);
	free_image_attributes(attr);
	if (!res) {
		close(fd);
		return -1;
	}

	unlink(new_image_path);
	return fd;
}

static void *imgimgpull_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	struct image_desc *desc;
	int handle, fd = -1;
	struct img_listing *il;

	if (err)
		*err = 0;

	handle = parse_handle(session->handle_hdr, session->handle_hdr_len);

	if (handle == -1) {
		if (err)
			*err = -ENOENT;
		return NULL;
	}

	printf("handle = %d\n", handle);

	il = get_listing(session->image_list, handle, err);

	if (il == NULL)
		return NULL;
	
	desc = parse_image_desc(session->desc_hdr, session->desc_hdr_len, err);

	if (desc == NULL)
		return NULL;

	fd = get_image_fd(il->image, desc, err);
	free_image_desc(desc);
	printf("fd = %d\n", fd);

	if (fd == -1)
		return NULL;
	
	if (!get_file_size(fd, size, err)) {
		close(fd);
		return NULL;
	}

	printf("imgimgpull_open\n");

	return GINT_TO_POINTER(fd);
}

static ssize_t imgimgpull_read(void *object, void *buf, size_t count)
{
	ssize_t ret;
	
	printf("imgimgpull_read %p %p %u\n", object, buf, count);

	ret = read(GPOINTER_TO_INT(object), buf, count);
	printf("read %u\n", ret);
	if (ret < 0)
		return -errno;

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

static struct obex_mime_type_driver imgimgpull_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = imgimgpull_open,
	.close = imgimgpull_close,
	.read = imgimgpull_read,
};

static struct obex_mime_type_driver img_capabilities_pull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-capabilities",
	.open = img_capabilities_open,
	.close = string_free,
	.read = img_capabilities_read,
};

static struct obex_mime_type_driver img_capabilities_pull_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-capabilities",
	.open = img_capabilities_open,
	.close = string_free,
	.read = img_capabilities_read,
};

static int imgimgpull_init(void)
{
	int ret;
	if ((ret = obex_mime_type_driver_register(&img_capabilities_pull)) < 0)
		return ret;

	if ((ret = obex_mime_type_driver_register(&img_capabilities_pull_aos))
									< 0)
		return ret;

	if ((ret = obex_mime_type_driver_register(&imgimgpull)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imgimgpull_aos);
}

static void imgimgpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgimgpull_aos);
	obex_mime_type_driver_unregister(&imgimgpull);
	obex_mime_type_driver_unregister(&img_capabilities_pull_aos);
	obex_mime_type_driver_unregister(&img_capabilities_pull);
}

OBEX_PLUGIN_DEFINE(imgimgpull, imgimgpull_init, imgimgpull_exit)
