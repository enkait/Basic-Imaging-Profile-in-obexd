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
#include "imgimgpull.h"
#include "imglisting.h"
#include "image_pull.h"
#include "remote_camera.h"
#include "filesystem.h"
#include "bip_util.h"
#include "imgimg.h"

#define EOL_CHARS "\n"
#define CAPABILITIES_BEGIN "<imaging-capabilities version=\"1.0\">" EOL_CHARS

#define IMAGE_FORMATS "" \
	"<image-formats encoding=\"JPEG\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS \
	"<image-formats encoding=\"GIF\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS \
	"<image-formats encoding=\"WBMP\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS \
	"<image-formats encoding=\"PNG\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS \
	"<image-formats encoding=\"JPEG2000\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS \
	"<image-formats encoding=\"BMP\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS

#define FILTERING_PARAM "<filtering-parameters created=\"1\" modified=\"1\"" \
			" pixel=\"1\" encoding=\"1\">" EOL_CHARS

#define CAPABILITIES_END "</imaging-capabilities>" EOL_CHARS

struct imgimgpull_data {
	void *context;
	char * (*get_image_path) (void *context, int handle);
	int fd, handle;
	size_t size;
	gboolean size_sent, write;
	struct img_desc *desc;
};

static struct img_desc *create_img_desc() {
	struct img_desc *desc = g_new0(struct img_desc, 1);
	desc->upper[0] = desc->upper[1] = UINT_MAX;
	desc->maxsize = UINT_MAX;
	return desc;
}

static void free_img_desc(struct img_desc *desc) {
	g_free(desc->encoding);
	g_free(desc->transform);
	g_free(desc);
}

gboolean img_elem_attr(struct img_desc *desc, const gchar *key,
					const gchar *value, GError **gerr)
{
	if (g_str_equal(key, "maxsize")) {
		if (sscanf(value, "%u", &desc->maxsize) < 1)
			goto invalid;
	}
	else if (g_str_equal(key, "encoding")) {
		if (desc->recv_enc)
			goto invalid;
		desc->recv_enc = TRUE;

		if (value == NULL || strlen(value) == 0)
			goto ok;

		if (desc->encoding != NULL)
			goto invalid;
		desc->encoding = g_strdup(convBIP2IM(value));

		if (desc->encoding == NULL)
			goto invalid;
	}
	else if (g_str_equal(key, "transformation")) {
		if (!verify_transform(value))
			goto invalid;

		if (desc->transform != NULL)
			goto invalid;
		desc->transform = g_strdup(value);
	}
	else if (g_str_equal(key, "pixel")) {
		if (desc->recv_pixel)
			goto invalid;
		desc->recv_pixel = TRUE;

		if (value == NULL || strlen(value) == 0)
			goto ok;

		if (!parse_pixel_range(value, desc->lower, desc->upper,
							&desc->fixed_ratio))
			goto invalid;
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

void img_elem(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	struct img_desc **desc = user_data;
	gchar **key;

	if (g_str_equal(element, "image") != TRUE)
		return;

	if (*desc != NULL) {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_INVALID_CONTENT, NULL);
		return;
	}

	*desc = create_img_desc();

	for (key = (gchar **) names; *key; key++, values++)
		if (!img_elem_attr(*desc, *key, *values, gerr))
			return;
}

static const GMarkupParser img_desc_parser = {
	img_elem,
	NULL,
	NULL,
	NULL,
	NULL
};

struct img_desc *parse_img_desc(char *data, unsigned int length,
								int *err)
{
	struct img_desc *desc = NULL;
	GError *gerr = NULL;
	GMarkupParseContext *ctxt = g_markup_parse_context_new(
					&img_desc_parser, 0, &desc, NULL);
	if (err != NULL)
		*err = 0;

	if (g_markup_parse_context_parse(ctxt, data, length, &gerr)) {
		if (desc->recv_pixel && desc->recv_enc)
			goto cleanup;
	}

	if (err != NULL)
		*err = -EINVAL;
	free_img_desc(desc);
	desc = NULL;
cleanup:
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

struct image_attributes *new_image_attr(struct image_attributes *orig,
					struct img_desc *desc)
{
	struct image_attributes *attr = g_new0(struct image_attributes, 1);
	attr->encoding = g_strdup(desc->encoding);

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
	return attr;
}

static int get_image_fd(char *image_path, struct img_desc *desc, int *err)
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

	orig = get_image_attributes(image_path, err);

	if (orig == NULL) {
		close(fd);
		return -1;
	}

	attr = new_image_attr(orig, desc);
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

static struct imgimgpull_data *imgimgpull_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimgpull_data *data = g_new0(struct imgimgpull_data, 1);

	if (err != NULL)
		*err = 0;

	if (oflag & O_WRONLY)
		data->write = TRUE;

	data->context = context;
	data->fd = -1;

	return data;
}

static char *image_pull_cb(void *context, int handle)
{
	int err = 0;
	struct image_pull_session *session = context;
	struct img_listing *il = NULL;

	if (session == NULL)
		return NULL;

	il = get_listing(session->image_list, handle, &err);

	if (il == NULL)
		return NULL;

	return g_strdup(il->image);
}

static void *image_pull_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimgpull_data *data = imgimgpull_open(name, oflag, mode,
							context, size, err);

	data->get_image_path = image_pull_cb;

	return data;
}

static char *remote_camera_cb(void *context, int handle)
{
	int err = 0;
	struct remote_camera_session *session = context;
	struct img_listing *il = NULL;

	if (session == NULL)
		return NULL;

	il = get_listing(session->image_list, handle, &err);

	if (il == NULL)
		return NULL;

	return g_strdup(il->image);
}

static void *remote_camera_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct imgimgpull_data *data = imgimgpull_open(name, oflag, mode,
							context, size, err);

	data->get_image_path = remote_camera_cb;

	return data;
}

static ssize_t get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct imgimgpull_data *data = object;
	printf("imgimg_get_next_header\n");

	if (data == NULL) {
		return -EBADR;
	}

	if (data->size_sent) {
		data->size_sent = TRUE;
		*hi = OBEX_HDR_LENGTH;
		return put_hdr_u32(buf, mtu, data->size);
	}

	*hi = OBEX_HDR_EMPTY;
	return 0;
}

static int feed_next_header(void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct imgimgpull_data *data = object;
	char *header;
	unsigned int hdr_len;
	int err, handle;
	if (data == NULL)
		return -EBADR;
	printf("feed_next_header\n");

	if (data->write)
		return 0;

	if (hi == IMG_HANDLE_HDR) {
		header = decode_img_handle(hv.bs, hv_size, &hdr_len);

		if (header == NULL)
			return -EBADR;

		handle = parse_handle(header);

		if (handle < 0)
			return -EBADR;

		data->handle = handle;
	}
	else if (hi == IMG_DESC_HDR) {
		if (data->desc != NULL)
			return -EBADR;

		header = decode_img_descriptor(hv.bs, hv_size, &hdr_len);

		if (header == NULL)
			return -EBADR;

		data->desc = parse_img_desc(header, hdr_len, &err);

		if (data->desc == NULL)
			return -EBADR;
	}
	else if (hi == OBEX_HDR_EMPTY) {
		size_t size = 0;
		char *image_path;

		if (data->handle < 0)
			return -EBADR;

		if (data->desc == NULL)
			return -EBADR;

		image_path = data->get_image_path(data->context, data->handle);

		if (image_path == NULL)
			return -EBADR;

		data->fd = get_image_fd(image_path, data->desc, &err);
		printf("fd = %d\n", data->fd);

		if (data->fd == -1)
			return -EBADR;

		if (!get_file_size(data->fd, &size, &err)) {
			close(data->fd);
			return -EBADR;
		}

		data->size = size;
	}
	return 0;
}

static ssize_t imgimgpull_read(void *object, void *buf, size_t count)
{
	struct imgimgpull_data *data = object;
	ssize_t ret;

	printf("imgimgpull_read %p %p %u\n", object, buf, count);

	ret = read(data->fd, buf, count);
	printf("read %u\n", ret);
	if (ret < 0)
		return -errno;

	return ret;
}

static int imgimgpull_close(void *object)
{
	struct imgimgpull_data *data = object;
	if (close(data->fd) < 0)
		return -errno;

	return 0;
}

static struct obex_mime_type_driver imgimgpull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = image_pull_open,
	.close = imgimgpull_close,
	.read = imgimgpull_read,
	.feed_next_header = feed_next_header,
	.get_next_header = get_next_header,
};

static struct obex_mime_type_driver imgimgpull_rc = {
	.target = REMOTE_CAMERA_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = remote_camera_open,
	.close = imgimgpull_close,
	.read = imgimgpull_read,
	.feed_next_header = feed_next_header,
	.get_next_header = get_next_header,
};

static struct obex_mime_type_driver imgimgpull_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = image_pull_open,
	.close = imgimgpull_close,
	.read = imgimgpull_read,
	.feed_next_header = feed_next_header,
	.get_next_header = get_next_header,
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

	if ((ret = obex_mime_type_driver_register(&imgimgpull_rc)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imgimgpull_aos);
}

static void imgimgpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgimgpull_aos);
	obex_mime_type_driver_unregister(&imgimgpull_rc);
	obex_mime_type_driver_unregister(&imgimgpull);
	obex_mime_type_driver_unregister(&img_capabilities_pull_aos);
	obex_mime_type_driver_unregister(&img_capabilities_pull);
}

OBEX_PLUGIN_DEFINE(imgimgpull, imgimgpull_init, imgimgpull_exit)
