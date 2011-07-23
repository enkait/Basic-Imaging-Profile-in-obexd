/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
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

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "image_push.h"
#include "bip_util.h"

#define IMAGE_PUSH_CHANNEL 20
#define IMAGE_PUSH_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
<record>								\
  <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"0x111b\"/>						\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0008\"/>					\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
  </attribute>								\
									\
  <attribute id=\"0x0009\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x111a\"/>					\
        <uint16 value=\"0x0100\" name=\"version\"/>			\
      </sequence>							\
    </sequence>								\
  </attribute>								\
</record>"

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

#define HANDLE_LIMIT 10000000

//static const char * bip_root="/tmp/bip/";

void free_image_push_session(struct image_push_session *session) {
	g_free(session);
}

struct pushed_image *get_pushed_image(struct image_push_session *session,
					int handle)
{
	GSList *images = session->pushed_images;
	while (images != NULL) {
		struct pushed_image *image = images->data;
		if (image->handle == handle)
			return image;
		images = g_slist_next(images);
	}
	return NULL;
}

static void *image_push_connect(struct obex_session *os, int *err)
{
	struct image_push_session *ips;
	printf("IMAGE PUSH CONNECT\n");
	manager_register_session(os);

	ips = g_new0(struct image_push_session, 1);
	ips->os = os;

	if (err)
		*err = 0;

	return ips;
}

static int image_push_get(struct obex_session *os, obex_object_t *obj,
							void *user_data)
{
	int ret = obex_get_stream_start(os, "");
	printf("IMAGE PUSH GET\n");
	if (ret < 0)
		return ret;
	return 0;
}

static int image_push_chkput(struct obex_session *os, void *user_data)
{
	//struct image_push_session *ips = user_data;
	int ret;
	printf("IMAGE PUSH CHKPUT\n");

	ret = obex_put_stream_start(os, "");
	return ret;
	//return 0;
}

int obex_handle_write(struct obex_session *os, obex_object_t *obj, const char *data, unsigned int size) {
	obex_headerdata_t hd;
	unsigned int headersize;

	hd.bs = encode_img_handle(data, size, &headersize);

	if (hd.bs == NULL)
		return -1;

	return OBEX_ObjectAddHeader(os->obex, obj,
			IMG_HANDLE_HDR, hd, headersize, 0);
}

int get_new_handle(struct image_push_session *session) {
	if (session->next_handle >= HANDLE_LIMIT) {
		return -1;
	}
	return session->next_handle++;
}
/*
static gboolean add_reply_handle(struct obex_session *os, obex_object_t *obj, int handle) {
	GString *handle_str = g_string_new("");
	obex_headerdata_t handle_hdr;
	unsigned int handle_hdr_len;
	if (handle < 0 || handle >= HANDLE_LIMIT) {
		g_string_free(handle_str, TRUE);
		return FALSE;
	}
	g_string_append_printf(handle_str, "%07d", handle);
	handle_hdr.bs = encode_img_handle(handle_str->str, handle_str->len, &handle_hdr_len);
	g_string_free(handle_str, TRUE);
	if (handle_hdr.bs == NULL)
		return FALSE;
	OBEX_ObjectAddHeader(os->obex, obj, IMG_HANDLE_HDR, handle_hdr, handle_hdr_len, OBEX_FL_FIT_ONE_PACKET);
	return TRUE;
}
*/
struct att_desc {
	char *name;
};

static void att_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	struct att_desc *desc = user_data;
	gchar **key;

	printf("element: %s\n", element);
	printf("names\n");

	if (g_str_equal(element, "attachment") != TRUE)
		return;

	printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++) {
		printf("key: %s\n", *key);
		if (g_str_equal(*key, "name")) {
			desc->name = g_strdup(*values);
			printf("name: %s\n", desc->name);
		}
	}
}

static const GMarkupParser handles_desc_parser = {
	att_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static struct att_desc *parse_att_desc(char *data, unsigned int length)
{
	struct att_desc *desc = g_try_new0(struct att_desc, 1);
	GMarkupParseContext *ctxt = g_markup_parse_context_new(&handles_desc_parser,
			0, desc, NULL);
	g_markup_parse_context_parse(ctxt, data, length, NULL);
	g_markup_parse_context_free(ctxt);
	return desc;
}

static int image_push_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	struct image_push_session *ips = user_data;
	//struct pushed_image *img;
	//printf("IMAGE PUSH PUT %s\n", os->name);
	printf("%p\n", parse_att_desc);

	parse_bip_user_headers(os, obj, &ips->desc_hdr, &ips->desc_hdr_len,
				&ips->handle_hdr, &ips->handle_hdr_len);

	printf("os->type = %s\n", os->type);
	if (g_strcmp0(os->type, "x-bt/img-img") == 0) {
		/*
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
						OBEX_RSP_PARTIAL_CONTENT);
						*/
	}
	else if (g_strcmp0(os->type, "x-bt/img-thm") == 0) {
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
		*/
	}
	else if(g_strcmp0(os->type, "x-bt/img-attachment") == 0) {
		/*
		int handle = parse_handle(ips->handle_hdr, ips->handle_hdr_len);
		char *att_path, *new_path;
		struct stat file_stat;
		struct att_desc *desc;
		printf("handle: %s\n", ips->handle_hdr);
		printf("%d\n", handle);
		if (handle < 0)
			return -EBADR;

		img = get_pushed_image(ips, handle);

		printf("%p\n", img);

		if (img == NULL)
			return -EEXIST;

		att_path = get_att_dir(img->image);

		printf("att_path = %s\n", att_path);

		if (lstat(att_path, &file_stat) < 0) {
			if (mkdir(att_path, 0700) < 0)
				return -errno;
		}
		else if (!S_ISDIR(file_stat.st_mode))
			return -EBADR;

		printf("name: %s\n", os->name);

		desc = parse_att_desc(ips->desc_hdr, ips->desc_hdr_len);

		if ((new_path = safe_rename(desc->name, att_path, ips->file_path)) == NULL) {
			return -errno;
		}
		*/
	}
	return 0;
	//obex_put_stream_start(os, "");
}

static void image_push_disconnect(struct obex_session *os, void *user_data)
{
	struct image_push_session *ips = user_data;
	printf("IMAGE PUSH DISCONNECT\n");
	free_image_push_session(ips);
	manager_unregister_session(os);
}

static struct obex_service_driver image_push = {
	.name = "OBEXD Image Push Server",
	.service = OBEX_BIP_PUSH,
	.channel = IMAGE_PUSH_CHANNEL,
	.record = IMAGE_PUSH_RECORD,
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.connect = image_push_connect,
	.get = image_push_get,
	.put = image_push_put,
	.chkput = image_push_chkput,
	.disconnect = image_push_disconnect
};

static int image_push_init(void)
{
	return obex_service_driver_register(&image_push);
}

static void image_push_exit(void)
{
	obex_service_driver_unregister(&image_push);
}

OBEX_PLUGIN_DEFINE(image_push, image_push_init, image_push_exit)
