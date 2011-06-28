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

#define HANDLE_LIMIT 10000000

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

static const char * bip_root="/tmp/bip/";

static const gchar * valid_name_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const gchar rep_char='_';

void free_image_push_session(struct image_push_session *session) {
	g_free(session->file_path);
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

void *image_push_connect(struct obex_session *os, int *err)
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

int image_push_get(struct obex_session *os, obex_object_t *obj, gboolean *stream,
		void *user_data)
{
	int ret = obex_get_stream_start(os, "");
	printf("IMAGE PUSH GET\n");
	if (ret < 0)
		return ret;
	return 0;
}

int image_push_chkput(struct obex_session *os, void *user_data)
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

static int get_new_handle(struct image_push_session *ips) {
	if (ips->next_handle >= HANDLE_LIMIT) {
		return -1;
	}
	return ips->next_handle++;
}

static char *filter_name(const char *name) {
	char *new_name = g_strdup(name);
	return g_strcanon(new_name, valid_name_chars, rep_char);
}

static char *append_number(const char *path, unsigned int number) {
	GString *new_path;
	if (number > 1000000)
		return NULL;
	new_path = g_string_new(path);
	g_string_append_printf(new_path, "_%u", number);
	return g_string_free(new_path, FALSE);
}

static char *safe_rename(const char *name, const char *folder, const char *orig_path) {
	char *new_name = filter_name(name);
	char *new_path = g_build_filename(folder, new_name, NULL);
	char *test_path = g_strdup(new_path);
	int lock_fd = -1, number = 1;
	
	while((lock_fd = open(new_path, O_CREAT | O_EXCL, 0600)) < 0 &&
			errno == EEXIST) {
		number++;
		g_free(test_path);
		test_path = append_number(new_path, number);
		if (test_path == NULL)
			goto cleanup;
	}
	if (lock_fd < 0) {
		g_free(test_path);
		test_path = NULL;
		goto cleanup;
	}
	if (rename(orig_path, test_path) < 0) {
		g_free(test_path);
		test_path = NULL;
	}
	close(lock_fd);

cleanup:
	g_free(new_name);
	g_free(new_path);
	return test_path;
}

int image_push_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	struct image_push_session *ips = user_data;
	struct pushed_image *img;
	printf("IMAGE PUSH PUT %s\n", os->name);

	parse_bip_user_headers(os, obj, &ips->desc_hdr, &ips->desc_hdr_len,
				&ips->handle_hdr, &ips->handle_hdr_len);

	if (g_strcmp0(os->type, "x-bt/img-img")) {
		char *new_path;
		if ((new_path = safe_rename(os->name, bip_root, ips->file_path))
				!= NULL) {
			return -errno;
		}
		img = g_try_new0(struct pushed_image, 1);
		img->handle = get_new_handle(ips);
		if (img->handle < 0) {
			g_free(img);
			g_free(new_path);
			return -EBADR;
		}
		img->image = new_path;
		ips->pushed_images = g_slist_append(ips->pushed_images, img);


	}
	else if(g_strcmp0(os->type, "x-bt/img-attachment")) {
		int handle = get_handle(ips->handle_hdr, ips->handle_hdr_len);
		char *att_path, *new_path;
		struct stat file_stat;
		if (handle < 0)
			return -EBADR;

		img = get_pushed_image(ips, handle);

		if (img == NULL)
			return -EEXIST;

		att_path = get_att_dir(img->image);

		if (lstat(att_path, &file_stat) < 0) {
			if (mkdir(att_path, 0600) < 0)
				return -errno;
		}
		else if (!S_ISDIR(file_stat.st_mode))
			return -EBADR;

		if ((new_path = safe_rename(os->name, att_path, ips->file_path)) == NULL) {
			return -errno;
		}
	}
	return 0;
	//obex_put_stream_start(os, "");
}

void image_push_disconnect(struct obex_session *os, void *user_data)
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
