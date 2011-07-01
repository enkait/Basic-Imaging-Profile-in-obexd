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

#define __USE_XOPEN
#include <time.h>

#include <glib.h>
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "image_pull.h"
#include "bip_util.h"

#define IMAGE_PULL_CHANNEL 21
#define IMAGE_PULL_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
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

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
			0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static const char * bip_dir="/tmp/bip/";

void img_listing_free(struct img_listing *listing)
{
	g_free(listing->image);
	free_image_attributes(listing->attr);
	g_free(listing);
}

static void free_image_pull_session(struct image_pull_session *session)
{
	GSList *image_list = session->image_list;
	while (image_list != NULL) {
		img_listing_free(image_list->data);
		image_list = g_slist_next(image_list);
	}
	g_slist_free(session->image_list);
	g_free(session->aparam_data);
	g_free(session->handle_hdr);
	g_free(session->desc_hdr);
	g_free(session);
}

struct img_listing *get_listing(struct image_pull_session *session, int handle, int *err)
{
	GSList *images = session->image_list;

	if (err != NULL)
		*err = 0;

	while (images != NULL) {
		struct img_listing *il = images->data;
		if (il->handle == handle)
			return il;
		images = g_slist_next(images);
	}
	
	if (err != NULL)
		*err = -ENOENT;
	return NULL;
}

static gboolean remove_image(struct image_pull_session *session, struct img_listing *il, int *err) {
	if (il == NULL) {
		if (err != NULL)
			*err = -ENOENT;
		return FALSE;
	}

	if (unlink(il->image) < 0) {
		if (err != NULL)
			*err = -errno;
		return FALSE;
	}

	session->image_list = g_slist_remove(session->image_list, il);

	if (err != NULL)
		*err = 0;
	return TRUE;
}

static GSList *get_image_list(int *err) {
	struct dirent *file;
	GSList *images = NULL;
	struct img_listing *il = NULL;
	struct stat file_stat;
	int handle = 0;
	DIR *img_dir = opendir(bip_dir);

	if (img_dir != NULL) {
		if (err != NULL)
			*err = -errno;
		return NULL;
	}

	while ((file = readdir(img_dir)) != NULL) {
		char *path = g_build_filename(bip_dir, file->d_name, NULL);
		struct image_attributes *attr;
		
		if (lstat(path, &file_stat) < 0) {
			g_free(path);
			continue;
		}

		if (!(file_stat.st_mode & S_IFREG)) {
			g_free(path);
			continue;
		}

		attr = g_new0(struct image_attributes, 1);
		if (get_image_attributes(path, attr, err) < 0) {
			g_free(attr);
			g_free(path);
			continue;
		}

		printf("passed verification: %s\n", path);

		il = g_new0(struct img_listing, 1);
		il->image = path;
		il->mtime = file_stat.st_mtime;
		il->ctime = file_stat.st_ctime;
		il->handle = handle++;
		il->attr = attr;
		images = g_slist_append(images, il);

		printf("image added: %s\n", il->image);
	}

	closedir(img_dir);
	if (err != NULL)
		*err = 0;
	return images;
}

void *image_pull_connect(struct obex_session *os, int *err) {
	struct image_pull_session *session;
	printf("IMAGE PULL CONNECT\n");
	manager_register_session(os);

	session = g_new0(struct image_pull_session, 1);
	session->os = os;
	session->image_list = get_image_list(err);

	if (session->image_list == NULL)
		return NULL;

	if (err != NULL)
		*err = 0;

	return session;
}

int image_pull_get(struct obex_session *os, obex_object_t *obj,
		gboolean *stream, void *user_data) {
	struct image_pull_session *session = user_data;
	const uint8_t *buffer;
	int ret;
	ssize_t rsize = obex_aparam_read(os, obj, &buffer);

	printf("IMAGE PULL GET\n");

	g_free(session->aparam_data);
	session->aparam_data = NULL;
	session->aparam_data_len = 0;

	if (rsize >= 0) {
		session->aparam_data = g_memdup(buffer, rsize);
		session->aparam_data_len = rsize;
	}

	parse_bip_user_headers(os, obj,	&session->desc_hdr,
					&session->desc_hdr_len,
					&session->handle_hdr,
					&session->handle_hdr_len);

	ret = obex_get_stream_start(os, os->name);

	if (ret < 0)
		return ret;
	return 0;
}

int image_pull_chkput(struct obex_session *os, void *user_data) {
	printf("IMAGE PULL CHKPUT\n");

	if (obex_get_size(os) == OBJECT_SIZE_DELETE)
		return 0;

	return -EBADR;
}

int image_pull_put(struct obex_session *os, obex_object_t *obj,
							void *user_data)
{
	struct image_pull_session *session = user_data;
	struct img_listing *il;
	int handle, err;
	printf("IMAGE PULL PUT\n");

	if (obex_get_size(os) != OBJECT_SIZE_DELETE)
		return -EBADR;

	parse_bip_user_headers(os, obj, &session->desc_hdr,
					&session->desc_hdr_len,
					&session->handle_hdr,
					&session->handle_hdr_len);
	
	handle = get_handle(session->handle_hdr, session->handle_hdr_len);

	if (handle < 0)
		return -EBADR;

	if ((il = get_listing(session, handle, &err)) == NULL)
		return err;
	
	if (!remove_image(session, il, &err))
		return err;
	
	return 0;
}

void image_pull_disconnect(struct obex_session *os, void *user_data)
{
	struct image_pull_session *session = user_data;
	printf("IMAGE PULL DISCONNECT\n");
	free_image_pull_session(session);
	manager_unregister_session(os);
}

static struct obex_service_driver image_pull = {
	.name = "OBEXD Image Pull Server",
	.service = OBEX_BIP_PULL,
	.channel = IMAGE_PULL_CHANNEL,
	.record = IMAGE_PULL_RECORD,
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.connect = image_pull_connect,
	.get = image_pull_get,
	.put = image_pull_put,
	.chkput = image_pull_chkput,
	.disconnect = image_pull_disconnect
};

static int image_pull_init(void)
{
	return obex_service_driver_register(&image_pull);
}

static void image_pull_exit(void)
{
	obex_service_driver_unregister(&image_pull);
}

OBEX_PLUGIN_DEFINE(image_pull, image_pull_init, image_pull_exit)
