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
									\
  <attribute id=\"0x0310\">						\
    <uint8 value=\"0x0001\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0311\">						\
    <uint16 value=\"0x0002\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0312\">						\
    <uint32 value=\"0x000f\"/>						\
  </attribute>								\
</record>"

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

#define HANDLE_LIMIT 10000000

static const char * bip_root="/tmp/bip/";

void free_pushed_image(struct pushed_image *pi) {
	if (pi == NULL)
		return;
	g_free(pi->image);
	g_free(pi);
}

void free_image_push_session(struct image_push_session *session) {
	g_free(session);
}

struct pushed_image *get_pushed_image(GSList *image_list, int handle)
{
	while (image_list != NULL) {
		struct pushed_image *image = image_list->data;
		if (image->handle == handle)
			return image;
		image_list = g_slist_next(image_list);
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
	ips->bip_root = bip_root;

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
	int ret;
	printf("IMAGE PUSH CHKPUT\n");

	ret = obex_put_stream_start(os, "");
	return ret;
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

static int image_push_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	DBG("");

	return 0;
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
