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
#include "image_pull.h"

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

#define IMG_HANDLE_HDR OBEX_HDR_TYPE_BYTES | 0x30

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
			0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

//static const char * bip_root="/tmp/bip/";
static void free_image_pull_session(struct image_pull_session *session) {
}

void *image_pull_connect(struct obex_session *os, int *err) {
    struct image_pull_session *ips;
    printf("IMAGE PULL CONNECT\n");
	manager_register_session(os);

    ips = g_new0(struct image_pull_session, 1);
    ips->os = os;

    if (err)
        *err = 0;

	return ips;
}

int image_pull_get(struct obex_session *os, obex_object_t *obj,
        gboolean *stream, void *user_data) {
    int ret = obex_get_stream_start(os, "");
    printf("IMAGE PULL GET\n");
    if (ret < 0)
        return ret;
    return 0;
}

int image_pull_chkput(struct obex_session *os, void *user_data) {
    printf("IMAGE PULL CHKPUT\n");
    return 0;
}

int image_pull_put(struct obex_session *os, obex_object_t *obj, void *user_data) {
    printf("IMAGE PULL PUT\n");
    return 0;
}

void image_pull_disconnect(struct obex_session *os, void *user_data)
{
    struct image_pull_session *ips = user_data;
    printf("IMAGE PULL DISCONNECT\n");
    free_image_pull_session(ips);
	manager_unregister_session(os);
}

static struct obex_service_driver image_pull = {
	.name = "OBEXD Image Pull Server",
	.service = OBEX_BIP,
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
