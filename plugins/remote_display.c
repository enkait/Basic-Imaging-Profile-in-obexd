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
#include "remote_display.h"
#include "bip_util.h"

#define REMOTE_DISPLAY_CHANNEL 20
#define REMOTE_DISPLAY_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?> \
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

//static const char * bip_root="/tmp/bip/";

static void free_remote_display_session(struct remote_display_session *session) {
	g_free(session);
}

static void *remote_display_connect(struct obex_session *os, int *err)
{
	struct remote_display_session *session;
	printf("REMOTE_DISPLAY CONNECT\n");
	manager_register_session(os);

	session = g_new0(struct remote_display_session, 1);
	session->os = os;
	session->dir = "/tmp/display/1/";

	if (err == NULL)
		*err = 0;

	return session;
}

static int remote_display_get(struct obex_session *os, obex_object_t *obj,
							void *user_data)
{
	int ret = obex_get_stream_start(os, "");
	printf("REMOTE_DISPLAY_GET\n");
	if (ret < 0)
		return ret;
	return 0;
}

static int remote_display_chkput(struct obex_session *os, void *user_data)
{
	//struct image_push_session *ips = user_data;
	int ret;
	printf("REMOTE DISPLAY CHKPUT\n");

	ret = obex_put_stream_start(os, "");
	return ret;
	//return 0;
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

static int remote_display_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	//struct remote_display_session *session = user_data;
	printf("REMOTE DISPLAY PUT\n");

	return 0;
}

static void remote_display_disconnect(struct obex_session *os, void *user_data)
{
	struct remote_display_session *ips = user_data;
	printf("REMOTE DISPLAY DISCONNECT\n");
	free_remote_display_session(ips);
	manager_unregister_session(os);
}

static struct obex_service_driver remote_display = {
	.name = "OBEXD Remote Display Server",
	.service = OBEX_BIP_RD,
	.channel = REMOTE_DISPLAY_CHANNEL,
	.record = REMOTE_DISPLAY_RECORD,
	.target = REMOTE_DISPLAY_TARGET,
	.target_size = TARGET_SIZE,
	.connect = remote_display_connect,
	.get = remote_display_get,
	.put = remote_display_put,
	.chkput = remote_display_chkput,
	.disconnect = remote_display_disconnect
};

static int remote_display_init(void)
{
	return obex_service_driver_register(&remote_display);
}

static void remote_display_exit(void)
{
	obex_service_driver_unregister(&remote_display);
}

OBEX_PLUGIN_DEFINE(remote_display, remote_display_init, remote_display_exit)