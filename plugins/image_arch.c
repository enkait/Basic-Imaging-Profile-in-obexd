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
#include <dbus/dbus.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "image_arch.h"
#include "bip_util.h"
#include "btio.h"

#define IMAGE_ARCH_CHANNEL 22
#define IMAGE_ARCH_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
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
    <uint16 value=\"0x0040\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0312\">						\
    <uint32 value=\"0x12000\"/>						\
  </attribute>								\
</record>"

static const uint8_t IMAGE_ARCH_TARGET[TARGET_SIZE] = {
			0x94, 0x01, 0x26, 0xC0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static void free_archive_session(struct archive_session *session) {
}

void *image_arch_connect(struct obex_session *os, int *err) {
	struct archive_session *as;
	printf("ARCHIVE CONNECT\n");
	manager_register_session(os);

	as = g_new0(struct archive_session, 1);
	as->os = os;
	as->status = 1;

	if (err)
		*err = 0;

	return as;
}

int image_arch_get(struct obex_session *os, obex_object_t *obj,
							void *user_data)
{
	struct archive_session *session = user_data;
	int ret = -EBADR;

	printf("IMAGE ARCH GET\n");
	if (g_str_equal(os->type,"x-bt/img-status")) {
		printf("%d\n", session->status);
		//OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
		//					OBEX_RSP_CONTINUE);
		/*
		if (session->status == 1)
			OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
							OBEX_RSP_CONTINUE);
		else
			os_set_response(obj, session->status);
		*/
		obex_get_stream_start(os, os->name);
		ret = OBEX_RSP_CONTINUE;
		//ret = OBEX_RSP_SUCCESS;
	}
	return ret;
}

static gboolean get_ret_address(struct obex_session *os, char *address) {
	GError *err = NULL;
	bt_io_get(os->io, BT_IO_RFCOMM, &err, BT_IO_OPT_DEST, address,
							BT_IO_OPT_INVALID);
	if (err != NULL) {
		g_error_free(err);
		return FALSE;
	}
	return TRUE;
}

int image_arch_chkput(struct obex_session *os, void *user_data) {
	struct archive_session *session = user_data;
	int i;
	printf("IMAGE ARCH CHKPUT\n");

	if (obex_get_size(os) == OBJECT_SIZE_DELETE) {
		if (g_str_equal(os->type, "x-bt/img-status"))
			return 0;
		session->address = g_malloc0(18);

		if (!get_ret_address(os, session->address))
			return -EBADR;

		for (i = 0;i<10;i++)
			printf("%c\n", session->address[i]);
		printf("%p\n", session->address);

		return obex_put_stream_start(os, NULL);
	}

	return -EBADR;
}

int image_arch_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	//struct archive_session *session = user_data;
	printf("IMAGE ARCH PUT\n");

	if (obex_get_size(os) != OBJECT_SIZE_DELETE)
		return -EBADR;
	return 0;
}

void image_arch_disconnect(struct obex_session *os, void *user_data)
{
	struct archive_session *as = user_data;
	printf("IMAGE PULL DISCONNECT\n");
	free_archive_session(as);
	manager_unregister_session(os);
}

static struct obex_service_driver image_arch = {
	.name = "OBEXD Automatic Archive Server",
	.service = OBEX_BIP_ARCH,
	.channel = IMAGE_ARCH_CHANNEL,
	.record = IMAGE_ARCH_RECORD,
	.target = IMAGE_ARCH_TARGET,
	.target_size = TARGET_SIZE,
	.connect = image_arch_connect,
	.get = image_arch_get,
	.put = image_arch_put,
	.chkput = image_arch_chkput,
	.disconnect = image_arch_disconnect
};

static int image_arch_init(void)
{
	return obex_service_driver_register(&image_arch);
}

static void image_arch_exit(void)
{
	obex_service_driver_unregister(&image_arch);
}

OBEX_PLUGIN_DEFINE(image_arch, image_arch_init, image_arch_exit)
