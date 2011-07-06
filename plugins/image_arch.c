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
	as->err = 0;

	if (err)
		*err = 0;

	return as;
}

struct sa_aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

static struct aa_aparam *parse_aparam(const uint8_t *buffer, uint32_t hlen)
{
	struct aa_aparam *param = g_new0(struct aa_aparam, 1);
	struct sa_aparam_header *hdr;
	uint32_t len = 0;
	int i;


	while (len < hlen) {
		printf("got %u %u of data\n", len, hlen);
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
		case SID_TAG:
			if (hdr->len != SID_LEN)
				goto failed;
			memcpy(param->serviceid, hdr->val,
					SID_LEN);
			break;

		default:
			goto failed;
		}

		len += hdr->len + sizeof(struct sa_aparam_header);
	}
	for(i=0;i<16;i++) {
		printf("%x\n", (char) param->serviceid[i]);
	}

	return param;

failed:
	g_free(param);

	return NULL;
}

int image_arch_get(struct obex_session *os, obex_object_t *obj,
		gboolean *stream, void *user_data) {
	int ret;

	printf("IMAGE PULL GET\n");

	ret = obex_get_stream_start(os, os->name);
	if (ret < 0)
		return ret;
	return 0;
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
	printf("IMAGE PULL CHKPUT\n");
	if (obex_get_size(os) == OBJECT_SIZE_DELETE) {
		session->address = g_malloc0(18);

		if (!get_ret_address(os, session->address))
			return -EBADR;

		return obex_put_stream_start(os, NULL);
	}

	return -EBADR;
}

int image_arch_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	//struct archive_session *session = user_data;
	static struct aa_aparam *aparam;
	const uint8_t *buffer;
	ssize_t rsize;
	printf("IMAGE PULL PUT\n");

	if (obex_get_size(os) != OBJECT_SIZE_DELETE)
		return -EBADR;
	
	rsize = obex_aparam_read(os, obj, &buffer);
	aparam = parse_aparam(buffer, rsize);
	/*
	if (g_strcmp0(os->type, "x-bt/img-archive") == 0) {
		int i;
		DBusConnection *conn;
		for(i=0;i<16;i++) {
			printf("%x\n", (char) aparam->serviceid[i]);
		}

		for(i=0;i<18;i++) {
			printf("lol:%x\n", session->address[i]);
		}

		if ((conn = connect_to_client()) == NULL)
			return -EBADR;

		get_aos_interface(session, conn);

		printf("start archive\n");

	}
	*/
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
