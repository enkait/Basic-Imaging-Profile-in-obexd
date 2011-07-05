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

#define CLIENT_ADDRESS "org.openobex.client"
#define CLIENT_PATH "/"
#define CLIENT_INTERFACE "org.openobex.Client"
const char *dest_entry = "Destination";
const char *channel_entry = "Channel";
const char *bip_aos = "BIP:AOS";

static const uint8_t IMAGE_ARCH_TARGET[TARGET_SIZE] = {
			0x94, 0x01, 0x26, 0xC0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static DBusConnection *connect_to_client(void) {
	return obex_dbus_get_connection();
}

static void get_aos_interface_callback(DBusPendingCall *call, void *user_data) {
	//struct archive_session *session = user_data;
	//DBusMessage *msg;
	//dbus_pending_call_steal_reply(call);
	printf("callback\n");
}

static void append_sv_dict_entry(DBusMessageIter *dict, const char *key,
							int type, void *val)
{
	DBusMessageIter entry, value;
	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s",
							&value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(dict, &entry);
}

static DBusConnection *get_aos_interface(struct archive_session *session,
							DBusConnection *conn)
{
	DBusMessage *msg;
	DBusMessageIter args, dict;
	DBusError err;
	DBusPendingCall *result;
	msg = dbus_message_new_method_call(CLIENT_ADDRESS, CLIENT_PATH,
							CLIENT_INTERFACE,
							"CreateSession");

	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &dict);
	append_sv_dict_entry(&dict, "Destination", DBUS_TYPE_STRING,
							&session->address);
	append_sv_dict_entry(&dict, "Target", DBUS_TYPE_STRING,	&bip_aos);
	dbus_message_iter_close_container(&args, &dict);
	
	dbus_error_init(&err);
	if (!dbus_connection_send_with_reply(conn, msg, &result, -1)) {
		fprintf(stderr, "Conn error: (%s)\n", err.message);
		return NULL;
	}

	dbus_pending_call_set_notify(result, get_aos_interface_callback,
								session, NULL);

	printf("lawl %p\n", get_aos_interface_callback);

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	printf("omg?\n");

	return NULL;
}

static void *imgarch_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct archive_session *session = context;
	printf("imgarch open\n");
	session->called = FALSE;
	return session;
}

static int imgarch_close(void *object)
{
	printf("imgarch close\n");
	return 0;
}

static ssize_t imgarch_write(void *object, const void *buf, size_t count)
{
	struct archive_session *session = object;
	DBusConnection *conn;
	printf("imgarch write\n");
	if ((conn = connect_to_client()) == NULL)
		return -EBADR;
	get_aos_interface(session, conn);
	return -EAGAIN;
}

static ssize_t imgarch_flush(void *object)
{
	struct archive_session *session = object;
	DBusConnection *conn;
	printf("imgarch flush\n");
	if ((conn = connect_to_client()) == NULL)
		return -EBADR;
	get_aos_interface(session, conn);
	return -EAGAIN;
}

static struct obex_mime_type_driver imgarch = {
	.target = IMAGE_ARCH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-archive",
	.open = imgarch_open,
	.close = imgarch_close,
	.write = imgarch_write,
	.flush = imgarch_flush,
};

static int imgarch_init(void)
{
	return obex_mime_type_driver_register(&imgarch);
}

static void imgarch_exit(void)
{
	obex_mime_type_driver_unregister(&imgarch);
}

OBEX_PLUGIN_DEFINE(imgarch, imgarch_init, imgarch_exit)
