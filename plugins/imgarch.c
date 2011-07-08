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
#define AOS_INTERFACE "org.openobex.ImagePull"
const char *dest_entry = "Destination";
const char *channel_entry = "Channel";
const char *bip_aos = "BIP:AOS";

static const uint8_t IMAGE_ARCH_TARGET[TARGET_SIZE] = {
			0x94, 0x01, 0x26, 0xC0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

typedef void (*listing_callback) (struct archive_session *, GSList *);

struct listing_object {
	char *handle, *ctime, *mtime;
};
/*
static void free_listing_object(struct listing_object *object) {
	if (object == NULL)
		return;
	g_free(object->handle);
	g_free(object->ctime);
	g_free(object->mtime);
	g_free(object);
}*/

static DBusConnection *connect_to_client(void) {
	return obex_dbus_get_connection();
}

static gboolean append_sv_dict_entry(DBusMessageIter *dict, const char *key,
					int type, const char *str_type, void *val)
{
	DBusMessageIter entry, value;
	if (!dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry))
		return FALSE;

	if (!dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key))
		return FALSE;

	if (!dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, str_type,
									&value))
		return FALSE;

	if (!dbus_message_iter_append_basic(&value, type, val))
		return FALSE;

	if (!dbus_message_iter_close_container(&entry, &value))
		return FALSE;

	if (!dbus_message_iter_close_container(dict, &entry))
		return FALSE;

	return TRUE;
}

struct get_listing_data {
	struct archive_session *session;
	listing_callback cb;
};

static struct listing_object *parse_listing_dict(DBusMessageIter *dict)
{
	struct listing_object *obj = g_new0(struct listing_object, 1);
	printf("parse_listing_dict\n");
	while (dbus_message_iter_get_arg_type(dict) ==	DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		char *key, *val;
		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &val);

		if (g_str_equal(key, "handle"))
			obj->handle = val;
		if (g_str_equal(key, "created"))
			obj->ctime = val;
		if (g_str_equal(key, "modified"))
			obj->mtime = val;
		dbus_message_iter_next(dict);
	}
	return obj;
}

static void get_listing_callback(DBusPendingCall *call, void *user_data)
{
	struct get_listing_data *data = user_data;
	DBusMessageIter iter, array;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	GSList *list = NULL;

	printf("get_listing_callback\n");

	if (msg == NULL) {
		printf("error with reply\n");
		return;
	}

	if (!dbus_message_iter_init(msg, &iter)) {
		printf("error with reply\n");
		return;
	}
	dbus_message_iter_recurse(&iter, &array);
	
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_ARRAY) {
		DBusMessageIter dict;
		struct listing_object *obj;
		dbus_message_iter_recurse(&array, &dict);
		obj = parse_listing_dict(&dict);
		list = g_slist_append(list, obj);
		dbus_message_iter_next(&array);
	}

	if (data->cb != NULL)
		data->cb(data->session, list);
}

static gboolean get_listing(struct archive_session *session, listing_callback cb)
{
	DBusMessageIter args, dict;
	DBusPendingCall *result;
	struct get_listing_data *data;
	gboolean truth = TRUE;
	DBusMessage *msg = dbus_message_new_method_call(CLIENT_ADDRESS, session->path,
					AOS_INTERFACE, "GetImagesListing");

	if (msg == NULL)
		return FALSE;

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}",
									&dict))
		return FALSE;

	if (!append_sv_dict_entry(&dict, "latest", DBUS_TYPE_BOOLEAN,
					DBUS_TYPE_BOOLEAN_AS_STRING, &truth))
		return FALSE;

	if (!dbus_message_iter_close_container(&args, &dict))
		return FALSE;
	
	if (!dbus_connection_send_with_reply(session->conn, msg, &result, -1))
		return FALSE;

	data = g_new0(struct get_listing_data, 1);
	data->session = session;
	data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_listing_callback,
								data, NULL))
		return FALSE;

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return TRUE;
}

static void get_listing_finished(struct archive_session *session, GSList *list) {
	printf("get_listing_finished\n");
	while (list != NULL) {
		struct listing_object * obj = list->data;
		printf("handle: %s, created: %s, modified: %s\n", obj->handle, obj->ctime, obj->mtime);
		list = g_slist_next(list);
	}
}

static void get_aos_interface_callback(DBusPendingCall *call, void *user_data) {
	struct archive_session *session = user_data;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	char *path;

	if (msg == NULL) {
		session->err = -EBADR;
		goto failed;
	}

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID)) {
		session->err = -EBADR;
		goto failed;
	}

	session->path = path;

	get_listing(session, get_listing_finished);

	printf("got path: %s\n", session->path);

	printf("callback\n");

failed:
	printf("failed\n");
	obex_object_set_io_flags(session, G_IO_OUT, 0);
}

static gboolean get_aos_interface(struct archive_session *session,
							DBusConnection *conn)
{
	DBusMessage *msg;
	DBusMessageIter args, dict;
	DBusError err;
	DBusPendingCall *result;
	msg = dbus_message_new_method_call(CLIENT_ADDRESS, CLIENT_PATH,
							CLIENT_INTERFACE,
							"CreateSession");
	if (msg == NULL)
		return FALSE;

	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}",
									&dict))
		return FALSE;

	if (!append_sv_dict_entry(&dict, "Destination", DBUS_TYPE_STRING,
				DBUS_TYPE_STRING_AS_STRING, &session->address))
		return FALSE;

	if (!append_sv_dict_entry(&dict, "Target", DBUS_TYPE_STRING,
					DBUS_TYPE_STRING_AS_STRING, &bip_aos))
		return FALSE;

	if (!dbus_message_iter_close_container(&args, &dict))
		return FALSE;
	
	dbus_error_init(&err);
	if (!dbus_connection_send_with_reply(conn, msg, &result, -1)) {
		fprintf(stderr, "Conn error: (%s)\n", err.message);
		return FALSE;
	}

	if (!dbus_pending_call_set_notify(result, get_aos_interface_callback,
								session, NULL))
		return FALSE;

	printf("lawl %p\n", get_aos_interface_callback);

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	printf("omg?\n");

	return TRUE;
}

static void *imgarch_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct archive_session *session = context;
	printf("imgarch open\n");
	return session;
}

static int imgarch_close(void *object)
{
	printf("imgarch close\n");
	return 0;
}

static ssize_t imgarch_write(void *object, const void *buf, size_t count)
{
	return -EINVAL;
}

static ssize_t imgarch_flush(void *object)
{
	struct archive_session *session = object;
	DBusConnection *conn;
	if (session->path != NULL || session->err < 0)
		return session->err;
	printf("imgarch flush\n");
	if ((conn = connect_to_client()) == NULL)
		return -EBADR;
	session->conn = conn;
	if (!get_aos_interface(session, conn))
		return -EBADR;
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
