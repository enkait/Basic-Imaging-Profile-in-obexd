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

#include "gdbus.h"
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

struct archive_context {
	struct archive_session *session;
	DBusConnection *conn;
	char *aos_path;
	GSList *image_list;
	unsigned int completed_watch, failed_watch;
	gboolean reg_watches;

	char *cur_path;
	struct listing_object *cur_image;
	struct properties_object *cur_prop;
};

typedef void (*aos_callback) (struct archive_context *, int err);

static gboolean reg_get_image_watches(struct archive_context *context, aos_callback cb);
static void unreg_get_image_watches(struct archive_context *context);
static void get_next_image(struct archive_context *context, int err);

const char *dest_entry = "Destination";
const char *channel_entry = "Channel";
const char *bip_aos = "BIP:AOS";

static const uint8_t IMAGE_ARCH_TARGET[TARGET_SIZE] = {
			0x94, 0x01, 0x26, 0xC0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static const char * bip_dir="/tmp/bip/";

struct properties_object {
	char *handle, *name;
};

struct listing_object {
	char *handle, *ctime, *mtime;
};

static void free_listing_object(struct listing_object *object) {
	if (object == NULL)
		return;
	g_free(object->handle);
	g_free(object->ctime);
	g_free(object->mtime);
	g_free(object);
}

static void free_archive_context(struct archive_context *context) {
	GSList *l;
	if (context == NULL)
		return;
	g_free(context->aos_path);
	for (l = context->image_list; l != NULL; l = g_slist_next(l))
		free_listing_object(l->data);
	g_slist_free(context->image_list);
	g_free(context);
}

static void free_properties_object(struct properties_object *object) {
	if (object == NULL)
		return;
	g_free(object->handle);
	g_free(object->name);
	g_free(object);
}

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

struct callback_data {
	struct archive_context *context;
	aos_callback cb;
};

static struct listing_object *parse_listing_dict(DBusMessageIter *dict)
{
	struct listing_object *obj = g_new0(struct listing_object, 1);
	printf("parse_listing_dict\n");
	while (dbus_message_iter_get_arg_type(dict) ==	DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		char *key, *val;
		dbus_message_iter_recurse(dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto failed;
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto failed;
		dbus_message_iter_get_basic(&entry, &val);

		if (g_str_equal(key, "handle"))
			obj->handle = g_strdup(val);
		if (g_str_equal(key, "created"))
			obj->ctime = g_strdup(val);
		if (g_str_equal(key, "modified"))
			obj->mtime = g_strdup(val);
		dbus_message_iter_next(dict);
	}

	if (obj->handle == NULL)
		goto failed;
	return obj;
failed:
	free_listing_object(obj);
	return NULL;
}

static void get_listing_callback(DBusPendingCall *call, void *user_data)
{
	struct callback_data *data = user_data;
	struct archive_context *context = data->context;
	DBusMessageIter iter, array;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	GSList *list = NULL;

	printf("get_listing_callback\n");
	g_assert(data->cb != NULL);

	if (msg == NULL)
		goto failed;

	if (dbus_message_get_error_name(msg) != NULL) {
		printf("dbus error %s\n", dbus_message_get_error_name(msg));
		goto failed;
	}

	if (!dbus_message_iter_init(msg, &iter))
		goto failed;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		goto failed;

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_ARRAY) {
		DBusMessageIter dict;
		struct listing_object *obj;
		dbus_message_iter_recurse(&array, &dict);
		obj = parse_listing_dict(&dict);
		if (obj == NULL)
			goto failed;
		list = g_slist_append(list, obj);
		dbus_message_iter_next(&array);
	}

	dbus_message_unref(msg);
	context->image_list = list;

	data->cb(data->context, 0);
	return;
failed:
	while (list != NULL) {
		free_listing_object(list->data);
		list = g_slist_remove(list, list->data);
	}

	if (msg != NULL)
		dbus_message_unref(msg);
	data->cb(data->context, -EBADR);
	return;
}

static gboolean get_listing(struct archive_context *context, aos_callback cb)
{
	DBusMessageIter args, dict;
	DBusPendingCall *result;
	struct callback_data *data;
	gboolean truth = TRUE;
	DBusMessage *msg = dbus_message_new_method_call(CLIENT_ADDRESS, context->aos_path,
					AOS_INTERFACE, "GetImagesListing");

	printf("get_listing\n");

	if (msg == NULL)
		return FALSE;

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}",
									&dict))
		goto failed;

	if (!append_sv_dict_entry(&dict, "latest", DBUS_TYPE_BOOLEAN,
					DBUS_TYPE_BOOLEAN_AS_STRING, &truth))
		goto failed;

	if (!dbus_message_iter_close_container(&args, &dict))
		goto failed;
	
	if (!dbus_connection_send_with_reply(context->conn, msg, &result, -1))
		goto failed;

	data = g_new0(struct callback_data, 1);
	data->context = context;
	data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_listing_callback,
								data, g_free)) {
		g_free(data);
		goto failed;
	}

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return TRUE;
failed:
	dbus_message_unref(msg);
	return FALSE;
}

static struct properties_object *parse_properties_dict(DBusMessageIter *dict)
{
	struct properties_object *obj = g_new0(struct properties_object, 1);
	printf("parse_listing_dict\n");
	while (dbus_message_iter_get_arg_type(dict) ==	DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		char *key, *val;
		dbus_message_iter_recurse(dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto failed;
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto failed;
		dbus_message_iter_get_basic(&entry, &val);

		if (g_str_equal(key, "handle"))
			obj->handle = g_strdup(val);
		if (g_str_equal(key, "name"))
			obj->name = g_strdup(val);
		dbus_message_iter_next(dict);
	}

	if (obj->handle == NULL)
		goto failed;
	return obj;
failed:
	free_properties_object(obj);
	return NULL;
}

static void get_properties_callback(DBusPendingCall *call, void *user_data)
{
	struct callback_data *data = user_data;
	struct archive_context *context = data->context;
	struct properties_object *obj;
	DBusMessageIter iter, array, dict;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);

	g_assert(data->cb != NULL);

	printf("get_properties_callback\n");

	if (msg == NULL)
		goto failed;

	if (dbus_message_get_error_name(msg) != NULL)
		goto failed;

	if (!dbus_message_iter_init(msg, &iter))
		goto failed;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		goto failed;

	dbus_message_iter_recurse(&iter, &array);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		goto failed;

	dbus_message_iter_recurse(&array, &dict);

	obj = parse_properties_dict(&dict);

	if (obj == NULL)
		goto failed;

	context->cur_prop = obj;

	dbus_message_unref(msg);
	data->cb(data->context, 0);
	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	data->cb(data->context, -EINVAL);
}

static void get_properties(struct archive_context *context, char *handle, 
							aos_callback cb)
{
	DBusMessageIter args;
	DBusPendingCall *result;
	struct callback_data *data;
	DBusMessage *msg;

	g_assert(cb != NULL);

	msg = dbus_message_new_method_call(CLIENT_ADDRESS,
					context->aos_path, AOS_INTERFACE,
						"GetImageProperties");

	if (msg == NULL)
		goto failed;

	dbus_message_iter_init_append(msg, &args);
	
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &handle))
		goto failed;

	if (!dbus_connection_send_with_reply(context->conn, msg, &result, -1))
		goto failed;

	data = g_new0(struct callback_data, 1);
	data->context = context;
	data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_properties_callback,
								data, NULL)) {
		g_free(data);
		goto failed;
	}

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	cb(context, -EBADR);
	return;
}

static void get_image_callback(DBusPendingCall *call, void *user_data)
{
	struct callback_data *data = user_data;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	g_assert(data->cb);
	printf("get_image_callback\n");

	if (msg == NULL)
		goto failed;

	if (dbus_message_get_error_name(msg) != NULL)
		goto failed;

	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	data->cb(data->context, -EINVAL);
}

static gboolean get_image_completed(DBusConnection *connection, DBusMessage *message,
							void *user_data)
{
	struct callback_data *data = user_data;
	printf("get_image_completed\n");
	data->cb(data->context, 0);
	return TRUE;
}

static gboolean get_image_failed(DBusConnection *connection, DBusMessage *message,
							void *user_data)
{
	struct callback_data *data = user_data;
	printf("get_image_failed\n");
	data->cb(data->context, -EINVAL);
	return TRUE;
}

static gboolean reg_get_image_watches(struct archive_context *context, aos_callback cb)
{
	struct callback_data *data;

	if (context->reg_watches)
		return TRUE;

	data = g_new0(struct callback_data, 1);
	data->context = context;
	data->cb = cb;

	context->completed_watch = g_dbus_add_signal_watch(context->conn, NULL,
						context->aos_path,
						AOS_INTERFACE, "GetImageCompleted",
						get_image_completed, data, NULL);

	if (context->completed_watch == 0) {
		g_free(data);
		return FALSE;
	}

	context->failed_watch = g_dbus_add_signal_watch(context->conn, NULL,
						context->aos_path,
						AOS_INTERFACE, "GetImageFailed",
						&get_image_failed, data, g_free);

	if (context->failed_watch == 0) {
		g_dbus_remove_watch(context->conn, context->completed_watch);
		g_free(data);
		return FALSE;
	}

	context->reg_watches = TRUE;
	return TRUE;
}

static void unreg_get_image_watches(struct archive_context *context)
{
	if (!context->reg_watches)
		return;

	g_assert(g_dbus_remove_watch(context->conn, context->completed_watch));
	g_assert(g_dbus_remove_watch(context->conn, context->failed_watch));
}

static void get_image(struct archive_context *context, char *path,
						char *handle, aos_callback cb)
{
	struct callback_data *data;
	DBusMessageIter args, dict;
	DBusPendingCall *result;
	DBusMessage *msg;

	printf("get_image\n");

	g_assert(cb != NULL);

	msg = dbus_message_new_method_call(CLIENT_ADDRESS, context->aos_path,
						AOS_INTERFACE, "GetImage");

	if (msg == NULL)
		goto failed;

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &path))
		goto failed;

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &handle))
		goto failed;

	if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{ss}",
									&dict))
		goto failed;

	if (!dbus_message_iter_close_container(&args, &dict))
		goto failed;

	if (!dbus_connection_send_with_reply(context->conn, msg, &result, -1))
		goto failed;

	if (!reg_get_image_watches(context, cb))
		goto failed;

	data = g_new0(struct callback_data, 1);
	data->context = context;
	data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_image_callback,
								data, g_free)) {
		g_free(data);
		goto failed;
	}

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	printf("error in get_image\n");
	cb(context, -EBADR);
}

static void end_aos_session(struct archive_context *context) {
	DBusMessageIter args;
	DBusMessage *msg = dbus_message_new_method_call(CLIENT_ADDRESS,
					context->aos_path,
					AOS_INTERFACE, "RemoveSession");

	if (msg == NULL)
		goto cleanup;

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH,
							&context->aos_path))
		goto cleanup_msg;

	if (!dbus_connection_send(context->conn, msg, NULL))
		goto cleanup_msg;

cleanup_msg:
	dbus_message_unref(msg);
cleanup:
	unreg_get_image_watches(context);
	free_archive_context(context);
}

static void reset_context(struct archive_context *context) {
	free_properties_object(context->cur_prop);
	context->cur_prop = NULL;
	free_listing_object(context->cur_image);
	context->cur_image = NULL;
	g_free(context->cur_path);
	context->cur_path = NULL;
}

static void rename_image(struct archive_context *context, int err) {
	char *new_path = NULL, *name = NULL;
	printf("rename_image, err: %d\n", err);
	if (err == -EBADR) {
		//critical error - abort
		context->session->status = -EBADR;
		end_aos_session(context);
		return;
	}
	else if (err == -EINVAL) {
		//error with current image - get new one
		get_next_image(context, 0);
		return;
	}
	if (context->cur_prop != NULL)
		name = context->cur_prop->name;
	new_path = safe_rename(name, bip_dir, context->cur_path);
	if (new_path == NULL) {
		unlink(context->cur_path);
		get_next_image(context, 0);
		return;
	}
	g_free(new_path);
	get_next_image(context, 0);
	return;
}

static void save_image_to_temp(struct archive_context *context, int err) {
	int fd;
	printf("save_image_to_temp, err: %d\n", err);
	if (err == -EBADR) {
		//critical error - abort
		context->session->status = -EBADR;
		end_aos_session(context);
		return;
	}
	// finished obtaining properties
	if ((fd = g_file_open_tmp(NULL, &context->cur_path, NULL)) < 0) {
		get_next_image(context, 0);
		return;
	}
	close(fd);
	if (context->cur_prop != NULL) {
		printf("getting image: [%s: %s]\n", context->cur_prop->handle,
						context->cur_prop->name);
	}
	get_image(context, context->cur_path, context->cur_image->handle,
							rename_image);
	return;
}

static void get_next_image(struct archive_context *context, int err) {
	printf("get_next_image, err: %d\n", err);
	reset_context(context);
	// start with new image
	if (context->image_list == NULL) {
		end_aos_session(context);
		return;
	}
	context->cur_image = context->image_list->data;
	context->image_list = g_slist_remove(context->image_list,
						context->cur_image);

	get_properties(context, context->cur_image->handle, save_image_to_temp);
}

static void get_listing_finished(struct archive_context *context, int err)
{
	printf("get_listing_finished, status: %d\n", err);
	if (err < 0) {
		context->session->status = err;
		end_aos_session(context);
		return;
	}
	get_next_image(context, 0);
}

static void get_aos_interface_callback(DBusPendingCall *call, void *user_data)
{
	struct archive_context *context = user_data;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	char *path;

	printf("get_aos_interface_callback\n");

	if (msg == NULL) {
		// assign int is atomic? - possible concurrency issue
		context->session->status = -EBADR;
		return;
	}

	if (dbus_message_get_error_name(msg) != NULL) {
		// assign int is atomic? - possible concurrency issue
		context->session->status = -EBADR;
		return;
	}

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID)) {
		context->session->status = -EBADR;
		return;
	}

	context->aos_path = g_strdup(path);

	if (!get_listing(context, get_listing_finished)) {
		end_aos_session(context);
		context->session->status = -EBADR;
		return;
	}
}

static gboolean get_aos_interface(struct archive_context *context)
{
	DBusMessage *msg;
	DBusMessageIter args, dict;
	DBusPendingCall *result;
	msg = dbus_message_new_method_call(CLIENT_ADDRESS, CLIENT_PATH,
							CLIENT_INTERFACE,
							"CreateSession");
	if (msg == NULL)
		return FALSE;

	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}",
									&dict))
		goto failed;

	if (!append_sv_dict_entry(&dict, "Destination", DBUS_TYPE_STRING,
				DBUS_TYPE_STRING_AS_STRING, &context->session->address))
		goto failed;

	if (!append_sv_dict_entry(&dict, "Target", DBUS_TYPE_STRING,
					DBUS_TYPE_STRING_AS_STRING, &bip_aos))
		goto failed;

	if (!dbus_message_iter_close_container(&args, &dict))
		goto failed;
	
	if (!dbus_connection_send_with_reply(context->conn, msg, &result, -1))
		goto failed;

	if (!dbus_pending_call_set_notify(result, get_aos_interface_callback,
								context, NULL))
		goto failed;

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return TRUE;
failed:
	dbus_message_unref(msg);
	return FALSE;
}

static void *imgarch_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct archive_session *session = context;
	struct archive_context *object = g_new0(struct archive_context, 1);
	object->session = session;

	if ((object->conn = connect_to_client()) == NULL)
		goto failed;

	if (!get_aos_interface(object))
		goto failed;
	printf("imgarch open\n");
	return object;
failed:
	free_archive_context(object);
	if (err != NULL)
		*err = -EBADR;
	return NULL;
}

static int imgarch_close(void *object)
{
	//struct archive_context *context = object;
	printf("imgarch close\n");
	return 0;
}

static ssize_t imgarch_write(void *object, const void *buf, size_t count)
{
	return -EINVAL;
}

static ssize_t imgarch_flush(void *object)
{
	printf("imgarch flush\n");

	return 0;
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
