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
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

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

struct sarchive_data {
	struct archive_session *session;
	DBusConnection *conn;
	char *aos_path;
	char *service_id;
	GSList *image_list;
	unsigned int completed_watch, failed_watch;
	gboolean reg_watches;

	char *cur_path;
	struct listing_object *cur_image;
	struct properties_object *cur_prop;
};

typedef void (*aos_callback) (struct sarchive_data *, int err);

static gboolean reg_get_image_watches(struct sarchive_data *data, aos_callback cb);
static void unreg_get_image_watches(struct sarchive_data *data);
static void get_next_image(struct sarchive_data *data, int err);

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

static void free_sarchive_data(struct sarchive_data *data) {
	GSList *l;
	if (data == NULL)
		return;
	g_free(data->aos_path);
	for (l = data->image_list; l != NULL; l = g_slist_next(l))
		free_listing_object(l->data);
	g_slist_free(data->image_list);
	g_free(data);
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
	struct sarchive_data *data;
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
	struct callback_data *cb = user_data;
	struct sarchive_data *data = cb->data;
	DBusMessageIter iter, array;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	GSList *list = NULL;

	printf("get_listing_callback\n");
	g_assert(cb->cb != NULL);

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
	data->image_list = list;

	cb->cb(cb->data, 0);
	return;
failed:
	while (list != NULL) {
		free_listing_object(list->data);
		list = g_slist_remove(list, list->data);
	}

	if (msg != NULL)
		dbus_message_unref(msg);
	cb->cb(cb->data, -EBADR);
	return;
}

static gboolean get_listing(struct sarchive_data *data, aos_callback cb)
{
	DBusMessageIter args, dict;
	DBusPendingCall *result;
	struct callback_data *cb_data = NULL;
	gboolean truth = TRUE;
	DBusMessage *msg = dbus_message_new_method_call(CLIENT_ADDRESS, data->aos_path,
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
	
	if (!dbus_connection_send_with_reply(data->conn, msg, &result, -1))
		goto failed;

	cb_data = g_new0(struct callback_data, 1);
	cb_data->data = data;
	cb_data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_listing_callback,
								cb_data, g_free)) {
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
	struct callback_data *cb = user_data;
	struct sarchive_data *data = cb->data;
	struct properties_object *obj;
	DBusMessageIter iter, array, dict;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);

	g_assert(cb->cb != NULL);

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

	data->cur_prop = obj;

	dbus_message_unref(msg);
	cb->cb(cb->data, 0);
	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	cb->cb(cb->data, -EINVAL);
}

static void get_properties(struct sarchive_data *data, char *handle, 
							aos_callback cb)
{
	DBusMessageIter args;
	DBusPendingCall *result;
	struct callback_data *cb_data = NULL;
	DBusMessage *msg;

	g_assert(cb != NULL);

	msg = dbus_message_new_method_call(CLIENT_ADDRESS,
					data->aos_path, AOS_INTERFACE,
						"GetImageProperties");

	if (msg == NULL)
		goto failed;

	dbus_message_iter_init_append(msg, &args);
	
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &handle))
		goto failed;

	if (!dbus_connection_send_with_reply(data->conn, msg, &result, -1))
		goto failed;

	cb_data = g_new0(struct callback_data, 1);
	cb_data->data = data;
	cb_data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_properties_callback,
								cb_data, NULL)) {
		g_free(cb_data);
		goto failed;
	}

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	cb(data, -EBADR);
	return;
}

static void get_image_callback(DBusPendingCall *call, void *user_data)
{
	struct callback_data *cb_data = user_data;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	g_assert(cb_data->cb);
	printf("get_image_callback\n");

	if (msg == NULL)
		goto failed;

	if (dbus_message_get_error_name(msg) != NULL)
		goto failed;

	return;
failed:
	if (msg != NULL)
		dbus_message_unref(msg);
	cb_data->cb(cb_data->data, -EINVAL);
}

static gboolean get_image_completed(DBusConnection *connection, DBusMessage *message,
							void *user_data)
{
	struct callback_data *data = user_data;
	printf("get_image_completed\n");
	data->cb(data->data, 0);
	return TRUE;
}

static gboolean get_image_failed(DBusConnection *connection, DBusMessage *message,
							void *user_data)
{
	struct callback_data *data = user_data;
	printf("get_image_failed\n");
	data->cb(data->data, -EINVAL);
	return TRUE;
}

static gboolean reg_get_image_watches(struct sarchive_data *data, aos_callback cb)
{
	struct callback_data *cb_data = NULL;

	if (data->reg_watches)
		return TRUE;

	cb_data = g_new0(struct callback_data, 1);
	cb_data->data = data;
	cb_data->cb = cb;

	data->completed_watch = g_dbus_add_signal_watch(data->conn, NULL,
						data->aos_path,
						AOS_INTERFACE, "GetImageCompleted",
						get_image_completed, cb_data, NULL);

	if (data->completed_watch == 0) {
		g_free(cb_data);
		return FALSE;
	}

	data->failed_watch = g_dbus_add_signal_watch(data->conn, NULL,
						data->aos_path,
						AOS_INTERFACE, "GetImageFailed",
						&get_image_failed, cb_data, g_free);

	if (data->failed_watch == 0) {
		g_dbus_remove_watch(data->conn, data->completed_watch);
		g_free(cb_data);
		return FALSE;
	}

	data->reg_watches = TRUE;
	return TRUE;
}

static void unreg_get_image_watches(struct sarchive_data *data)
{
	if (!data->reg_watches)
		return;

	g_assert(g_dbus_remove_watch(data->conn, data->completed_watch));
	g_assert(g_dbus_remove_watch(data->conn, data->failed_watch));
}

static void get_image(struct sarchive_data *data, char *path,
						char *handle, aos_callback cb)
{
	struct callback_data *cb_data;
	DBusMessageIter args, dict;
	DBusPendingCall *result;
	DBusMessage *msg;

	printf("get_image\n");

	g_assert(cb != NULL);

	msg = dbus_message_new_method_call(CLIENT_ADDRESS, data->aos_path,
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

	if (!dbus_connection_send_with_reply(data->conn, msg, &result, -1))
		goto failed;

	if (!reg_get_image_watches(data, cb))
		goto failed;

	cb_data = g_new0(struct callback_data, 1);
	cb_data->data = data;
	cb_data->cb = cb;

	if (!dbus_pending_call_set_notify(result, get_image_callback,
								cb_data, g_free)) {
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
	cb(data, -EBADR);
}

static void end_aos_session(struct sarchive_data *data) {
	DBusMessageIter args;
	DBusMessage *msg = dbus_message_new_method_call(CLIENT_ADDRESS,
					data->aos_path,
					AOS_INTERFACE, "RemoveSession");

	if (msg == NULL)
		goto cleanup;

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH,
							&data->aos_path))
		goto cleanup_msg;

	if (!dbus_connection_send(data->conn, msg, NULL))
		goto cleanup_msg;

cleanup_msg:
	dbus_message_unref(msg);
cleanup:
	unreg_get_image_watches(data);
	free_sarchive_data(data);
}

static void reset_data(struct sarchive_data *data) {
	free_properties_object(data->cur_prop);
	data->cur_prop = NULL;
	free_listing_object(data->cur_image);
	data->cur_image = NULL;
	g_free(data->cur_path);
	data->cur_path = NULL;
}

static void rename_image(struct sarchive_data *data, int err) {
	char *new_path = NULL, *name = NULL;
	printf("rename_image, err: %d\n", err);
	if (err == -EBADR) {
		//critical error - abort
		data->session->status = -EBADR;
		end_aos_session(data);
		free_sarchive_data(data);
		return;
	}
	else if (err == -EINVAL) {
		//error with current image - get new one
		get_next_image(data, 0);
		return;
	}
	if (data->cur_prop != NULL)
		name = data->cur_prop->name;
	new_path = safe_rename(name, bip_dir, data->cur_path, &err);
	if (new_path == NULL) {
		unlink(data->cur_path);
		get_next_image(data, 0);
		return;
	}
	g_free(new_path);
	get_next_image(data, 0);
	return;
}

static void save_image_to_temp(struct sarchive_data *data, int err) {
	int fd;
	printf("save_image_to_temp, err: %d\n", err);
	if (err == -EBADR) {
		//critical error - abort
		data->session->status = -EBADR;
		end_aos_session(data);
		free_sarchive_data(data);
		return;
	}
	// finished obtaining properties
	if ((fd = g_file_open_tmp(NULL, &data->cur_path, NULL)) < 0) {
		get_next_image(data, 0);
		return;
	}
	close(fd);
	if (data->cur_prop != NULL) {
		printf("getting image: [%s: %s]\n", data->cur_prop->handle,
						data->cur_prop->name);
	}
	get_image(data, data->cur_path, data->cur_image->handle,
							rename_image);
	return;
}

static void get_next_image(struct sarchive_data *data, int err) {
	printf("get_next_image, err: %d\n", err);
	reset_data(data);
	// start with new image
	if (data->image_list == NULL) {
		data->session->status = 0;
		end_aos_session(data);
		free_sarchive_data(data);
		return;
	}
	data->cur_image = data->image_list->data;
	data->image_list = g_slist_remove(data->image_list,
						data->cur_image);

	get_properties(data, data->cur_image->handle, save_image_to_temp);
}

static void get_listing_finished(struct sarchive_data *data, int err)
{
	printf("get_listing_finished, status: %d\n", err);
	if (err < 0) {
		data->session->status = err;
		end_aos_session(data);
		free_sarchive_data(data);
		return;
	}
	get_next_image(data, 0);
}

static void get_aos_interface_callback(DBusPendingCall *call, void *user_data)
{
	struct sarchive_data *data = user_data;
	DBusMessage *msg = dbus_pending_call_steal_reply(call);
	char *path;

	printf("get_aos_interface_callback\n");
	printf("session: %p\n", data->session);

	if (msg == NULL) {
		// assign int is atomic? - possible concurrency issue
		data->session->status = -EBADR;
		return;
	}

	if (dbus_message_get_error_name(msg) != NULL) {
		// assign int is atomic? - possible concurrency issue
		data->session->status = -EBADR;
		return;
	}

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID)) {
		data->session->status = -EBADR;
		return;
	}

	data->aos_path = g_strdup(path);

	if (!get_listing(data, get_listing_finished)) {
		end_aos_session(data);
		data->session->status = -EBADR;
		free_sarchive_data(data);
		return;
	}
}

static gboolean get_aos_interface(struct sarchive_data *data)
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
				DBUS_TYPE_STRING_AS_STRING, &data->session->address))
		goto failed;

	if (!append_sv_dict_entry(&dict, "Target", DBUS_TYPE_STRING,
					DBUS_TYPE_STRING_AS_STRING, &bip_aos))
		goto failed;

	if (!append_sv_dict_entry(&dict, "Parameters", DBUS_TYPE_STRING,
					DBUS_TYPE_STRING_AS_STRING,
					&data->service_id))
		goto failed;

	if (!dbus_message_iter_close_container(&args, &dict))
		goto failed;
	
	if (!dbus_connection_send_with_reply(data->conn, msg, &result, -1))
		goto failed;

	if (!dbus_pending_call_set_notify(result, get_aos_interface_callback,
								data, NULL))
		goto failed;

	dbus_message_unref(msg);
	dbus_pending_call_unref(result);

	return TRUE;
failed:
	dbus_message_unref(msg);
	return FALSE;
}

struct sa_aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

static char *parse_aparam(const uint8_t *buffer, int32_t hlen)
{
	struct sa_aparam_header *hdr;
	int32_t len = 0;
	char *service_id = NULL;
	uint128_t beval;
	uuid_t uuid;
	char temp[MAX_LEN_UUID_STR];
	while (len < hlen) {
		printf("got %u %u %u of data\n", len, hlen, sizeof(struct sa_aparam_header));
		hdr = (void *) buffer + len;
		if (hlen - len < (int32_t) sizeof(struct sa_aparam_header))
			goto failed;

		switch (hdr->tag) {
		case SID_TAG:
			if (hdr->len != SID_LEN)
				goto failed;
			if (service_id != NULL)
				goto failed;

			memcpy(&beval, hdr->val, SID_LEN);
			sdp_uuid128_create(&uuid, &beval);
			sdp_uuid2strn(&uuid, temp, MAX_LEN_UUID_STR);

			service_id = g_strdup(temp);
			printf("service_id = %s\n", service_id);
			break;

		default:
			goto failed;
		}

		len += hdr->len + sizeof(struct sa_aparam_header);
	}
	return service_id;

failed:
	g_free(service_id);

	return NULL;
}

static int feed_next_header (void *object, uint8_t hi, obex_headerdata_t hv,
							uint32_t hv_size)
{
	struct sarchive_data *data = object;
	printf("feed_next_header\n");

	if (hi == OBEX_HDR_APPARAM) {
		char *service_id = NULL;
		service_id = parse_aparam(hv.bs, hv_size);

		if (service_id == NULL)
			return -EBADR;

		data->service_id = service_id;
	}
	return 0;
}

static ssize_t get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi) {
	struct sarchive_data *data = object;

	*hi = OBEX_HDR_EMPTY;
	if ((data->conn = connect_to_client()) == NULL) {
		free_sarchive_data(data);
		return -EBADR;
	}

	if (!get_aos_interface(data)) {
		free_sarchive_data(data);
		return -EBADR;
	}
	return 0;
}

static void *imgarch_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct archive_session *session = context;
	struct sarchive_data *data = g_new0(struct sarchive_data, 1);
	data->session = session;

	printf("imgarch open\n");
	return data;
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
	.feed_next_header = feed_next_header,
	.get_next_header = get_next_header,
};

static void *imgstatus_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	printf("imgstatus open\n");
	*size = 0;
	return context;
}

static int imgstatus_close(void *object)
{
	//struct sarchive_data *data = object;
	printf("imgstatus close\n");
	return 0;
}

static struct obex_mime_type_driver imgstatus = {
	.target = IMAGE_ARCH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-status",
	.open = imgstatus_open,
	.close = imgstatus_close,
};

static int imgarch_init(void)
{
	int ret;
	if ((ret = obex_mime_type_driver_register(&imgstatus)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imgarch);
}

static void imgarch_exit(void)
{
	obex_mime_type_driver_unregister(&imgarch);
	obex_mime_type_driver_unregister(&imgstatus);
}

OBEX_PLUGIN_DEFINE(imgarch, imgarch_init, imgarch_exit)
