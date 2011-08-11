/*
 *
 *  OBEX Client
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>

#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "manager.h"

#define CLIENT_SERVICE  "org.openobex.client"

#define CLIENT_INTERFACE  "org.openobex.Client"
#define CLIENT_PATH       "/"

struct send_data {
	DBusConnection *connection;
	DBusMessage *message;
	gchar *sender;
	gchar *agent;
	char *filename;
	GPtrArray *files;
};

static GSList *sessions = NULL;

static void shutdown_session(struct session_data *session)
{
	sessions = g_slist_remove(sessions, session);
	session_shutdown(session);
	session_unref(session);
}

static void unregister_session(void *data)
{
	struct session_data *session = data;

	if (g_slist_find(sessions, session) == NULL)
		return;

	sessions = g_slist_remove(sessions, session);
	session_unref(session);
}

static void create_callback(struct session_data *session, GError *err,
							void *user_data)
{
	struct send_data *data = user_data;
	unsigned int i;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(data->message,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(data->connection, error);
		shutdown_session(session);
		goto done;
	}

	if (session_get_target(session) != NULL) {
		const char *path;

		path = session_register(session, unregister_session);

		g_dbus_send_reply(data->connection, data->message,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);
		goto done;
	}

	g_dbus_send_reply(data->connection, data->message, DBUS_TYPE_INVALID);

	session_set_agent(session, data->sender, data->agent);

	for (i = 0; i < data->files->len; i++) {
		const gchar *filename = g_ptr_array_index(data->files, i);
		gchar *basename = g_path_get_basename(filename);

		if (session_send(session, filename, basename) < 0) {
			g_free(basename);
			break;
		}

		g_free(basename);
	}

	/* No need to keep a reference for SendFiles */
	sessions = g_slist_remove(sessions, session);
	session_unref(session);

done:
	if (data->files)
		g_ptr_array_free(data->files, TRUE);
	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data->agent);
	g_free(data);
}

static int parse_device_dict(DBusMessageIter *iter,
		const char **source, const char **dest, const char **target,
		const char **params, uint8_t *channel)
{
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "Source") == TRUE)
				dbus_message_iter_get_basic(&value, source);
			else if (g_str_equal(key, "Destination") == TRUE)
				dbus_message_iter_get_basic(&value, dest);
			else if (g_str_equal(key, "Target") == TRUE)
				dbus_message_iter_get_basic(&value, target);
			else if (g_str_equal(key, "Parameters") == TRUE)
				dbus_message_iter_get_basic(&value, params);
			break;
		case DBUS_TYPE_BYTE:
			if (g_str_equal(key, "Channel") == TRUE)
				dbus_message_iter_get_basic(&value, channel);
			break;
		}

		dbus_message_iter_next(iter);
	}

	return 0;
}

static DBusMessage *send_files(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, array;
	struct session_data *session;
	GPtrArray *files;
	struct send_data *data;
	const char *agent, *source = NULL, *dest = NULL, *target = NULL;
	const char *sender, *params = NULL;
	uint8_t channel = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	parse_device_dict(&array, &source, &dest, &target, &params, &channel);
	if (dest == NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &array);

	files = g_ptr_array_new();
	if (files == NULL)
		return g_dbus_create_error(message,
					"org.openobex.Error.NoMemory", NULL);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		char *value;

		dbus_message_iter_get_basic(&array, &value);
		g_ptr_array_add(files, value);

		dbus_message_iter_next(&array);
	}

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &agent);

	if (files->len == 0) {
		g_ptr_array_free(files, TRUE);
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	}

	sender = dbus_message_get_sender(message);

	data = g_try_malloc0(sizeof(*data));
	if (data == NULL) {
		g_ptr_array_free(files, TRUE);
		return g_dbus_create_error(message,
					"org.openobex.Error.NoMemory", NULL);
	}

	data->connection = dbus_connection_ref(connection);
	data->message = dbus_message_ref(message);
	data->sender = g_strdup(sender);
	data->agent = g_strdup(agent);
	data->files = files;

	session = session_create(source, dest, "OPP", params, channel, sender,
							create_callback, data);
	if (session != NULL) {
		sessions = g_slist_append(sessions, session);
		return NULL;
	}

	g_ptr_array_free(data->files, TRUE);
	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data->agent);
	g_free(data);

	return g_dbus_create_error(message, "org.openobex.Error.Failed", NULL);
}

static void pull_complete_callback(struct session_data *session,
					GError *err, void *user_data)
{
	struct send_data *data = user_data;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(data->message,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(data->connection, error);
		goto done;
	}

	g_dbus_send_reply(data->connection, data->message, DBUS_TYPE_INVALID);

done:
	shutdown_session(session);
	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->filename);
	g_free(data->sender);
	g_free(data);
}

static void pull_session_callback(struct session_data *session,
					GError *err, void *user_data)
{
	struct send_data *data = user_data;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(data->message,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(data->connection, error);
		shutdown_session(session);
		goto done;
	}

	session_pull(session, "text/x-vcard", data->filename,
						pull_complete_callback, data);

	return;

done:
	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->filename);
	g_free(data->sender);
	g_free(data);
}

static DBusMessage *pull_business_card(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, dict;
	struct session_data *session;
	struct send_data *data;
	const char *source = NULL, *dest = NULL, *target = NULL;
	const char *name = NULL, *params = NULL;
	uint8_t channel = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	parse_device_dict(&dict, &source, &dest, &target, &params, &channel);
	if (dest == NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	dbus_message_iter_get_basic(&iter, &name);

	data = g_try_malloc0(sizeof(*data));
	if (data == NULL)
		return g_dbus_create_error(message,
					"org.openobex.Error.NoMemory", NULL);

	data->connection = dbus_connection_ref(connection);
	data->message = dbus_message_ref(message);
	data->sender = g_strdup(dbus_message_get_sender(message));
	data->filename = g_strdup(name);

	session = session_create(source, dest, "OPP", params, channel, data->sender,
					pull_session_callback, data);
	if (session != NULL) {
		sessions = g_slist_append(sessions, session);
		return NULL;
	}

	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data->filename);
	g_free(data);

	return g_dbus_create_error(message, "org.openobex.Error.Failed", NULL);
}

static DBusMessage *exchange_business_cards(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	return g_dbus_create_error(message, "org.openobex.Error.Failed", NULL);
}

static struct session_data *find_session(const char *path)
{
	GSList *l;

	for (l = sessions; l; l = l->next) {
		struct session_data *session = l->data;

		if (g_str_equal(session_get_path(session), path) == TRUE)
			return session;
	}

	return NULL;
}

static DBusMessage *create_session(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, dict;
	struct session_data *session;
	struct send_data *data;
	const char *source = NULL, *dest = NULL, *target = NULL;
	const char *params = NULL;
	uint8_t channel = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	parse_device_dict(&dict, &source, &dest, &target, &params, &channel);
	if (dest == NULL || target == NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	data = g_try_malloc0(sizeof(*data));
	if (data == NULL)
		return g_dbus_create_error(message,
					"org.openobex.Error.NoMemory", NULL);

	data->connection = dbus_connection_ref(connection);
	data->message = dbus_message_ref(message);
	data->sender = g_strdup(dbus_message_get_sender(message));

	session = session_create(source, dest, target, params, channel,
					data->sender, create_callback, data);
	if (session != NULL) {
		sessions = g_slist_append(sessions, session);
		return NULL;
	}

	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data);

	return g_dbus_create_error(message, "org.openobex.Error.Failed", NULL);
}

static DBusMessage *remove_session(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session;
	const gchar *sender, *path;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	session = find_session(path);
	if (session == NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	sender = dbus_message_get_sender(message);
	if (g_str_equal(sender, session_get_owner(session)) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	shutdown_session(session);

	return dbus_message_new_method_return(message);
}

static void capabilities_complete_callback(struct session_data *session,
						GError *err, void *user_data)
{
	struct transfer_data *transfer = session_get_transfer(session);
	struct send_data *data = user_data;
	const char *capabilities;
	int size;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(data->message,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(data->connection, error);
		goto done;
	}

	capabilities = transfer_get_buffer(transfer, &size);
	if (size == 0)
		capabilities = "";

	g_dbus_send_reply(data->connection, data->message,
			DBUS_TYPE_STRING, &capabilities,
			DBUS_TYPE_INVALID);

done:

	shutdown_session(session);
	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data);
}

static void capability_session_callback(struct session_data *session,
						GError *err, void *user_data)
{
	struct send_data *data = user_data;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(data->message,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(data->connection, error);
		shutdown_session(session);
		goto done;
	}

	session_pull(session, "x-obex/capability", NULL,
				capabilities_complete_callback, data);

	return;

done:
	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data);
}

static DBusMessage *get_capabilities(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, dict;
	struct session_data *session;
	struct send_data *data;
	const char *source = NULL, *dest = NULL, *target = NULL;
	const char *params = NULL;
	uint8_t channel = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	parse_device_dict(&dict, &source, &dest, &target, &params, &channel);
	if (dest == NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	data = g_try_malloc0(sizeof(*data));
	if (data == NULL)
		return g_dbus_create_error(message,
					"org.openobex.Error.NoMemory", NULL);

	data->connection = dbus_connection_ref(connection);
	data->message = dbus_message_ref(message);
	data->sender = g_strdup(dbus_message_get_sender(message));

	if (!target)
		target = "OPP";

	session = session_create(source, dest, target, params,
					channel, data->sender,
					capability_session_callback,
					data);
	if (session != NULL) {
		sessions = g_slist_append(sessions, session);
		return NULL;
	}

	dbus_message_unref(data->message);
	dbus_connection_unref(data->connection);
	g_free(data->sender);
	g_free(data);

	return g_dbus_create_error(message, "org.openobex.Error.Failed", NULL);
}

static GDBusMethodTable client_methods[] = {
	{ "SendFiles", "a{sv}aso", "", send_files,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "PullBusinessCard", "a{sv}s", "", pull_business_card,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "ExchangeBusinessCards", "a{sv}ss", "", exchange_business_cards,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "CreateSession", "a{sv}", "o", create_session,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RemoveSession", "o", "", remove_session,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetCapabilities", "a{sv}", "s", get_capabilities,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

static DBusConnection *conn = NULL;

int manager_init(void)
{
	DBusError derr;

	dbus_error_init(&derr);

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, CLIENT_SERVICE, &derr);
	if (dbus_error_is_set(&derr) == TRUE) {
		g_printerr("%s: %s\n", derr.name, derr.message);
		dbus_error_free(&derr);
		return -1;
	}

	if (g_dbus_register_interface(conn, CLIENT_PATH, CLIENT_INTERFACE,
						client_methods, NULL, NULL,
							NULL, NULL) == FALSE) {
		g_printerr("Can't register client interface\n");
		dbus_connection_unref(conn);
		conn = NULL;
		return -1;
	}

	return 0;
}

void manager_exit(void)
{
	if (conn == NULL)
		return;

	g_dbus_unregister_interface(conn, CLIENT_PATH, CLIENT_INTERFACE);
	dbus_connection_unref(conn);
}
