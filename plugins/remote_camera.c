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

#include "gdbus.h"
#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "remote_camera.h"
#include "bip_util.h"

#define REMOTE_CAMERA_CHANNEL 27
#define REMOTE_CAMERA_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?> \
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
    <uint8 value=\"0x0002\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0311\">						\
    <uint16 value=\"0x0080\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0312\">						\
    <uint32 value=\"0x41c0\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0313\">						\
    <uint64 value=\"0xffffffffffffffff\"/>				\
  </attribute>								\
</record>"

#define HANDLE_LIMIT 10000000

#define RC_MANAGER_SERVICE "org.openobex.RCManager"
#define RC_MANAGER_PATH "/rcmanager"
#define RC_MANAGER_INTERFACE RC_MANAGER_SERVICE ".RCManager"
#define RC_MANAGER_ERROR_INTERFACE RC_MANAGER_SERVICE ".RCManagerError"

struct rc_agent {
	char *bus_name;
	char *path;
	unsigned int watch_id;
	int (*cb) ();
};

static DBusConnection *connection = NULL;
static struct rc_agent *agent = NULL;

static void free_remote_camera_session(struct remote_camera_session *session) {
	g_free(session);
}

int get_new_handle_rc(struct remote_camera_session *session) {
	if (session->next_handle >= HANDLE_LIMIT) {
		return -1;
	}
	return session->next_handle++;
}

static void *remote_camera_connect(struct obex_session *os, int *err)
{
	struct remote_camera_session *session;
	manager_register_session(os);

	session = g_new0(struct remote_camera_session, 1);
	session->os = os;

	if (err != NULL)
		*err = 0;

	return session;
}

static int remote_camera_get(struct obex_session *os, obex_object_t *obj,
							void *user_data)
{
	int ret;

	if (user_data == NULL)
		return -EBADR;

	ret = obex_get_stream_start(os, "");
	if (ret < 0)
		return ret;
	return 0;
}

static void remote_camera_disconnect(struct obex_session *os, void *user_data)
{
	struct remote_camera_session *session = user_data;
	free_remote_camera_session(session);
	manager_unregister_session(os);
}

static struct obex_service_driver remote_camera = {
	.name = "OBEXD Remote Camera Server",
	.service = OBEX_BIP_RC,
	.channel = REMOTE_CAMERA_CHANNEL,
	.record = REMOTE_CAMERA_RECORD,
	.target = REMOTE_CAMERA_TARGET,
	.target_size = TARGET_SIZE,
	.connect = remote_camera_connect,
	.get = remote_camera_get,
	.disconnect = remote_camera_disconnect
};

static void rc_agent_free(struct rc_agent* agent) {
	g_free(agent->bus_name);
	g_free(agent->path);
	g_dbus_remove_watch(connection, agent->watch_id);
	g_free(agent);
}

static void agent_disconnected(DBusConnection *conn, void *user_data)
{
	DBG("Agent exited");
	rc_agent_free(agent);
	agent = NULL;
}

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RC_MANAGER_ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *agent_already_exists(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RC_MANAGER_ERROR_INTERFACE ".AlreadyExists",
			"Agent already exists");
}

static inline DBusMessage *agent_does_not_exist(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RC_MANAGER_ERROR_INTERFACE ".DoesNotExist",
			"Agent does not exist");
}

static inline DBusMessage *not_authorized(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RC_MANAGER_ERROR_INTERFACE ".NotAuthorized",
			"Not authorized");
}

static DBusMessage *rc_register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *sender;

	if (agent)
		return agent_already_exists(msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return invalid_args(msg);

	sender = dbus_message_get_sender(msg);
	agent = g_new0(struct rc_agent, 1);
	agent->bus_name = g_strdup(sender);
	agent->path = g_strdup(path);

	agent->watch_id = g_dbus_add_disconnect_watch(conn, sender,
					agent_disconnected, NULL, NULL);

	DBG("Agent registered");

	return dbus_message_new_method_return(msg);
}

static DBusMessage *rc_unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *sender;

	if (!agent)
		return agent_does_not_exist(msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return invalid_args(msg);

	if (strcmp(agent->path, path) != 0)
		return agent_does_not_exist(msg);

	sender = dbus_message_get_sender(msg);
	if (strcmp(agent->bus_name, sender) != 0)
		return not_authorized(msg);

	rc_agent_free(agent);
	agent = NULL;

	DBG("Agent unregistered");

	return dbus_message_new_method_return(msg);
}

struct monit_image_data {
	monit_image_cb cb;
	void *user_data;
};

static void get_monitoring_image_cb(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct monit_image_data *data = user_data;
	char *monit_image = NULL, *image = NULL;
	DBusError err;
	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		dbus_error_free(&err);
		data->cb(data->user_data, NULL, NULL, -EBADR);
		goto cleanup;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_STRING, &monit_image,
				DBUS_TYPE_STRING, &image,
				DBUS_TYPE_INVALID)) {
		data->cb(data->user_data, NULL, NULL, -EBADR);
		goto cleanup;
	}

	data->cb(data->user_data, g_strdup(monit_image), g_strdup(image), 0);
cleanup:
	dbus_message_unref(reply);
	g_free(data);
}

int get_monitoring_image(gboolean store, monit_image_cb cb, void *user_data)
{
	DBusMessage *msg = NULL;
	DBusPendingCall *call = NULL;
	struct monit_image_data *data = NULL;

	if (agent == NULL) {
		printf("Get monitoring image Failed\n");
		return -EBADR;
	}

	msg = dbus_message_new_method_call(agent->bus_name, agent->path,
					"org.openobex.GetMonitoringImage",
					"GetMonitoringImage");

	if (msg == NULL)
		return -ENOMEM;

	if (!dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &store,
                                        DBUS_TYPE_INVALID)) {
		dbus_message_unref(msg);
		return -ENOMEM;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &call, -1)) {
		dbus_message_unref(msg);
		return -ENOMEM;
	}

	data = g_new0(struct monit_image_data, 1);
	data->cb = cb;
	data->user_data = user_data;
	dbus_pending_call_set_notify(call, get_monitoring_image_cb, data, NULL);
	return 0;
}

static GDBusMethodTable rc_manager_methods[] = {
	{ "RegisterAgent",	"o",	"",	rc_register_agent	},
	{ "UnregisterAgent",	"o",	"",	rc_unregister_agent	},
	{ }
};

static gboolean rc_manager_init(void)
{
	DBusError err;

	DBG("");

	dbus_error_init(&err);

	connection = g_dbus_setup_bus(DBUS_BUS_SESSION, RC_MANAGER_SERVICE,
									&err);
	if (connection == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		return FALSE;
	}

	printf("Service: %s\n", RC_MANAGER_SERVICE);
	printf("Interface: %s\n", RC_MANAGER_INTERFACE);
	printf("Path: %s\n", RC_MANAGER_PATH);

	return g_dbus_register_interface(connection, RC_MANAGER_PATH,
					RC_MANAGER_INTERFACE,
					rc_manager_methods, NULL, NULL,
					NULL, NULL);
}

static int remote_camera_init(void)
{
	if (!rc_manager_init())
		return -EPERM;
	return obex_service_driver_register(&remote_camera);
}

static void remote_camera_exit(void)
{
	obex_service_driver_unregister(&remote_camera);
}

OBEX_PLUGIN_DEFINE(remote_camera, remote_camera_init, remote_camera_exit)
