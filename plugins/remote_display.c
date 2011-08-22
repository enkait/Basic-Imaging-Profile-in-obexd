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
#include <wand/MagickWand.h>

#include "gdbus.h"
#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "remote_display.h"
#include "bip_util.h"

#define REMOTE_DISPLAY_CHANNEL 26
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
									\
  <attribute id=\"0x0310\">						\
    <uint8 value=\"0x0008\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0311\">						\
    <uint16 value=\"0x0100\"/>						\
  </attribute>								\
									\
  <attribute id=\"0x0312\">						\
    <uint32 value=\"0x003b\"/>						\
  </attribute>								\
</record>"

#define HANDLE_LIMIT 10000000

#define RD_MANAGER_SERVICE "org.openobex.RDManager"
#define RD_MANAGER_PATH "/rdmanager"
#define RD_MANAGER_INTERFACE RD_MANAGER_SERVICE ".RDManager"
#define RD_MANAGER_ERROR_INTERFACE RD_MANAGER_SERVICE ".RDManagerError"

struct rd_agent {
	char *bus_name;
	char *path;
	unsigned int watch_id;
	int (*cb) ();
};

static DBusConnection *connection = NULL;
static struct rd_agent *agent = NULL;


static void free_remote_display_session(struct remote_display_session *session)
{
	DBG("");

	g_free(session);
}

int get_new_handle_rd(struct remote_display_session *session)
{
	DBG("");

	if (session->next_handle >= HANDLE_LIMIT) {
		return -1;
	}
	return session->next_handle++;
}

static void *remote_display_connect(struct obex_session *os, int *err)
{
	struct remote_display_session *session;

	DBG("");

	manager_register_session(os);

	session = g_new0(struct remote_display_session, 1);
	session->os = os;
	session->dir = "/tmp/display/1/";
	session->displayed_handle = -1;

	if (err != NULL)
		*err = 0;

	return session;
}

static int remote_display_get(struct obex_session *os, obex_object_t *obj,
							void *user_data)
{
	int ret;

	DBG("");

	ret = obex_get_stream_start(os, "");
	if (ret < 0)
		return ret;
	return 0;
}

static int remote_display_chkput(struct obex_session *os, void *user_data)
{
	int ret;

	DBG("");

	ret = obex_put_stream_start(os, "");
	return ret;
}

static int remote_display_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
	DBG("");
	return 0;
}

static void remote_display_disconnect(struct obex_session *os, void *user_data)
{
	struct remote_display_session *ips = user_data;

	DBG("");

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

static void rd_agent_free(struct rd_agent* agent) {
	g_free(agent->bus_name);
	g_free(agent->path);
	g_dbus_remove_watch(connection, agent->watch_id);
	g_free(agent);
}

static void agent_disconnected(DBusConnection *conn, void *user_data)
{
	DBG("Agent exited");
	rd_agent_free(agent);
	agent = NULL;
}

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RD_MANAGER_ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *agent_already_exists(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RD_MANAGER_ERROR_INTERFACE ".AlreadyExists",
			"Agent already exists");
}

static inline DBusMessage *agent_does_not_exist(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RD_MANAGER_ERROR_INTERFACE ".DoesNotExist",
			"Agent does not exist");
}

static inline DBusMessage *not_authorized(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			RD_MANAGER_ERROR_INTERFACE ".NotAuthorized",
			"Not authorized");
}

static DBusMessage *rd_register_agent(DBusConnection *conn,
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
	agent = g_new0(struct rd_agent, 1);
	agent->bus_name = g_strdup(sender);
	agent->path = g_strdup(path);

	agent->watch_id = g_dbus_add_disconnect_watch(conn, sender,
					agent_disconnected, NULL, NULL);

	DBG("Agent registered");

	return dbus_message_new_method_return(msg);
}

static DBusMessage *rd_unregister_agent(DBusConnection *conn,
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

	rd_agent_free(agent);
	agent = NULL;

	DBG("Agent unregistered");

	return dbus_message_new_method_return(msg);
}

int display_image(unsigned int id, char *image_path) {
	DBusMessage *msg = NULL;
	if (strlen(image_path) == 0)
		return -EINVAL;

	if (agent == NULL) {
		DBG("display image failed");
		return -EBADR;
	}

	msg = dbus_message_new_method_call(agent->bus_name, agent->path,
					"org.openobex.DisplayImage",
					"DisplayImage");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &image_path,
					DBUS_TYPE_UINT32, &id,
						DBUS_TYPE_INVALID);

	if (msg == NULL)
		return -ENOMEM;

	g_dbus_send_message(connection, msg);
	return 0;
}

static GDBusMethodTable rd_manager_methods[] = {
	{ "RegisterAgent",	"o",	"",	rd_register_agent	},
	{ "UnregisterAgent",	"o",	"",	rd_unregister_agent	},
	{ }
};

static gboolean rd_manager_init(void)
{
	DBusError err;

	DBG("");

	dbus_error_init(&err);

	connection = g_dbus_setup_bus(DBUS_BUS_SESSION, RD_MANAGER_SERVICE,
									&err);
	if (connection == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		return FALSE;
	}

	return g_dbus_register_interface(connection, RD_MANAGER_PATH,
					RD_MANAGER_INTERFACE,
					rd_manager_methods, NULL, NULL,
					NULL, NULL);
}

static int remote_display_init(void)
{
	if (!rd_manager_init())
		return -EPERM;
	MagickWandGenesis();
	return obex_service_driver_register(&remote_display);
}

static void remote_display_exit(void)
{
	MagickWandTerminus();
	obex_service_driver_unregister(&remote_display);
}

OBEX_PLUGIN_DEFINE(remote_display, remote_display_init, remote_display_exit)
