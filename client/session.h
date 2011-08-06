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

#include <glib.h>
#include <gdbus.h>
#include <gw-obex.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

struct agent_data;
struct session_callback;

struct session_data {
	gint refcount;
	bdaddr_t src;
	bdaddr_t dst;
	uint8_t channel;
	char *service;		/* Service friendly name */
	const char *target;	/* OBEX Target UUID */
	int target_len;
	uuid_t uuid;		/* Bluetooth Service Class */
	gchar *path;		/* Session path */
	DBusConnection *conn;
	DBusConnection *conn_system; /* system bus connection */
	DBusMessage *msg;
	GwObex *obex;
	GIOChannel *io;
	struct agent_data *agent;
	struct session_callback *callback;
	gchar *owner;		/* Session owner */
	guint watch;
	GSList *pending;
	GSList *pending_calls;
	void *priv;
	char *adapter;
};

typedef void (*session_callback_t) (struct session_data *session,
					GError *err, void *user_data);

struct session_data *session_create(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner,
						session_callback_t function,
						void *user_data);

struct session_data *session_ref(struct session_data *session);
void session_unref(struct session_data *session);
void session_shutdown(struct session_data *session);

int session_set_owner(struct session_data *session, const char *name,
			GDBusWatchFunction func);
const char *session_get_owner(struct session_data *session);

int session_set_agent(struct session_data *session, const char *name,
							const char *path);
const char *session_get_agent(struct session_data *session);

int session_send(struct session_data *session, const char *filename,
				const char *remotename);
int session_get(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8  *apparam, gint apparam_size,
		session_callback_t func);
int session_pull(struct session_data *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data);
int session_register(struct session_data *session);
void *session_get_data(struct session_data *session);
void session_set_data(struct session_data *session, void *priv);
int session_put(struct session_data *session, char *buf,
				const char *targetname);
int session_put_with_aheaders(struct session_data *session, const char *type,
		char *buf, const char *filename, const char *targetname,
		const guint8 *apparam, gint apparam_size,
		const GSList *aheaders,
		session_callback_t func);
int session_get_with_aheaders(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8 *apparam, gint apparam_size,
        const GSList * aheaders,
		session_callback_t func);
