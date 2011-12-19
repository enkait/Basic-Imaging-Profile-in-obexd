#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "bip_push.h"
static DBusConnection *conn = NULL;

struct bip_push_data {
	struct obc_session *session;
	DBusMessage *msg;
};

static DBusMessage *failed(DBusMessage *message)
{
	return g_dbus_create_error(message, ERROR_INTERFACE, "Failed");
}

static DBusMessage *invalid_argument(DBusMessage *message)
{
	return g_dbus_create_error(message, ERROR_INTERFACE,
							"InvalidArgument");
}

static DBusMessage *report_error(DBusMessage *message, char *err)
{
	return g_dbus_create_error(message,
					ERROR_INTERFACE, "%s", err);
}

static void get_img_cap_cb(struct obc_session *session, GError *err,
						void *user_data)
{
	struct bip_push_data *bip_push = user_data;
	struct obc_transfer *transfer = obc_session_get_transfer(session);
	DBusMessage *reply;
	const char *buf;
	int size;

	DBG("");

	if (err) {
		reply = report_error(bip_push->msg, err->message);
		goto done;
	}

	buf = obc_transfer_get_buffer(transfer, &size);

	reply = dbus_message_new_method_return(bip_push->msg);
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &buf,
				DBUS_TYPE_INVALID);
	obc_transfer_clear_buffer(transfer);

done:
	g_dbus_send_message(conn, reply);
	dbus_message_unref(bip_push->msg);
	bip_push->msg = NULL;

	obc_transfer_unregister(transfer);
	return;
}

static DBusMessage *get_img_cap(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct bip_push_data *bip_push = user_data;
	int err;

	DBG("");

	if ((err=obc_session_get(bip_push->session, "x-bt/img-capabilities",
				NULL, NULL, NULL, 0,
				get_img_cap_cb, user_data)) < 0)
		return failed(message);

	bip_push->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *put_img(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	char *image_path;
	DBusMessage *reply;

	DBG("");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = invalid_argument(message);
		goto cleanup;
	}

	if (image_path == NULL || strlen(image_path)==0) {
		reply = invalid_argument(message);
		goto cleanup;
	}

	reply = dbus_message_new_method_return(message);
cleanup:
	return reply;
}

static GDBusMethodTable bip_push_methods[] = {
	{ "GetImagingCapabilities",	"", "s", get_img_cap,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "PutImage",	"s", "", put_img,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

static GDBusSignalTable bip_push_signals[] = {
	{ }
};

static void bip_push_free(void *data)
{
	struct bip_push_data *bip_push = data;

	obc_session_unref(bip_push->session);
	g_free(bip_push);
}

static int bip_push_probe(struct obc_session *session)
{
	struct bip_push_data *bip_push;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	bip_push = g_try_new0(struct bip_push_data, 1);
	if (!bip_push)
		return -ENOMEM;

	bip_push->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path,
			IMAGE_PUSH_INTERFACE, bip_push_methods,
			NULL, NULL, bip_push, bip_push_free)) {
		bip_push_free(bip_push);
		return -ENOMEM;
	}

	if (!g_dbus_register_interface(conn, path,
			BIP_SIGNAL_INTERFACE, NULL, bip_push_signals,
			NULL, bip_push, NULL)) {
		g_dbus_unregister_interface(conn, path, IMAGE_PUSH_INTERFACE);
		return -ENOMEM;
	}

	return 0;
}

static void bip_push_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, BIP_SIGNAL_INTERFACE);
	g_dbus_unregister_interface(conn, path, IMAGE_PUSH_INTERFACE);
}

static struct obc_driver bip_push = {
	.service = "IMAGE_PUSH",
	.uuid = IMAGE_PUSH_UUID,
	.target = OBEX_IMAGE_PUSH_UUID,
	.target_len = OBEX_IMAGE_PUSH_UUID_LEN,
	.probe = bip_push_probe,
	.remove = bip_push_remove
};

int bip_push_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&bip_push);
	if (err < 0)
		goto failed;

	return 0;

failed:
	dbus_connection_unref(conn);
	conn = NULL;
	return err;
}

void bip_push_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&bip_push);
}
