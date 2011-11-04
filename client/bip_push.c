#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>
#include <sys/stat.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "bip_push.h"
static DBusConnection *conn = NULL;

struct bip_push_data {
	struct obc_session *session;
};

static GDBusMethodTable bip_push_methods[] = {
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
