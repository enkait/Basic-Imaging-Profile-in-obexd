#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "obex-xfer.h"
#include "obex-priv.h"
#include "wand/MagickWand.h"
#include "bip_pull.h"
#include "bip_push.h"
#include "bip_rc.h"
#include "bip_util.h"
#include "bip_arch.h"

struct monit_image_aparam {
    uint8_t sftag;
    uint8_t sflen;
    uint8_t sf;
} __attribute__ ((packed));

static gboolean get_monit_image_completed(struct session_data *session, char *handle)
{
	return g_dbus_emit_signal(session->conn, session->path,
			BIP_SIGNAL_INTERFACE, "GetMonitImageCompleted",
			DBUS_TYPE_STRING, &handle,
			DBUS_TYPE_INVALID);
}

static gboolean get_monit_image_failed(struct session_data *session, char *err)
{
	return g_dbus_emit_signal(session->conn, session->path,
				BIP_SIGNAL_INTERFACE, "GetMonitImageFailed",
				DBUS_TYPE_STRING, &err,
				DBUS_TYPE_INVALID);
}

static DBusMessage *invalid_argument(DBusMessage *message)
{
	return g_dbus_create_error(message, ERROR_INTERFACE,
							"InvalidArgument");
}

static DBusMessage *failed(DBusMessage *message)
{
	return g_dbus_create_error(message, ERROR_INTERFACE,
							"Failed");
}

static struct monit_image_aparam *new_monit_image_aparam(gboolean sf)
{
	struct monit_image_aparam *aparam =
				g_new0(struct monit_image_aparam, 1);
	aparam->sftag = STOREFLAG_TAG;
	aparam->sflen = STOREFLAG_LEN;
	if (sf)
		aparam->sf = 1;
	else
		aparam->sf = 0;
	return aparam;
}

static void get_monit_image_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	unsigned int length = 0;
	char *handle = NULL;
	printf("get_monit_image_callback\n");

	if (err != NULL) {
		get_monit_image_failed(session, err->message);
		goto cleanup;
	}

	parse_client_user_headers(transfer->xfer, NULL, NULL, &handle,
								&length);

	if (handle == NULL || parse_handle(handle, length) < 0) {
		get_monit_image_completed(session, "");
		goto cleanup;
	}

	get_monit_image_completed(session, handle);
cleanup:
	transfer_unregister(transfer);
	g_free(handle);
}

static DBusMessage *get_monit_image(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply = NULL;
	struct monit_image_aparam *aparam = NULL;
	char *image_path = NULL;
	gboolean sf;

	printf("requested get monitoring image\n");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_BOOLEAN, &sf,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = invalid_argument(message);
		goto cleanup;
	}

	aparam = new_monit_image_aparam(sf);

	session->msg = dbus_message_ref(message);
	if (aparam == NULL) {
		reply = failed(message);
		goto cleanup;
	}

	if (session_get_with_aheaders(session, "x-bt/img-monitoring", NULL,
					image_path, (const guint8 *) aparam,
					sizeof(struct monit_image_aparam),
					NULL, get_monit_image_callback,
								NULL) < 0) {
		reply = failed(message);
		goto cleanup;
	}

cleanup:
	g_free(aparam);

	return reply;
}

GDBusMethodTable remote_camera_methods[] = {
	{ "GetImage",	"ssa{ss}", "", get_image },
	{ "GetImageThumbnail",	"ss", "", get_image_thumbnail },
	{ "GetMonitoringImage",	"sb", "", get_monit_image },
	{ "GetImageProperties",	"s", "aa{ss}", get_image_properties },
	{ }
};

GDBusSignalTable remote_camera_signals[] = {
	{ "GetImageCompleted", "" },
	{ "GetImageFailed", "s" },
	{ "GetMonitImageCompleted", "s" },
	{ "GetMonitImageFailed", "s" },
	{ "GetImageThumbnailCompleted", "" },
	{ "GetImageThumbnailFailed", "s" },
	{ }
};

gboolean bip_rc_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy)
{
	if (!g_dbus_register_interface(connection, path,
							REMOTE_CAMERA_INTERFACE,
							remote_camera_methods,
							NULL,
							NULL, user_data,
							destroy))
		return FALSE;

	return g_dbus_register_interface(connection, path,
							BIP_SIGNAL_INTERFACE,
							NULL,
							remote_camera_signals,
							NULL, user_data,
							destroy);
}

void bip_rc_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data)
{
	g_dbus_unregister_interface(connection, path, REMOTE_CAMERA_INTERFACE);
	g_dbus_unregister_interface(connection, path, BIP_SIGNAL_INTERFACE);
}
