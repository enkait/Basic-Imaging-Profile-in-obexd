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
	gboolean required = FALSE;
	printf("get_monit_image_callback\n");

	if (err != NULL) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PULL_INTERFACE, "GetMonitImageFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		goto cleanup;
	}

	parse_client_user_headers(transfer->xfer, NULL, NULL, &handle,
								&length);

	if (handle == NULL) {
		put_image_failed(session, "Failed");
		return;
	}

	g_dbus_emit_signal(session->conn, session->path,
			IMAGE_PULL_INTERFACE, "GetMonitImageCompleted",
			DBUS_TYPE_STRING, &handle,
			DBUS_TYPE_INVALID);
cleanup:
	transfer_unregister(transfer);
	g_free(handle);
}

DBusMessage *get_monit_image(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply = NULL;
	struct monit_image_aparam *aparam = NULL;
	struct a_header *hdesc = NULL;
	GSList *aheaders = NULL;
	gboolean sf;

	printf("requested get monitoring image\n");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_BOOLEAN, &sf,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "InvalidArguments");
		goto cleanup;
	}

	hdesc = create_handle(handle);

	aheaders = g_slist_append(NULL, hdesc);

	aparam = new_monit_image_aparam(sf);

	session->msg = dbus_message_ref(message);
	if (hdesc == NULL || aheaders == NULL || aparam == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "Out of memory");
		goto cleanup;
	}

	if ((err=session_get_with_aheaders(session, "x-bt/img-monitoring", NULL,
					NULL, (const guint8 *) aparam,
					sizeof(struct monit_image_aparam),
					aheaders, get_monit_image_callback,
								NULL)) < 0) {
		reply = g_dbus_create_error(message, "org.openobex.Error",
								"Failed");
		goto cleanup;
	}

cleanup:
	a_header_free(hdesc);
	g_slist_free(aheaders);
	g_free(aparam);

	return reply;
}

GDBusMethodTable remote_display_methods[] = {
	{ "GetImage",	"ssa{ss}", "", get_image },
	{ "GetImageThumbnail",	"ss", "", get_image_thumbnail },
	{ "GetImageProperties",	"s", "aa{ss}", get_image_properties },
	{ }
};

GDBusSignalTable remote_display_signals[] = {
	{ "GetImageCompleted", "" },
	{ "GetImageFailed", "s" },
	{ "GetImageThumbnailCompleted", "" },
	{ "GetImageThumbnailFailed", "s" },
	{ }
};
