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
#include "bip_rd.h"
#include "bip_util.h"
#include "bip_arch.h"



static int remote_display(DBusConnection *conn, struct session_data *session,
						struct rd_aparam *aparam,
						struct a_header *handles_desc)
{
	GSList *aheaders = NULL;
	int err;

	printf("requested remote display\n");

	aheaders = g_slist_append(NULL, handles_desc);

	if (!gw_obex_put_buf_with_aheaders(session->obex, NULL,
						"x-bt/img-display",
						(const guint8 *)aparam,
						sizeof(struct rd_aparam),
						aheaders,
						NULL, 0, -1, &err)) {
		return err;
	}

	if (session->obex->xfer != NULL) {
		printf("win\n");
	}
	else {
		printf("fail\n");
	}

	return 0;
}

static struct rd_aparam *new_rd_aparam(int operation) {
	struct rd_aparam *aparam;
	if (operation < 1 && operation > 4)
		return NULL;
	aparam = g_new0(struct rd_aparam, 1);
	aparam->rdtag = RD_TAG;
	aparam->rdlen = RD_LEN;
	aparam->rd = operation;
	return aparam;
}

static DBusMessage *select_image(DBusConnection *connection,
				DBusMessage *message, void *user_data) {
	struct a_header *ah = NULL;
	char *handle = NULL;
	int ret_handle = 0;
	DBusMessage *ret = NULL;
	struct rd_aparam *aparam = NULL;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE) {
		ret = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	ah = create_handle(handle);

	if (ah == NULL) {
		ret = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	aparam = new_rd_aparam(RD_OP_SELECT);

	if (aparam == NULL) {
		ret = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	ret_handle = remote_display(connection, user_data, aparam, ah);
	printf("%d\n", ret_handle);

cleanup:
	return ret;
}

GDBusMethodTable remote_display_methods[] = {
	{ "SelectImage", "s", "", select_image },
	{ "PutImage", "s", "", put_image },
	{ "PutModifiedImage", "ssuus", "", put_modified_image },
	{ "GetImagesListing",	"a{sv}", "aa{ss}", get_images_listing,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "RemoteDisplay",	"a{sv}", "s", get_images_listing,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

GDBusSignalTable remote_display_signals[] = {
	{ "PutImageCompleted",	"s" },
	{ "PutImageFailed",	"s" },
	{ }
};
