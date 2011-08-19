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

static char *remote_display(DBusConnection *conn, struct session_data *session,
						struct rd_aparam *aparam,
						struct a_header *handles_desc,
						int *err)
{
	GSList *aheaders = NULL;
	char *handle = NULL, *ret = NULL;
	unsigned int handle_len = 0;

	if (err != NULL)
		*err = 0;

	printf("requested remote display %x\n", aparam->rd);

	aheaders = g_slist_append(NULL, handles_desc);

	if (!gw_obex_put_buf_with_aheaders(session->obex, NULL,
						"x-bt/img-display",
						(const guint8 *)aparam,
						sizeof(struct rd_aparam),
						aheaders,
						NULL, 0, -1, err)) {
		goto cleanup;
	}

	g_assert(session->obex->xfer != NULL);

	parse_client_user_headers(session->obex->xfer->aheaders, NULL, NULL,
					&handle, &handle_len);

	printf("parse_client_user_headers\n");
	printf("GOT HANDLE LEN: %d\n", handle_len);

	if (handle_len == 0) {
		ret = g_strdup("");
	}
	else if (parse_handle(handle) < 0) {
		if (err != NULL)
			*err = -EINVAL;
		goto cleanup;
	}

	printf("get_null_terminated %u\n", handle_len);
	ret = get_null_terminated(handle, handle_len);
	printf("%d %s\n", handle_len, ret);
cleanup:
	g_free(handle);
	return ret;
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

static DBusMessage *rd_operation(DBusConnection *connection,
					DBusMessage *message,
					void *user_data, int operation)
{
	struct a_header *ah = NULL;
	char *ret_handle = 0;
	int err = 0;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct rd_aparam *aparam = NULL;
	printf("select_image\n");

	ah = create_handle("");

	if (ah == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "Failed");
		goto cleanup;
	}

	aparam = new_rd_aparam(operation);

	if (aparam == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "InvalidArguments");
		goto cleanup;
	}

	ret_handle = remote_display(connection, user_data, aparam, ah, &err);
	if (ret_handle == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "Failed");
		goto cleanup;
	}
	printf("%s\n", ret_handle);
	reply = dbus_message_new_method_return(message);
	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ret_handle)) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "Failed");
		goto cleanup;
	}

cleanup:
	return reply;
}

static DBusMessage *next_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	printf("NEXT IMAGE\n");
	return rd_operation(connection, message, user_data, RD_OP_NEXT);
}

static DBusMessage *previous_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	printf("PREVIOUS IMAGE\n");
	return rd_operation(connection, message, user_data, RD_OP_PREVIOUS);
}

static DBusMessage *current_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	printf("CURRENT IMAGE\n");
	return rd_operation(connection, message, user_data, RD_OP_CURRENT);
}

static DBusMessage *select_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct a_header *ah = NULL;
	char *handle = NULL;
	char *ret_handle = 0;
	int err = 0;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	struct rd_aparam *aparam = NULL;
	printf("select_image\n");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	ah = create_handle(handle);

	if (ah == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	aparam = new_rd_aparam(RD_OP_SELECT);

	if (aparam == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	if ((ret_handle = remote_display(connection, user_data,
						aparam, ah, &err)) == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "Failed");
		goto cleanup;
	}

	printf("remote_display returned\n");
	printf("%p\n", ret_handle);
	reply = dbus_message_new_method_return(message);
	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ret_handle)) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error", "Failed");
		goto cleanup;
	}

cleanup:
	return reply;
}

GDBusMethodTable remote_display_methods[] = {
	{ "SelectImage", "s", "s", select_image },
	{ "NextImage", "", "s", next_image },
	{ "PreviousImage", "", "s", previous_image },
	{ "CurrentImage", "", "s", current_image },
	{ "PutImage", "s", "", put_image },
	{ "PutModifiedImage", "ssuus", "", put_modified_image },
	{ "GetImagesListing",	"a{sv}", "aa{ss}", get_images_listing,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

GDBusSignalTable remote_display_signals[] = {
	{ "PutImageCompleted",	"s" },
	{ "PutImageFailed",	"s" },
	{ }
};

gboolean bip_rd_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy)
{
	if (!g_dbus_register_interface(connection, path,
							REMOTE_DISPLAY_INTERFACE,
							remote_display_methods,
							NULL,
							NULL, user_data,
							destroy))
		return FALSE;

	return g_dbus_register_interface(connection, path,
							BIP_SIGNAL_INTERFACE,
							NULL,
							remote_display_signals,
							NULL, user_data,
							destroy);
}

void bip_rd_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data)
{
	g_dbus_unregister_interface(connection, path,
						REMOTE_DISPLAY_INTERFACE);
	g_dbus_unregister_interface(connection, path, BIP_SIGNAL_INTERFACE);
}
