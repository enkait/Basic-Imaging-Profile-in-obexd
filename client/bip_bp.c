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
#include "bip_bp.h"
#include "bip_push.h"
#include "bip_arch.h"

struct sp_aparam {
    uint8_t sidtag;
    uint8_t sidlen;
    uint8_t sid[16];
} __attribute__ ((packed));

static DBusMessage *invalid_argument(DBusMessage *message)
{
	return g_dbus_create_error(message, ERROR_INTERFACE,
							"InvalidArgument");
}

static DBusMessage *report_error(DBusMessage *message, char *err)
{
	return g_dbus_create_error(message, ERROR_INTERFACE, "%s", err);
}

static DBusMessage *failed(DBusMessage *message)
{
	return g_dbus_create_error(message, ERROR_INTERFACE,
							"Failed");
}

static struct sp_aparam *new_sp_aparam(const char *serviceid)
{
	struct sp_aparam *sp = g_new0(struct sp_aparam, 1);
	sp->sidtag = SID_TAG;
	sp->sidlen = SID_LEN;
	g_memmove(sp->sid, serviceid, SID_LEN);
	return sp;
}

static void start_print_callback(struct session_data *session, GError *err,
							void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	char *handle = NULL;
	DBusMessage *reply = NULL;
	printf("start_print_callback\n");

	if (err != NULL) {
		reply = report_error(session->msg, err->message);
		goto cleanup;
	}

	if ((reply = dbus_message_new_method_return(session->msg)) == NULL) {
		reply = failed(session->msg);
		goto cleanup;
	}
cleanup:
	g_dbus_send_message(session->conn, reply);
	transfer_unregister(transfer);
	g_free(handle);
}

static DBusMessage *start_print(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply = NULL;
	struct sp_aparam *aparam = NULL;
	char *dpof_path = NULL;

	printf("requested start print\n");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &dpof_path,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = invalid_argument(message);
		goto cleanup;
	}

	aparam = new_sp_aparam(BP_SID);

	if (aparam == NULL) {
		reply = failed(message);
		goto cleanup;
	}

	session->msg = dbus_message_ref(message);

	if (session_put_with_aheaders(session, "x-bt/img-print",
					dpof_path, NULL,
					(const guint8 *) aparam,
					sizeof(struct sp_aparam),
					NULL, start_print_callback,
							NULL) < 0) {
		reply = failed(message);
		goto cleanup;
	}


cleanup:
	g_free(aparam);

	return reply;
}

GDBusMethodTable basic_printing_methods[] = {
	{ "StartPrint",	"s", "", start_print },
	{ "GetStatus",	"", "s", get_status },
	{ }
};

gboolean bip_bp_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy)
{
	return g_dbus_register_interface(connection, path,
							BP_INTERFACE,
							basic_printing_methods,
							NULL,
							NULL, user_data,
							destroy);
}

void bip_bp_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data)
{
	g_dbus_unregister_interface(connection, path, BP_INTERFACE);
}
