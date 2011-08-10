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
#include "bip_util.h"
#include "bip_arch.h"

static struct sa_aparam *create_sa_aparam(const char *serviceid) {
	struct sa_aparam *sa = g_new0(struct sa_aparam, 1);
	sa->sidtag = SID_TAG;
	sa->sidlen = SID_LEN;
	g_memmove(sa->sid, serviceid, SID_LEN);
	return sa;
}

static DBusMessage *start_archive(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	struct sa_aparam *aparam;
	int err;

	printf("requested start archive\n");
	
	aparam = create_sa_aparam(AOS_SID);

	if (!gw_obex_put_buf_with_aheaders(session->obex, NULL,
						"x-bt/img-archive",
						(uint8_t *) aparam,
						sizeof(struct sa_aparam),
						NULL, NULL, 0, -1, &err)) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
		goto cleanup;
	}

	reply = dbus_message_new_method_return(message);
cleanup:
	g_free(aparam);
	return reply;
}

DBusMessage *get_status(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;
	int err, size;
	char *data;
	const char *cont = "Continue", *failed = "Failed", *success = "Success";

	printf("requested start archive\n");
	
	if (!gw_obex_get_buf_with_aheaders(session->obex, NULL,
						"x-bt/img-status",
						NULL, 0, NULL, &data,
						&size, &err)) {
		printf("err = %d\n", err);
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
	}
	reply = dbus_message_new_method_return(message);
	dbus_message_iter_init_append(reply, &iter);

	printf("status = %d\n", session->obex->obex_rsp);
	if (session->obex->obex_rsp == OBEX_RSP_CONTINUE)
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &cont);
	else if (session->obex->obex_rsp == OBEX_RSP_SUCCESS)
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &success);
	else
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &failed);

	return reply;
}

GDBusMethodTable archive_methods[] = {
	{ "StartArchive", "", "", start_archive },
	{ "GetStatus", "", "s", get_status },
	{ }
};

gboolean bip_arch_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy)
{
	return g_dbus_register_interface(connection, path,
							ARCHIVE_INTERFACE,
							archive_methods,
							NULL,
							NULL, user_data,
							destroy);
}

void bip_arch_unregister_interface(DBusConnection *connection, const char *path,
							void *user_data)
{
	g_dbus_unregister_interface(connection, path, ARCHIVE_INTERFACE);
}
