#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "bip.h"
#include "gwobex/obex-xfer.h"

static void put_image_callback(struct session_data *session, GError *err,
        void *user_data)
{
    DBusMessage *message = session->msg;
    DBusMessage *reply = dbus_message_new_method_return(message);
    printf("callback called!!!!FTW!!\n");
    g_dbus_send_message(session->conn, reply);
    dbus_message_unref(session->msg);
    session->msg = NULL;
}

static DBusMessage * put_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *image_file;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

    if (!image_file || strlen(image_file)==0) {
        return g_dbus_create_error(message,"org.openobex.Error.InvalidArguments", NULL);
    }

    printf("requested put_image on file %s\n", image_file);

    if (session_put_with_aheaders(session, "x-bt/img-img", image_file, image_file, NULL, put_image_callback) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "Failed");
    }

    printf("lol\n");
    session->msg = dbus_message_ref(message);
    printf("lol\n");
	
    return dbus_message_new_method_return(message);
}

static GDBusMethodTable image_push_methods[] = {
//	{ "GetImagingCapabilities",	"", "s",	get_imaging_capabilities },
	{ "PutImage",	"s", "",	put_image	},
	{ }
};

gboolean bip_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy)
{
    struct session_data * session = user_data;
    /** should be memcmp0 from obex.c */
    if(memcmp(session->target, IMAGE_PUSH_UUID, session->target_len)==0) {
        printf("PUSH_INTERFACE\n");
	    return g_dbus_register_interface(connection, path, IMAGE_PUSH_INTERFACE,
			image_push_methods, NULL, NULL, user_data, destroy);
    }
    printf("FALSE\n");
    return FALSE;
}

void bip_unregister_interface(DBusConnection *connection, const char *path,
				void *user_data)
{
	g_dbus_unregister_interface(connection, path, IMAGE_PUSH_INTERFACE);
}
