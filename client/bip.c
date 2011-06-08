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
#include "gwobex/obex-priv.h"

/* gunichar2 byte order? */
gunichar2 *extract_handle(struct session_data *session, unsigned int *size);

gunichar2 *extract_handle(struct session_data *session, unsigned int *size) {
    struct gw_obex_xfer *xfer = session->obex->xfer;
    struct a_header *ah;
    gunichar2 *buf;
    if(!xfer)
        return NULL;
    ah = a_header_find(xfer->aheaders, IMG_HANDLE_HDR);
    if(!ah)
        return NULL;
    buf = g_try_malloc(ah->hv_size-2);
    g_memmove(buf,ah->hv.bs+2,ah->hv_size-2);
    *size = (ah->hv_size-3)/2;
    return buf;
}

static void put_image_callback(struct session_data *session, GError *err,
        void *user_data)
{
    unsigned int utf16size;
    glong size;
    gunichar2 *utf16_handle;
    char *handle;
    int required = 1;
    if(err) {
	    g_dbus_emit_signal(session->conn, session->path,
	        IMAGE_PUSH_INTERFACE, "PutImageFailed",
            DBUS_TYPE_STRING, &err->message,
		    DBUS_TYPE_INVALID);
        return;
    }
    utf16_handle = extract_handle(session, &utf16size);
    if(!utf16_handle) {
	    g_dbus_emit_signal(session->conn, session->path,
	        IMAGE_PUSH_INTERFACE, "PutImageFailed",
            DBUS_TYPE_STRING, &("Improper handle returned"),
		    DBUS_TYPE_INVALID);
    }
    handle = g_utf16_to_utf8(utf16_handle,utf16size,NULL,&size,NULL);
    g_free(utf16_handle);
    printf("callback called!!!!FTW!! %s\n", handle);
    dbus_message_unref(session->msg);
    session->msg = NULL;
	
	/* fix to handle partial content */
	g_dbus_emit_signal(session->conn, session->path,
		IMAGE_PUSH_INTERFACE, "PutImageCompleted",
		DBUS_TYPE_STRING, &handle,
		DBUS_TYPE_BOOLEAN, &required,
		DBUS_TYPE_INVALID);
    return;
}

static DBusMessage *put_image(DBusConnection *connection,
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
    session->msg = dbus_message_ref(message);

    return dbus_message_new_method_return(message);
}

static GDBusMethodTable image_push_methods[] = {
    //	{ "GetImagingCapabilities",	"", "s",	get_imaging_capabilities },
    { "PutImage",	"s", "",	put_image	},
    { }
};

static GDBusSignalTable image_push_signals[] = {
	{ "PutImageCompleted",	"sb" },
	{ "PutImageFailed",	"s" },
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
                image_push_methods, image_push_signals, NULL, user_data, destroy);
    }
    printf("FALSE\n");
    return FALSE;
}

void bip_unregister_interface(DBusConnection *connection, const char *path,
        void *user_data)
{
    g_dbus_unregister_interface(connection, path, IMAGE_PUSH_INTERFACE);
}
