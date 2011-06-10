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
#include "bip.h"
#include "gwobex/obex-xfer.h"
#include "gwobex/obex-priv.h"
#include "wand/MagickWand.h"

#define EOL_CHARS "\n"

#define IMG_DESCRIPTOR_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_DESCRIPTOR_FORMAT "<image encoding=\"%s\" pixel=\"%zu*%zu\" size=\"%lu\"/>" EOL_CHARS

#define IMG_DESCRIPTOR_WITH_TRANSFORM_FORMAT "<image encoding=\"%s\" pixel=\"%zu*%zu\" size=\"%lu\" transform=\"%s\"/>" EOL_CHARS

#define IMG_DESCRIPTOR_END "</image-descriptor>" EOL_CHARS

#define IMG_DESCRIPTOR_HDR OBEX_HDR_TYPE_BYTES | 0x71

#define BIP_TEMP_FOLDER /tmp/bip/

/* gunichar2 byte order? */
static gunichar2 *extract_handle(struct session_data *session, unsigned int *size) {
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
    unsigned int utf16size = 0;
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

struct image_attributes {
    char * format;
    size_t width, height;
    unsigned long length;
    char * transform;
};

static int get_image_attributes(const char * image_file, struct image_attributes * attr) {
    int err;
    MagickWand *wand;
    MagickSizeType size;
    MagickWandGenesis();
    wand = NewMagickWand();
    err = MagickPingImage(wand, image_file);
    if (err == MagickFalse) {
        return -1;
    }
    attr->format = g_strdup(MagickGetImageFormat(wand));
    attr->width = MagickGetImageWidth(wand);
    attr->height = MagickGetImageHeight(wand);
    MagickGetImageLength(wand, &size);
    attr->length = (unsigned long) size;
    MagickWandTerminus();
    return 0;
}

static void create_image_descriptor(struct image_attributes *attr, struct a_header *ah) {
    GString *descriptor = g_string_new(IMG_DESCRIPTOR_BEGIN);
    if (attr->transform) {
        g_string_append_printf(descriptor,
            IMG_DESCRIPTOR_WITH_TRANSFORM_FORMAT,
            attr->format, attr->width, attr->height, attr->length, attr->transform);
    }
    else {
        g_string_append_printf(descriptor,
            IMG_DESCRIPTOR_FORMAT,
            attr->format, attr->width, attr->height, attr->length);
    }
    descriptor = g_string_append(descriptor, IMG_DESCRIPTOR_END);
    ah->hi = IMG_DESCRIPTOR_HDR;
    ah->hv.bs = (guint8 *) g_string_free(descriptor, FALSE);
    ah->hv_size = attr->length;
}

static int make_modified_image(const char *image_path, const char *modified_path, struct image_attributes *attr) {
    MagickWand *wand;
    MagickWandGenesis();
    wand = NewMagickWand();
    if (MagickReadImage(wand, image_path) == MagickFalse)
        return -1;
    if (g_strcmp0(attr->transform, "crop") == 0) {
        printf("crop\n");
        if(MagickCropImage(wand, attr->width, attr->height, 0, 0) == MagickFalse)
            return -1;
    }
    else if (g_strcmp0(attr->transform, "fill") == 0) {
        printf("fill\n");
        if(MagickExtentImage(wand, attr->width, attr->height, 0, 0) == MagickFalse)
            return -1;
    }
    else if (g_strcmp0(attr->transform, "stretch") == 0){
        printf("stretch\n");
        if(MagickResizeImage(wand, attr->width, attr->height, LanczosFilter, 1.0) == MagickFalse)
            return -1;
    }
    else {
        return -1;
    }
    if (MagickSetImageFormat(wand, attr->format) == MagickFalse) {
        return -1;
    }
    if (MagickWriteImage(wand, modified_path) == MagickFalse) {
        return -1;
    }
    MagickWandTerminus();
    return 0;
}

static DBusMessage *put_modified_image(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    const char *image_path;
    int err, fd;
    struct image_attributes attr;
    struct a_header descriptor;
    GSList *aheaders = NULL;
    GString *new_image_path;

    if (dbus_message_get_args(message, NULL,
            DBUS_TYPE_STRING, &image_path,
            DBUS_TYPE_STRING, &attr.format,
            DBUS_TYPE_UINT32, &attr.width,
            DBUS_TYPE_UINT32, &attr.height,
            DBUS_TYPE_STRING, &attr.transform,
            DBUS_TYPE_INVALID) == FALSE)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);

    if (!image_path || strlen(image_path)==0) {
        return g_dbus_create_error(message,"org.openobex.Error.InvalidArguments", NULL);
    }

    printf("requested put_modified_image on file %s\n", image_path);
    new_image_path = g_string_new(image_path);
    new_image_path = g_string_append(new_image_path, "XXXXXX");
    if ((fd = mkstemp(new_image_path->str)) < 0) {
        return g_dbus_create_error(message,
            "org.openobex.Error.CanNotCreateTemporaryFile", NULL);
    }
    close(fd);

    printf("new path: %s\n", new_image_path->str);

    if (make_modified_image(image_path, new_image_path->str, &attr) < 0) {
        return g_dbus_create_error(message,
            "org.openobex.Error.CanNotCreateModifiedImage", NULL);
    }

    if (get_image_attributes(image_path, &attr) < 0) {
        return g_dbus_create_error(message,
            "org.openobex.Error.InvalidArguments", NULL);
    }

    create_image_descriptor(&attr, &descriptor);
    aheaders = g_slist_append(NULL, &descriptor);

    if ((err=session_put_with_aheaders(session, "x-bt/img-img",
            new_image_path->str, image_path, aheaders, put_image_callback)) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "Failed");
    }
    session->msg = dbus_message_ref(message);

    return dbus_message_new_method_return(message);
}

static DBusMessage *put_image(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    const char *image_file;
    int err;
    struct image_attributes attr;
    struct a_header descriptor;
    GSList * aheaders = NULL;

    if (dbus_message_get_args(message, NULL,
                DBUS_TYPE_STRING, &image_file,
                DBUS_TYPE_INVALID) == FALSE)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);

    if (!image_file || strlen(image_file)==0) {
        return g_dbus_create_error(message,"org.openobex.Error.InvalidArguments", NULL);
    }

    printf("requested put_image on file %s\n", image_file);

    if (get_image_attributes(image_file, &attr) < 0) {
        return g_dbus_create_error(message,
            "org.openobex.Error.InvalidArguments", NULL);
    }

    create_image_descriptor(&attr, &descriptor);
    aheaders = g_slist_append(NULL, &descriptor);

    if ((err=session_put_with_aheaders(session, "x-bt/img-img",
            image_file, image_file, aheaders, put_image_callback)) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "Failed");
    }
    session->msg = dbus_message_ref(message);

    return dbus_message_new_method_return(message);
}

char *get_null_terminated(char *buffer, int len);
char *get_null_terminated(char *buffer, int len) {
    char *newbuffer;
    if (buffer[len-1] != '\0') {
        newbuffer = g_try_malloc(len + 1);
        g_memmove(newbuffer, buffer, len);
        newbuffer[len]='\0';
        printf("null terminating\n");
    }
    else {
        newbuffer = g_memdup(buffer, len);
    }
    return newbuffer;
}

static void get_imaging_capabilities_callback(
        struct session_data *session, GError *err,
        void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
    char *capabilities;
    int i;
	struct transfer_data *transfer = session->pending->data;
    printf("get_imaging_capabilities_callback called\n");
    if(err) {
        reply = g_dbus_create_error(session->msg,
            "org.openobex.Error", "%s", err->message);
        goto done;
    }
	
    reply = dbus_message_new_method_return(session->msg);
	
    if (transfer->filled == 0)
        goto done;

    for (i = transfer->filled - 1; i > 0; i--) {
		if (transfer->buffer[i] != '\0')
			break;

		transfer->filled--;
	}

    capabilities = get_null_terminated(transfer->buffer, transfer->filled);

    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
        &capabilities);
    g_free(capabilities);

done:
    g_dbus_send_message(session->conn, reply);
    dbus_message_unref(reply);
    dbus_message_unref(session->msg);

    return;
}

static DBusMessage *get_imaging_capabilities(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    int err;

    printf("requested get imaging capabilities\n");

    if ((err=session_get(session, "x-bt/img-capabilities", NULL, NULL, NULL, 0, get_imaging_capabilities_callback)) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "Failed");
    }

    session->msg = dbus_message_ref(message);

    return NULL;
}

static GDBusMethodTable image_push_methods[] = {
    { "GetImagingCapabilities",	"", "s", get_imaging_capabilities,
        G_DBUS_METHOD_FLAG_ASYNC },
    { "PutImage", "s", "", put_image },
    { "PutImage", "ssuus", "", put_modified_image },
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
