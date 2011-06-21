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
#include "bip_util.h"
#include "gwobex/obex-xfer.h"
#include "gwobex/obex-priv.h"
#include "wand/MagickWand.h"

#define EOL_CHARS "\n"

#define IMG_DESC_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_DESC_FORMAT "<image encoding=\"%s\" pixel=\"%zu*%zu\" size=\"%lu\"/>" EOL_CHARS

#define IMG_DESC_WITH_TRANSFORM_FORMAT "<image encoding=\"%s\" pixel=\"%zu*%zu\" size=\"%lu\" transform=\"%s\"/>" EOL_CHARS

#define IMG_DESC_END "</image-descriptor>" EOL_CHARS

#define IMG_HANDLES_DESC "<image-handles-descriptor version=\"1.0\">" EOL_CHARS \
    "<filtering_parameters%s/>" EOL_CHARS \
    "</image-handles-descriptor>" EOL_CHARS

#define FILTERING_CREATED " created=\"%s\""
#define FILTERING_MODIFIED " modified=\"%s\""
#define FILTERING_ENCODING " encoding=\"%s\""
#define FILTERING_PIXEL " pixel=\"%s\""

#define BIP_TEMP_FOLDER /tmp/bip/

/* gunichar2 byte order? */
static gunichar2 *extract_handle(struct session_data *session, unsigned int *size) {
	struct transfer_data *transfer = session->pending->data;
	GwObexXfer *xfer = transfer->xfer;
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
	struct transfer_data *transfer = session->pending->data;
    unsigned int utf16size = 0;
    glong size;
    gunichar2 *utf16_handle;
    char *handle;
    int required;
    if(err) {
	    g_dbus_emit_signal(session->conn, session->path,
	        IMAGE_PUSH_INTERFACE, "PutImageFailed",
            DBUS_TYPE_STRING, &err->message,
		    DBUS_TYPE_INVALID);
        transfer_unregister(transfer);
        return;
    }
    required = (session->obex->obex_rsp == OBEX_RSP_PARTIAL_CONTENT)?(1):(0);
    utf16_handle = extract_handle(session, &utf16size);
    if(!utf16_handle) {
	    g_dbus_emit_signal(session->conn, session->path,
	        IMAGE_PUSH_INTERFACE, "PutImageFailed",
            DBUS_TYPE_STRING, &("Improper handle returned"),
		    DBUS_TYPE_INVALID);
    }
    handle = g_utf16_to_utf8(utf16_handle,utf16size,NULL,&size,NULL);
    g_free(utf16_handle);
    printf("callback called %s\n", handle);
    dbus_message_unref(session->msg);
    session->msg = NULL;
	
	/* fix to handle partial content */
	g_dbus_emit_signal(session->conn, session->path,
		IMAGE_PUSH_INTERFACE, "PutImageCompleted",
		DBUS_TYPE_STRING, &handle,
		DBUS_TYPE_BOOLEAN, &required,
		DBUS_TYPE_INVALID);
    transfer_unregister(transfer);
    return;
}

static void create_image_descriptor(const struct image_attributes *attr, const char *transform, struct a_header *ah) {
    GString *descriptor = g_string_new(IMG_DESC_BEGIN);
    if (transform) {
        g_string_append_printf(descriptor,
            IMG_DESC_WITH_TRANSFORM_FORMAT,
            attr->format, attr->width, attr->height, attr->length, transform);
    }
    else {
        g_string_append_printf(descriptor,
            IMG_DESC_FORMAT,
            attr->format, attr->width, attr->height, attr->length);
    }
    descriptor = g_string_append(descriptor, IMG_DESC_END);
    ah->hi = IMG_DESC_HDR;
    ah->hv_size = descriptor->len;
    ah->hv.bs = (guint8 *) g_string_free(descriptor, FALSE);
}

static int make_modified_image(const char *image_path, const char *modified_path, struct image_attributes *attr, const char *transform) {
    MagickWand *wand;
    MagickWandGenesis();
    wand = NewMagickWand();
    if (MagickReadImage(wand, image_path) == MagickFalse)
        return -1;
    if (g_strcmp0(transform, "crop") == 0) {
        printf("crop\n");
        if(MagickCropImage(wand, attr->width, attr->height, 0, 0) == MagickFalse)
            return -1;
    }
    else if (g_strcmp0(transform, "fill") == 0) {
        printf("fill\n");
        if(MagickExtentImage(wand, attr->width, attr->height, 0, 0) == MagickFalse)
            return -1;
    }
    else if (g_strcmp0(transform, "stretch") == 0){
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

static DBusMessage *put_transformed_image(DBusMessage *message, struct session_data *session,
        const char *local_image, const char *remote_image, const char *transform)
{
    int err;
    struct image_attributes attr;
    struct a_header *descriptor = g_try_new(struct a_header, 1);
    GSList * aheaders = NULL;

    attr.format = NULL;
    if (get_image_attributes(local_image, &attr) < 0) {
        free_image_attributes(&attr);
        return g_dbus_create_error(message,
            "org.openobex.Error.InvalidArguments", NULL);
    }

    create_image_descriptor(&attr, transform, descriptor);
    printf("descriptor: %p %d\n", descriptor->hv.bs, descriptor->hv_size);
    aheaders = g_slist_append(NULL, descriptor);

    if ((err=session_put_with_aheaders(session, "x-bt/img-img",
            local_image, remote_image, aheaders, put_image_callback)) < 0) {
        free_image_attributes(&attr);
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "258Failed");
    }
    session->msg = dbus_message_ref(message);
    free_image_attributes(&attr);
    g_slist_free(aheaders);
    a_header_free(descriptor);

    return dbus_message_new_method_return(message);
}

static DBusMessage *put_modified_image(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    const char *image_path, *format, *transform;
    int fd;
    struct image_attributes attr;
    GString *new_image_path;
    DBusMessage *result;

    if (dbus_message_get_args(message, NULL,
            DBUS_TYPE_STRING, &image_path,
            DBUS_TYPE_STRING, &format,
            DBUS_TYPE_UINT32, &attr.width,
            DBUS_TYPE_UINT32, &attr.height,
            DBUS_TYPE_STRING, &transform,
            DBUS_TYPE_INVALID) == FALSE)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);
    attr.format = g_strdup(format);

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

    if (make_modified_image(image_path, new_image_path->str, &attr, transform) < 0) {
        return g_dbus_create_error(message,
            "org.openobex.Error.CanNotCreateModifiedImage", NULL);
    }

    result = put_transformed_image(message, session, new_image_path->str, image_path, transform);

    free_image_attributes(&attr);
    return result;
}

static DBusMessage *put_image(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    const char *image_path;
    
    if (dbus_message_get_args(message, NULL,
                DBUS_TYPE_STRING, &image_path,
                DBUS_TYPE_INVALID) == FALSE)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);
    
    if (!image_path || strlen(image_path)==0) {
        return g_dbus_create_error(message,"org.openobex.Error.InvalidArguments", NULL);
    }

    return put_transformed_image(message, session, image_path, image_path, NULL);
}

static char *get_null_terminated(char *buffer, int len) {
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

    transfer_unregister(transfer);
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
                "334Failed");
    }

    session->msg = dbus_message_ref(message);

    return NULL;
}

static void get_images_listing_callback(
        struct session_data *session, GError *err,
        void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
    char *listing;
    int i;
	struct transfer_data *transfer = session->pending->data;
    printf("get_images_listing_callback called\n");
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

    listing = get_null_terminated(transfer->buffer, transfer->filled);

    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
        &listing);
    g_free(listing);

done:
    g_dbus_send_message(session->conn, reply);
    dbus_message_unref(reply);
    dbus_message_unref(session->msg);

    transfer_unregister(transfer);
    return;
}

static struct images_listing_aparam *new_images_listing_aparam(uint16_t nb, uint16_t ls, uint8_t lc) {
    struct images_listing_aparam *aparam = g_try_malloc(sizeof(struct images_listing_aparam));
    aparam->nbtag = NBRETURNEDHANDLES_TAG;
    aparam->nblen = NBRETURNEDHANDLES_LEN;
    aparam->nb = GUINT16_TO_BE(nb);
    aparam->lstag = LISTSTARTOFFSET_TAG;
    aparam->lslen = LISTSTARTOFFSET_LEN;
    aparam->ls = GUINT16_TO_BE(ls);
    aparam->lctag = LATESTCAPTUREDIMAGES_TAG;
    aparam->lclen = LATESTCAPTUREDIMAGES_LEN;
    aparam->lc = lc;
    return aparam;
}

static DBusMessage *get_images_listing_all(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    struct images_listing_aparam *aparam;
    int err;

    printf("requested get images listing for all\n");

    aparam = new_images_listing_aparam(GETALLIMAGES, 0, 0);

    if ((err=session_get(session, "x-bt/img-listing", NULL, NULL, (const guint8 *)aparam,
            sizeof(struct images_listing_aparam), get_images_listing_callback)) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "334Failed");
    }

    session->msg = dbus_message_ref(message);

    return NULL;
}

static int parse_filter_dict(DBusMessageIter *iter,
		char **created, char **modified, char **encoding,
		char **pixel) {
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *key, *value;
		
        dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

        if (g_str_equal(key, "created") == TRUE)
            *created = g_strdup(value);
        else if (g_str_equal(key, "modified") == TRUE)
            *modified = g_strdup(value);
        else if (g_str_equal(key, "encoding") == TRUE)
            *encoding = g_strdup(value);
        else if (g_str_equal(key, "pixel") == TRUE)
            *pixel = g_strdup(value);

        dbus_message_iter_next(iter);
    }

    printf("c: %s\nm: %s\ne: %s\np: %s\n",
            (*created)?(*created):(""),
            (*modified)?(*modified):(""),
            (*encoding)?(*encoding):(""),
            (*pixel)?(*pixel):("")
          );

    return 0;
}

static void create_filtering_descriptor(char *created, char *modified,
        char *encoding, char *pixel, struct a_header *ah) {
    GString *filter = g_string_new("");
    GString *object = g_string_new("");
    guint8 *encoded_data;
    unsigned int length;

    if (created)
        g_string_append_printf(filter, FILTERING_CREATED, created);
    if (modified)
        g_string_append_printf(filter, FILTERING_MODIFIED, modified);
    if (encoding)
        g_string_append_printf(filter, FILTERING_ENCODING, encoding);
    if (pixel)
        g_string_append_printf(filter, FILTERING_PIXEL, pixel);

    g_string_printf(object, IMG_HANDLES_DESC, filter->str);
    g_string_free(filter, TRUE);

    encoded_data = encode_img_descriptor(object->str, object->len, &length);
    g_string_free(object, TRUE);

    ah->hi = IMG_DESC_HDR;
    ah->hv_size = length;
    ah->hv.bs = encoded_data;
}

static DBusMessage *get_images_listing_range_filter(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    DBusMessageIter iter, dict;
    struct images_listing_aparam *aparam;
    char *created = NULL, *modified = NULL,
         *encoding = NULL, *pixel = NULL;
    struct a_header *handles_desc = g_try_new(struct a_header, 1);
    uint16_t count, begin;
    GSList *aheaders;
    int err;

    printf("requested get images listing with range and filtering\n");

    if (dbus_message_get_args(message, NULL,
                DBUS_TYPE_UINT16, &count,
                DBUS_TYPE_UINT16, &begin,
                DBUS_TYPE_INVALID) == FALSE)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);

    if (count==0)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);

    dbus_message_iter_init(message, &iter);
    dbus_message_iter_next(&iter);
    dbus_message_iter_next(&iter);
    dbus_message_iter_recurse(&iter, &dict);

    parse_filter_dict(&dict, &created, &modified, &encoding, &pixel);
    create_filtering_descriptor(created, modified, encoding, pixel, handles_desc);
    aheaders = g_slist_append(NULL, &handles_desc);

    aparam = new_images_listing_aparam(count, begin, 0);

    printf("rozmiar aparam: %u\n", sizeof(struct images_listing_aparam));

    if ((err=session_get(session, "x-bt/img-listing", NULL, NULL, (const guint8 *)aparam,
                    sizeof(struct images_listing_aparam), get_images_listing_callback)) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "334Failed");
    }

    g_slist_free(aheaders);
    a_header_free(handles_desc);

    session->msg = dbus_message_ref(message);

    return NULL;
}

static DBusMessage *get_images_listing_range(DBusConnection *connection,
        DBusMessage *message, void *user_data)
{
    struct session_data *session = user_data;
    struct images_listing_aparam *aparam;
    uint16_t count, begin;
    int err;

    printf("requested get images listing with range\n");

    if (dbus_message_get_args(message, NULL,
                DBUS_TYPE_UINT16, &count,
                DBUS_TYPE_UINT16, &begin,
                DBUS_TYPE_INVALID) == FALSE)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);

    if (count==0)
        return g_dbus_create_error(message,
                "org.openobex.Error.InvalidArguments", NULL);

    aparam = new_images_listing_aparam(count, begin, 0);

    printf("rozmiar aparam: %u\n", sizeof(struct images_listing_aparam));

    if ((err=session_get(session, "x-bt/img-listing", NULL, NULL, (const guint8 *)aparam,
                    sizeof(struct images_listing_aparam), get_images_listing_callback)) < 0) {
        return g_dbus_create_error(message,
                "org.openobex.Error.Failed",
                "334Failed");
    }

    session->msg = dbus_message_ref(message);

    return NULL;
}

static GDBusMethodTable image_pull_methods[] = {
    { "GetImagesListing",	"", "s", get_images_listing_all,
        G_DBUS_METHOD_FLAG_ASYNC },
    { "GetImagesListingRange",	"qq", "s", get_images_listing_range,
        G_DBUS_METHOD_FLAG_ASYNC },
    { "GetImagesListingRangeFilter",	"qqa{ss}", "s", get_images_listing_range_filter,
        G_DBUS_METHOD_FLAG_ASYNC },
    { }
};

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
    printf("INTERFACE\n");
    /** should be memcmp0 from obex.c */
    if(memcmp(session->target, IMAGE_PUSH_UUID, session->target_len)==0) {
        printf("PUSH_INTERFACE\n");
        return g_dbus_register_interface(connection, path, IMAGE_PUSH_INTERFACE,
                image_push_methods, image_push_signals, NULL, user_data, destroy);
    }
    else if(memcmp(session->target, IMAGE_PULL_UUID, session->target_len)==0) {
        printf("PULL_INTERFACE\n");
        return g_dbus_register_interface(connection, path, IMAGE_PULL_INTERFACE,
                image_pull_methods, NULL, NULL, user_data, destroy);
    }
    printf("FALSE\n");
    return FALSE;
}

void bip_unregister_interface(DBusConnection *connection, const char *path,
        void *user_data)
{
    struct session_data * session = user_data;
    if(memcmp(session->target, IMAGE_PUSH_UUID, session->target_len)==0) {
        g_dbus_unregister_interface(connection, path, IMAGE_PUSH_INTERFACE);
    }
    else if(memcmp(session->target, IMAGE_PULL_UUID, session->target_len)==0) {
        g_dbus_unregister_interface(connection, path, IMAGE_PULL_INTERFACE);
    }
}
