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
#include "bip_pull.h"
#include "bip_util.h"
#include "gwobex/obex-xfer.h"
#include "gwobex/obex-priv.h"
#include "wand/MagickWand.h"

#define EOL_CHARS "\n"

#define IMG_DESC_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_DESC_PULL "<image encoding=\"%s\" pixel=\"%s\" transformation=\"%s\"/>" EOL_CHARS

#define IMG_DESC_END "</image-descriptor>" EOL_CHARS

#define IMG_HANDLES_DESC "<image-handles-descriptor version=\"1.0\">" EOL_CHARS \
	"<filtering-parameters%s/>" EOL_CHARS \
	"</image-handles-descriptor>" EOL_CHARS

#define FILTERING_CREATED " created=\"%s\""
#define FILTERING_MODIFIED " modified=\"%s\""
#define FILTERING_ENCODING " encoding=\"%s\""
#define FILTERING_PIXEL " pixel=\"%s\""

#define BIP_TEMP_FOLDER /tmp/bip/

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

static struct a_header *create_filtering_descriptor(char *created, char *modified,
					char *encoding, char *pixel) {
	GString *filter = g_string_new("");
	GString *object = g_string_new("");
	guint8 *encoded_data;
	unsigned int length;
	struct a_header *ah = g_try_new(struct a_header, 1);
	if (ah == NULL)
		return NULL;

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
	return ah;
}

static DBusMessage *get_images_listing_range_filter(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessageIter iter, dict;
	struct images_listing_aparam *aparam;
	char *created = NULL, *modified = NULL,
	     *encoding = NULL, *pixel = NULL;
	struct a_header *handles_desc;
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
	handles_desc = create_filtering_descriptor(created, modified, encoding, pixel);
	aheaders = g_slist_append(NULL, handles_desc);

	aparam = new_images_listing_aparam(count, begin, 0);

	printf("rozmiar aparam: %u\n", sizeof(struct images_listing_aparam));

	if ((err=session_get_with_aheaders(session, "x-bt/img-listing", NULL, NULL,
					(const guint8 *)aparam, sizeof(struct images_listing_aparam),
					aheaders, get_images_listing_callback)) < 0) {
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

static struct a_header *create_img_desc(const char *encoding, const char *pixel,
						const char *transform)
{
	guint8 *data;
	struct a_header *ah = g_try_new(struct a_header, 1);
	GString *descriptor = g_string_new(IMG_DESC_BEGIN);
	g_string_append_printf(descriptor,IMG_DESC_PULL, encoding, pixel,
				transform);
	descriptor = g_string_append(descriptor, IMG_DESC_END);
	data = encode_img_descriptor(descriptor->str, descriptor->len, &ah->hv_size);
	g_string_free(descriptor, TRUE);

	ah->hi = IMG_DESC_HDR;
	ah->hv.bs = data;
	return ah;
}

static struct a_header *create_handle(const char *handle) {
	struct a_header *ah = g_try_new(struct a_header, 1);
	ah->hi = IMG_HANDLE_HDR;
	ah->hv.bs = encode_img_handle(handle, strlen(handle), &ah->hv_size);
	return ah;
}

static void get_image_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("get_image_callback\n");
	if (err) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PULL_INTERFACE, "GetImageFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}

	g_dbus_emit_signal(session->conn, session->path,
			IMAGE_PULL_INTERFACE, "GetImageCompleted",
			DBUS_TYPE_INVALID);
	transfer_unregister(transfer);
	return;
}

static void get_image_thumbnail_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("get_image_callback\n");
	if (err) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PULL_INTERFACE, "GetImageFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}

	g_dbus_emit_signal(session->conn, session->path,
			IMAGE_PULL_INTERFACE, "GetImageThumbnailCompleted",
			DBUS_TYPE_INVALID);
	transfer_unregister(transfer);
	return;
}


static DBusMessage *get_image_thumbnail(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *handle, *image_path;
	GSList *aheaders = NULL;
	struct a_header *hdesc = NULL;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	
	printf("requested get image thumbnail %s %s\n", image_path, handle);

	hdesc = create_handle(handle);
	
	if (hdesc == NULL)
		return g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
	
	aheaders = g_slist_append(NULL, hdesc);

	if ((err=session_get_with_aheaders(session, "x-bt/img-thm", NULL, image_path,
						NULL, 0, aheaders,
						get_image_thumbnail_callback)) < 0) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"334Failed");
	}

	session->msg = dbus_message_ref(message);

	return dbus_message_new_method_return(message);
}

static DBusMessage *get_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *transform, *handle, *encoding, *image_path, *pixel;
	GSList *aheaders = NULL;
	struct a_header *imgdesc = NULL, *hdesc = NULL;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_STRING, &encoding,
				DBUS_TYPE_STRING, &pixel,
				DBUS_TYPE_STRING, &transform,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	
	printf("requested get image %s %s %s %s %s\n", image_path, handle,
			encoding, transform, pixel);

	imgdesc = create_img_desc(encoding, pixel, transform);
	hdesc = create_handle(handle);
	
	if (imgdesc == NULL || hdesc == NULL)
		return g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
	
	aheaders = g_slist_append(NULL, hdesc);
	aheaders = g_slist_append(aheaders, imgdesc);

	printf("rozmiar aparam: %u\n", sizeof(struct images_listing_aparam));

	if ((err=session_get_with_aheaders(session, "x-bt/img-img", NULL, image_path,
						NULL, 0, aheaders,
						get_image_callback)) < 0) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"334Failed");
	}

	session->msg = dbus_message_ref(message);

	return dbus_message_new_method_return(message);
}

GDBusMethodTable image_pull_methods[] = {
	{ "GetImage",	"sssss", "", get_image,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImageThumbnail",	"ss", "", get_image_thumbnail,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImagesListing",	"", "s", get_images_listing_all,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImagesListingRange",	"qq", "s", get_images_listing_range,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImagesListingRangeFilter",	"qqa{ss}", "s", get_images_listing_range_filter,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

GDBusSignalTable image_pull_signals[] = {
	{ "GetImageCompleted", "" },
	{ "GetImageThumbnailCompleted", "" },
	{ "GetImageFailed", "" },
	{ }
};
