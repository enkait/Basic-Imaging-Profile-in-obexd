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

#define EOL_CHARS "\n"

#define IMG_DESC_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_DESC_PULL "<image encoding=\"%s\" pixel=\"%s\" transformation=\"%s\"/>" EOL_CHARS

#define IMG_DESC_END "</image-descriptor>" EOL_CHARS

#define IMG_HANDLES_DESC "<image-handles-descriptor version=\"1.0\">" EOL_CHARS \
	"<filtering-parameters %s/>" EOL_CHARS \
	"</image-handles-descriptor>" EOL_CHARS

#define FILTERING_CREATED "created=\"%s\" "
#define FILTERING_MODIFIED "modified=\"%s\" "
#define FILTERING_ENCODING "encoding=\"%s\" "
#define FILTERING_PIXEL "pixel=\"%s\" "

#define BIP_TEMP_FOLDER /tmp/bip/

static char *get_null_terminated(char *buffer, unsigned int len, unsigned int *newlen) {
	char *newbuffer;
	while (len > 0 && buffer[len - 1] == '\0')
		len--;
	if (buffer[len - 1] != '\0') {
		newbuffer = g_try_malloc(len + 1);
		g_memmove(newbuffer, buffer, len);
		newbuffer[len]='\0';
		printf("null terminating\n");
	}
	else {
		newbuffer = g_memdup(buffer, len);
	}
	*newlen = len;
	return newbuffer;
}

struct listing_object {
	char *handle, *ctime, *mtime;
};

static void free_listing_object(struct listing_object *object) {
	g_free(object->handle);
	g_free(object->ctime);
	g_free(object->mtime);
	g_free(object);
}

static gboolean listing_parse_attr(struct listing_object *object, const gchar *key,
					const gchar *value, GError **gerr)
{
	printf("key: %s\n", key);
	if (g_str_equal(key, "handle")) {
		if (value == NULL)
			goto invalid;
		if (get_handle(value, strlen(value)) < 0)
			goto invalid;
		object->handle = g_strdup(value);
		printf("handle: %s\n", object->handle);
	}
	else if (g_str_equal(key, "created")) {
		if (parse_iso8601_bip(value, strlen(value)) == -1)
			goto invalid;
		object->ctime = g_strdup(value);
	}
	else if (g_str_equal(key, "modified")) {
		if (parse_iso8601_bip(value, strlen(value)) == -1)
			goto invalid;
		object->mtime = g_strdup(value);
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
	printf("ok\n");
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
	return FALSE;
}


static void listing_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	GSList **listing = user_data;
	struct listing_object *obj;
	gchar **key;

	printf("element: %s\n", element);
	printf("names\n");

	if (g_str_equal(element, "image") != TRUE) {
		return;
	}
	
	obj = g_new0(struct listing_object, 1);

	printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++) {
		if (!listing_parse_attr(obj, *key, *values, gerr)) {
			free_listing_object(obj);
			return;
		}
	}
	*listing = g_slist_append(*listing, obj);
	printf("%p\n", *listing);
}

static const GMarkupParser images_listing_parser = {
	listing_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static GSList *parse_images_listing(char *data,
						unsigned int length, int *err)
{
	GSList *listing = NULL;
	gboolean status;
	GError *gerr = NULL;
	GMarkupParseContext *ctxt = g_markup_parse_context_new(
					&images_listing_parser, 0, &listing, NULL);
	if (err != NULL)
		*err = 0;
	status = g_markup_parse_context_parse(ctxt, data, length, &gerr);
	g_markup_parse_context_free(ctxt);
	printf("%d %p\n", status, listing);
	if (!status) {
		printf("%s\n", gerr->message);
		if (err != NULL)
			*err = -EINVAL;
		while (listing != NULL) {
			struct listing_object *obj = listing->data;
			listing = g_slist_remove(listing, obj);
			free_listing_object(obj);
		}
	}
	return listing;
}

static gboolean append_sv_dict_entry(DBusMessageIter *dict, const char *key,
							int type, void *val)
{
	DBusMessageIter entry, value;
	if (!dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry))
		return FALSE;

	if (!dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key))
		return FALSE;

	if (!dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s",
									&value))
		return FALSE;

	if (!dbus_message_iter_append_basic(&value, type, val))
		return FALSE;

	if (!dbus_message_iter_close_container(&entry, &value))
		return FALSE;

	if (!dbus_message_iter_close_container(dict, &entry))
		return FALSE;

	return TRUE;
}

static gboolean append_listing_dict(DBusMessageIter *args,
							const GSList *listing)
{
	DBusMessageIter dict;
	if (!dbus_message_iter_open_container(args, DBUS_TYPE_ARRAY, "a{sv}",
									&dict))
		return FALSE;

	while (listing != NULL) {
		DBusMessageIter image;
		struct listing_object *obj = listing->data;
		
		if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_ARRAY,
								"{sv}", &image))
			return FALSE;

		if (obj->handle != NULL && !append_sv_dict_entry(&image,
				"handle", DBUS_TYPE_STRING, &obj->handle))
			return FALSE;
		
		if (obj->ctime != NULL && !append_sv_dict_entry(&image,
				"created", DBUS_TYPE_STRING, &obj->ctime))
			return FALSE;

		if (obj->mtime != NULL && !append_sv_dict_entry(&image,
				"modified", DBUS_TYPE_STRING, &obj->mtime))
			return FALSE;

		if (!dbus_message_iter_close_container(&dict, &image))
			return FALSE;

		listing = g_slist_next(listing);
	}

	if (!dbus_message_iter_close_container(args, &dict))
		return FALSE;
	return TRUE;
}

static void get_images_listing_callback(
		struct session_data *session, GError *gerr,
		void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	int err;
	struct transfer_data *transfer = session->pending->data;
	GSList *listing;
	printf("get_images_listing_callback called\n");
	if (gerr != NULL) {
		reply = g_dbus_create_error(session->msg, "org.openobex.Error",
							"%s", gerr->message);
		goto done;
	}

	listing = parse_images_listing(transfer->buffer, transfer->filled, &err);

	printf("%p\n", listing);

	if (err < 0) {
		reply = g_dbus_create_error(session->msg, "org.openobex.Error",
									NULL);
		goto done;
	}
	
	reply = dbus_message_new_method_return(session->msg);
	dbus_message_iter_init_append(reply, &iter);
	append_listing_dict(&iter, listing);
	while (listing != NULL) {
		struct listing_object *obj = listing->data;
		listing = g_slist_remove(listing, obj);
		free_listing_object(obj);
	}

done:
	g_dbus_send_message(session->conn, reply);
	dbus_message_unref(reply);
	dbus_message_unref(session->msg);

	transfer_unregister(transfer);
	return;
}

static struct images_listing_aparam *new_images_listing_aparam(uint16_t nb, uint16_t ls, gboolean latest)
{
	struct images_listing_aparam *aparam = g_try_malloc(sizeof(struct images_listing_aparam));
	aparam->nbtag = NBRETURNEDHANDLES_TAG;
	aparam->nblen = NBRETURNEDHANDLES_LEN;
	aparam->nb = GUINT16_TO_BE(nb);
	aparam->lstag = LISTSTARTOFFSET_TAG;
	aparam->lslen = LISTSTARTOFFSET_LEN;
	aparam->ls = GUINT16_TO_BE(ls);
	aparam->lctag = LATESTCAPTUREDIMAGES_TAG;
	aparam->lclen = LATESTCAPTUREDIMAGES_LEN;
	if (latest)
		aparam->lc = 1;
	else
		aparam->lc = 0;
	return aparam;
}

static struct a_header *create_handle(const char *handle) {
	struct a_header *ah = g_try_new(struct a_header, 1);
	ah->hi = IMG_HANDLE_HDR;
	ah->hv.bs = encode_img_handle(handle, strlen(handle), &ah->hv_size);
	return ah;
}

static DBusMessage *get_image_properties(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;
	char *handle, *buffer, *object;
	struct a_header *hdesc;
	GSList *aheaders;
	int err, length;
	unsigned newlen;

	printf("requested get image properties\n");
	
	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &handle,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	hdesc = create_handle(handle);
	
	if (hdesc == NULL)
		return g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
	
	aheaders = g_slist_append(NULL, hdesc);

	if (!gw_obex_get_buf_with_aheaders(session->obex, NULL, "x-bt/img-properties",
					NULL, 0, aheaders,
					&buffer, &length, &err)) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"334Failed");
	}
	
	object = get_null_terminated(buffer, length, &newlen);
	reply = dbus_message_new_method_return(message);
	
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &object);
	g_free(object);
	g_free(buffer);

	return reply;
}

static DBusMessage *delete_image(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	char *handle;
	struct a_header *hdesc;
	GSList *aheaders;
	int err;

	printf("requested delete image\n");
	
	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &handle,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	hdesc = create_handle(handle);
	
	if (hdesc == NULL)
		return g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
	
	aheaders = g_slist_append(NULL, hdesc);

	if (!gw_obex_put_buf_with_aheaders(session->obex, NULL, "x-bt/img-img",
					NULL, 0, aheaders,
					NULL, 0, -1, &err)) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"334Failed");
	}
	
	reply = dbus_message_new_method_return(message);
	return reply;
}

static gboolean parse_filter_dict(DBusMessageIter *iter,
		uint16_t *count, uint16_t *start, gboolean *latest,
		char **created, char **modified, char **encoding,
		char **pixel)
{
	*count = 65535;
	*start = 0;
	*latest = FALSE;
	*created = NULL;
	*modified = NULL;
	*encoding = NULL;
	*pixel = NULL;

	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *val;

		dbus_message_iter_recurse(iter, &entry);
		printf("get basic\n");
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		printf("recurse\n");
		dbus_message_iter_recurse(&entry, &value);
		
		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			dbus_message_iter_get_basic(&value, &val);
			printf("val: %s\n", val);
			if (g_str_equal(key, "created"))
				*created = g_strdup(val);
			else if (g_str_equal(key, "modified"))
				*modified = g_strdup(val);
			else if (g_str_equal(key, "encoding"))
				*encoding = g_strdup(val);
			else if (g_str_equal(key, "pixel"))
				*pixel = g_strdup(val);
			break;
		case DBUS_TYPE_UINT16:
			printf("val2 %s\n", key);
			if (g_str_equal(key, "count"))
				dbus_message_iter_get_basic(&value, count);
			else if (g_str_equal(key, "offset"))
				dbus_message_iter_get_basic(&value, start);
			break;
		case DBUS_TYPE_BOOLEAN:
			printf("val3 %s\n", key);
			if (g_str_equal(key, "latest"))
				dbus_message_iter_get_basic(&value, latest);
		}
		dbus_message_iter_next(iter);
	}

	printf("c: %s\nm: %s\ne: %s\np: %s\nc: %u\no: %u\nl: %u\n",
			(*created)?(*created):(""),
			(*modified)?(*modified):(""),
			(*encoding)?(*encoding):(""),
			(*pixel)?(*pixel):(""),
			*count, *start, *latest
	      );

	return TRUE;
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

static DBusMessage *get_images_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessageIter iter, dict;
	struct images_listing_aparam *aparam;
	char *created = NULL, *modified = NULL,
	     *encoding = NULL, *pixel = NULL;
	struct a_header *handles_desc;
	uint16_t count, begin;
	gboolean latest;
	GSList *aheaders;
	int err;

	printf("requested get images listing with range and filtering\n");

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	parse_filter_dict(&dict, &count, &begin, &latest, &created, &modified, &encoding, &pixel);
	
	handles_desc = create_filtering_descriptor(created, modified, encoding, pixel);
	aheaders = g_slist_append(NULL, handles_desc);

	aparam = new_images_listing_aparam(count, begin, latest);

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

static void get_image_attachment_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("get_image_attachment_callback\n");
	if (err) {
		printf("emitting message\n");
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PULL_INTERFACE, "GetImageAttachmentFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}

	g_dbus_emit_signal(session->conn, session->path,
			IMAGE_PULL_INTERFACE, "GetImageAttachmentCompleted",
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

static DBusMessage *get_image_attachment(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *handle, *file_path, *att_name;
	GSList *aheaders = NULL;
	struct a_header *hdesc = NULL;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &file_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_STRING, &att_name,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	
	printf("requested get image attachment %s %s %s\n", file_path, handle, att_name);

	hdesc = create_handle(handle);
	
	if (hdesc == NULL)
		return g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
	
	aheaders = g_slist_append(NULL, hdesc);

	if ((err=session_get_with_aheaders(session, "x-bt/img-attachment", att_name, file_path,
						NULL, 0, aheaders,
						get_image_attachment_callback)) < 0) {
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
	{ "GetImage",	"sssss", "", get_image },
	{ "GetImageThumbnail",	"ss", "", get_image_thumbnail },
	{ "GetImageAttachment",	"sss", "", get_image_attachment },
	{ "GetImagesListing",	"a{sv}", "aa{sv}", get_images_listing,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImageProperties",	"s", "s", get_image_properties },
	{ "DeleteImage", "s", "", delete_image },
	{ }
};

GDBusSignalTable image_pull_signals[] = {
	{ "GetImageCompleted", "" },
	{ "GetImageFailed", "s" },
	{ "GetImageThumbnailCompleted", "" },
	{ "GetImageThumbnailFailed", "s" },
	{ "GetImageAttachmentCompleted", "" },
	{ "GetImageAttachmentFailed", "s" },
	{ }
};
