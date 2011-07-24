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
#include "bip_util.h"

#define EOL_CHARS "\n"

#define IMG_DESC_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_BEGIN "<image encoding=\"%s\" pixel=\"%s\""

#define IMG_TRANSFORM " transformation=\"%s\""

#define IMG_END "/>" EOL_CHARS

#define IMG_DESC_END "</image-descriptor>" EOL_CHARS

#define IMG_HANDLES_DESC "<image-handles-descriptor version=\"1.0\">" EOL_CHARS \
	"<filtering-parameters %s/>" EOL_CHARS \
	"</image-handles-descriptor>" EOL_CHARS

#define FILTERING_CREATED "created=\"%s\" "
#define FILTERING_MODIFIED "modified=\"%s\" "
#define FILTERING_ENCODING "encoding=\"%s\" "
#define FILTERING_PIXEL "pixel=\"%s\" "

#define BIP_TEMP_FOLDER /tmp/bip/

struct listing_object {
	char *handle, *ctime, *mtime;
};

static void free_listing_object(struct listing_object *object) {
	if (object == NULL)
		return;
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
		if (parse_handle(value, strlen(value)) < 0)
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
}

static const GMarkupParser images_listing_parser = {
	listing_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static GSList *parse_images_listing(char *data,	unsigned int length, int *err)
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
	if (!status) {
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

static gboolean append_ss_dict_entry(DBusMessageIter *dict, const char *key,
								const char *val)
{
	DBusMessageIter entry;
	if (val == NULL)
		return TRUE;

	if (!dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
								&entry))
		return FALSE;

	if (!dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key))
		return FALSE;

	if (!dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &val))
		return FALSE;

	if (!dbus_message_iter_close_container(dict, &entry))
		return FALSE;

	return TRUE;
}

static gboolean append_listing_dict(DBusMessageIter *args,
							const GSList *listing)
{
	DBusMessageIter dict;
	if (!dbus_message_iter_open_container(args, DBUS_TYPE_ARRAY, "a{ss}",
									&dict))
		return FALSE;

	while (listing != NULL) {
		DBusMessageIter image;
		struct listing_object *obj = listing->data;
		
		if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_ARRAY,
							"{ss}", &image))
			return FALSE;

		if (obj->handle != NULL && !append_ss_dict_entry(&image,
						"handle", obj->handle))
			return FALSE;
		
		if (obj->ctime != NULL && !append_ss_dict_entry(&image,
						"created", obj->ctime))
			return FALSE;

		if (obj->mtime != NULL && !append_ss_dict_entry(&image,
						"modified", obj->mtime))
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
	GSList *listing = NULL;
	printf("get_images_listing_callback called\n");

	if (gerr != NULL) {
		reply = g_dbus_create_error(session->msg, "org.openobex.Error",
							"%s", gerr->message);
		goto cleanup;
	}

	listing = parse_images_listing(transfer->buffer, transfer->filled, &err);

	if (err < 0) {
		reply = g_dbus_create_error(session->msg,
				"org.openobex.Error.Failed", "Failed");
		goto cleanup;
	}

	if ((reply = dbus_message_new_method_return(session->msg)) == NULL) {
		reply = g_dbus_create_error(session->msg,
				"org.openobex.Error.Failed", "Failed");
		goto cleanup;
	}
	
	dbus_message_iter_init_append(reply, &iter);
	if (!append_listing_dict(&iter, listing)) {
		reply = g_dbus_create_error(session->msg,
				"org.openobex.Error.Failed", "Failed");
		goto cleanup;
	}

cleanup:
	g_dbus_send_message(session->conn, reply);
	dbus_message_unref(session->msg);
	
	while (listing != NULL) {
		struct listing_object *obj = listing->data;
		listing = g_slist_remove(listing, obj);
		free_listing_object(obj);
	}

	transfer_unregister(transfer);
	return;
}

static struct images_listing_aparam *new_images_listing_aparam(uint16_t nb,
						uint16_t ls, gboolean latest)
{
	struct images_listing_aparam *aparam =
				g_new0(struct images_listing_aparam, 1);
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
	struct a_header *ah = g_new0(struct a_header, 1);
	ah->hi = IMG_HANDLE_HDR;
	ah->hv.bs = encode_img_handle(handle, strlen(handle), &ah->hv_size);
	return ah;
}

struct native_prop {
	char *encoding, *pixel, *size;
};

struct variant_prop {
	char *encoding, *pixel, *maxsize, *transform;
};

struct att_prop {
	char *content_type, *charset, *name, *size, *ctime, *mtime;
};

struct prop_object {
	char *handle, *name;
	GSList *native, *variant, *att;
};

static void free_native_prop(struct native_prop *prop) {
	if (prop == NULL)
		return;
	g_free(prop->encoding);
	g_free(prop->pixel);
	g_free(prop->size);
	g_free(prop);
}

static void free_variant_prop(struct variant_prop *prop) {
	if (prop == NULL)
		return;
	g_free(prop->encoding);
	g_free(prop->pixel);
	g_free(prop->maxsize);
	g_free(prop->transform);
	g_free(prop);
}

static void free_att_prop(struct att_prop *prop) {
	if (prop == NULL)
		return;
	g_free(prop->content_type);
	g_free(prop->charset);
	g_free(prop->name);
	g_free(prop->size);
	g_free(prop->ctime);
	g_free(prop->mtime);
	g_free(prop);
}

static void free_prop_object(struct prop_object *object) {
	GSList *list;

	if (object == NULL)
		return;
	for (list = object->native; list != NULL; list = g_slist_next(list))
		free_native_prop(list->data);
	for (list = object->variant; list != NULL; list = g_slist_next(list))
		free_variant_prop(list->data);
	for (list = object->att; list != NULL; list = g_slist_next(list))
		free_att_prop(list->data);
	g_slist_free(object->native);
	g_slist_free(object->variant);
	g_slist_free(object->att);
	g_free(object->handle);
	g_free(object->name);
	g_free(object);
}

static gboolean parse_attrib_native(struct native_prop *prop, const gchar *key,
					const gchar *value, GError **gerr)
{
	if (g_str_equal(key, "encoding")) {
		if (convBIP2IM(value) == NULL)
			goto invalid;
		prop->encoding = g_strdup(value);
	}
	else if (g_str_equal(key, "pixel")) {
		if (!parse_pixel_range(value, NULL, NULL, NULL))
			goto invalid;
		prop->pixel = g_strdup(value);
	}
	else if (g_str_equal(key, "size")) {
		prop->size = parse_unsignednumber(value);
		if (prop->size == NULL)
			goto invalid;
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
	return FALSE;
}

static gboolean parse_attrib_variant(struct variant_prop *prop, const gchar *key,
					const gchar *value, GError **gerr)
{
	if (g_str_equal(key, "encoding")) {
		if (convBIP2IM(value) == NULL)
			goto invalid;
		prop->encoding = g_strdup(value);
	}
	else if (g_str_equal(key, "pixel")) {
		if (!parse_pixel_range(value, NULL, NULL, NULL))
			goto invalid;
		prop->pixel = g_strdup(value);
	}
	else if (g_str_equal(key, "maxsize")) {
		prop->maxsize = parse_unsignednumber(value);
		if (prop->maxsize == NULL)
			goto invalid;
	}
	else if (g_str_equal(key, "transform")) {
		prop->transform = parse_transform_list(value);
		if (prop->transform == NULL)
			goto invalid;
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
	return FALSE;
}

static gboolean parse_attrib_att(struct att_prop *prop, const gchar *key,
					const gchar *value, GError **gerr)
{
	if (g_str_equal(key, "content-type")) {
		prop->content_type = g_strdup(value);
	}
	else if (g_str_equal(key, "charset")) {
		prop->charset = g_strdup(value);
	}
	else if (g_str_equal(key, "name")) {
		prop->name = g_strdup(value);
	}
	else if (g_str_equal(key, "size")) {
		prop->size = parse_unsignednumber(value);
		if (prop->size == NULL)
			goto invalid;
	}
	else if (g_str_equal(key, "created")) {
		if (parse_iso8601_bip(value, strlen(value)) == -1)
			goto invalid;
		prop->ctime = g_strdup(value);
	}
	else if (g_str_equal(key, "modified")) {
		if (parse_iso8601_bip(value, strlen(value)) == -1)
			goto invalid;
		prop->mtime = g_strdup(value);
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
	return FALSE;
}

static struct att_prop *parse_elem_att(const gchar **names,
					const gchar **values, GError **gerr)
{
	gchar **key;
	struct att_prop *prop = g_new0(struct att_prop, 1);
	for (key = (gchar **) names; *key; key++, values++) {
		if (!parse_attrib_att(prop, *key, *values, gerr)) {
			free_att_prop(prop);
			return NULL;
		}
	}
	return prop;
}

static struct variant_prop *parse_elem_variant(const gchar **names,
					const gchar **values, GError **gerr)
{
	gchar **key;
	struct variant_prop *prop = g_new0(struct variant_prop, 1);
	for (key = (gchar **) names; *key; key++, values++) {
		if (!parse_attrib_variant(prop, *key, *values, gerr)) {
			free_variant_prop(prop);
			return NULL;
		}
	}
	if (prop->transform == NULL)
		prop->transform = g_strdup("stretch crop fill");
	return prop;
}

static struct native_prop *parse_elem_native(const gchar **names,
					const gchar **values, GError **gerr)
{
	gchar **key;
	struct native_prop *prop = g_new0(struct native_prop, 1);
	for (key = (gchar **) names; *key; key++, values++) {
		if (!parse_attrib_native(prop, *key, *values, gerr)) {
			printf("freeing\n");
			free_native_prop(prop);
			return NULL;
		}
	}
	return prop;
}

static gboolean parse_attrib_prop(struct prop_object *prop, const gchar *key,
					const gchar *value, GError **gerr)
{
	printf("key: %s\n", key);
	if (g_str_equal(key, "handle")) {
		if (parse_handle(value, strlen(value)) < 0)
			goto invalid;
		prop->handle = g_strdup(value);
	}
	else if (g_str_equal(key, "friendly-name")) {
		prop->name = g_strdup(value);
	}
	else if (g_str_equal(key, "version")) {
		// pass;
	}
	else {
		g_set_error(gerr, G_MARKUP_ERROR,
				G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE, NULL);
		return FALSE;
	}
	return TRUE;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
	return FALSE;
}

static struct prop_object *parse_elem_prop(const gchar **names,
					const gchar **values, GError **gerr)
{
	gchar **key;
	struct prop_object *prop = g_new0(struct prop_object, 1);
	for (key = (gchar **) names; *key; key++, values++) {
		if (!parse_attrib_prop(prop, *key, *values, gerr)) {
			free_prop_object(prop);
			return NULL;
		}
	}
	return prop;
}

static void prop_element(GMarkupParseContext *ctxt,
		const gchar *element,
		const gchar **names,
		const gchar **values,
		gpointer user_data,
		GError **gerr)
{
	struct prop_object **obj = user_data;

	printf("element: %s\n", element);

	if (g_str_equal(element, "image-properties")) {
		if (*obj != NULL) {
			free_prop_object(*obj);
			*obj = NULL;
			goto invalid;
		}
		*obj = parse_elem_prop(names, values, gerr);
	}
	else if (g_str_equal(element, "native")) {
		struct native_prop *prop;

		if (*obj == NULL)
			goto invalid;
		prop = parse_elem_native(names, values, gerr);
		(*obj)->native = g_slist_append((*obj)->native, prop);
	}
	else if (g_str_equal(element, "variant")) {
		struct variant_prop *prop;

		if (*obj == NULL)
			goto invalid;
		prop = parse_elem_variant(names, values, gerr);
		(*obj)->variant = g_slist_append((*obj)->variant, prop);
	}
	else if (g_str_equal(element, "attachment")) {
		struct att_prop *prop;

		if (*obj == NULL)
			goto invalid;
		prop = parse_elem_att(names, values, gerr);
		(*obj)->att = g_slist_append((*obj)->att, prop);
	}
	else {
		if (*obj != NULL) {
			free_prop_object(*obj);
			*obj = NULL;
		}
		goto invalid;
	}
	
	return;
invalid:
	g_set_error(gerr, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, NULL);
}

static const GMarkupParser properties_parser = {
	prop_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static struct prop_object *parse_properties(char *data, unsigned int length, int *err)
{
	struct prop_object *prop = NULL;
	gboolean status;
	GError *gerr = NULL;
	GMarkupParseContext *ctxt = g_markup_parse_context_new(
					&properties_parser, 0, &prop, NULL);
	if (err != NULL)
		*err = 0;
	status = g_markup_parse_context_parse(ctxt, data, length, &gerr);
	g_markup_parse_context_free(ctxt);
	if (!status) {
		if (err != NULL)
			*err = -EINVAL;
		free_prop_object(prop);
		prop = NULL;
	}
	return prop;
}

static gboolean append_prop(DBusMessageIter *args,
						struct prop_object *obj)
{
	DBusMessageIter dict, iter;
	GSList *list;
	if (!dbus_message_iter_open_container(args, DBUS_TYPE_ARRAY, "a{ss}",
									&dict))
		return FALSE;
	
	if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_ARRAY,
							"{ss}", &iter))
		return FALSE;

	if (obj->handle == NULL || !append_ss_dict_entry(&iter, "handle",
								obj->handle))
		return FALSE;
	
	if (!append_ss_dict_entry(&iter, "name", obj->name))
		return FALSE;

	if (!dbus_message_iter_close_container(&dict, &iter))
		return FALSE;

	for (list = obj->native; list != NULL; list = g_slist_next(list)) {
		struct native_prop *prop = list->data;
		
		if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_ARRAY,
							"{ss}", &iter))
			return FALSE;
		
		if (!append_ss_dict_entry(&iter, "type", "native"))
			return FALSE;

		if (prop->encoding == NULL || !append_ss_dict_entry(&iter,
						"encoding", prop->encoding))
			return FALSE;
		
		if (prop->pixel == NULL || !append_ss_dict_entry(&iter,
						"pixel", prop->pixel))
			return FALSE;
		
		if (!append_ss_dict_entry(&iter, "size", prop->size))
			return FALSE;
		
		if (!dbus_message_iter_close_container(&dict, &iter))
			return FALSE;
	}

	for (list = obj->variant; list != NULL; list = g_slist_next(list)) {
		struct variant_prop *prop = list->data;
		
		if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_ARRAY,
							"{ss}", &iter))
			return FALSE;

		if (!append_ss_dict_entry(&iter, "type", "variant"))
			return FALSE;

		if (prop->encoding == NULL || !append_ss_dict_entry(&iter,
						"encoding", prop->encoding))
			return FALSE;
		
		if (prop->pixel == NULL || !append_ss_dict_entry(&iter,
						"pixel", prop->pixel))
			return FALSE;
		
		if (!append_ss_dict_entry(&iter, "maxsize", prop->maxsize))
			return FALSE;
		
		if (!append_ss_dict_entry(&iter, "transformation",
							prop->transform))
			return FALSE;
		
		if (!dbus_message_iter_close_container(&dict, &iter))
			return FALSE;
	}

	for (list = obj->att; list != NULL; list = g_slist_next(list)) {
		struct att_prop *prop = list->data;
		
		if (!dbus_message_iter_open_container(&dict, DBUS_TYPE_ARRAY,
							"{ss}", &iter))
			return FALSE;

		if (!append_ss_dict_entry(&iter, "type", "attachment"))
			return FALSE;

		if (prop->content_type == NULL || !append_ss_dict_entry(&iter,
					"content-type", prop->content_type))
			return FALSE;

		if (!append_ss_dict_entry(&iter, "charset", prop->charset))
			return FALSE;

		if (prop->name == NULL || !append_ss_dict_entry(&iter,
						"name", prop->name))
			return FALSE;

		if (!append_ss_dict_entry(&iter, "size", prop->size))
			return FALSE;
		
		if (!append_ss_dict_entry(&iter, "created", prop->ctime))
			return FALSE;
		
		if (!append_ss_dict_entry(&iter, "modified", prop->mtime))
			return FALSE;
		
		if (!dbus_message_iter_close_container(&dict, &iter))
			return FALSE;
	}

	if (!dbus_message_iter_close_container(args, &dict))
		return FALSE;
	return TRUE;
}


DBusMessage *get_image_properties(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	char *handle = NULL, *buffer = NULL;
	struct a_header *hdesc = NULL;
	GSList *aheaders = NULL;
	int err, length;
	struct prop_object *prop = NULL;

	printf("requested get image properties\n");
	
	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &handle,
					DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	if (parse_handle(handle, strlen(handle)) < 0) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	hdesc = create_handle(handle);
	
	if (hdesc == NULL) {
		reply = g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}
	
	aheaders = g_slist_append(NULL, hdesc);

	if (!gw_obex_get_buf_with_aheaders(session->obex, NULL,
					"x-bt/img-properties",
					NULL, 0, aheaders,
					&buffer, &length, &err)) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"TransferFailed");
		goto cleanup;
	}
	
	prop = parse_properties(buffer, length, &err);

	if (prop == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"ParseResultFailed");
		goto cleanup;
	}

	reply = dbus_message_new_method_return(message);
	dbus_message_iter_init_append(reply, &iter);

	if (!append_prop(&iter, prop)) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"AppendResultFailed");
		goto cleanup;
	}

cleanup:
	g_free(buffer);
	//dbus_message_unref(message);
	printf("reply: %p\n", reply);
	a_header_free(hdesc);
	g_slist_free(aheaders);
	return reply;
}

DBusMessage *delete_image(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	char *handle = NULL;
	struct a_header *hdesc = NULL;
	GSList *aheaders = NULL;
	int err;

	printf("requested delete image\n");
	
	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &handle,
					DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	if (parse_handle(handle, strlen(handle)) < 0) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	hdesc = create_handle(handle);
	
	if (hdesc == NULL) {
		reply = g_dbus_create_error(message,
			"org.openobex.Error.Failed", "Out Of Memory");
		goto cleanup;
	}
	
	aheaders = g_slist_append(NULL, hdesc);

	if (!gw_obex_put_buf_with_aheaders(session->obex, NULL, "x-bt/img-img",
					NULL, 0, aheaders,
					NULL, 0, -1, &err)) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
		goto cleanup;
	}
	
	reply = dbus_message_new_method_return(message);
cleanup:
	a_header_free(hdesc);
	g_slist_free(aheaders);
	dbus_message_unref(message);
	return reply;
}

static gboolean parse_filter_arg(const char *key, DBusMessageIter *value, uint16_t *count,
			uint16_t *start, gboolean *latest, char **created,
			char **modified, char **encoding, char **pixel)
{
	char *val = NULL;
	switch (dbus_message_iter_get_arg_type(value)) {
	case DBUS_TYPE_STRING:
		dbus_message_iter_get_basic(value, &val);
		if (g_str_equal(key, "created")) {
			if (parse_iso8601_bip(val, strlen(val)) == -1)
				return FALSE;
			*created = g_strdup(val);
		}
		else if (g_str_equal(key, "modified")) {
			if (parse_iso8601_bip(val, strlen(val)) == -1)
				return FALSE;
			*modified = g_strdup(val);
		}
		else if (g_str_equal(key, "encoding")) {
			*encoding = g_strdup(convBIP2IM(val));
			if (*encoding == NULL)
				return FALSE;
		}
		else if (g_str_equal(key, "pixel")) {
			if (!parse_pixel_range(val, NULL, NULL, NULL))
				return FALSE;
			*pixel = g_strdup(val);
		}
		break;
	case DBUS_TYPE_UINT16:
		if (g_str_equal(key, "count"))
			dbus_message_iter_get_basic(value, count);
		else if (g_str_equal(key, "offset"))
			dbus_message_iter_get_basic(value, start);
		break;
	case DBUS_TYPE_BOOLEAN:
		if (g_str_equal(key, "latest"))
			dbus_message_iter_get_basic(value, latest);
	}
	return TRUE;
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
		char *key;

		dbus_message_iter_recurse(iter, &entry);
		printf("get basic\n");
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		printf("recurse\n");
		dbus_message_iter_recurse(&entry, &value);

		if (!parse_filter_arg(key, &value, count, start, latest,
					created, modified, encoding, pixel))
			return FALSE;

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
	struct a_header *ah;

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

	if (encoded_data == NULL)
		return NULL;

	ah = g_new0(struct a_header, 1);
	ah->hi = IMG_DESC_HDR;
	ah->hv_size = length;
	ah->hv.bs = encoded_data;
	return ah;
}

DBusMessage *get_images_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessageIter iter, dict;
	DBusMessage *reply = NULL;
	struct images_listing_aparam *aparam = NULL;
	char *created = NULL, *modified = NULL,
	     *encoding = NULL, *pixel = NULL;
	struct a_header *handles_desc = NULL;
	uint16_t count, begin;
	gboolean latest;
	GSList *aheaders = NULL;
	int err;

	printf("requested get images listing with range and filtering\n");

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	if (!parse_filter_dict(&dict, &count, &begin, &latest, &created,
					&modified, &encoding, &pixel)) {
		reply = g_dbus_create_error(message,
					"org.openobex.Error.Failed", "Failed");
		goto cleanup;
	}
	
	handles_desc = create_filtering_descriptor(created, modified, encoding,
									pixel);

	if (handles_desc == NULL) {
		reply = g_dbus_create_error(message,
					"org.openobex.Error.Failed", "Failed");
		goto cleanup;
	}

	aheaders = g_slist_append(NULL, handles_desc);

	aparam = new_images_listing_aparam(count, begin, latest);

	session->msg = dbus_message_ref(message);

	if ((err=session_get_with_aheaders(session, "x-bt/img-listing", NULL,
					NULL, (const guint8 *)aparam,
					sizeof(struct images_listing_aparam),
					aheaders, get_images_listing_callback,
								NULL)) < 0) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
		goto cleanup;
	}

cleanup:
	a_header_free(handles_desc);
	g_slist_free(aheaders);
	g_free(aparam);

	return reply;
}

static struct a_header *create_img_desc(const char *encoding, const char *pixel,
						const char *transform)
{
	guint8 *data;
	struct a_header *ah;
	unsigned int length;
	GString *descriptor = g_string_new(IMG_DESC_BEGIN);
	g_string_append_printf(descriptor,IMG_BEGIN, encoding, pixel);
	if (transform != NULL)
		g_string_append_printf(descriptor,IMG_TRANSFORM, transform);
	g_string_append(descriptor,IMG_END);
	descriptor = g_string_append(descriptor, IMG_DESC_END);
	data = encode_img_descriptor(descriptor->str, descriptor->len,
								&length);
	g_string_free(descriptor, TRUE);
	if (data == NULL)
		return NULL;

	ah = g_new0(struct a_header, 1);
	ah->hi = IMG_DESC_HDR;
	ah->hv.bs = data;
	ah->hv_size = length;
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

static void get_image_thumbnail_callback(struct session_data *session,
						GError *err, void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("get_image_callback\n");
	if (err) {
		g_dbus_emit_signal(session->conn, session->path,
					IMAGE_PULL_INTERFACE,
					"GetImageThumbnailFailed",
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

static void get_image_attachment_callback(struct session_data *session,
						GError *err, void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("get_image_attachment_callback\n");
	if (err) {
		printf("emitting message\n");
		g_dbus_emit_signal(session->conn, session->path,
					IMAGE_PULL_INTERFACE,
					"GetImageAttachmentFailed",
					DBUS_TYPE_STRING, &err->message,
					DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}

	g_dbus_emit_signal(session->conn, session->path, IMAGE_PULL_INTERFACE,
						"GetImageAttachmentCompleted",
							DBUS_TYPE_INVALID);
	transfer_unregister(transfer);
	return;
}


DBusMessage *get_image_thumbnail(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *handle = NULL, *image_path = NULL;
	GSList *aheaders = NULL;
	struct a_header *hdesc = NULL;
	DBusMessage *reply = NULL;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}
	
	if (parse_handle(handle, strlen(handle)) < 0) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}
	printf("requested get image thumbnail %s %s\n", image_path, handle);

	hdesc = create_handle(handle);
	
	if (hdesc == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}
	
	aheaders = g_slist_append(NULL, hdesc);

	if ((err=session_get_with_aheaders(session, "x-bt/img-thm", NULL,
						image_path, NULL, 0, aheaders,
						get_image_thumbnail_callback,
								NULL)) < 0) {
		reply = g_dbus_create_error(message,
					"org.openobex.Error.Failed", "Failed");
		goto cleanup;
	}

	session->msg = dbus_message_ref(message);
	reply = dbus_message_new_method_return(message);
cleanup:
	a_header_free(hdesc);
	g_slist_free(aheaders);
	dbus_message_unref(message);
	return reply;
}
///////////////////////////////////////////////////////////////////
DBusMessage *get_image_attachment(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *handle = NULL, *file_path = NULL, *att_name = NULL;
	GSList *aheaders = NULL;
	struct a_header *hdesc = NULL;
	DBusMessage *reply = NULL;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &file_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_STRING, &att_name,
				DBUS_TYPE_INVALID) == FALSE) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	printf("requested get image attachment %s %s %s\n", file_path, handle, att_name);
	if (parse_handle(handle, strlen(handle)) < 0) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	hdesc = create_handle(handle);
	
	if (hdesc == NULL) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}
	
	aheaders = g_slist_append(NULL, hdesc);

	if ((err=session_get_with_aheaders(session, "x-bt/img-attachment",
						att_name, file_path,
						NULL, 0, aheaders,
						get_image_attachment_callback,
						NULL)) < 0) {
		reply = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
		goto cleanup;
	}

	session->msg = dbus_message_ref(message);
	reply = dbus_message_new_method_return(message);
cleanup:
	a_header_free(hdesc);
	g_slist_free(aheaders);
	dbus_message_unref(message);
	return reply;
}

static gboolean parse_get_image_dict(DBusMessage *msg, char **path,
					char **handle, char **pixel,
					char **encoding, char **maxsize,
							char **transform)
{
	DBusMessageIter iter, array;
	
	*path = NULL;
	*handle = NULL;
	*pixel = NULL;
	*encoding = NULL;
	*maxsize = NULL;
	*transform = NULL;
	
	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto failed;
	dbus_message_iter_get_basic(&iter, path);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto failed;
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, handle);
	dbus_message_iter_next(&iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		goto failed;
	
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *key, *val;

		dbus_message_iter_recurse(&array, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &val);
		
		if (g_str_equal(key, "pixel")) {
			if (!parse_pixel_range(val, NULL, NULL, NULL))
				goto failed;
			*pixel = g_strdup(val);
		}
		else if (g_str_equal(key, "encoding")) {
			*encoding = g_strdup(convBIP2IM(val));
			if (*encoding == NULL)
				goto failed;
		}
		else if (g_str_equal(key, "maxsize")) {
			*maxsize = parse_unsignednumber(val);
			if (*maxsize == NULL)
				goto failed;
		}
		else if (g_str_equal(key, "transformation")) {
			*transform = parse_transform(val);
			if (*transform == NULL)
				goto failed;
		}
		dbus_message_iter_next(&array);
	}

	if (*pixel == NULL)
		*pixel = strdup("");
	if (*encoding == NULL)
		*encoding = strdup("");

	printf("p: %s\ne: %s\nm: %s\nt: %s\n",
			(*pixel)?(*pixel):("(null)"),
			(*encoding)?(*encoding):("(null)"),
			(*maxsize)?(*maxsize):("(null)"),
			(*transform)?(*transform):("(null)")
	      );

	return TRUE;
failed:
	g_free(*path);
	g_free(*handle);
	g_free(*pixel);
	g_free(*encoding);
	g_free(*maxsize);
	g_free(*transform);
	return FALSE;
}

DBusMessage *get_image(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	char *transform = NULL, *handle = NULL, *encoding = NULL,
				*image_path = NULL, *pixel = NULL,
						*maxsize = NULL;
	GSList *aheaders = NULL;
	struct a_header *imgdesc = NULL, *hdesc = NULL;
	struct DBusMessage *reply = NULL;
	int err;

	if (!parse_get_image_dict(message, &image_path, &handle, &pixel,
					&encoding, &maxsize, &transform)) {
		reply = g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	printf("requested get image %s %s %s %s %s %s\n", image_path, handle,
			encoding, transform, pixel, maxsize);

	imgdesc = create_img_desc(encoding, pixel, transform);
	hdesc = create_handle(handle);

	if (imgdesc == NULL || hdesc == NULL) {
		reply = g_dbus_create_error(message,
			"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}
	
	aheaders = g_slist_append(NULL, hdesc);
	aheaders = g_slist_append(aheaders, imgdesc);

	printf("rozmiar aparam: %u\n", sizeof(struct images_listing_aparam));

	if ((err=session_get_with_aheaders(session, "x-bt/img-img", NULL,
					image_path, NULL, 0, aheaders,
					get_image_callback, NULL)) < 0) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
	}

	session->msg = dbus_message_ref(message);
	reply = dbus_message_new_method_return(message);
cleanup:
	a_header_free(hdesc);
	a_header_free(imgdesc);
	g_slist_free(aheaders);
	dbus_message_unref(message);
	return reply;
}

GDBusMethodTable image_pull_methods[] = {
	{ "GetImage",	"ssa{ss}", "", get_image },
	{ "GetImagingCapabilities", "", "s", get_imaging_capabilities,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImageThumbnail",	"ss", "", get_image_thumbnail },
	{ "GetImageAttachment",	"sss", "", get_image_attachment },
	{ "GetImagesListing",	"a{sv}", "aa{ss}", get_images_listing,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetImageProperties",	"s", "aa{ss}", get_image_properties },
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
