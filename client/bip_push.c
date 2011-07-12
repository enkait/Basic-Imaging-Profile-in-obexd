#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>
#include <sys/stat.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "obex-xfer.h"
#include "obex-priv.h"
#include "wand/MagickWand.h"
#include "bip_util.h"
#include "bip_push.h"
#include "bip_pull.h"
#include "bip_arch.h"

#define EOL_CHARS "\n"

#define IMG_DESC_BEGIN "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_DESC_FORMAT "<image encoding=\"%s\" pixel=\"%zu*%zu\" size=\"%lu\"/>" EOL_CHARS

#define IMG_DESC_WITH_TRANSFORM_FORMAT "<image encoding=\"%s\" pixel=\"%zu*%zu\" size=\"%lu\" transform=\"%s\"/>" EOL_CHARS

#define IMG_DESC_END "</image-descriptor>" EOL_CHARS

#define IMG_HANDLES_DESC "<image-handles-descriptor version=\"1.0\">" EOL_CHARS \
	"<filtering-parameters%s/>" EOL_CHARS \
	"</image-handles-descriptor>" EOL_CHARS

#define FILTERING_CREATED " created=\"%s\""
#define FILTERING_MODIFIED " modified=\"%s\""
#define FILTERING_ENCODING " encoding=\"%s\""
#define FILTERING_PIXEL " pixel=\"%s\""

#define ATT_DESC "<attachment-descriptor version=\"1.0\">" EOL_CHARS \
	"<attachment name=\"%s\" size=\"%lu\" created=\"%s\"/>" EOL_CHARS \
	"</attachment-descriptor>" EOL_CHARS

#define BIP_TEMP_FOLDER /tmp/bip/

void parse_client_user_headers(const struct session_data *session,
				char **desc_hdr,
				unsigned int *desc_hdr_len,
				char **handle_hdr,
				unsigned int *handle_hdr_len)
{
	struct transfer_data *transfer = session->pending->data;
	GwObexXfer *xfer = transfer->xfer;
	struct a_header *ah;
	
	if (desc_hdr != NULL && desc_hdr_len != NULL) {
		g_free(*desc_hdr);
		*desc_hdr_len = 0;
	}

	if (handle_hdr != NULL && handle_hdr_len != NULL) {
		g_free(*handle_hdr);
		*handle_hdr_len = 0;
	}

	if (!xfer)
		return;

	ah = a_header_find(xfer->aheaders, IMG_HANDLE_HDR);
	
	if (ah != NULL) {
		printf("handle: %u\n", ah->hv_size);
		*handle_hdr = decode_img_handle(ah->hv.bs, ah->hv_size, handle_hdr_len);
	}
	
	ah = a_header_find(xfer->aheaders, IMG_DESC_HDR);

	if (ah != NULL) {
		printf("desc: %u\n", ah->hv_size);
		*desc_hdr = decode_img_descriptor(ah->hv.bs, ah->hv_size, desc_hdr_len);
	}
}

const char *improper = "Improper handle returned";

static void put_image_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	unsigned int length = 0;
	char *handle = NULL;
	int required;
	if (err) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PUSH_INTERFACE, "PutImageFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}
	required = (session->obex->obex_rsp == OBEX_RSP_PARTIAL_CONTENT)?(1):(0);
	parse_client_user_headers(session, NULL, NULL, &handle, &length);
	
	printf("callback called %s\n", handle);

	if (handle == NULL) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PUSH_INTERFACE, "PutImageFailed",
				DBUS_TYPE_STRING, &improper,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}

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

static void put_attachment_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("attachment callback called\n");

	if (err) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PUSH_INTERFACE, "PutAttachmentFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}
	
	g_dbus_emit_signal(session->conn, session->path,
			IMAGE_PUSH_INTERFACE, "PutAttachmentCompleted",
			DBUS_TYPE_INVALID);
	transfer_unregister(transfer);
	return;
}

static void put_thumbnail_callback(struct session_data *session, GError *err,
		void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	printf("thumbnail callback called\n");

	if (err) {
		g_dbus_emit_signal(session->conn, session->path,
				IMAGE_PUSH_INTERFACE, "PutThumbnailFailed",
				DBUS_TYPE_STRING, &err->message,
				DBUS_TYPE_INVALID);
		transfer_unregister(transfer);
		return;
	}
	
	g_dbus_emit_signal(session->conn, session->path,
			IMAGE_PUSH_INTERFACE, "PutThumbnailCumpleted",
			DBUS_TYPE_INVALID);
	transfer_unregister(transfer);
	return;
}

static void create_image_descriptor(const struct image_attributes *attr, const char *transform, struct a_header *ah) {
	GString *descriptor = g_string_new(IMG_DESC_BEGIN);
	if (transform) {
		g_string_append_printf(descriptor,
				IMG_DESC_WITH_TRANSFORM_FORMAT,
				attr->encoding, attr->width, attr->height, attr->length, transform);
	}
	else {
		g_string_append_printf(descriptor,
				IMG_DESC_FORMAT,
				attr->encoding, attr->width, attr->height, attr->length);
	}
	descriptor = g_string_append(descriptor, IMG_DESC_END);
	ah->hi = IMG_DESC_HDR;
	ah->hv_size = descriptor->len;
	ah->hv.bs = (guint8 *) g_string_free(descriptor, FALSE);
}

static struct a_header *create_att_descriptor(const char *att_path) {
	char ctime[18], *name;
	struct stat file_stat;
	unsigned long size;
	struct a_header *ah = g_try_new(struct a_header, 1);
	GString *descriptor = g_string_new("");
	
	if (lstat(att_path, &file_stat) < 0) {
		return NULL;
	}

	if (!S_ISREG(file_stat.st_mode)) {
		return NULL;
	}

	strftime(ctime, 17, "%Y%m%dT%H%M%SZ", gmtime(&file_stat.st_ctime));
	name = g_path_get_basename(att_path);
	size = file_stat.st_size;
	
	g_string_append_printf(descriptor, ATT_DESC, name, size, ctime);
	
	g_free(name);

	ah->hi = IMG_DESC_HDR;
	ah->hv.bs = encode_img_descriptor(descriptor->str, descriptor->len, &ah->hv_size);
	g_string_free(descriptor, TRUE);
	return ah;
}

static DBusMessage *put_transformed_image(DBusMessage *message, struct session_data *session,
		const char *local_image, const char *remote_image, const char *transform)
{
	int err;
	struct image_attributes *attr;
	struct a_header *descriptor = g_try_new(struct a_header, 1);
	GSList * aheaders = NULL;

	if ((attr = get_image_attributes(local_image, &err)) == NULL) {
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	}

	create_image_descriptor(attr, transform, descriptor);
	printf("descriptor: %p %d\n", descriptor->hv.bs, descriptor->hv_size);
	aheaders = g_slist_append(NULL, descriptor);

	if ((err=session_put_with_aheaders(session, "x-bt/img-img", NULL,
						local_image, remote_image,
						NULL, 0, aheaders,
						put_image_callback)) < 0) {
		free_image_attributes(attr);
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"258Failed");
	}
	session->msg = dbus_message_ref(message);
	free_image_attributes(attr);
	g_slist_free(aheaders);
	a_header_free(descriptor);

	return dbus_message_new_method_return(message);
}

static DBusMessage *put_modified_image(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *image_path, *encoding, *transform;
	int fd, err;
	struct image_attributes *attr = g_new0(struct image_attributes, 1);
	GString *new_image_path;
	DBusMessage *result;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_STRING, &encoding,
				DBUS_TYPE_UINT32, &attr->width,
				DBUS_TYPE_UINT32, &attr->height,
				DBUS_TYPE_STRING, &transform,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	attr->encoding = g_strdup(convBIP2IM(encoding));

	if (attr->encoding == NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (!image_path || strlen(image_path)==0)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	printf("requested put_modified_image on file %s\n", image_path);
	new_image_path = g_string_new(image_path);
	new_image_path = g_string_append(new_image_path, "XXXXXX");
	if ((fd = mkstemp(new_image_path->str)) < 0) {
		return g_dbus_create_error(message,
				"org.openobex.Error.CanNotCreateTemporaryFile",
									NULL);
	}
	close(fd);

	printf("new path: %s\n", new_image_path->str);

	if (make_modified_image(image_path, new_image_path->str, attr,
							transform, &err) < 0) {
		return g_dbus_create_error(message,
				"org.openobex.Error.CanNotCreateModifiedImage",
									NULL);
	}

	result = put_transformed_image(message, session, new_image_path->str,
							image_path, transform);

	free_image_attributes(attr);
	return result;
invalid:
	return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
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

DBusMessage *get_imaging_capabilities(DBusConnection *connection,
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

static struct a_header *create_handle(const char *handle) {
	struct a_header *ah = g_try_new(struct a_header, 1);
	ah->hi = IMG_HANDLE_HDR;
	ah->hv.bs = encode_img_handle(handle, 7, &ah->hv_size);
	return ah;
}

static DBusMessage *put_thumbnail(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	char *thm_path, *image_path, *handle;
	struct a_header *ah;
	GSList *aheaders;
	int fd, err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &image_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
	if (!image_path || strlen(image_path)==0) {
		return g_dbus_create_error(message,"org.openobex.Error.InvalidArguments", NULL);
	}
	
	ah = create_handle(handle);
	printf("handle: %p\n", ah);
	aheaders = g_slist_append(NULL, ah);

	fd = g_file_open_tmp(NULL, &thm_path, NULL);
	close(fd);
	printf("requested put_thumbnail from %s\n", thm_path);

	printf("new path: %s\n", thm_path);

	if (!make_thumbnail(image_path, thm_path, &err)) {
		return g_dbus_create_error(message,
				"org.openobex.Error.CanNotCreateModifiedImage", NULL);
	}

	if ((err=session_put_with_aheaders(session, "x-bt/img-thm", NULL,
						thm_path, NULL, NULL, 0,
						aheaders,
						put_thumbnail_callback)) < 0) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"258Failed");
	}
	
	return dbus_message_new_method_return(message);
}

static DBusMessage *put_image_attachment(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *att_path = NULL, *handle = NULL;
	struct a_header *ah;
	GSList *aheaders = NULL;
	DBusMessage *ret;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &att_path,
				DBUS_TYPE_STRING, &handle,
				DBUS_TYPE_INVALID) == FALSE) {
		ret = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	if (!att_path || strlen(att_path)==0) {
		ret = g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);
		goto cleanup;
	}

	ah = create_handle(handle);
	printf("handle: %p\n", ah);
	aheaders = g_slist_append(NULL, ah);
	ah = create_att_descriptor(att_path);
	printf("att: %p\n", ah);
	aheaders = g_slist_append(aheaders, ah);

	if ((err=session_put_with_aheaders(session, "x-bt/img-attachment", NULL,
						att_path, NULL,
						NULL, 0, aheaders,
						put_attachment_callback)) < 0) {
		ret = g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");
		goto cleanup;
	}
	
	ret = dbus_message_new_method_return(message);

cleanup:
	while (aheaders != NULL) {
		ah = aheaders->data;
		aheaders = g_slist_remove(aheaders, ah);
		a_header_free(ah);
	}
	g_free(att_path);
	g_free(handle);
	return ret;
}

static GDBusMethodTable image_push_methods[] = {
	{ "GetImagingCapabilities",	"", "s", get_imaging_capabilities,
		G_DBUS_METHOD_FLAG_ASYNC },
	{ "PutImage", "s", "", put_image },
	{ "PutModifiedImage", "ssuus", "", put_modified_image },
	{ "PutImageAttachment", "ss", "", put_image_attachment },
	{ "PutImageThumbnail", "ss", "", put_thumbnail },
	{ }
};

static GDBusSignalTable image_push_signals[] = {
	{ "PutImageCompleted",	"sb" },
	{ "PutImageFailed",	"s" },
	{ "PutAttachmentCompleted",	"" },
	{ "PutAttachmentFailed",	"s" },
	{ }
};

gboolean bip_register_interface(DBusConnection *connection, const char *path,
		void *user_data, GDBusDestroyFunction destroy)
{
	struct session_data * session = user_data;
	printf("INTERFACE\n");
	/** should be memcmp0 from obex.c */
	if (memcmp(session->target, IMAGE_PUSH_UUID,
				session->target_len) == 0) {
		printf("PUSH_INTERFACE\n");
		return g_dbus_register_interface(connection, path,
							IMAGE_PUSH_INTERFACE,
							image_push_methods,
							image_push_signals,
							NULL, user_data,
							destroy);
	}
	else if (memcmp(session->target, IMAGE_PULL_UUID,
				session->target_len) == 0) {
		printf("PULL_INTERFACE\n");
		return g_dbus_register_interface(connection, path,
							IMAGE_PULL_INTERFACE,
							image_pull_methods,
							image_pull_signals,
							NULL, user_data,
							destroy);
	}
	else if (memcmp(session->target, ARCHIVE_UUID,
				session->target_len) == 0) {
		printf("AUTOMATIC_ARCHIVE_INTERFACE\n");
		return g_dbus_register_interface(connection, path,
							ARCHIVE_INTERFACE,
							archive_methods,
							archive_signals,
							NULL, user_data,
							destroy);
	}
	else if (memcmp(session->target, ARCHIVED_OBJECTS_UUID,
				session->target_len) == 0) {
		printf("ARCHIVE_OBJECT_SERVICE_INTERFACE\n");
		return g_dbus_register_interface(connection, path,
							IMAGE_PULL_INTERFACE,
							image_pull_methods,
							image_pull_signals,
							NULL, user_data,
							destroy);
	}

	printf("FALSE\n");
	return FALSE;
}

void bip_unregister_interface(DBusConnection *connection, const char *path,
		void *user_data)
{
	struct session_data * session = user_data;
	if (memcmp(session->target, IMAGE_PUSH_UUID, session->target_len) == 0)
		g_dbus_unregister_interface(connection, path, IMAGE_PUSH_INTERFACE);
	else if (memcmp(session->target, IMAGE_PULL_UUID, session->target_len) == 0)
		g_dbus_unregister_interface(connection, path, IMAGE_PULL_INTERFACE);
	else if (memcmp(session->target, ARCHIVE_UUID, session->target_len) == 0)
		g_dbus_unregister_interface(connection, path, ARCHIVE_INTERFACE);
	else if (memcmp(session->target, ARCHIVED_OBJECTS_UUID, session->target_len) == 0)
		g_dbus_unregister_interface(connection, path, IMAGE_PULL_INTERFACE);
}
