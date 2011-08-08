#define IMAGE_PULL_INTERFACE "org.openobex.ImagePull"

#define IMAGE_PULL_UUID \
    "\x8E\xE9\xB3\xD0\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"
/** Length of IMAGE_PULL_UUID */
#define IMAGE_PULL_UUID_LEN 16

static const uint32_t image_pull_supp_feat = 0x10;

#define ARCHIVED_OBJECTS_UUID \
    "\x8E\x61\xF9\x5E\x1A\x79\x11\xD4\x8E\xA4\x00\x80\x5F\x9B\x98\x34"
/** Length of ARCHIVED_OBJECTS_UUID */
#define ARCHIVED_OBJECTS_UUID_LEN 16

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

DBusMessage *get_image(DBusConnection *connection,
					DBusMessage *message, void *user_data);
DBusMessage *get_image_thumbnail(DBusConnection *connection,
					DBusMessage *message, void *user_data);
DBusMessage *get_image_attachment(DBusConnection *connection,
					DBusMessage *message, void *user_data);
DBusMessage *get_images_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data);
DBusMessage *get_image_properties(DBusConnection *connection,
					DBusMessage *message, void *user_data);
DBusMessage *delete_image(DBusConnection *connection,
					DBusMessage *message, void *user_data);

gboolean bip_pull_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
gboolean aos_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
void bip_pull_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data);
void aos_unregister_interface(DBusConnection *connection, const char *path,
							void *user_data);
gboolean aos_sdp_filter(const void *user_data, const sdp_record_t *record,
							const char *params);
