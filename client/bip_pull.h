#define IMAGE_PULL_INTERFACE "org.openobex.ImagePull"

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

#define NBRETURNEDHANDLES_TAG 0x01
#define NBRETURNEDHANDLES_LEN 0x02
#define LISTSTARTOFFSET_TAG 0x02
#define LISTSTARTOFFSET_LEN 0x02
#define LATESTCAPTUREDIMAGES_TAG 0x03
#define LATESTCAPTUREDIMAGES_LEN 0x01

#define GETALLIMAGES 65535


extern GDBusMethodTable image_pull_methods[];
extern GDBusSignalTable image_pull_signals[];

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
