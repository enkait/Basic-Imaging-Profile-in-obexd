#define IMAGE_PUSH_INTERFACE "org.openobex.ImagePush"
#define BIP_SIGNAL_INTERFACE "org.openobex.BipSignal"
#define ERROR_INTERFACE "org.openobex.Error"

#define IMAGE_PUSH_UUID \
    "\xE3\x3D\x95\x45\x83\x74\x4A\xD7\x9E\xC5\xC1\x6B\xE3\x1E\xDE\x8E"
/** Length of IMAGE_PUSH_UUID */
#define IMAGE_PUSH_UUID_LEN 16

static const uint32_t image_push_supp_feat = 0xf;

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

#define NBRETURNEDHANDLES_TAG 0x01
#define NBRETURNEDHANDLES_LEN 0x02
#define LISTSTARTOFFSET_TAG 0x02
#define LISTSTARTOFFSET_LEN 0x02
#define LATESTCAPTUREDIMAGES_TAG 0x03
#define LATESTCAPTUREDIMAGES_LEN 0x01

#define GETALLIMAGES 65535

DBusMessage *get_imaging_capabilities(DBusConnection *connection,
				DBusMessage *message, void *user_data);
DBusMessage *put_image(DBusConnection *connection,
					DBusMessage *message, void *user_data);
DBusMessage *put_modified_image(DBusConnection *connection,
					DBusMessage *message, void *user_data);
gboolean bip_push_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
void bip_push_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data);

gboolean bip_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy);
void bip_unregister_interface(DBusConnection *connection, const char *path,
				void *user_data);

gboolean bip_sdp_filter(const void *user_data, const sdp_record_t *record);
