#define IMAGE_PUSH_UUID \
    "\xE3\x3D\x95\x45\x83\x74\x4A\xD7\x9E\xC5\xC1\x6B\xE3\x1E\xDE\x8E"
/** Length of IMAGE_PUSH_UUID */
#define IMAGE_PUSH_UUID_LEN 16

#define IMAGE_PUSH_INTERFACE "org.openobex.ImagePush"

#define IMAGE_PULL_UUID \
    "\x8E\xE9\xB3\xD0\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"
/** Length of IMAGE_PULL_UUID */
#define IMAGE_PULL_UUID_LEN 16

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

gboolean bip_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy);
void bip_unregister_interface(DBusConnection *connection, const char *path,
				void *user_data);
void parse_client_user_headers(const struct session_data *session,
				char **desc_hdr,
				unsigned int *desc_hdr_len,
				char **handle_hdr,
				unsigned int *handle_hdr_len);
