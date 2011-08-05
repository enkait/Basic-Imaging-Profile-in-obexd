#define REMOTE_CAMERA_INTERFACE "org.openobex.RemoteCamera"

#define REMOTE_CAMERA_UUID \
    "\x94\x7E\x74\x20\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"
/** Length of REMOTE_CAMERA_UUID */
#define REMOTE_CAMERA_UUID_LEN 16

static const uint32_t remote_camera_supp_feat = 0x80;

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

#define STOREFLAG_TAG 0x0A
#define STOREFLAG_LEN 0x01

gboolean bip_rc_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
void bip_rc_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data);
