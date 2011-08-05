#define REMOTE_DISPLAY_INTERFACE "org.openobex.RemoteDisplay"

#define REMOTE_DISPLAY_UUID \
    "\x94\xC7\xCD\x20\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"
/** Length of REMOTE_DISPLAY_UUID */
#define REMOTE_DISPLAY_UUID_LEN 16

static const uint32_t remote_display_supp_feat = 0x100;

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

#define RD_TAG 0x08
#define RD_LEN 1
#define RD_OP_NEXT 0x01
#define RD_OP_PREVIOUS 0x02
#define RD_OP_SELECT 0x03
#define RD_OP_CURRENT 0x04

struct rd_aparam {
    uint8_t rdtag;
    uint8_t rdlen;
    uint8_t rd;
} __attribute__ ((packed));

gboolean bip_rd_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
void bip_rd_unregister_interface(DBusConnection *connection,
					const char *path, void *user_data);
