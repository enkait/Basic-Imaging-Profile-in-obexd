#define ARCHIVE_INTERFACE "org.openobex.Archive"

#define ARCHIVE_UUID \
    "\x94\x01\x26\xC0\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"
/** Length of AUTOMATIC_ARCHIVE_UUID */
#define ARCHIVE_UUID_LEN 16

static const uint32_t archive_supp_feat = 0x40;

#define SID_TAG 0x09
#define SID_LEN 16

#define AOS_SID \
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

struct sa_aparam {
    uint8_t sidtag;
    uint8_t sidlen;
    uint8_t sid[16];
} __attribute__ ((packed));

gboolean bip_arch_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
void bip_arch_unregister_interface(DBusConnection *connection, const char *path,
							void *user_data);
