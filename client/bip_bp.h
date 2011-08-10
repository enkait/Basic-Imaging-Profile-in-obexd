#define BP_INTERFACE "org.openobex.BP"

#define BP_UUID \
    "\x94\x01\x26\xC0\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"
/** Length of AUTOMATIC_ARCHIVE_UUID */
#define ARCHIVE_UUID_LEN 16

static const uint32_t bp_supp_feat = 0x40;

#define SID_TAG 0x09
#define SID_LEN 16

#define BP_SID \
	"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x01\x23\x45\x67\x89\xAB\xCD\xEF"

gboolean bip_bp_register_interface(DBusConnection *connection,
						const char *path,
						void *user_data,
						GDBusDestroyFunction destroy);
void bip_bp_unregister_interface(DBusConnection *connection, const char *path,
							void *user_data);
