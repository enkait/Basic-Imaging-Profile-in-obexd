#define OBEX_IMAGE_PUSH_UUID \
    "\xE3\x3D\x95\x45\x83\x74\x4A\xD7\x9E\xC5\xC1\x6B\xE3\x1E\xDE\x8E"
/** Length of IMAGE_PUSH_UUID */
#define OBEX_IMAGE_PUSH_UUID_LEN 16

#define IMAGE_PUSH_INTERFACE "org.openobex.ImagePush"
#define BIP_SIGNAL_INTERFACE "org.openobex.BipSignal"
#define ERROR_INTERFACE "org.openobex.Error"
#define IMAGE_PUSH_UUID "00001106-0000-1000-8000-00805f9b34fb"
int bip_push_init(void);
void bip_push_exit(void);
