#define REMOTE_DISPLAY_INTERFACE "org.openobex.RemoteDisplay"

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

extern GDBusMethodTable remote_display_methods[];
extern GDBusSignalTable remote_display_signals[];
