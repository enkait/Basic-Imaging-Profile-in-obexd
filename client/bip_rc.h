#define REMOTE_CAMERA_INTERFACE "org.openobex.RemoteCamera"

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

extern GDBusMethodTable remote_camera_methods[];
extern GDBusSignalTable remote_camera_signals[];
