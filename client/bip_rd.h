#define REMOTE_DISPLAY_INTERFACE "org.openobex.RemoteDisplay"

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

extern GDBusMethodTable remote_display_methods[];
extern GDBusSignalTable remote_display_signals[];
