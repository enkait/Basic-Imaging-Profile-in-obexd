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

struct images_listing_aparam {
    uint8_t nbtag;
    uint8_t nblen;
    uint16_t nb;
    uint8_t lstag;
    uint8_t lslen;
    uint16_t ls;
    uint8_t lctag;
    uint8_t lclen;
    uint8_t lc;
} __attribute__ ((packed));

extern GDBusMethodTable image_pull_methods[];
extern GDBusSignalTable image_pull_signals[];
