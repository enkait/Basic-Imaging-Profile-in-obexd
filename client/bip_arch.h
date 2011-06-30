#define SID_TAG 0x09
#define SID_LEN 16

#define AOS_SID \
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

struct sa_aparam {
    uint8_t sidtag;
    uint8_t sidlen;
    uint8_t sid[18];
} __attribute__ ((packed));

extern GDBusMethodTable archive_methods[];
extern GDBusSignalTable archive_signals[];
