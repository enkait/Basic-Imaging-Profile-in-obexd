#define SID_TAG 0x09
#define SID_LEN 16

#define AOS_SID \
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

struct sa_aparam {
    uint8_t sidtag;
    uint8_t sidlen;
    uint8_t sid[16];
} __attribute__ ((packed));

extern GDBusMethodTable archive_methods[];
extern GDBusSignalTable archive_signals[];
