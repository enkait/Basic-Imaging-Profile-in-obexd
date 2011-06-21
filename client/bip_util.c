#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "bip.h"
#include "bip_util.h"
#include "gwobex/obex-xfer.h"
#include "gwobex/obex-priv.h"
#include "wand/MagickWand.h"

guint8 *encode_img_descriptor(const gchar *data, unsigned int length, unsigned int *newsize) {
    guint16 len = length;
    guint8 *buf = g_try_malloc(2+length);
    len = GUINT16_TO_BE(len);
    if(!buf)
        return NULL;
    g_memmove(buf, &len, 2);
    g_memmove(buf+2, data, length);
    *newsize = length+2;
    return buf;
}

struct encconv_pair {
    gchar *bip, *im;
} encconv_table[] = {
    { "JPEG", "JPEG" },
    { "GIF", "GIF" },
    { "WBMP", "WBMP" },
    { "PNG", "PNG" },
    { "JPEG2000", "JP2" },
    { "BMP", "BMP" },
    { }
};

const gchar *convert_encoding_BIP_to_IM(const gchar *encoding) {
    struct encconv_pair *et = encconv_table;
    while (et->bip) {
        if (g_strcmp0(encoding, et->bip) == 0) {
            return et->im;
        }
        et++;
    }
    return NULL;
}

const gchar *convert_encoding_IM_to_BIP(const gchar *encoding) {
    struct encconv_pair *et = encconv_table;
    while (et->im) {
        if (g_strcmp0(encoding, et->im) == 0) {
            return et->bip;
        }
        et++;
    }
    return NULL;
}

int get_image_attributes(const char *image_file, struct image_attributes *attr) {
    int err;
    MagickWand *wand;
    MagickSizeType size;
    MagickWandGenesis();
    wand = NewMagickWand();
    err = MagickPingImage(wand, image_file);
    if (err == MagickFalse) {
        return -1;
    }
    attr->format = g_strdup(convert_encoding_IM_to_BIP(MagickGetImageFormat(wand)));
    attr->width = MagickGetImageWidth(wand);
    attr->height = MagickGetImageHeight(wand);
    MagickGetImageLength(wand, &size);
    attr->length = (unsigned long) size;
    MagickWandTerminus();
    return 0;
}

void free_image_attributes(struct image_attributes *attr) {
    g_free(attr->format);
}
