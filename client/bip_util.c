#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>

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
