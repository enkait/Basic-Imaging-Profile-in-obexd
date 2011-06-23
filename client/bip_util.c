#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <glib.h>
#include <gdbus.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "bip_util.h"
#include "wand/MagickWand.h"

uint8_t *encode_img_handle(const char *data, unsigned int length, unsigned int *newsize) {
	glong newlen;
	gunichar2 *utf16buf = g_utf8_to_utf16(data,length,NULL,&newlen,NULL);
	guint8 *buf;
	uint16_t len;

	if (utf16buf == NULL)
		return NULL;
	
	buf = g_try_malloc(3+sizeof(gunichar2) * newlen);
	len = sizeof(gunichar2) * newlen;
	len = GUINT16_TO_BE(len);
	if (buf == NULL)
		return NULL;
	g_memmove(buf, &len, 2);
	g_memmove(buf + 2, data, sizeof(gunichar2) * length);
	buf[sizeof(gunichar2) * length + 2] = '\0';
	*newsize = sizeof(gunichar2) * length + 3;
	return buf;
}

char *decode_img_handle(const uint8_t *data, unsigned int length, unsigned int *newsize) {
	gunichar2 *buf = g_try_malloc(length - 2);
	glong size;
	char *handle;
	g_memmove(buf, data + 2, length - 2);
	handle = g_utf16_to_utf8(buf, length - 2, NULL, &size, NULL);
	*newsize = size;
	return handle;
}


uint8_t *encode_img_descriptor(const char *data, unsigned int length, unsigned int *newsize) {
	uint16_t len = length;
	uint8_t *buf = g_try_malloc(2+length);
	len = GUINT16_TO_BE(len);
	if(!buf)
		return NULL;
	g_memmove(buf, &len, 2);
	g_memmove(buf+2, data, length);
	*newsize = length+2;
	return buf;
}

char *decode_img_descriptor(const uint8_t *data, unsigned int length, unsigned int *newsize) {
	uint16_t len = length;
	char *buf;
	printf("%u\n", len);
	len = GUINT16_FROM_BE(len);
	buf = g_try_malloc(len-2);

	if (buf == NULL)
		return NULL;

	g_memmove(buf, data+2, len);
	*newsize = len;
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

