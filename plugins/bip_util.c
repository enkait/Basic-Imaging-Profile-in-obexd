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
	g_memmove(buf + 2, utf16buf, sizeof(gunichar2) * length);
	buf[sizeof(gunichar2) * length + 2] = '\0';
	*newsize = sizeof(gunichar2) * length + 3;
	return buf;
}

char *decode_img_handle(const uint8_t *data, unsigned int length, unsigned int *newsize) {
	glong size;
	char *handle;
	handle = g_utf16_to_utf8((gunichar2 *) (data + 2), length - 3, NULL, &size, NULL);
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

struct encconv_pair encconv_table[] = {
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

time_t parse_iso8601_bip(const gchar *str, int len) {
	gchar    *tstr;
	struct tm tm;
	gint      nr;
	gchar     tz;
	time_t    time;
	time_t    tz_offset = 0;

	memset (&tm, 0, sizeof (struct tm));

	/* According to spec the time doesn't have to be null terminated */
	if (str[len - 1] != '\0') {
		tstr = g_malloc(len + 1);
		strncpy(tstr, str, len);
		tstr[len] = '\0';
	}
	else
		tstr = g_strdup(str);

	nr = sscanf (tstr, "%04u%02u%02uT%02u%02u%02u%c",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec,
			&tz);

	g_free(tstr);

	/* Fixup the tm values */
	tm.tm_year -= 1900;       /* Year since 1900 */
	tm.tm_mon--;              /* Months since January, values 0-11 */
	tm.tm_isdst = -1;         /* Daylight savings information not avail */

	if (nr < 6) {
		/* Invalid time format */
		return -1;
	}

	time = mktime (&tm);

#if defined(HAVE_TM_GMTOFF)
	tz_offset = tm.tm_gmtoff;
#elif defined(HAVE_TIMEZONE)
	tz_offset = -timezone;
	if (tm.tm_isdst > 0) {
		tz_offset += 3600;
	}
#endif

	if (nr == 7) { /* Date/Time was in localtime (to remote device)
			* already. Since we don't know anything about the
			* timezone on that one we won't try to apply UTC offset
			*/
		time += tz_offset;
	}

	return time;
}

gboolean parse_pixel_range(const gchar *dim, unsigned int *lower, unsigned int *upper, gboolean *fixed_ratio)
{
	static regex_t no_range;
	static regex_t range;
	static regex_t range_fixed;
	static int regex_initialized = 0;
	if (!regex_initialized) {
		regcomp(&no_range, "^([[:digit:]]+)\\*([[:digit:]]+)$", REG_EXTENDED);
		regcomp(&range, "^([[:digit:]]+)\\*([[:digit:]]+)-([[:digit:]]+)\\*([[:digit:]]+)$", REG_EXTENDED);
		regcomp(&range_fixed, "^([[:digit:]]+)\\*\\*-([[:digit:]]+)\\*([[:digit:]]+)$", REG_EXTENDED);
		regex_initialized = 1;
	}
	printf("dim=%s\n", dim);
	if (regexec(&no_range, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u*%u", &lower[0], &lower[1]);
		upper[0] = lower[0];
		upper[1] = lower[1];
		*fixed_ratio = FALSE;
	}
	else if (regexec(&range, dim, 0, NULL, 0) == 0) {
		printf("range\n");
		sscanf(dim, "%u*%u-%u*%u", &lower[0], &lower[1], &upper[0], &upper[1]);
		*fixed_ratio = FALSE;
	}
	else if (regexec(&range_fixed, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u**-%u*%u", &lower[0], &upper[0], &upper[1]);
		lower[1] = 0;
		*fixed_ratio = TRUE;
	}
	if (lower[0] > 65535 || lower[1] > 65535 || upper[0] > 65535 || upper[1] > 65535)
		return FALSE;
	return TRUE;
}

int make_modified_image(const char *image_path, const char *modified_path,
			struct image_attributes *attr, const char *transform) {
	MagickWand *wand;
	MagickWandGenesis();
	wand = NewMagickWand();
	if (MagickReadImage(wand, image_path) == MagickFalse)
		return -1;
	if (g_strcmp0(transform, "crop") == 0) {
		printf("crop\n");
		if(MagickCropImage(wand, attr->width, attr->height, 0, 0) == MagickFalse)
			return -1;
	}
	else if (g_strcmp0(transform, "fill") == 0) {
		printf("fill\n");
		if(MagickExtentImage(wand, attr->width, attr->height, 0, 0) == MagickFalse)
			return -1;
	}
	else if (g_strcmp0(transform, "stretch") == 0){
		printf("stretch\n");
		if(MagickResizeImage(wand, attr->width, attr->height,
					LanczosFilter, 1.0) == MagickFalse)
			return -1;
	}
	else {
		return -1;
	}
	if (MagickSetImageFormat(wand, attr->format) == MagickFalse) {
		return -1;
	}
	if (MagickWriteImage(wand, modified_path) == MagickFalse) {
		return -1;
	}
	MagickWandTerminus();
	return 0;
}

gboolean make_thumbnail(const char *image_path, const char *modified_path) {
	gboolean status = TRUE;
	MagickWand *wand;
	MagickWandGenesis();
	wand = NewMagickWand();
	printf("lol\n");

	if (MagickReadImage(wand, image_path) == MagickFalse) {
		printf("read failed\n");
		status = FALSE;
		goto cleanup;
	}
	
	if (MagickSetImageColorspace(wand, sRGBColorspace) == MagickFalse) {
		printf("set colorspace failed\n");
		status = FALSE;
		goto cleanup;
	}
	
	if (MagickResizeImage(wand, THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT,
				LanczosFilter, 1.0) == MagickFalse) {
		printf("resize failed\n");
		status = FALSE;
		goto cleanup;
	}
	
	if (MagickSetImageFormat(wand, "JPEG") == MagickFalse) {
		printf("set format failed\n");
		status = FALSE;
		goto cleanup;
	}
	
	if (MagickWriteImage(wand, modified_path) == MagickFalse) {
		printf("write failed\n");
		status = FALSE;
		goto cleanup;
	}
	status = TRUE;
	printf("lol\n");
cleanup:
	MagickWandTerminus();
	return status;
}

int get_handle(char *data, unsigned int length)
{
	int handle, ret;
	if (data == NULL)
		return -1;
	ret = sscanf(data, "%d", &handle);
	if (ret < 1)
		return -1;
	return handle;
}
