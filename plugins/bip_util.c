#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <wait.h>

#include <glib.h>
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "log.h"
#include "obex-priv.h"
#include "bip_util.h"
#include "wand/MagickWand.h"

#define HANDLE_LEN 7
#define HANDLE_MAX 10000000

const char *att_suf = "_att";

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
	char *buf;
	printf("%u\n", length);
	buf = g_try_malloc(length-2);

	if (buf == NULL)
		return NULL;

	g_memmove(buf, data+2, length-2);
	*newsize = length-2;
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

const gchar *convBIP2IM(const gchar *encoding) {
	struct encconv_pair *et = encconv_table;
	while (et->bip) {
		if (g_strcmp0(encoding, et->bip) == 0) {
			return et->im;
		}
		et++;
	}
	return NULL;
}

const gchar *convIM2BIP(const gchar *encoding) {
	struct encconv_pair *et = encconv_table;
	while (et->im) {
		if (g_strcmp0(encoding, et->im) == 0) {
			return et->bip;
		}
		et++;
	}
	return NULL;
}

char *transforms[] = {
	"crop",
	"stretch",
	"fill",
	NULL
};

gboolean verify_transform(const char *transform) {
	char **str = transforms;
	while (*str != NULL) {
		if (g_str_equal(transform, *str))
			return TRUE;
		str++;
	}
	return FALSE;
}

struct image_attributes *get_image_attributes(const char *image_file, int *err)
{
	struct image_attributes *attr;
	MagickWand *wand;
	MagickSizeType size;
	char *encoding;
	MagickWandGenesis();
	wand = NewMagickWand();
	printf("pinging path: %s\n", image_file);
	if (!MagickPingImage(wand, image_file)) {
		if (err)
			*err = -ENOENT;
		return NULL;
	}
	encoding = MagickGetImageFormat(wand);
	attr = g_new0(struct image_attributes, 1);
	attr->encoding = g_strdup(convIM2BIP(encoding));
	attr->width = MagickGetImageWidth(wand);
	attr->height = MagickGetImageHeight(wand);
	MagickGetImageLength(wand, &size);
	attr->length = (unsigned long) size;
	MagickWandTerminus();

	if (err)
		*err = 0;
	return attr;
}

void free_image_attributes(struct image_attributes *attr) {
	g_free(attr->encoding);
	g_free(attr);
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

gboolean make_modified_image(const char *image_path, const char *modified_path,
					struct image_attributes *attr,
					const char *transform, int *err)
{
	MagickWand *wand;
	MagickWandGenesis();
	wand = NewMagickWand();

	if (err != NULL)
		*err = 0;

	if (!MagickReadImage(wand, image_path)) {
		if (err != NULL)
			*err = -ENOENT;
		MagickWandTerminus();
		return FALSE;
	}

	if (g_strcmp0(transform, "crop") == 0) {
		printf("crop\n");
		if (!MagickCropImage(wand, attr->width, attr->height, 0, 0))
			goto failed;
	}
	else if (g_strcmp0(transform, "fill") == 0) {
		printf("fill\n");
		if (!MagickExtentImage(wand, attr->width, attr->height, 0, 0))
			goto failed;
	}
	else {
		printf("defaulted to: stretch\n");
		if(MagickResizeImage(wand, attr->width, attr->height,
					LanczosFilter, 1.0) == MagickFalse)
			goto failed;
	}

	if (attr->encoding != NULL && !MagickSetImageFormat(wand, attr->encoding))
		goto failed;

	if (!MagickWriteImage(wand, modified_path))
		goto failed;

	MagickWandTerminus();
	return TRUE;
failed:
	MagickWandTerminus();
	if (err != NULL)
		*err = -EBADR;
	return FALSE;
}

gboolean make_thumbnail(const char *image_path, const char *modified_path,
								int *err)
{
	MagickWand *wand;
	MagickWandGenesis();
	wand = NewMagickWand();
	printf("lol\n");
	
	if (err != NULL)
		*err = 0;

	if (!MagickReadImage(wand, image_path)) {
		printf("read failed\n");
		if (err != NULL)
			*err = -ENOENT;
		MagickWandTerminus();
		return FALSE;
	}
	
	if (!MagickSetImageColorspace(wand, sRGBColorspace))
		goto failed;
	
	if (!MagickResizeImage(wand, THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT,
							LanczosFilter, 1.0))
		goto failed;
	
	if (!MagickSetImageFormat(wand, "JPEG"))
		goto failed;
	
	if (!MagickWriteImage(wand, modified_path))
		goto failed;
	
	printf("lol\n");
	MagickWandTerminus();
	return TRUE;
failed:
	MagickWandTerminus();
	if (err != NULL)
		*err = -EBADR;
	return FALSE;
}

int get_handle(const char *data, unsigned int length)
{
	int handle, ret;
	if (data == NULL)
		return -1;
	if (length != HANDLE_LEN)
		return -1;
	ret = sscanf(data, "%d", &handle);
	if (ret < 1)
		return -1;
	if (handle < 0 || handle >= HANDLE_MAX)
		return -1;
	return handle;
}

void parse_bip_user_headers(const struct obex_session *os,
		obex_object_t *obj, char **desc_hdr, unsigned int *desc_hdr_len,
		char **handle_hdr, unsigned int *handle_hdr_len)
{
	obex_headerdata_t hd;
	unsigned int hlen;
	uint8_t hi;
	
	if (desc_hdr != NULL && desc_hdr_len != NULL) {
		g_free(*desc_hdr);
		*desc_hdr_len = 0;
	}
	
	if (handle_hdr != NULL && handle_hdr_len != NULL) {
		g_free(*handle_hdr);
		*handle_hdr_len = 0;
	}

	while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen));
	OBEX_ObjectReParseHeaders(os->obex, obj);
	printf("header search: %d %d\n", IMG_DESC_HDR, IMG_HANDLE_HDR);
	while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen)) {
		printf("header: %d %d %d\n", hi, IMG_DESC_HDR, IMG_HANDLE_HDR);
		switch (hi) {
		case IMG_DESC_HDR:
			if (desc_hdr == NULL || desc_hdr_len == NULL)
				continue;
			*desc_hdr = decode_img_descriptor(hd.bs, hlen,
								desc_hdr_len);
			break;
		case IMG_HANDLE_HDR:
			printf("handle header\n");
			if (handle_hdr == NULL || handle_hdr_len == NULL)
				continue;
			*handle_hdr = decode_img_handle(hd.bs, hlen,
							handle_hdr_len);
			break;
		}
	}
	OBEX_ObjectReParseHeaders(os->obex, obj);
}

char *get_att_dir(const char *image_path) {
	GString *att_path = g_string_new(image_path);
	printf("img Path :%s\n", image_path);
	att_path = g_string_append(att_path, att_suf);
	return g_string_free(att_path, FALSE);
}
