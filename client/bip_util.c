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
#include <wand/MagickWand.h>

#include "log.h"
#include "obex-xfer.h"
#include "obex-priv.h"
#include "bip_util.h"

#define HANDLE_LEN 7
#define HANDLE_LIMIT 10000000

static const char *att_suf = "_att/";
static const char *default_name = "image";
static const gchar rep_char='_';

uint8_t *encode_img_handle(const char *data, unsigned int length, unsigned int *newsize) {
	uint8_t *utf16buf;
	if (length == 0) {
		*newsize = 0;
		return NULL;
	}
	utf16buf = (uint8_t *) g_convert(data, length,
					"UTF16BE", "UTF8", NULL, newsize, NULL);

	if (utf16buf == NULL)
		return NULL;

	*newsize += 2;
	return utf16buf;
}

char *decode_img_handle(const uint8_t *data, unsigned int length, unsigned int *newsize) {
	gsize size;
	char *handle;

	if (length == 0) {
		*newsize = 0;
		return g_strdup("");
	}

	if (length < 2)
		return NULL;

	if (data[length-1] != '\0' || data[length-2] != '\0')
		return NULL;

	handle = g_convert((char *) data, length - 2,
					"UTF8", "UTF16BE", NULL, &size, NULL);
	if (handle == NULL) {
		return NULL;
	}
	*newsize = size;
	return handle;
}

uint8_t *encode_img_descriptor(const char *data, unsigned int length, unsigned int *newsize) {
	uint8_t *buf = g_try_malloc(length);
	if(!buf)
		return NULL;
	g_memmove(buf, data, length);
	*newsize = length;
	return buf;
}

char *decode_img_descriptor(const uint8_t *data, unsigned int length, unsigned int *newsize) {
	char *buf;
	buf = g_try_malloc(length);

	if (buf == NULL)
		return NULL;

	g_memmove(buf, data, length);
	*newsize = length;
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

struct image_attributes *get_image_attributes(const char *image_file, int *err)
{
	struct image_attributes *attr;
	MagickWand *wand;
	MagickSizeType size;
	char *encoding;
	MagickWandGenesis();
	wand = NewMagickWand();
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
	wand = DestroyMagickWand(wand);
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

	if (str == NULL)
		return -1;

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

gboolean parse_pixel_range(const gchar *dim, unsigned int *lower_ret,
						unsigned int *upper_ret,
						gboolean *fixed_ratio_ret)
{
	static regex_t no_range;
	static regex_t range;
	static regex_t range_fixed;
	static int regex_initialized = 0;
	unsigned int lower[2], upper[2];
	gboolean fixed_ratio = FALSE;
	if (!regex_initialized) {
		regcomp(&no_range, "^([[:digit:]]{1,5})\\*([[:digit:]]{1,5})$",
							REG_EXTENDED);
		regcomp(&range, "^([[:digit:]]{1,5})\\*([[:digit:]]{1,5})"
				"-([[:digit:]]{1,5})\\*([[:digit:]]{1,5})$",
							REG_EXTENDED);
		regcomp(&range_fixed, "^([[:digit:]]{1,5})\\*\\*"
				"-([[:digit:]]{1,5})\\*([[:digit:]]{1,5})$",
							REG_EXTENDED);
		regex_initialized = 1;
	}
	if (dim == NULL)
		return FALSE;
	if (regexec(&no_range, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u*%u", &lower[0], &lower[1]);
		upper[0] = lower[0];
		upper[1] = lower[1];
		fixed_ratio = FALSE;
	}
	else if (regexec(&range, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u*%u-%u*%u", &lower[0], &lower[1], &upper[0], &upper[1]);
		fixed_ratio = FALSE;
	}
	else if (regexec(&range_fixed, dim, 0, NULL, 0) == 0) {
		sscanf(dim, "%u**-%u*%u", &lower[0], &upper[0], &upper[1]);
		lower[1] = 0;
		fixed_ratio = TRUE;
	}
	else {
		return FALSE;
	}
	if (lower[0] > 65535 || lower[1] > 65535 || upper[0] > 65535 || upper[1] > 65535)
		return FALSE;
	if (lower_ret == NULL || upper_ret == NULL || fixed_ratio_ret == NULL)
		return TRUE;
	if (upper[0] < lower[0] || upper[1] < lower[1])
		return FALSE;
	lower_ret[0] = lower[0];
	lower_ret[1] = lower[1];
	upper_ret[0] = upper[0];
	upper_ret[1] = upper[1];
	*fixed_ratio_ret = fixed_ratio;

	return TRUE;
}

int parse_handle(const char *data)
{
	int handle;
	char *ptr;
	if (data == NULL)
		return -1;
	if (strlen(data) != HANDLE_LEN)
		return -1;
	handle = strtol(data, &ptr, 10);
	if (ptr != data + HANDLE_LEN)
		return -1;
	if (handle < 0 || handle >= HANDLE_LIMIT)
		return -1;
	return handle;
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

char *parse_transform(const char *transform) {
	if (!verify_transform(transform))
		return NULL;
	return g_strdup(transform);
}

char *parse_transform_list(const char *transform) {
	char **args = NULL, **arg = NULL;
	gboolean used[3] = { FALSE, FALSE, FALSE };
	if (transform == NULL)
		return NULL;
	if (strlen(transform) == 0)
		return NULL;
	args = g_strsplit(transform, " ", 0);
	for (arg = args; *arg != NULL; arg++) {
		char *t = *arg;
		if (!verify_transform(t)) {
			g_strfreev(args);
			return NULL;
		}
		switch (t[0]) {
		case 's':
			if (used[0])
				goto failure;
			used[0] = TRUE;
			break;
		case 'c':
			if (used[1])
				goto failure;
			used[1] = TRUE;
			break;
		case 'f':
			if (used[2])
				goto failure;
			used[2] = TRUE;
			break;
		}
	}
	g_strfreev(args);
	return g_strdup(transform);
failure:
	g_strfreev(args);
	return NULL;
}

char *parse_unsignednumber(const char *size) {
	static regex_t unumber;
	static int regex_initialized = 0;
	if (!regex_initialized) {
		regcomp(&unumber, "^[[:digit:]]+$", REG_EXTENDED);
		regex_initialized = 1;
	}
	if (regexec(&unumber, size, 0, NULL, 0) != 0)
		return NULL;
	return g_strdup(size);
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
		if (!MagickCropImage(wand, attr->width, attr->height, 0, 0))
			goto failed;
	}
	else if (g_strcmp0(transform, "fill") == 0) {
		if (!MagickExtentImage(wand, attr->width, attr->height, 0, 0))
			goto failed;
	}
	else {
		if(MagickResizeImage(wand, attr->width, attr->height,
					LanczosFilter, 1.0) == MagickFalse)
			goto failed;
	}

	if (attr->encoding != NULL && !MagickSetImageFormat(wand, attr->encoding))
		goto failed;

	if (!MagickWriteImage(wand, modified_path))
		goto failed;

	wand = DestroyMagickWand(wand);
	MagickWandTerminus();
	return TRUE;
failed:
	wand = DestroyMagickWand(wand);
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
	
	if (err != NULL)
		*err = 0;

	if (!MagickReadImage(wand, image_path)) {
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
	
	wand = DestroyMagickWand(wand);
	MagickWandTerminus();
	return TRUE;
failed:
	MagickWandTerminus();
	if (err != NULL)
		*err = -EBADR;
	return FALSE;
}

void parse_client_user_headers(const GSList *aheaders,
				char **desc_hdr,
				unsigned int *desc_hdr_len,
				char **handle_hdr,
				unsigned int *handle_hdr_len)
{
	struct a_header *ah;

	if (desc_hdr != NULL && desc_hdr_len != NULL) {
		g_free(*desc_hdr);
		*desc_hdr = NULL;
		*desc_hdr_len = 0;
	}

	if (handle_hdr != NULL && handle_hdr_len != NULL) {
		g_free(*handle_hdr);
		*handle_hdr = NULL;
		*handle_hdr_len = 0;
	}

	ah = a_header_find(aheaders, IMG_HANDLE_HDR);

	if (ah != NULL)
		*handle_hdr = decode_img_handle(ah->hv.bs, ah->hv_size,
							handle_hdr_len);

	ah = a_header_find(aheaders, IMG_DESC_HDR);

	if (ah != NULL)
		*desc_hdr = decode_img_descriptor(ah->hv.bs, ah->hv_size,
							desc_hdr_len);
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
		*desc_hdr = NULL;
		*desc_hdr_len = 0;
	}
	
	if (handle_hdr != NULL && handle_hdr_len != NULL) {
		g_free(*handle_hdr);
		*handle_hdr = NULL;
		*handle_hdr_len = 0;
	}

	while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen));
	OBEX_ObjectReParseHeaders(os->obex, obj);
	while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen)) {
		switch (hi) {
		case IMG_DESC_HDR:
			if (desc_hdr == NULL || desc_hdr_len == NULL)
				continue;
			*desc_hdr = decode_img_descriptor(hd.bs, hlen,
								desc_hdr_len);
			break;
		case IMG_HANDLE_HDR:
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
	att_path = g_string_append(att_path, att_suf);
	return g_string_free(att_path, FALSE);
}

struct a_header *create_handle(const char *handle) {
	struct a_header *ah = g_new0(struct a_header, 1);
	ah->hi = IMG_HANDLE_HDR;
	ah->hv.bs = encode_img_handle(handle, strlen(handle), &ah->hv_size);
	return ah;
}

char *insert_number(const char *path, unsigned int number) {
	GString *new_path;
	char *spl;
	if (number > 10000000)
		return NULL;
	spl = g_utf8_strchr(path, -1, '.');
	if (spl == NULL)
		new_path = g_string_new(path);
	else
		new_path = g_string_new_len(path, spl-path);
	g_string_append_printf(new_path, "_%u", number);

	if (spl != NULL)
		new_path = g_string_append(new_path, spl);
	return g_string_free(new_path, FALSE);
}

char *safe_rename(const char *name, const char *folder, const char *orig_path,
								int *err)
{
	char *new_name, *new_path, *test_path = NULL, *dest_folder;
	int lock_fd = -1, number = 1;
	gboolean root;

	if (err != NULL)
		*err = 0;

	if (name == NULL || strlen(name) == 0)
		new_name = g_strdup(default_name);
	else
		new_name = (char *) name;

	new_path = g_build_filename(folder, name, NULL);

	dest_folder = g_path_get_dirname(new_path);
	root = g_strcmp0(folder, dest_folder);

	if (!root) {
		if (err != NULL)
			*err = -EBADR;
		goto cleanup;
	}

	test_path = g_strdup(new_path);

	while ((lock_fd = open(test_path, O_CREAT | O_EXCL, 0600)) < 0 &&
							errno == EEXIST) {
		number++;
		g_free(test_path);
		test_path = insert_number(new_path, number);
		if (test_path == NULL) {
			if (err != NULL)
				*err = -errno;
			goto cleanup;
		}
	}

	if (lock_fd < 0) {
		g_free(test_path);
		test_path = NULL;
		if (err != NULL)
			*err = -EBADR;
		goto cleanup;
	}

	if (rename(orig_path, test_path) < 0) {
		g_free(test_path);
		test_path = NULL;
	}
	close(lock_fd);

cleanup:
	if (name == NULL || strlen(name) == 0)
		g_free(new_name);
	g_free(new_path);
	return test_path;
}

char *get_null_terminated(char *buffer, int len) {
	char *newbuffer;
	if (len <= 0) {
		newbuffer = g_strdup("");
	}
	else if (buffer[len-1] != '\0') {
		newbuffer = g_try_malloc(len + 1);
		g_memmove(newbuffer, buffer, len);
		newbuffer[len]='\0';
	}
	else {
		newbuffer = g_memdup(buffer, len);
	}
	return newbuffer;
}

ssize_t add_reply_handle(void *buf, size_t mtu, uint8_t *hi, int handle)
{
	GString *handle_str = g_string_new("");
	uint8_t *handle_hdr;
	unsigned int handle_hdr_len;

	if (handle < -1 || handle >= HANDLE_LIMIT) {
		g_string_free(handle_str, TRUE);
		return -EBADR;
	}
	if (handle != -1) {
		g_string_append_printf(handle_str, "%07d", handle);
	}
	handle_hdr = encode_img_handle(handle_str->str, handle_str->len,
							&handle_hdr_len);
	g_string_free(handle_str, TRUE);

	if (handle_hdr == NULL)
		return -ENOMEM;

	*hi = IMG_HANDLE_HDR;

	if (handle_hdr_len > mtu) {
		g_free(handle_hdr);
		return -ENOMEM;
	}
	g_memmove(buf, handle_hdr, handle_hdr_len);
	g_free(handle_hdr);
	return handle_hdr_len;
}

