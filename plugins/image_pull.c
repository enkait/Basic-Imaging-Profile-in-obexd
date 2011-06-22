/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define __USE_XOPEN
#include <time.h>

#include <glib.h>
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "image_pull.h"
#include "bip_util.h"

#define IMAGE_PULL_CHANNEL 21
#define IMAGE_PULL_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
<record>								\
  <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"0x111b\"/>						\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0008\"/>					\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
  </attribute>								\
									\
  <attribute id=\"0x0009\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x111a\"/>					\
        <uint16 value=\"0x0100\" name=\"version\"/>			\
      </sequence>							\
    </sequence>								\
  </attribute>								\
</record>"

#define IMG_HANDLE_HDR (OBEX_HDR_TYPE_BYTES | 0x30)
#define IMG_DESC_HDR (OBEX_HDR_TYPE_BYTES | 0x71)

#define NBRETURNEDHANDLES_TAG 0x01
#define NBRETURNEDHANDLES_LEN 0x02
#define LISTSTARTOFFSET_TAG 0x02
#define LISTSTARTOFFSET_LEN 0x02
#define LATESTCAPTUREDIMAGES_TAG 0x03
#define LATESTCAPTUREDIMAGES_LEN 0x01

#define GETALLIMAGES 65535

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
			0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

//static const char * bip_root="/tmp/bip/";

struct image_handles_desc *new_hdesc() {
    struct image_handles_desc *hdesc = g_new0(struct image_handles_desc, 1);
    hdesc->upper[0] = hdesc->upper[1] = -1;
    return hdesc;
}

static void free_image_pull_session(struct image_pull_session *session) {
}

void *image_pull_connect(struct obex_session *os, int *err) {
    struct image_pull_session *ips;
    printf("IMAGE PULL CONNECT\n");
	manager_register_session(os);

    ips = g_new0(struct image_pull_session, 1);
    ips->os = os;

    if (err)
        *err = 0;

	return ips;
}

static struct pull_aparam_field *parse_aparam(const uint8_t *buffer, uint32_t hlen)
{
	struct pull_aparam_field *param;
	struct pull_aparam_header *hdr;
	uint32_t len = 0;
	uint16_t val16;

	param = g_new0(struct pull_aparam_field, 1);

	while (len < hlen) {
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
		case NBRETURNEDHANDLES_TAG:
			if (hdr->len != NBRETURNEDHANDLES_LEN)
				goto failed;

			memcpy(&val16, hdr->val, sizeof(val16));
			param->nbreturnedhandles = GUINT16_FROM_BE(val16);
			break;

		case LISTSTARTOFFSET_TAG:
			if (hdr->len != LISTSTARTOFFSET_LEN)
				goto failed;

			memcpy(&val16, hdr->val, sizeof(val16));
			param->liststartoffset = GUINT16_FROM_BE(val16);
			break;
		case LATESTCAPTUREDIMAGES_TAG:
			if (hdr->len != LATESTCAPTUREDIMAGES_LEN)
				goto failed;

			param->latestcapturedimages = hdr->val[0];
			break;
		default:
			goto failed;
		}

		len += hdr->len + sizeof(struct pull_aparam_header);
	}

	DBG("nb %x ls %x lc %x",
			param->nbreturnedhandles, param->liststartoffset, param->latestcapturedimages);

	return param;

failed:
	g_free(param);

	return NULL;
}

static gboolean parse_time_range(const gchar *range, time_t *res, gboolean *bounded) {
    gchar **arr = g_strsplit(range, "-", 2);
    gchar **pos = arr;
    int i;
    for(i=0;i<2;i++) {
		int len = strlen(*pos);

        if (range[i] == '*')
            bounded[i] = FALSE;
        else
            bounded[i] = TRUE;

        res[i] = parse_iso8601(*pos, len);
		if (res[i] == -1)
			return FALSE;
		pos++;
    }
    printf("time_range: %lu %lu %d %d\n", res[0], res[1], bounded[0], bounded[1]);
    g_strfreev(arr);
    return TRUE;
}

static gboolean parse_pixel_range(const gchar *dim, unsigned int *lower, unsigned int *upper, gboolean *fixed_ratio) {
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

static void handles_listing_element(GMarkupParseContext *ctxt,
        const gchar *element,
        const gchar **names,
        const gchar **values,
        gpointer user_data,
        GError **gerr)
{
    struct image_handles_desc *desc = user_data;
    gchar **key;

	printf("element: %s\n", element);
    printf("names\n");

    if (g_str_equal(element, "filtering-parameters") != TRUE)
        return;

    printf("names: %p\n", names);
	for (key = (gchar **) names; *key; key++, values++) {
        printf("key: %s\n", *key);
		if (g_str_equal(*key, "created")) {
            parse_time_range(*values, desc->ctime, desc->ctime_bounded);
        }
        else if (g_str_equal(*key, "modified")) {
            parse_time_range(*values, desc->mtime, desc->mtime_bounded);
        }
        else if (g_str_equal(*key, "encoding")) {
            desc->encoding = g_strdup(*values);
            printf("encoding: %s\n", desc->encoding);
        }
        else if (g_str_equal(*key, "pixel")) {
            parse_pixel_range(*values, desc->lower, desc->upper, &desc->fixed_ratio);
            printf("pixel: %u %u %u %u %d\n", desc->lower[0], desc->lower[1], desc->upper[0], desc->upper[1], desc->fixed_ratio);
        }
    }
}

static const GMarkupParser handles_desc_parser = {
    handles_listing_element,
    NULL,
    NULL,
    NULL,
    NULL
};

static struct image_handles_desc *parse_handles_desc(const struct obex_session *os, obex_object_t *obj) {
    obex_headerdata_t hd;
    unsigned int hlen;
    uint8_t hi;
    struct image_handles_desc *desc = new_hdesc();
    GMarkupParseContext *ctxt = g_markup_parse_context_new(&handles_desc_parser, 0, desc, NULL);
    while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen));
	OBEX_ObjectReParseHeaders(os->obex, obj);
    while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen)) {
		printf("%d %d\n", hi, IMG_DESC_HDR);
        if (hi == IMG_DESC_HDR) {
			unsigned int len;
			gchar *desc = (gchar *) decode_img_descriptor((gchar *) hd.bs, hlen, &len);
			if (desc == NULL) {
				g_free(desc);
				return NULL;
			}
			g_markup_parse_context_parse(ctxt, desc, len, NULL);
        }
    }
	OBEX_ObjectReParseHeaders(os->obex, obj);
	g_markup_parse_context_free(ctxt);
    return desc;
}

int image_pull_get(struct obex_session *os, obex_object_t *obj,
        gboolean *stream, void *user_data) {
    struct image_pull_session *ips = user_data;
    const uint8_t *buffer;
    int ret;
    ssize_t rsize = obex_aparam_read(os, obj, &buffer);

    ips->aparam = parse_aparam(buffer, rsize);
    ips->hdesc = parse_handles_desc(os, obj);

    ret = obex_get_stream_start(os, "");
    printf("IMAGE PULL GET\n");
    if (ret < 0)
        return ret;
    return 0;
}

int image_pull_chkput(struct obex_session *os, void *user_data) {
    printf("IMAGE PULL CHKPUT\n");
    return 0;
}

int image_pull_put(struct obex_session *os, obex_object_t *obj, void *user_data) {
    printf("IMAGE PULL PUT\n");
    return 0;
}

void image_pull_disconnect(struct obex_session *os, void *user_data)
{
    struct image_pull_session *ips = user_data;
    printf("IMAGE PULL DISCONNECT\n");
    free_image_pull_session(ips);
    manager_unregister_session(os);
}

static struct obex_service_driver image_pull = {
    .name = "OBEXD Image Pull Server",
    .service = OBEX_BIP_PULL,
    .channel = IMAGE_PULL_CHANNEL,
    .record = IMAGE_PULL_RECORD,
    .target = IMAGE_PULL_TARGET,
    .target_size = TARGET_SIZE,
    .connect = image_pull_connect,
    .get = image_pull_get,
    .put = image_pull_put,
    .chkput = image_pull_chkput,
    .disconnect = image_pull_disconnect
};

static int image_pull_init(void)
{
    return obex_service_driver_register(&image_pull);
}

static void image_pull_exit(void)
{
    obex_service_driver_unregister(&image_pull);
}

OBEX_PLUGIN_DEFINE(image_pull, image_pull_init, image_pull_exit)
