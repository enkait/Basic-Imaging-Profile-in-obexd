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

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"
#include "obex-priv.h"
#include "image_push.h"

#define IMAGE_PUSH_CHANNEL 20
#define IMAGE_PUSH_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>		\
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

#define IMG_HANDLE_HDR OBEX_HDR_TYPE_BYTES|0x30

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
			0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
			0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

static const char * bip_root="/tmp/bip/";

void free_image_descriptor(struct image_descriptor *id) {
    if(!id)
        return;
    g_free(id->version);
    g_free(id->encoding);
    g_free(id->pixel);
    g_free(id->size);
    g_free(id->maxsize);
    g_free(id->transformation);
    g_free(id);
}

void free_request_data(struct request_data *rd) {
    if (!rd)
        return;
    free_image_descriptor(rd->imgdesc);
    g_free(rd);
}

void free_image_push_session(struct image_push_session *session) {
    free_request_data(session->reqdata);
    g_free(session->image_path);
    g_free(session);
}

void *image_push_connect(struct obex_session *os, int *err)
{
    struct image_push_session *ips;
    printf("IMAGE PUSH CONNECT\n");
	manager_register_session(os);

    ips = g_new0(struct image_push_session, 1);
    ips->os = os;

    if (err)
        *err = 0;

	return ips;
}

int image_push_get(struct obex_session *os, obex_object_t *obj, gboolean *stream,
							void *user_data)
{
    printf("IMAGE PUSH GET\n");
	return 0;
}

int image_push_chkput(struct obex_session *os, void *user_data)
{
    struct image_push_session *ips = user_data;
    int ret;
    printf("IMAGE PUSH CHKPUT\n");
    
    g_free(ips->reqdata);
    ips->reqdata = g_new0(struct request_data, 1);
    ips->reqdata->imgdesc = g_new0(struct image_descriptor, 1);
	ret = obex_put_stream_start(os, "");
	return ret;
}

guint8 *encode_length_prefix(const gunichar2 *data, unsigned int length, unsigned int *newsize) {
    guint16 len = length;
    guint8 *buf = g_try_malloc(3+2*length);
    len = GUINT16_TO_BE(len);
    if(!buf)
        return NULL;
    g_memmove(buf,&len,2);
    g_memmove(buf+2,data,2*length);
    buf[2*length+2]='\0';
    *newsize = 2*length+3;
    return buf;
}

int obex_handle_write(struct obex_session *os, obex_object_t *obj, const char *data, unsigned int size) {
    obex_headerdata_t hd;
    glong newlen;
    unsigned int headersize;

    gunichar2 *buf = g_utf8_to_utf16(data,size,NULL,&newlen,NULL);
    hd.bs = encode_length_prefix(buf, newlen, &headersize);

    return OBEX_ObjectAddHeader(os->obex, obj,
            IMG_HANDLE_HDR, hd, headersize, 0);
}

char *get_handle(struct image_push_session *ips) {
    char *handle = g_try_malloc(7);
    printf("%d\n", ips->next_handle);
    snprintf(handle, 7, "%07d", ips->next_handle);
    ips->next_handle++;
    return handle;
}

/*
char * get_handle(char * image_name, char * image_folder) {
    DIR *image_dir = opendir(image_folder);
    struct dirent *dent;
    struct stat filestat;
    int len = strlen(image_folder) + strlen(image_name) + 1;
    time_t image_creation;
    int count_earlier = 0;
    char *image_path = g_try_malloc(len);
    char * handle;
    image_path[0]='\0';
    strcat(image_path, image_folder);
    strcat(image_path, image_name);
    stat(image_path, &filestat);
    image_creation = filestat.st_mtime;
    printf("%s\n", image_path);
    g_free(image_path);
    if (!image_dir)
        return NULL;
    while ((dent = readdir(image_dir))) {
        time_t filemodtime;
        stat(image_path, filestat);
        if (filestat->st_ctime<image_creation) {
            count_earlier++;
        }
    }
    handle = g_try_malloc(7);
    printf("%d\n", count_earlier);
    snprintf(handle, 7, "%d", count_earlier);
    return handle;
}
*/

int image_push_put(struct obex_session *os, obex_object_t *obj, void *user_data)
{
    struct image_push_session *ips = user_data;
	obex_headerdata_t hd;
	unsigned int hlen;
	uint8_t hi;
    int len;
    char *imagename;
    char *handle;
    printf("IMAGE PUSH PUT %s\n", os->name);
	while (OBEX_ObjectGetNextHeader(os->obex, obj, &hi, &hd, &hlen)) {
        printf("header numer=%d\n", hi);
    }
    len = strlen(bip_root) + strlen(os->name) + 7;
    imagename = g_try_malloc(len);
    imagename[0]='\0';
    strcat(imagename, bip_root);
    strcat(imagename, os->name);
    strcat(imagename, "XXXXXX");
    close(mkstemp(imagename));
    rename(ips->image_path, imagename);
    printf("imagename=%s\n", imagename);
    g_free(imagename);
    handle = get_handle(ips);
    obex_handle_write(os, obj, handle, 7);
    g_free(handle);
	return 0;
}

void image_push_disconnect(struct obex_session *os, void *user_data)
{
    struct image_push_session *ips = user_data;
    printf("IMAGE PUSH DISCONNECT\n");
    free_image_push_session(ips);
	manager_unregister_session(os);
}

static struct obex_service_driver image_push = {
	.name = "OBEXD Image Push Server",
	.service = OBEX_BIP,
	.channel = IMAGE_PUSH_CHANNEL,
	.record = IMAGE_PUSH_RECORD,
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.connect = image_push_connect,
	.get = image_push_get,
	.put = image_push_put,
	.chkput = image_push_chkput,
	.disconnect = image_push_disconnect
};

static int image_push_init(void)
{
	return obex_service_driver_register(&image_push);
}

static void image_push_exit(void)
{
	obex_service_driver_unregister(&image_push);
}

OBEX_PLUGIN_DEFINE(image_push, image_push_init, image_push_exit)
