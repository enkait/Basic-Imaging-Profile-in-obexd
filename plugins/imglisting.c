/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
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

#include <openobex/obex.h>
#include <openobex/obex_const.h>
#include "wand/MagickWand.h"

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imglisting.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"

#define EOL_CHARS "\n"

#define IMG_LISTING_BEGIN "<images-listing version=\"1.0\">" EOL_CHARS

#define IMG_LISTING_ELEMENT "<image handle=\"%s\" created=\"%s\" modified=\"%s\">" EOL_CHARS

#define IMG_LISTING_END "</images-listing>" EOL_CHARS

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
			0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
			0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static const char * bip_dir = "/tmp/bip/";

struct img_listing {
    char * image;
    time_t ctime;
    time_t mtime;
};

static void img_listing_free(struct img_listing *listing) {
    g_free(listing->image);
    g_free(listing);
}

static gint ctime_compare(gconstpointer a, gconstpointer b) {
    const struct img_listing *ail = a, *bil = b;
    if(ail->ctime < bil->ctime) return -1;
    else if(ail->ctime > bil->ctime) return 1;
    return g_strcmp0(ail->image, bil->image);
}

static gboolean verify_image(const gchar *image_file, const struct image_handles_desc *hdesc) {
    struct stat file_stat;
    struct image_attributes attr;
    lstat(image_file, &file_stat);

    if (!(file_stat.st_mode & S_IFREG)) {
        return FALSE;
    }

    if (!hdesc)
        return TRUE;

    if (!hdesc->ctime_bounded[0] && file_stat.st_ctime<hdesc->ctime[0])
        return FALSE;
    
    if (!hdesc->ctime_bounded[1] && file_stat.st_ctime>hdesc->ctime[1])
        return FALSE;
    
    if (!hdesc->mtime_bounded[0] && file_stat.st_mtime<hdesc->mtime[0])
        return FALSE;
    
    if (!hdesc->mtime_bounded[1] && file_stat.st_mtime>hdesc->mtime[1])
        return FALSE;

    if (get_image_attributes(image_file, &attr) < 0)
        return FALSE;

    if (hdesc->encoding != NULL && g_strcmp0(hdesc->encoding,attr.format) != 0)
        return FALSE;

    if (hdesc->lower[0] > attr.width || hdesc->lower[1] > attr.height)
        return FALSE;
    
    if (hdesc->upper[0] < attr.width || hdesc->upper[1] < attr.height)
        return FALSE;

    return TRUE;
}

static GString *create_images_listing(int count, int offset, int *res_count, int *err, const struct image_handles_desc *hdesc) {
    GString *listing_obj = g_string_new(IMG_LISTING_BEGIN);
    struct dirent* file;
    struct stat file_stat;
    GSList *images = NULL;
    struct img_listing *il = NULL;
    char *handle_str = g_try_malloc(8);
    char ctime[18], mtime[18];
    int handle = 0;
    DIR *img_dir = opendir(bip_dir);

    if (!img_dir) {
        if (err)
            *err = -errno;
        return NULL;
    }

    while ((file = readdir(img_dir))) {
        GString *str = g_string_new(bip_dir);
        str = g_string_append(str, file->d_name);

        lstat(str->str, &file_stat);
        if (!(file_stat.st_mode & S_IFREG)) {
            g_string_free(str, TRUE);
            continue;
        }

        if (!verify_image(str->str, hdesc)) {
            g_string_free(str, TRUE);
            continue;
        }
        il = g_try_malloc(sizeof(struct img_listing));
        il->image = g_string_free(str, FALSE);
        il->mtime = file_stat.st_mtime;
        il->ctime = file_stat.st_ctime;
        images = g_slist_append(images, il);
    }
    images = g_slist_sort(images, ctime_compare);
    
    while (offset) {
        images = g_slist_next(images);
        offset--;
    }

    *res_count = 0;
    while (images && count) {
        struct img_listing *listing = images->data;
        strftime(mtime, 17, "%Y%m%dT%H%M%SZ", gmtime(&listing->mtime));
	    strftime(ctime, 17, "%Y%m%dT%H%M%SZ", gmtime(&listing->ctime));
        snprintf(handle_str, 8, "%07d", handle++);
        g_string_append_printf(listing_obj, IMG_LISTING_ELEMENT, handle_str, ctime, mtime);
        img_listing_free(listing);
        images = g_slist_next(images);
        (*res_count)++;
        count--;
    }
    listing_obj = g_string_append(listing_obj, IMG_LISTING_END);
    g_free(handle_str);
    return listing_obj;
}

static void *imglisting_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err)
{
    struct image_pull_session *session = context;
    int res_count, count=0, offset=0;

    if(session->aparam) {
        printf("using aparams\n");
        count = session->aparam->nbreturnedhandles;
        offset = session->aparam->liststartoffset;
    }

    if (err)
        *err = 0;

    printf("imglisting_open\n");

    return create_images_listing(count, offset, &res_count, err, session->hdesc);
}

static ssize_t imglisting_read(void *object, void *buf, size_t count,
					uint8_t *hi, unsigned int *flags)
{
	if (flags)
		*flags = 0;
	*hi = OBEX_HDR_BODY;
    printf("imglisting_read\n");
	return string_read(object, buf, count);
}

static struct obex_mime_type_driver imglisting = {
    .target = IMAGE_PULL_TARGET,
    .target_size = TARGET_SIZE,
    .mimetype = "x-bt/img-listing",
	.open = imglisting_open,
	.close = string_free,
	.read = imglisting_read,
};


static int imglisting_init(void)
{
	return obex_mime_type_driver_register(&imglisting);
}

static void imglisting_exit(void)
{
	obex_mime_type_driver_unregister(&imglisting);
}

OBEX_PLUGIN_DEFINE(imglisting, imglisting_init, imglisting_exit)
