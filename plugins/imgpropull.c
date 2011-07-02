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
#include <regex.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>
#include "wand/MagickWand.h"

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imgpropull.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"

#define EOL_CHARS "\n"

#define IMG_PROPERTIES_BEGIN "<image-properties version=\"1.0\" handle=\"%07d\" friendly-name=\"%s\">" EOL_CHARS

#define NATIVE_ELEMENT "<native encoding=\"%s\" pixel=\"%u*%u\" size=\"%lu\"/>" EOL_CHARS

#define VARIANT_ELEMENT "<variant encoding=\"%s\" pixel=\"0*0-65535*65535\"/>" EOL_CHARS

#define ATTACHMENT_ELEMENT "<attachment content-type=\"application/octet-stream\" name=\"%s\" size=\"%jd\" created=\"%s\" modified=\"%s\"/>" EOL_CHARS

#define IMG_PROPERTIES_END "</image-properties>" EOL_CHARS

static const uint8_t IMAGE_PULL_TARGET[TARGET_SIZE] = {
	0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5,
	0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

static GString *append_attachments(GString *object, char *image_path) {
	char *att_dir_path = get_att_dir(image_path);
	DIR *att_dir = opendir(att_dir_path);
	struct dirent *file;
	struct stat file_stat;
	char mtime[18], ctime[18];
	
	if (att_dir == NULL)
		goto done;

	while ((file = readdir(att_dir)) != NULL) {
		char *path = g_build_filename(att_dir_path, file->d_name,
									NULL);
		printf("path: %s\n", path);
		if (!lstat(path, &file_stat) || !S_ISREG(file_stat.st_mode)) {
			printf("nie baldzo: %s\n", path);
			g_free(path);
			continue;
		}
		
		strftime(mtime, 17, "%Y%m%dT%H%M%SZ",
						gmtime(&file_stat.st_mtime));
		strftime(ctime, 17, "%Y%m%dT%H%M%SZ",
						gmtime(&file_stat.st_ctime));
		g_string_append_printf(object, ATTACHMENT_ELEMENT,
					file->d_name, file_stat.st_size,
					ctime, mtime);
		g_free(path);
	}
	printf("attachment not found\n");
	closedir(att_dir);

done:
	g_free(att_dir_path);
	return object;
}

static GString *create_image_properties(struct image_pull_session *session,
						struct img_listing *il) {
	struct encconv_pair * ep = encconv_table;
	char *image_name = g_path_get_basename(il->image);

	GString *object = g_string_new("");
	g_string_append_printf(object, IMG_PROPERTIES_BEGIN, il->handle,
								image_name);
	g_free(image_name);

	g_string_append_printf(object, NATIVE_ELEMENT, il->attr->encoding,
				il->attr->width, il->attr->height,
				il->attr->length);

	while (ep->bip != NULL) {
		g_string_append_printf(object, VARIANT_ELEMENT,	ep->bip);
		ep++;
	}

	object = append_attachments(object, il->image);

	object = g_string_append(object, IMG_PROPERTIES_END);
	return object;
}

static void *imgpropull_open(const char *name, int oflag, mode_t mode,
					void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	int handle;
	GString *object = NULL;
	struct img_listing *il;
	
	printf("imgpropull_open\n");

	if (err != NULL)
		*err = 0;

	handle = get_handle(session->handle_hdr, session->handle_hdr_len);

	if (handle < 0) {
		if (err != NULL)
			*err = -EINVAL;
		return NULL;
	}
	
	if ((il = get_listing(session, handle, err)) == NULL)
		return NULL;

	object = create_image_properties(session, il);
	return object;
}

static ssize_t imgpropull_read(void *object, void *buf, size_t count,
								uint8_t *hi)
{
	*hi = OBEX_HDR_BODY;
	printf("imgpropull_read\n");
	return string_read(object, buf, count);
}

static struct obex_mime_type_driver imgpropull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-properties",
	.open = imgpropull_open,
	.close = string_free,
	.read = imgpropull_read,
};


static int imgpropull_init(void)
{
	return obex_mime_type_driver_register(&imgpropull);
}

static void imgpropull_exit(void)
{
	obex_mime_type_driver_unregister(&imgpropull);
}

OBEX_PLUGIN_DEFINE(imgpropull, imgpropull_init, imgpropull_exit)
