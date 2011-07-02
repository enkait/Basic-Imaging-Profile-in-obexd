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

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"
#include "imgimg.h"
#include "image_push.h"
#include "filesystem.h"

#define EOL_CHARS "\n"

#define CAPABILITIES_BEGIN "<imaging-capabilities version=\"1.0\">" EOL_CHARS

#define IMAGE_FORMATS "<image-formats encoding=\"JPEG\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"GIF\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"WBMP\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"PNG\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"JPEG2000\" pixel=\"0*0-65535*65535\">" EOL_CHARS \
                      "<image-formats encoding=\"BMP\" pixel=\"0*0-65535*65535\">" EOL_CHARS \

#define CAPABILITIES_END "</imaging-capabilities>" EOL_CHARS

static const uint8_t IMAGE_PUSH_TARGET[TARGET_SIZE] = {
	0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7,
	0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E };

static void *imgimg_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_push_session *session = context;
	
	if (!name) {
		if (err != NULL)
			*err = -errno;
		return NULL;
	}
	
	session->fd = g_file_open_tmp(NULL, &session->file_path, NULL);

	if (session->fd < 0) {
		if (err != NULL)
			*err = -errno;
		return NULL;
	}

	printf("imging_open\n");
	return session;
}

static int imgimg_close(void *object)
{
	struct image_push_session *session = object;
	if (close(session->fd) < 0)
		return -errno;
	printf("imging_close\n");
	return 0;
}

static ssize_t imgimg_write(void *object, const void *buf, size_t count)
{
	struct image_push_session *session = object;
	ssize_t ret = write(session->fd, buf, count);
	printf("imging_write\n");
	if (ret < 0)
		return -errno;
	return ret;
}

static struct obex_mime_type_driver imgimg = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-img",
	.open = imgimg_open,
	.close = imgimg_close,
	.write = imgimg_write,
};

static void *img_capabilities_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	GString *capabilities = g_string_new(CAPABILITIES_BEGIN);
	capabilities = g_string_append(capabilities, IMAGE_FORMATS);
	capabilities = g_string_append(capabilities, CAPABILITIES_END);

	if (err)
		*err = 0;

	return capabilities;
}

static ssize_t img_capabilities_read(void *object, void *buf, size_t count,
		uint8_t *hi)
{
	*hi = OBEX_HDR_BODY;
	return string_read(object, buf, count);
}

static struct obex_mime_type_driver img_capabilities = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-capabilities",
	.open = img_capabilities_open,
	.close = string_free,
	.read = img_capabilities_read,
};

static int imgimg_init(void)
{
	int res;
	if ((res = obex_mime_type_driver_register(&img_capabilities)) < 0) {
		return res;
	}
	return obex_mime_type_driver_register(&imgimg);
}

static void imgimg_exit(void)
{
	obex_mime_type_driver_unregister(&img_capabilities);
	obex_mime_type_driver_unregister(&imgimg);
}

OBEX_PLUGIN_DEFINE(imgimg, imgimg_init, imgimg_exit)
