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
#include "imgattpush.h"
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

static void *imgattpush_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_push_session *session = context;
	printf("imgattpush_open\n");
	
	if (!name) {
		if (err)
			*err = -errno;
		return NULL;
	}

	session->fd = g_file_open_tmp(NULL, &session->file_path, NULL);

	if (session->fd < 0) {
		if (err)
			*err = -errno;
		return NULL;
	}

	return session;
}

static int imgattpush_close(void *object)
{
	struct image_push_session *session = object;
	if (close(session->fd) < 0)
		return -errno;
	printf("imgattpush_close\n");
	return 0;
}

static ssize_t imgattpush_write(void *object, const void *buf, size_t count)
{
	struct image_push_session *session = object;
	ssize_t ret = write(session->fd, buf, count);
	printf("imgattpush_write\n");
	if (ret < 0)
		return -errno;
	return ret;
}

static struct obex_mime_type_driver imgattpush = {
	.target = IMAGE_PUSH_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-attachment",
	.open = imgattpush_open,
	.close = imgattpush_close,
	.write = imgattpush_write,
};

static int imgattpush_init(void)
{
	return obex_mime_type_driver_register(&imgattpush);
}

static void imgattpush_exit(void)
{
	obex_mime_type_driver_unregister(&imgattpush);
}

OBEX_PLUGIN_DEFINE(imgattpush, imgattpush_init, imgattpush_exit)
