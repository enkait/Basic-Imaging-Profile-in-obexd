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
#include "imgthmpull.h"
#include "image_pull.h"
#include "filesystem.h"
#include "bip_util.h"

static int get_thumbnail_fd(char *image_path, int *err) {
	char *thm_path;
	int fd = g_file_open_tmp(NULL, &thm_path, NULL);
	
	if (fd < 0) {
		if (err != NULL)
			*err = -errno;
		return -1;
	}

	printf("fd = %d\n", fd);
	
	if (!make_thumbnail(image_path, thm_path, err)) {
		close(fd);
		return -1;
	}
	
	printf("thumbnail path: %s\n", thm_path);
	unlink(thm_path);
	return fd;
}

static void *imgthmpull_open(const char *name, int oflag, mode_t mode,
		void *context, size_t *size, int *err)
{
	struct image_pull_session *session = context;
	int handle, fd = -1;
	struct img_listing *il;

	if (err != NULL)
		*err = 0;
	
	printf("imgthmpull_open\n");

	handle = get_handle(session->handle_hdr, session->handle_hdr_len);

	if (handle == -1) {
		if (err != NULL)
			*err = -ENOENT;
		return NULL;
	}

	printf("handle = %d\n", handle);
	
	if ((il = get_listing(session, handle, err)) == NULL)
		return NULL;

	if ((fd = get_thumbnail_fd(il->image, err)) < 0)
		return NULL;

	printf("fd = %d\n", fd);

	return GINT_TO_POINTER(fd);
}

static ssize_t imgthmpull_read(void *object, void *buf, size_t count,
		uint8_t *hi)
{
	ssize_t ret;
	
	printf("imgthmpull_read %p %p %u\n", object, buf, count);

	ret = read(GPOINTER_TO_INT(object), buf, count);
	printf("read %u\n", ret);
	if (ret < 0)
		return -errno;

	*hi = OBEX_HDR_BODY;

	return ret;
}

static int imgthmpull_close(void *object)
{
	if (close(GPOINTER_TO_INT(object)) < 0)
		return -errno;

	return 0;
}

static struct obex_mime_type_driver imgthmpull = {
	.target = IMAGE_PULL_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = imgthmpull_open,
	.close = imgthmpull_close,
	.read = imgthmpull_read,
};

static struct obex_mime_type_driver imgthmpull_aos = {
	.target = IMAGE_AOS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/img-thm",
	.open = imgthmpull_open,
	.close = imgthmpull_close,
	.read = imgthmpull_read,
};

static int imgthmpull_init(void)
{
	int ret;
	if ((ret = obex_mime_type_driver_register(&imgthmpull)) < 0)
		return ret;

	return obex_mime_type_driver_register(&imgthmpull_aos);
}

static void imgthmpull_exit(void)
{
	obex_mime_type_driver_unregister(&imgthmpull_aos);
	obex_mime_type_driver_unregister(&imgthmpull);
}

OBEX_PLUGIN_DEFINE(imgthmpull, imgthmpull_init, imgthmpull_exit)
