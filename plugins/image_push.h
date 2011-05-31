/*
 *
 *  OBEX Server
 *
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

void *image_push_connect(struct obex_session *os, int *err);
int image_push_get(struct obex_session *os, obex_object_t *obj, gboolean *stream,
							void *user_data);
int image_push_chkput(struct obex_session *os, void *user_data);
int image_push_put(struct obex_session *os, obex_object_t *obj, void *user_data);
void image_push_disconnect(struct obex_session *os, void *user_data);

struct image_descriptor {
    char *version;
    char *encoding;
    char *pixel;
    char *size;
    char *maxsize;
    char *transformation;
};

struct request_data {
    struct image_descriptor *imgdesc;
};

struct image_push_session {
    struct obex_session *os;
    struct request_data *reqdata;
    guint8 *buf;
    gint bufsize;
};

void free_image_descriptor(struct image_descriptor *id);
void free_request_data(struct request_data *rd);
void free_image_push_session(struct image_push_session *session);
