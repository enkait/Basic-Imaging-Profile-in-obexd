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

#define SID_TAG 0x09
#define SID_LEN 16

struct archive_session {
    struct obex_session *os;
    char *address;
    int status;
};

void *image_arch_connect(struct obex_session *os, int *err);
int image_arch_get(struct obex_session *os, obex_object_t *obj,
							void *user_data);
int image_arch_chkput(struct obex_session *os, void *user_data);
int image_arch_put(struct obex_session *os, obex_object_t *obj, void *user_data);
void image_arch_disconnect(struct obex_session *os, void *user_data);
