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

struct img_listing {
	int handle;
	char *image;
	time_t ctime;
	time_t mtime;
	struct image_attributes *attr;
};

struct image_pull_session {
    struct obex_session *os;
    uint8_t *aparam_data;
    unsigned int aparam_data_len;
    char *handle_hdr;
    unsigned int handle_hdr_len;
    char *desc_hdr;
    unsigned int desc_hdr_len;
    GSList *image_list;
};

void *image_pull_connect(struct obex_session *os, int *err);
int image_pull_get(struct obex_session *os, obex_object_t *obj, gboolean *stream,
							void *user_data);
int image_pull_chkput(struct obex_session *os, void *user_data);
int image_pull_put(struct obex_session *os, obex_object_t *obj, void *user_data);
void image_pull_disconnect(struct obex_session *os, void *user_data);

struct image_handles_desc *new_hdesc();
void img_listing_free(struct img_listing *listing);
struct img_listing *get_listing(struct image_pull_session *session, int handle, int *err);
