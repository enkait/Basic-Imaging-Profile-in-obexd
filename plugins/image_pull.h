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

struct pull_aparam_field {
    uint16_t nbreturnedhandles;
    uint16_t liststartoffset;
    uint8_t latestcapturedimages;
};

struct image_handles_desc {
    time_t ctime[2];
    gboolean ctime_unbounded[2];
    time_t mtime[2];
    gboolean mtime_unbounded[2];
    char *encoding;
    unsigned int lower[2], upper[2];
    gboolean fixed_ratio;
};

struct pull_aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

struct image_pull_session {
    struct obex_session *os;
    struct pull_aparam_field *aparam;
    struct image_handles_desc *hdesc;
};

void *image_pull_connect(struct obex_session *os, int *err);
int image_pull_get(struct obex_session *os, obex_object_t *obj, gboolean *stream,
							void *user_data);
int image_pull_chkput(struct obex_session *os, void *user_data);
int image_pull_put(struct obex_session *os, obex_object_t *obj, void *user_data);
void image_pull_disconnect(struct obex_session *os, void *user_data);

