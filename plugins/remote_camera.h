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

static const uint8_t REMOTE_CAMERA_TARGET[TARGET_SIZE] = {
	0x94, 0x7E, 0x74, 0x20, 0x46, 0x08, 0x11, 0xD5,
	0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E };

struct remote_camera_session {
	struct obex_session *os;
	GSList *image_list;
	char *dir;
	int next_handle;
};

typedef void (*monit_image_cb) (void *user_data, char *monit_image,
							char *image, int err);

int get_new_handle_rc(struct remote_camera_session *session);
int get_monitoring_image(gboolean store, monit_image_cb cb, void *user_data);
