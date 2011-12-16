/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#ifndef __GOBEX_H
#define __GOBEX_H

#include <stdarg.h>
#include <glib.h>

#include <gobex/gobex-defs.h>
#include <gobex/gobex-packet.h>

typedef enum {
	G_OBEX_TRANSPORT_STREAM,
	G_OBEX_TRANSPORT_PACKET,
} GObexTransportType;

typedef struct _GObex GObex;
typedef struct _GObexTransfer GObexTransfer;

typedef void (*GObexFunc) (GObex *obex, GError *err, gpointer user_data);
typedef void (*GObexRequestFunc) (GObex *obex, GObexPacket *req,
							gpointer user_data);
typedef void (*GObexResponseFunc) (GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data);

gboolean g_obex_send(GObex *obex, GObexPacket *pkt, GError **err);

guint g_obex_send_req(GObex *obex, GObexPacket *req, gint timeout,
			GObexResponseFunc func, gpointer user_data,
			GError **err);
gboolean g_obex_cancel_req(GObex *obex, guint req_id,
						gboolean remove_callback);

gboolean g_obex_send_rsp(GObex *obex, guint8 rspcode, GError **err,
						guint8 first_hdr_type, ...);

void g_obex_set_disconnect_function(GObex *obex, GObexFunc func,
							gpointer user_data);
guint g_obex_add_request_function(GObex *obex, guint8 opcode,
						GObexRequestFunc func,
						gpointer user_data);
gboolean g_obex_remove_request_function(GObex *obex, guint id);

void g_obex_suspend(GObex *obex);
void g_obex_resume(GObex *obex);

GObex *g_obex_new(GIOChannel *io, GObexTransportType transport_type,
						gssize rx_mtu, gssize tx_mtu);

GObex *g_obex_ref(GObex *obex);
void g_obex_unref(GObex *obex);

/* High level client functions */

guint g_obex_connect(GObex *obex, GObexResponseFunc func, gpointer user_data,
				GError **err, guint8 first_hdr_id, ...);

guint g_obex_setpath(GObex *obex, const char *path, GObexResponseFunc func,
					gpointer user_data, GError **err);

guint g_obex_mkdir(GObex *obex, const char *path, GObexResponseFunc func,
					gpointer user_data, GError **err);

guint g_obex_delete(GObex *obex, const char *name, GObexResponseFunc func,
					gpointer user_data, GError **err);

guint g_obex_copy(GObex *obex, const char *name, const char *dest,
			GObexResponseFunc func, gpointer user_data,
			GError **err);

guint g_obex_move(GObex *obex, const char *name, const char *dest,
			GObexResponseFunc func, gpointer user_data,
			GError **err);

/* Transfer related high-level functions */

guint g_obex_put_req(GObex *obex, GObexDataProducer data_func,
			GObexFunc complete_func, gpointer user_data,
			GError **err, guint8 first_hdr_id, ...);

guint g_obex_put_req_pkt(GObex *obex, GObexPacket *req,
			GObexDataProducer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err);

guint g_obex_get_req(GObex *obex, GObexDataConsumer data_func,
			GObexFunc complete_func, gpointer user_data,
			GError **err, guint8 first_hdr_id, ...);

guint g_obex_get_req_pkt(GObex *obex, GObexPacket *req,
			GObexDataConsumer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err);

guint g_obex_put_rsp(GObex *obex, GObexPacket *req,
			GObexDataConsumer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err,
			guint8 first_hdr_id, ...);

guint g_obex_get_rsp(GObex *obex, GObexDataProducer data_func,
			GObexFunc complete_func, gpointer user_data,
			GError **err, guint8 first_hdr_id, ...);

gboolean g_obex_cancel_transfer(guint id);

const char *g_obex_strerror(guint8 err_code);

#endif /* __GOBEX_H */
