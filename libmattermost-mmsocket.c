/*
 *   Mattermost plugin for libpurple
 *   Copyright (C) 2016  Eion Robb
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include <glib.h>
#include "glibcompat.h"

#include <purple.h>
#include "purplecompat.h"

#include "libmattermost-mmsocket.h"
#include "libmattermost-json.h"
#include "libmattermost-helpers.h"
#include "libmattermost-msgprocess.h"

static gboolean
mm_process_frame(MattermostAccount *ma, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;

	purple_debug_info("mattermost", "got frame data: %s\n", frame);

	if (!json_parser_load_from_data(parser, frame, -1, NULL))
	{
		purple_debug_error("mattermost", "Error parsing response: %s\n", frame);
		return TRUE;
	}

	root = json_parser_get_root(parser);

	if (root != NULL) {
		mm_process_msg(ma, root);
	}

	g_object_unref(parser);
	return TRUE;
}


static size_t
mm_socket_write(MattermostAccount *ma, gconstpointer buffer, size_t len)
{
	if (ma->websocket) {
		return purple_ssl_write(ma->websocket, buffer, len);
	}
	
	return write(ma->websocket_fd, buffer, len);
}

static void
mm_socket_send_headers(MattermostAccount *ma)
{
	gchar *websocket_header;
	gchar *cookies;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy

	cookies = mm_cookies_to_string(ma);

//	websocket_header = g_strdup_printf("GET %s/users/websocket HTTP/1.1\r\n"
	websocket_header = g_strdup_printf("GET %s/websocket HTTP/1.0\r\n"
							"Host: %s\r\n"
							"Connection: Upgrade\r\n"
							"Pragma: no-cache\r\n"
							"Cache-Control: no-cache\r\n"
							"Upgrade: websocket\r\n"
							"Sec-WebSocket-Version: 13\r\n"
							"Sec-WebSocket-Key: %s\r\n"
							"User-Agent: " MATTERMOST_USERAGENT "\r\n"
							"Cookie: %s\r\n"
							"Authorization: Bearer %s\r\n"
							//"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
							"\r\n", ma->api_endpoint, ma->server,
							websocket_key, cookies, ma->session_token);

	mm_socket_write(ma, websocket_header, strlen(websocket_header));

	g_free(websocket_header);
	g_free(cookies);
}

static size_t mm_socket_read(MattermostAccount *ma, gpointer buffer, size_t len);
static void mm_socket_write_data(MattermostAccount *ma, guchar *data, gssize data_len, guchar type);

/* takes ownership of data parameter */
static void
mm_socket_write_json(MattermostAccount *ma, JsonObject *data)
{
	gchar *str;

	if (ma->websocket == NULL) {
		if (data != NULL) {
			ma->pending_writes = g_slist_append(ma->pending_writes, data);
		}
		return;
	}

	str = json_object_to_string(data);
	
	mm_socket_write_data(ma, (guchar *)str, -1, 0);

	g_free(str);
}

static void
mm_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	MattermostAccount *ma = userdata;
	guchar length_code;
	int read_len = 0;
	gboolean done_some_reads = FALSE;


	if (G_UNLIKELY(!ma->websocket_header_received)) {
		gint nlbr_count = 0;
		gchar nextchar;

		while(nlbr_count < 4 && (read_len = mm_socket_read(ma, &nextchar, 1)) == 1) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}

		if (nlbr_count == 4) {
			ma->websocket_header_received = TRUE;
			done_some_reads = TRUE;

			/* flush stuff that we attempted to send before the websocket was ready */
			while (ma->pending_writes) {
				mm_socket_write_json(ma, ma->pending_writes->data);
				ma->pending_writes = g_slist_delete_link(ma->pending_writes, ma->pending_writes);
			}
		}
	}

	while(ma->frame || (read_len = mm_socket_read(ma, &ma->packet_code, 1)) == 1) {
		if (!ma->frame) {
			if (ma->packet_code != 129) {
				if (ma->packet_code == 136) {
					purple_debug_error("mattermost", "websocket closed\n");

					// Try reconnect
					mm_start_socket(ma);

					return;
				} else if (ma->packet_code == 137) {
					// Ping
					gint ping_frame_len = 0;
					length_code = 0;
					mm_socket_read(ma, &length_code, 1);
					if (length_code <= 125) {
						ping_frame_len = length_code;
					} else if (length_code == 126) {
						guchar len_buf[2];
						mm_socket_read(ma, len_buf, 2);
						ping_frame_len = (len_buf[0] << 8) + len_buf[1];
					} else if (length_code == 127) {
						mm_socket_read(ma, &ping_frame_len, 8);
						ping_frame_len = GUINT64_FROM_BE(ping_frame_len);
					}
					if (ping_frame_len) {
						guchar *pong_data = g_new0(guchar, ping_frame_len);
						mm_socket_read(ma, pong_data, ping_frame_len);

						mm_socket_write_data(ma, pong_data, ping_frame_len, 138);
						g_free(pong_data);
					} else {
						mm_socket_write_data(ma, (guchar *) "", 0, 138);
					}
					return;
				} else if (ma->packet_code == 138) {
					// Pong
					//who cares
					return;
				}
				purple_debug_error("mattermost", "unknown websocket error %d\n", ma->packet_code);
				return;
			}

			length_code = 0;
			mm_socket_read(ma, &length_code, 1);
			if (length_code <= 125) {
				ma->frame_len = length_code;
			} else if (length_code == 126) {
				guchar len_buf[2];
				mm_socket_read(ma, len_buf, 2);
				ma->frame_len = (len_buf[0] << 8) + len_buf[1];
			} else if (length_code == 127) {
				mm_socket_read(ma, &ma->frame_len, 8);
				ma->frame_len = GUINT64_FROM_BE(ma->frame_len);
			}
			//purple_debug_info("mattermost", "frame_len: %" G_GUINT64_FORMAT "\n", ma->frame_len);

			ma->frame = g_new0(gchar, ma->frame_len + 1);
			ma->frame_len_progress = 0;
		}

		do {
			read_len = mm_socket_read(ma, ma->frame + ma->frame_len_progress, ma->frame_len - ma->frame_len_progress);
			if (read_len > 0) {
				ma->frame_len_progress += read_len;
			}
		} while (read_len > 0 && ma->frame_len_progress < ma->frame_len);
		done_some_reads = TRUE;

		if (ma->frame_len_progress == ma->frame_len) {
			gboolean success = mm_process_frame(ma, ma->frame);
			g_free(ma->frame); ma->frame = NULL;
			ma->packet_code = 0;
			ma->frame_len = 0;
			ma->frames_since_reconnect++;

			if (G_UNLIKELY((ma->websocket == NULL && ma->websocket_fd <= 0) || success == FALSE)) {
				return;
			}
		} else {
			return;
		}
	}

	if (done_some_reads == FALSE && read_len <= 0) {
		if (read_len < 0 && errno == EAGAIN) {
			return;
		}

		purple_debug_error("mattermost", "got errno %d, read_len %d from websocket thread\n", errno, read_len);

		if (ma->frames_since_reconnect < 2) {
			purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Lost connection to server"));
		} else {
			// Try reconnect
			mm_start_socket(ma);
		}
	}
}


static void
mm_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	MattermostAccount *ma = userdata;

	ma->websocket = conn;

	purple_ssl_input_add(ma->websocket, mm_socket_got_data, ma);

	mm_socket_send_headers(ma);
}

static void
mm_restart_channel(MattermostAccount *ma)
{
	purple_connection_set_state(ma->pc, PURPLE_CONNECTION_CONNECTING);
	mm_start_socket(ma);
}

static void
mm_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	MattermostAccount *ma = userdata;

	ma->websocket = NULL;
	ma->websocket_header_received = FALSE;

	if (ma->frames_since_reconnect < 1) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Couldn't connect to gateway"));
	} else {
		mm_restart_channel(ma);
	}
}


static void
mm_socket_got_data_nonssl(gpointer userdata, gint fd, PurpleInputCondition cond)
{
	mm_socket_got_data(userdata, NULL, cond);
}


static void
mm_socket_connected_nonssl(gpointer userdata, gint source, const gchar *error_message)
{
	MattermostAccount *ma = userdata;

	if (source < 0) {
		// Error when connecting
		mm_socket_failed(NULL, 0, ma);
		return;
	}

	ma->websocket_fd = source;
	ma->websocket_inpa = purple_input_add(source, PURPLE_INPUT_READ, mm_socket_got_data_nonssl, ma);
	
	mm_socket_send_headers(ma);
}


void
mm_start_socket(MattermostAccount *ma)
{
	gchar **server_split;
	gint port = 443;

	//Reset all the old stuff
	if (ma->websocket != NULL) {
		purple_ssl_close(ma->websocket);
	}
	if (ma->websocket_inpa) {
		purple_input_remove(ma->websocket_inpa);
	}
	if (ma->websocket_fd > 0) {
		close(ma->websocket_fd);
	}

	if (!purple_account_get_bool(ma->account, "use-ssl", TRUE)) {
		port = 80;
	}

	ma->websocket_fd = 0;
	ma->websocket_inpa = 0;
	ma->websocket = NULL;
	ma->websocket_header_received = FALSE;
	g_free(ma->frame); ma->frame = NULL;
	ma->packet_code = 0;
	ma->frame_len = 0;
	ma->frames_since_reconnect = 0;

	server_split = g_strsplit(ma->server, ":", 2);
	if (server_split[1] != NULL) {
		port = atoi(server_split[1]);
	}

	if (purple_account_get_bool(ma->account, "use-ssl", TRUE)) {
		ma->websocket = purple_ssl_connect(ma->account, server_split[0], port, mm_socket_connected, mm_socket_failed, ma);
	} else {
		purple_proxy_connect(ma->pc, ma->account, server_split[0], port, mm_socket_connected_nonssl, ma);
	}

	g_strfreev(server_split);
}


static size_t
mm_socket_read(MattermostAccount *ma, gpointer buffer, size_t len)
{
	if (ma->websocket) {
		return purple_ssl_read(ma->websocket, buffer, len);
	}

	return read(ma->websocket_fd, buffer, len);
}


static guchar *
mm_websocket_mask(guchar key[4], const guchar *pload, guint64 psize)
{
	guint64 i;
	guchar *ret = g_new0(guchar, psize);

	for (i = 0; i < psize; i++) {
		ret[i] = pload[i] ^ key[i % 4];
	}

	return ret;
}

static void
mm_socket_write_data(MattermostAccount *ma, guchar *data, gssize data_len, guchar type)
{
	guchar *full_data;
	guint len_size = 1;
	guchar mkey[4] = { 0x12, 0x34, 0x56, 0x78 };

	if (data_len == -1) {
		data_len = strlen((gchar *) data);
	}

	if (data_len) {
		purple_debug_info("mattermost", "sending frame: %*s\n", (int)data_len, data);
	}

	data = mm_websocket_mask(mkey, data, data_len);

	if (data_len > 125) {
		if (data_len <= G_MAXUINT16) {
			len_size += 2;
		} else {
			len_size += 8;
		}
	}
	full_data = g_new0(guchar, 1 + data_len + len_size + 4);

	if (type == 0) {
		type = 129;
	}
	full_data[0] = type;

	if (data_len <= 125) {
		full_data[1] = data_len | 0x80;
	} else if (data_len <= G_MAXUINT16) {
		guint16 be_len = GUINT16_TO_BE(data_len);
		full_data[1] = 126 | 0x80;
		memmove(full_data + 2, &be_len, 2);
	} else {
		guint64 be_len = GUINT64_TO_BE(data_len);
		full_data[1] = 127 | 0x80;
		memmove(full_data + 2, &be_len, 8);
	}

	memmove(full_data + (1 + len_size), &mkey, 4);
	memmove(full_data + (1 + len_size + 4), data, data_len);

	mm_socket_write(ma, full_data, 1 + data_len + len_size + 4);

	g_free(full_data);
	g_free(data);
}

guint
mm_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, MattermostAccount *ma)
{
	PurpleConnection *pc;
	const gchar *room_id;
	JsonObject *data;
	JsonObject *data_inside;

	if (state != PURPLE_IM_TYPING) {
		return 0;
	}

	pc = ma ? ma->pc : purple_conversation_get_connection(conv);

	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return 0;

	if (g_strcmp0(purple_protocol_get_id(purple_connection_get_protocol(pc)), MATTERMOST_PLUGIN_ID))
		return 0;

	if (ma == NULL) {
		ma = purple_connection_get_protocol_data(pc);
	}
	
	room_id = purple_conversation_get_data(conv, "id");

	if (PURPLE_IS_IM_CONVERSATION(conv)) {
		room_id = g_hash_table_lookup(ma->one_to_ones_rev, purple_conversation_get_name(conv));
	} else {
		room_id = g_hash_table_lookup(ma->group_chats_rev, room_id);		
	}

	g_return_val_if_fail(room_id, -1); // this can happen if we try to type in a removed chat for which conv still exists ?
	
	data = json_object_new();
	data_inside = json_object_new();
	
	json_object_set_string_member(data_inside, "channel_id", room_id);
	json_object_set_string_member(data_inside, "parent_id", ""); //TODO what is this? (a reply to a post ?)
		
	json_object_set_string_member(data, "action", "user_typing");
	json_object_set_object_member(data, "data", data_inside);
	json_object_set_int_member(data, "seq", mm_get_next_seq(ma));
	
	mm_socket_write_json(ma, data);
	
	return 10;
}

void 
mm_refresh_statuses(MattermostAccount *ma, const gchar *id)
{
	JsonObject *obj;
	JsonObject *data;
	JsonArray *user_ids;

	obj = json_object_new();
	data = json_object_new();
	user_ids = json_array_new();

	if (id != NULL) {		
		json_array_add_string_element(user_ids, id);
		json_object_set_array_member(data, "user_ids", user_ids);
		json_object_set_string_member(obj, "action", "get_statuses_by_ids");
		json_object_set_object_member(obj, "data", data);
	} else {
		json_object_set_string_member(obj, "action", "get_statuses");
	}

	json_object_set_int_member(obj, "seq", mm_get_next_seq_callback(ma, mm_got_hello_user_statuses, NULL));

	mm_socket_write_json(ma, obj);
}







