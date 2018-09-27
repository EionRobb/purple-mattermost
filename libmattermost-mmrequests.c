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

#include <purple.h>
#include "purplecompat.h"
#include "image-store.h"
#include "image.h"

#include "libmattermost.h"
#include "libmattermost-mmrequests.h"
#include "libmattermost-json.h"
#include "libmattermost-helpers.h"
#include "libmattermost-markdown.h"
#include "libmattermost-msgprocess.h"
#include "libmattermost-mmsocket.h"

extern gulong chat_conversation_typing_signal;
extern gulong conversation_updated_signal;

static void mm_get_users_of_room(MattermostAccount *ma, MattermostChannel *channel);

static gboolean 
mm_check_mattermost_response(MattermostAccount *ma, JsonNode *node, gchar *errtitle, gchar *errtext, gboolean show)
{
	if (json_node_get_node_type(node) == JSON_NODE_OBJECT) {
		JsonObject *response = json_node_get_object(node);
		if (json_object_get_int_member(response, "status_code") >= 400) {
			if (show) {
				purple_notify_error(ma->pc, errtitle, errtext, json_object_get_string_member(response, "message"), purple_request_cpar_from_connection(ma->pc));
			}
		return FALSE;
		}
		return TRUE;
	}
	if (json_node_get_node_type(node) == JSON_NODE_ARRAY) {
		return TRUE;
}
	purple_notify_error(ma->pc, _("Error"), _("Cannot parse Mattermost reply"), _("(not json object or array)"), purple_request_cpar_from_connection(ma->pc));
	return FALSE;
}


static void
mm_update_cookies(MattermostAccount *ma, const GList *cookie_headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	const GList *cur;

	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur))
	{
		cookie_start = cur->data;
		
		cookie_end = strchr(cookie_start, '=');
		if (cookie_end != NULL) {
			cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
			cookie_start = cookie_end + 1;
			cookie_end = strchr(cookie_start, ';');
			if (cookie_end != NULL) {
				cookie_value = g_strndup(cookie_start, cookie_end-cookie_start);
				cookie_start = cookie_end;

				g_hash_table_replace(ma->cookie_table, cookie_name, cookie_value);
			}
		}
	}
}

static void
mm_response_callback(PurpleHttpConnection *http_conn, 
PurpleHttpResponse *response, gpointer user_data)
{
	gsize body_len;
	const gchar *body = purple_http_response_get_data(response, &body_len);
	const gchar *error_message = purple_http_response_get_error(response);
	const GList *headers = purple_http_response_get_headers_by_name(response, "Set-Cookie");

	MattermostProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();

	conn->ma->http_conns = g_slist_remove(conn->ma->http_conns, http_conn);

	mm_update_cookies(conn->ma, headers);

	if (body == NULL && error_message != NULL) {
		//connection error - unersolvable dns name, non existing server
		gchar *error_msg_formatted = g_strdup_printf(_("Connection error: %s."), error_message);
		purple_connection_error(conn->ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg_formatted);
		g_free(error_msg_formatted);
		g_free(conn);
		return;
	}

	if (body != NULL && !json_parser_load_from_data(parser, body, body_len, NULL)) {
		//purple_debug_error("mattermost", "Error parsing response: %s\n", body);
		if (conn->callback) {
			JsonNode *dummy_node = json_node_new(JSON_NODE_OBJECT);
			JsonObject *dummy_object = json_object_new();
			
			json_node_set_object(dummy_node, dummy_object);
			json_object_set_string_member(dummy_object, "body", body);
			json_object_set_int_member(dummy_object, "len", body_len);
			if (body_len >= 12 && g_str_has_prefix(body, "HTTP/1.")) {
				json_object_set_int_member(dummy_object, "status_code", g_ascii_strtoll(body + 9, NULL, 10));
			} else {
				json_object_set_int_member(dummy_object, "status_code", 500);
			}
			g_dataset_set_data(dummy_node, "raw_body", (gpointer) body);

			conn->callback(conn->ma, dummy_node, conn->user_data);

			g_dataset_destroy(dummy_node);
			json_node_free(dummy_node);
			json_object_unref(dummy_object);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);
		
		purple_debug_misc("mattermost", "Got response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ma, root, conn->user_data);
		}
	}
	
	g_object_unref(parser);
	g_free(conn);
}


gchar *
mm_build_url(MattermostAccount *ma, const gchar *url_format, ...)
	__attribute__ ((format (printf, 2, 3)));

gchar *
mm_build_url(MattermostAccount *ma, const gchar *url_format, ...)
{
	GString *url = g_string_new(NULL);
	const gchar *last_cur, *cur, *tok;
	va_list args;
	
	if (purple_account_get_bool(ma->account, "use-ssl", TRUE)) {
		g_string_append(url, "https://");
	} else {
		g_string_append(url, "http://");
	}
	g_string_append(url, ma->server);
	
	g_string_append(url, ma->api_endpoint);

	va_start(args, url_format);
	for(last_cur = cur = url_format; cur; last_cur = cur, cur = strchr(cur, '%')) {
		g_string_append_len(url, last_cur, cur - last_cur);
		
		if (*cur == '%') {
			if (*(cur + 1) == 's') {
				tok = va_arg(args, char *);
				g_string_append_uri_escaped(url, tok, NULL, TRUE);
			} else if (*(cur + 1) == '%') {
				g_string_append_c(url, '%');
			} else if (*(cur + 1) == 'd') {
				int d = va_arg(args, int);
				g_string_append_printf(url, "%d", d);
			} else if (*(cur + 1) == 'c') {
				char c = va_arg(args, int);
				g_string_append_c(url, c);
			} else if (strncmp((cur + 1), G_GINT64_FORMAT, sizeof(G_GINT64_FORMAT) - 1) == 0) {
				gint64 i = va_arg(args, gint64);
				g_string_append_printf(url, "%" G_GINT64_FORMAT, i);
				cur += sizeof(G_GINT64_FORMAT) - 2;
			}
			cur += 2;
		}
	}
	va_end(args);
	
	g_string_append(url, last_cur);
	
	return g_string_free(url, FALSE);
}

static void
mm_fetch_url(MattermostAccount *ma, const gchar *url, const guint optype, const gchar *postdata, const guint postdata_size, MattermostProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	MattermostProxyConnection *conn;
	gchar *cookies;
	PurpleHttpConnection *http_conn;
	
	account = ma->account;
	if (purple_account_is_disconnected(account)) return;
	
	conn = g_new0(MattermostProxyConnection, 1);
	conn->ma = ma;
	conn->callback = callback;
	conn->user_data = user_data;
	
	cookies = mm_cookies_to_string(ma);
	
	purple_debug_info("mattermost", "Fetching url %s\n", url);


	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", MATTERMOST_USERAGENT);
	purple_http_request_header_set(request, "Cookie", cookies);
	if (ma->session_token) {
		purple_http_request_header_set_printf(request, "Authorization", "Bearer %s", ma->session_token);
	}
	
	if (postdata) {
		purple_debug_info("mattermost", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
			purple_http_request_set_contents(request, postdata, -1);
		} else if (postdata_size > 0){
			purple_http_request_header_set(request, "Content-Type", "application/octet-stream");
			purple_http_request_set_contents(request, postdata, postdata_size);
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
			purple_http_request_set_contents(request, postdata, -1);
		}
		
	}
	switch(optype) {
		case MATTERMOST_HTTP_DELETE: purple_http_request_set_method(request,"DELETE"); break;
		case MATTERMOST_HTTP_PUT: purple_http_request_set_method(request,"PUT"); break;
		case MATTERMOST_HTTP_POST: purple_http_request_set_method(request,"POST"); break;
		default: purple_http_request_set_method(request,"GET"); 
	}

	http_conn = purple_http_request(ma->pc, request, mm_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL)
		ma->http_conns = g_slist_prepend(ma->http_conns, http_conn);

	g_free(cookies);
}

static gint64
mm_find_channel_approximate_view_time(MattermostAccount *ma, const gchar *id)
{
//	GList *prefs;
	gint64 now = (g_get_real_time() / 1000); // -(60*60*24*5*1000); //(- 5 days for debug, remove !)
//	gint64 then = 0;

//	if (!id) return now;

//OK, so this does not work as expected in MM server 5.0 .. lets do timekeeping ourselves.
//	for (prefs=ma->user_prefs; prefs != NULL; prefs = g_list_next(prefs)) {
//		MattermostUserPref *pref = prefs->data;
//		if (purple_strequal(pref->category,"channel_approximate_view_time") && purple_strequal(pref->name,id)) {
//			then = g_ascii_strtoll(pref->value,NULL,10);
//			return (then ? then : now);
//		}
//	}
	return now;
}

static gboolean
mm_channel_is_hidden(MattermostAccount *ma, const gchar *id) 
{
	GList *prefs;

	for(prefs=ma->user_prefs; prefs != NULL; prefs = g_list_next(prefs)) {
		MattermostUserPref *pref = prefs->data;
		if(purple_strequal(pref->name,id)) {
			if(purple_strequal(pref->category,"direct_channel_show") || purple_strequal(pref->category,"group_channel_show")) {
				if(purple_strequal(pref->value,"false")) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

static void
mm_get_open_channels_for_team_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *team_id = user_data;
	//gboolean first_team = FALSE;

	//if (purple_strequal(mm_get_first_team_id(ma),team_id)) first_team = TRUE;
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost channels"),TRUE)) return;

	JsonArray *channels = json_node_get_array(node);
	guint i, len = json_array_get_length(channels);
	GList *mm_users = NULL;
	GList *mm_channels = NULL;
	GList *j = NULL;
	GList *removenodes = NULL;
	PurpleBlistNode *bnode;

	// channels = buddies and chats 
	for (i = 0; i < len; i++) {
		MattermostChannel *mm_channel = g_new0(MattermostChannel,1);
		JsonObject *channel = json_array_get_object_element(channels, i);
		mm_channel->id = g_strdup(json_object_get_string_member(channel, "id"));
		mm_channel->display_name = g_strdup(json_object_get_string_member(channel, "display_name"));
		mm_channel->type = g_strdup(json_object_get_string_member(channel, "type"));
		mm_channel->creator_id = g_strdup(json_object_get_string_member(channel, "creator_id"));
		mm_channel->channel_approximate_view_time = mm_find_channel_approximate_view_time(ma, mm_channel->id);

		const gchar *name = json_object_get_string_member(channel, "name");

		if (mm_channel->type && *(mm_channel->type) == MATTERMOST_CHANNEL_DIRECT) {
			MattermostUser *mm_user = g_new0(MattermostUser, 1);
			gchar **names = g_strsplit(name, "__", 2);
			mm_user->user_id = g_strdup(purple_strequal(names[0], ma->self->user_id) ? names[1] : names[0]);
			mm_user->room_id = g_strdup(mm_channel->id);
			g_strfreev(names);

			if (mm_channel_is_hidden(ma, mm_user->user_id)) {
				mm_g_free_mattermost_user(mm_user);
			} else {
				mm_users = g_list_prepend(mm_users, mm_user);
			}

		} else {
			// group channels do not belong to any team, avoid duplicating.
			//if (mm_channel->type && *(mm_channel->type) == MATTERMOST_CHANNEL_GROUP && !first_team) continue;
			//OK : this is done for each team now, but we get group channels below other in initial sort list. no dups.
	
			mm_channel->name=g_strdup(name);
			mm_channel->team_id = g_strdup(json_object_get_string_member(channel, "team_id")); // NULL for group channels
			if (mm_channel_is_hidden(ma, mm_channel->id)) {
				mm_g_free_mattermost_channel(mm_channel); 
			} else {
				mm_channels = g_list_prepend(mm_channels, mm_channel);
			}
		}

	}

	// remove from blist unseen buddies and chats (removed MM channels)
	for (bnode = purple_blist_get_root(); bnode != NULL; bnode = purple_blist_node_next(bnode, FALSE)) {
		MattermostChannel *tmpchannel = g_new0(MattermostChannel,1);
		MattermostUser *tmpuser = g_new0(MattermostUser,1);

		gboolean founduser, foundchannel;

		if (PURPLE_IS_CHAT(bnode) && purple_chat_get_account(PURPLE_CHAT(bnode)) == ma->account) {
			GHashTable *components = purple_chat_get_components(PURPLE_CHAT(bnode));
			tmpchannel->id = g_hash_table_lookup(components, "id");
			tmpchannel->team_id = g_hash_table_lookup(components, "team_id");
			tmpchannel->name = g_hash_table_lookup(components, "name");
			tmpchannel->type = g_hash_table_lookup(components, "type");
			tmpchannel->display_name = g_hash_table_lookup(components, "display_name");

			if(tmpchannel->team_id == NULL || purple_strequal(tmpchannel->team_id, team_id)) {
				GList *tmplist;foundchannel = FALSE;
				for(tmplist=mm_channels;tmplist != NULL; tmplist=g_list_next(tmplist)){
					MattermostChannel *tmp2channel = tmplist->data;
					if(purple_strequal(tmp2channel->id,tmpchannel->id)) {
						foundchannel = TRUE;
					}
				}
				if (!foundchannel || mm_channel_is_hidden(ma, tmpchannel->id)) {
						removenodes = g_list_prepend(removenodes, bnode);
				} 
			}

		} else if (PURPLE_IS_BUDDY(bnode) && purple_buddy_get_account(PURPLE_BUDDY(bnode)) == ma->account) {
			tmpuser->room_id = g_strdup(purple_blist_node_get_string(bnode, "room_id"));
			tmpuser->user_id = g_strdup(purple_blist_node_get_string(bnode, "user_id"));
			tmpuser->email = g_strdup(purple_blist_node_get_string(bnode, "email"));
			GList *tmplist;founduser = FALSE;
				for(tmplist=mm_users;tmplist != NULL; tmplist=g_list_next(tmplist)){
					MattermostUser *tmp2user = tmplist->data;
					if(purple_strequal(tmp2user->user_id,tmpuser->user_id)) {
						founduser = TRUE;
					}
				}
			if (!founduser || mm_channel_is_hidden(ma, tmpuser->room_id)) {
				removenodes = g_list_prepend(removenodes, bnode);
			}	
		}
		g_free(tmpchannel);
		g_free(tmpuser);
	}

	//TODO: use mm_remove_blist_by_id here.
	for (j = removenodes; j != NULL; j = j->next) {
		if (PURPLE_IS_CHAT(j->data)) {
			purple_blist_remove_chat(PURPLE_CHAT(j->data));
		} else if (PURPLE_IS_BUDDY(j->data)) {
			purple_blist_remove_buddy(PURPLE_BUDDY(j->data));
		}
	}
	g_list_free(removenodes);

	//gboolean autojoin = purple_account_get_bool(ma->account, "use-autojoin", FALSE);


	mm_channels = g_list_sort(mm_channels, mm_compare_channels_by_display_name_int);
	mm_channels = g_list_sort(mm_channels, mm_compare_channels_by_type_int);

	for (j = mm_channels; j != NULL; j=j->next) {
		MattermostChannel *channel = j->data;
		mm_set_group_chat(ma, channel->team_id, channel->name, channel->id);

		PurpleChat *chat = mm_purple_blist_find_chat(ma, channel->id); 
 
		if (chat == NULL) {
			GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

			const gchar *alias;
			g_hash_table_insert(defaults, "team_id", g_strdup(channel->team_id));
			g_hash_table_insert(defaults, "id", g_strdup(channel->id));
			g_hash_table_insert(defaults, "creator_id", g_strdup(channel->creator_id));
			g_hash_table_insert(defaults, "type", g_strdup(channel->type));
			g_hash_table_insert(defaults, "display_name", g_strdup(channel->display_name));

			alias = mm_get_chat_alias(ma,channel);

			if (channel->type && *(channel->type) != MATTERMOST_CHANNEL_GROUP) {
				g_hash_table_insert(defaults, "name", g_strconcat(channel->name, MATTERMOST_CHANNEL_SEPARATOR, g_hash_table_lookup(ma->teams, channel->team_id), NULL));
			} else {
				g_hash_table_insert(defaults, "name", g_strdup(channel->name));
			}

			//g_hash_table_insert(defaults,"display_name",g_strdup(alias));

			chat = purple_chat_new(ma->account, alias, defaults);
			purple_blist_add_chat(chat, mm_get_or_create_default_group(), NULL);
			purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin", FALSE /*autojoin*/);
			purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-persistent", TRUE);
			purple_blist_node_set_string(PURPLE_BLIST_NODE(chat), "channel_approximate_view_time", g_strdup_printf("%" G_GINT64_FORMAT,(channel->channel_approximate_view_time)));

			purple_chat_set_alias(chat, alias);
			g_hash_table_replace(ma->group_chats, g_strdup(channel->id), g_strdup(channel->name));
			g_hash_table_replace(ma->group_chats_rev, g_strdup(channel->name), g_strdup(channel->id));
			g_hash_table_replace(ma->aliases,g_strdup(channel->id),g_strdup(alias));
			if (channel->creator_id) {
				g_hash_table_replace(ma->group_chats_creators, g_strdup(channel->id), g_strdup(channel->creator_id));
			}
		}

		const gchar *alias;
		alias = mm_get_chat_alias(ma,channel);

		g_hash_table_replace(ma->aliases,g_strdup(channel->id),g_strdup(alias));

		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel->id));

		if (chatconv || purple_blist_node_get_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin")) {

			PurpleChatConversation *conv = purple_serv_got_joined_chat(ma->pc, g_str_hash(channel->id), alias);
			purple_conversation_set_data(PURPLE_CONVERSATION(conv), "id", g_strdup(channel->id));
			purple_conversation_set_data(PURPLE_CONVERSATION(conv), "team_id", g_strdup(channel->team_id));
			purple_conversation_set_data(PURPLE_CONVERSATION(conv), "name", g_strdup(channel->name));
			purple_conversation_present(PURPLE_CONVERSATION(conv));
		}
		// already called from mm_join_chat
		if (!purple_blist_node_get_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin")) mm_get_channel_by_id(ma, channel->id);
	}

	mm_get_users_by_ids(ma,mm_users);

}

static void
mm_get_open_channels_for_team(MattermostAccount *ma, const gchar *team_id)
{
	gchar *url;

	//FIXME: v4 API bug ? 'me' instead of user_id does not work here ? ...
	url = mm_build_url(ma,"/users/%s/teams/%s/channels", ma->self->user_id, team_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_open_channels_for_team_response, g_strdup(team_id));
	g_free(url);
}

static void
mm_get_commands_for_team_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonArray *response = json_node_get_array(node);
	guint i, len = json_array_get_length(response);

	for (i = 0; i < len; i++) {
		JsonObject *command = json_array_get_object_element(response, i);
		//printf("command is:%s\n",json_object_to_string(command));
		MattermostCommand *cmd = g_new0(MattermostCommand,1);
		cmd->trigger = g_strdup(json_object_get_string_member(command,"trigger"));
		cmd->team_id = g_strdup(json_object_get_string_member(command,"team_id"));
		cmd->display_name = g_strdup(json_object_get_string_member(command,"display_name"));
		cmd->description = g_strdup(json_object_get_string_member(command,"description"));
		cmd->auto_complete_hint = g_strdup(json_object_get_string_member(command,"auto_complete_hint"));
		cmd->auto_complete_desc = g_strdup(json_object_get_string_member(command,"auto_complete_desc"));

		if (!g_list_find_custom(ma->commands,cmd,mm_compare_cmd_int)) {
			// we implement these commands ourselves.
			if (!purple_strequal(cmd->trigger,"help") && 
					!purple_strequal(cmd->trigger,"leave") &&
					!purple_strequal(cmd->trigger,"online") &&
					!purple_strequal(cmd->trigger,"away") &&
					!purple_strequal(cmd->trigger,"dnd") &&
					!purple_strequal(cmd->trigger,"offline") &&
					!purple_strequal(cmd->trigger,"logout")) {
				ma->commands=g_list_prepend(ma->commands,cmd);
				const gchar *info = g_strconcat(cmd->trigger," ",
				strlen(cmd->auto_complete_hint) ? g_strconcat(cmd->auto_complete_hint," | ",NULL) : " | ",
				strlen(cmd->auto_complete_desc) ? g_strconcat(cmd->auto_complete_desc," ",NULL) : "",
				( !strlen(cmd->auto_complete_desc) && strlen(cmd->description) ) ? g_strconcat(cmd->description," ",NULL) : " ",
				strlen(cmd->team_id) ? g_strconcat("[team only: ",g_hash_table_lookup(ma->teams, cmd->team_id),"]",NULL) : "",
				NULL);
			
				purple_cmd_register(cmd->trigger, "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command, info, NULL);
			} else {
				mm_g_free_mattermost_command(cmd);
			}
		} else {
			mm_g_free_mattermost_command(cmd);
		}
	}
	ma->commands = g_list_sort(ma->commands,mm_compare_cmd_2_int);
}


static void
mm_get_commands_for_team(MattermostAccount *ma,const gchar *team_id)
{
	gchar *url;

	url = mm_build_url(ma,"/commands?team_id=%s",team_id);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_commands_for_team_response, g_strdup(team_id));
	g_free(url);
}

void
mm_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const char *status_id = purple_status_get_id(status);
	JsonObject *data;
	gchar *setstatus; 
	gchar *postdata, *url;

	// tell MM that we are going offline but do not disconnect.
	// will stay in MM as offline until next status change.
	// when posting status changes for online for ~ 30 secs
	// then changes back again.

	if (purple_strequal(status_id, "invisible")) {
		setstatus = g_strdup("offline");
	} else {
		setstatus = g_strdup(status_id);
	}

	data = json_object_new();
	json_object_set_string_member(data, "status", setstatus);
	postdata = json_object_to_string(data);

	url = mm_build_url(ma,"/users/me/status");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_PUT, postdata, -1, NULL, NULL);
	g_free(url);
	
	g_free(postdata);
	json_object_unref(data);
	g_free(setstatus);
}

static void
mm_get_teams_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost teams"),TRUE)) { return; };

	JsonArray *teams = json_node_get_array(node);
	guint i, len = json_array_get_length(teams);

	for (i = 0; i < len; i++) {
		JsonObject *team = json_array_get_object_element(teams, i);

		const gchar *team_id = json_object_get_string_member(team, "id");
		const gchar *name = json_object_get_string_member(team, "name");
		const gchar *display_name = json_object_get_string_member(team, "display_name");

		g_hash_table_replace(ma->teams, g_strdup(team_id), g_strdup(name));
		g_hash_table_replace(ma->teams_display_names, g_strdup(team_id), g_strdup(display_name));

		mm_get_commands_for_team(ma, team_id);		
		mm_get_open_channels_for_team(ma, team_id);
	}
	purple_connection_set_state(ma->pc, PURPLE_CONNECTION_CONNECTED);

	mm_set_status(ma->account, purple_presence_get_active_status(purple_account_get_presence(ma->account)));
	ma->idle_timeout = g_timeout_add_seconds(270, mm_idle_updater_timeout, ma->pc);
}

static void
mm_get_teams(MattermostAccount *ma)
{
	gchar *url;

	url = mm_build_url(ma,"/users/me/teams"); 
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_teams_response, NULL);

	g_free(url);
}

static void
mm_info_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost user information"),TRUE)) return;

	JsonObject *user = json_node_get_object(node);

	PurpleBuddy *buddy = user_data;
	MattermostUser *mu = g_new0(MattermostUser, 1);

	mu->nickname = g_strdup(json_object_get_string_member(user, "nickname"));
	mu->first_name = g_strdup(json_object_get_string_member(user, "first_name"));
	mu->last_name = g_strdup(json_object_get_string_member(user, "last_name"));
	mu->email = g_strdup(json_object_get_string_member(user, "email"));
	mu->username = g_strdup(json_object_get_string_member(user, "username"));
	mu->user_id = g_strdup(json_object_get_string_member(user, "id"));
	mu->locale = g_strdup(json_object_get_string_member(user, "locale"));
	mu->position = g_strdup(json_object_get_string_member(user, "position"));
	mu->roles = mm_role_to_purple_flag(ma, json_object_get_string_member(user, "roles"));

	PurpleNotifyUserInfo *user_info = mm_user_info(mu);
	
	purple_notify_userinfo(ma->pc, purple_buddy_get_name(buddy), user_info, NULL, NULL);

	purple_notify_user_info_destroy(user_info);

	if (!purple_strequal(purple_buddy_get_name(buddy), ma->self->username)) {
		mm_set_user_blist(ma, mu, buddy);
	}

	mm_g_free_mattermost_user(mu);
}

void
mm_get_info(PurpleConnection *pc,const gchar *username)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, username);
	gchar *url;

	// Don't add BOT to buddies
	// hope no user account/alias ends in [BOT] ... 
	if (purple_str_has_suffix(username, MATTERMOST_BOT_LABEL)) {
		PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
		purple_notify_user_info_add_pair_plaintext(user_info,_("BOT Name"), purple_strreplace(username, MATTERMOST_BOT_LABEL, ""));
		gchar *info = g_strconcat(purple_account_get_bool(ma->account, "use-ssl", TRUE) ? "see https://" : "http://", ma->server, "/ -> team -> integrations", NULL); //We do not know which team is the BOT on.
		purple_notify_user_info_add_pair_plaintext(user_info,_("Information"), info);
		purple_notify_user_info_add_section_break(user_info);
		purple_notify_user_info_add_pair_plaintext(user_info, NULL, _("Mattermost webhook integration"));
		purple_notify_userinfo(ma->pc, username, user_info, NULL, NULL);
		purple_notify_user_info_destroy(user_info);
		g_free(info);
		return;
	}

	if (buddy == NULL) {
		buddy = purple_buddy_new(ma->account, username, NULL);
	}

	url = mm_build_url(ma,"/users/username/%s", username);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_info_response, buddy);
	g_free(url);
}

void 
mm_join_room(MattermostAccount *ma, MattermostChannel *channel)
{	
	mm_set_group_chat(ma, channel->team_id, channel->name, channel->id);
	mm_get_users_of_room(ma, channel);
}

static void 
mm_get_channel_by_id_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost channel information"),TRUE)) return;

	JsonObject *channel = json_node_get_object(node);
	const gchar *channel_id = json_object_get_string_member(channel, "id");
	const gchar *name = json_object_get_string_member(channel, "name");
	const gchar *display_name = json_object_get_string_member(channel, "display_name");
	const gchar *type = json_object_get_string_member(channel, "type");
	const gchar *creator_id = json_object_get_string_member(channel, "creator_id");
	const gchar *team_id = json_object_get_string_member(channel, "team_id");
	const gchar *header = json_object_get_string_member(channel, "header");
	const gchar *purpose = json_object_get_string_member(channel, "purpose");

	const gchar *alias;

	if (creator_id && *creator_id) {
		g_hash_table_replace(ma->group_chats_creators, g_strdup(channel_id), g_strdup(creator_id));
	}

	MattermostChannel *tmpchannel = g_new0(MattermostChannel,1);
	tmpchannel->id = g_strdup(channel_id);
	tmpchannel->display_name = g_strdup(display_name);
	tmpchannel->type = g_strdup(type);
	tmpchannel->creator_id = g_strdup(creator_id);
	tmpchannel->name = g_strdup(name);
	tmpchannel->team_id = g_strdup(team_id);

	alias = mm_get_chat_alias(ma, tmpchannel);

	if (mm_purple_blist_find_chat(ma, channel_id) == NULL) {

		PurpleChat *chat = NULL;
		GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

		g_hash_table_insert(defaults, "team_id", g_strdup(team_id));
		g_hash_table_insert(defaults, "id", g_strdup(channel_id));
		g_hash_table_insert(defaults, "type", g_strdup(type));
		g_hash_table_insert(defaults, "creator_id", g_strdup(creator_id));
		g_hash_table_insert(defaults,"display_name",g_strdup(display_name));

		if (type && *(type) != MATTERMOST_CHANNEL_GROUP) {
			g_hash_table_insert(defaults, "name", g_strconcat(name, MATTERMOST_CHANNEL_SEPARATOR, g_hash_table_lookup(ma->teams, team_id), NULL));
		} else {
			g_hash_table_insert(defaults, "name", g_strdup(name));	
		}

		chat = purple_chat_new(ma->account, alias, defaults);
		purple_blist_add_chat(chat, mm_get_or_create_default_group(), NULL);

		mm_set_group_chat(ma, team_id, name, channel_id);

		purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-persistent", TRUE);
		purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin", FALSE /*autojoin*/);

		purple_chat_set_alias(chat, alias);

	} 

	tmpchannel->channel_approximate_view_time = mm_find_channel_approximate_view_time(ma, tmpchannel->id);
	purple_chat_set_alias(mm_purple_blist_find_chat(ma, channel_id),alias);

	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(tmpchannel->id));
	if (chatconv != NULL) {
		purple_chat_conversation_set_topic(chatconv, NULL, mm_make_topic(header, purpose, purple_chat_conversation_get_topic(chatconv)));
	}

	mm_join_room(ma, tmpchannel);
}


void
mm_get_channel_by_id(MattermostAccount *ma, const gchar *channel_id)
{
	gchar *url;
	GList *tmpl;
	gboolean joined = FALSE;

	for(tmpl=ma->joined_channels;tmpl != NULL; tmpl=g_list_next(tmpl))
		if (purple_strequal(tmpl->data,channel_id)) { 
			joined = TRUE; continue;
		}

	// user list is lost when conv window is closed, we need to re-read data from MM
	// this is rather a workaround .. reimplement the workflow ? ...
	if (joined && purple_conv_chat_get_users(purple_conversations_find_chat(ma->pc, g_str_hash(channel_id))) != NULL) {
		return; } 
	if (!joined) ma->joined_channels = g_list_prepend(ma->joined_channels, g_strdup(channel_id));

	url = mm_build_url(ma,"/channels/%s",channel_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_channel_by_id_response, NULL);
	g_free(url);
}

static void mm_get_history_of_room(MattermostAccount *ma, MattermostChannel *channel, gint64 since);

static void 
mm_got_users_of_room(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostChannel *channel = user_data;
	PurpleGroup *default_group = mm_get_or_create_default_group();
	
	if (!mm_check_mattermost_response(ma,node,_("Error"),g_strconcat(_("Error getting Mattermost channel users ("),channel->display_name,")",NULL),TRUE)) {	
		channel->page_users = MATTERMOST_MAX_PAGES;
		return;
	}

	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel->id));

	GList *users_list = NULL, *flags_list = NULL;
		
	JsonArray *users = json_node_get_array(node);
	guint i, len = json_array_get_length(users);

	for (i = 0; i < len; i++) {
		JsonObject *user = json_array_get_object_element(users,i);
		const gchar *user_id = json_object_get_string_member(user, "id");
		const gchar *username = json_object_get_string_member(user, "username");
		const gchar *roles = json_object_get_string_member(user, "roles");

		if (!g_hash_table_contains(ma->ids_to_usernames, user_id)) {
			g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
			g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));
			
			if (chatconv == NULL && g_hash_table_contains(ma->one_to_ones, channel->id)) {
				//Probably a direct message, add them to the buddy list
				PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, username);
				if (buddy == NULL) {
					buddy = purple_buddy_new(ma->account, username, NULL);
					purple_blist_add_buddy(buddy, NULL, default_group, NULL);

					PurpleIMConversation *imconv = purple_conversations_find_im_with_account(username, ma->account);
					if (imconv == NULL) {
						imconv = purple_im_conversation_new(ma->account, username);
					}
						mm_add_buddy(ma->pc, buddy, NULL, NULL);
					}
				purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", channel->id);
			}
		}

		if (chatconv != NULL) {
			PurpleChatUserFlags flags = mm_role_to_purple_flag(ma, roles);
			if (purple_strequal(channel->creator_id, user_id)) {
				flags |= PURPLE_CHAT_USER_OP;
			}
			if (!purple_chat_conversation_has_user(chatconv,username)) {
				users_list = g_list_prepend(users_list, g_strdup(username));
				flags_list = g_list_prepend(flags_list, GINT_TO_POINTER(flags));
			}
		}
	}

	if (chatconv != NULL) {
		purple_chat_conversation_add_users(chatconv, users_list, NULL, flags_list, FALSE);
	}

	while (users_list != NULL) {
		g_free(users_list->data);
		users_list = g_list_delete_link(users_list, users_list);
	}
	g_list_free(users_list);
	g_list_free(flags_list);

	if (len == MATTERMOST_USER_PAGE_SIZE && channel->page_users < MATTERMOST_MAX_PAGES) {
		channel->page_users = channel->page_users + 1;
		mm_get_users_of_room(ma, channel);
	} else {
		channel->page_history = 0; 
		mm_get_history_of_room(ma, channel, -1);
	}
}



static void
mm_get_users_of_room(MattermostAccount *ma, MattermostChannel *channel)
{
	gchar *url;

	if (channel->page_users == MATTERMOST_MAX_PAGES) return; 

	url = mm_build_url(ma,"/users?in_channel=%s&page=%s&per_page=%s", channel->id,g_strdup_printf("%i",channel->page_users), g_strdup_printf("%i", MATTERMOST_USER_PAGE_SIZE));
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_got_users_of_room, channel);
	g_free(url);
}


static void mm_mark_room_messages_read_timeout_response(MattermostAccount *ma, JsonNode *node, gpointer user_data);

static void
mm_got_history_of_room(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostChannel *channel = user_data;

	if (!mm_check_mattermost_response(ma,node,_("Error"),g_strconcat(_("Error getting Mattermost channel history ("),channel->display_name,")",NULL),TRUE)) {	
		channel->page_history = MATTERMOST_MAX_PAGES;
		return;
	}

	JsonObject *obj = json_node_get_object(node);
	JsonObject *posts = json_object_get_object_member(obj, "posts");
	JsonArray *order = json_object_get_array_member(obj, "order");

	gint i, len = json_array_get_length(order);

	if (len > 0) {
		if (!g_hash_table_lookup(ma->one_to_ones,channel->id)) { // not one to one 
			PurpleChatConversation *chatconv=purple_conversations_find_chat(ma->pc, g_str_hash(channel->id));
			if (!chatconv) {
				PurpleChat *chat = mm_purple_blist_find_chat(ma,channel->id);
				if (chat) {
					GHashTable *components = purple_chat_get_components(chat);
					gchar *team_id = g_hash_table_lookup(components, "team_id");
					gchar *alias = g_hash_table_lookup(ma->aliases,channel->id);

					PurpleChatConversation *conv = purple_serv_got_joined_chat(ma->pc, g_str_hash(channel->id), alias);
					purple_conversation_set_data(PURPLE_CONVERSATION(conv), "id", g_strdup(channel->id));
					purple_conversation_set_data(PURPLE_CONVERSATION(conv), "team_id", g_strdup(team_id));
					purple_conversation_set_data(PURPLE_CONVERSATION(conv), "name", g_strdup(alias));
					purple_conversation_set_data(PURPLE_CONVERSATION(conv), "display_name", g_strdup(channel->display_name));
					purple_conversation_present(PURPLE_CONVERSATION(conv));

					//HERE we already went through mm_get_users_of_room but since 
					//chat window was not open, user list is empty, need to do it again
					//FIXME: this should be rewritten ...we call users read twice per channel
					channel->page_users = 0;
					mm_get_users_of_room(ma, channel);
					return;
				}
			}
		}
		// for IMCONV pidgin opens the conversation by itself.
  }


	for (i = len - 1; i >= 0; i--) {
		const gchar *post_id = json_array_get_string_element(order, i);
		JsonObject *post = json_object_get_object_member(posts, post_id);
		mm_process_room_message(ma, post, NULL);
	}

// BUG?: my mattermost server returns history unpaged, all messages 
// 'since' not respecting page size ??
//if (len == MATTERMOST_HISTORY_PAGE_SIZE && channel->page_history < MATTERMOST_MAX_PAGES) {
//		channel->page_history = channel->page_history + 1;
//
//		mm_get_history_of_room(ma, channel, -1); // FIXME: that should be parametrized !
//	} else {
		channel->page_history = MATTERMOST_MAX_PAGES;
		// history will be stored in purple log, even if channel not read now, avoid re-reading later.
		mm_mark_room_messages_read_timeout_response(ma, NULL, channel->id);

		mm_g_free_mattermost_channel(channel);
//	}
// for now we could just tell user...

}

static void
mm_get_history_of_room(MattermostAccount *ma, MattermostChannel *channel, gint64 since)
{
	gchar *url;

	if (channel->page_history == MATTERMOST_MAX_PAGES) return; 

	if (since < 0) {
		const gchar *tmptime = NULL;

		PurpleChat *chat = mm_purple_blist_find_chat(ma, channel->id);
		if (chat) {
			tmptime = purple_blist_node_get_string(PURPLE_BLIST_NODE(chat),"channel_approximate_view_time");
		} else {
			if (!channel->id) { /* printf ("NO CHANNEL ID\n");*/ return; }
			PurpleBuddy *buddy = purple_blist_find_buddy(ma->account,g_hash_table_lookup(ma->one_to_ones,channel->id));
			if (buddy) {
				tmptime = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy),"channel_approximate_view_time");
			}
		}

	if(!tmptime) {
		tmptime = g_strdup_printf("%" G_GINT64_FORMAT, (g_get_real_time() / 1000)); // now.
	}

	since = g_ascii_strtoll(tmptime, NULL, 10);
	}

	url = mm_build_url(ma,"/channels/%s/posts?page=%s&per_page=%s&since=%" G_GINT64_FORMAT "", channel->id, g_strdup_printf("%i",channel->page_history), g_strdup_printf("%i", MATTERMOST_HISTORY_PAGE_SIZE), since);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_got_history_of_room, channel);
	g_free(url);
}

static void
mm_mark_room_messages_read_timeout_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
//reply contains 'last_viewed_at_times' which does not correspond to our activity ?
//also prefs chanel_approximate_view_time is not updated ?
// do we miss something ? do we need to update this ourselves ?.. for now lets do our own timekeeping.
  gchar *channel_id = user_data;
  gint64 now = g_get_real_time()/1000;
	PurpleChat *chat = mm_purple_blist_find_chat(ma, channel_id); 
	if (chat) {
			purple_blist_node_set_string(PURPLE_BLIST_NODE(chat), "channel_approximate_view_time", g_strdup_printf("%" G_GINT64_FORMAT,now));
  } else {
    const gchar *username = g_hash_table_lookup(ma->one_to_ones,channel_id);
    if (username) {
      PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, username);
      if (buddy) {
        purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "channel_approximate_view_time", g_strdup_printf("%" G_GINT64_FORMAT,now));
      }
    }
  }
} 

static gboolean
mm_mark_room_messages_read_timeout(gpointer userdata)
{
	MattermostAccount *ma = userdata;
	JsonObject *obj;
	gchar *url;
	gchar *postdata;
	
	obj = json_object_new();
	json_object_set_string_member(obj, "channel_id", ma->current_channel_id);
	json_object_set_string_member(obj, "prev_channel_id", ma->last_channel_id);
	postdata = json_object_to_string(obj);

	//FIXME: this could be NULL on first call, but why later ? check!
	if (!ma->current_channel_id) {
		return FALSE;
	}

	g_free(ma->last_channel_id);
	ma->last_channel_id = g_strdup(ma->current_channel_id);

	url = mm_build_url(ma,"/channels/members/me/view");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_mark_room_messages_read_timeout_response, g_strdup(ma->current_channel_id));
	
	g_free(postdata);
	g_free(url);
	json_object_unref(obj);

	

	return FALSE;
}

void
mm_mark_room_messages_read(MattermostAccount *ma, const gchar *room_id)
{
	g_free(ma->current_channel_id);
	ma->current_channel_id = g_strdup(room_id);
	
	g_source_remove(ma->read_messages_timeout);
	ma->read_messages_timeout = g_timeout_add_seconds(1, mm_mark_room_messages_read_timeout, ma);
}


static void
mm_get_avatar_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		const gchar *buddy_name = user_data;
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;

		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");
		response_dup = g_memdup(response_str, response_len);

		if(purple_blist_find_buddy(ma->account, buddy_name)) {
			purple_buddy_icons_set_for_user(ma->account, buddy_name, response_dup, response_len, NULL);
		}
	}
}


static void
mm_get_avatar(MattermostAccount *ma, PurpleBuddy *buddy)
{
	gchar *url = mm_build_url(ma,"/users/%s/image", purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "user_id"));
	const gchar *buddy_name = g_strdup(purple_buddy_get_name(buddy));
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_avatar_response, (gpointer) buddy_name);
	g_free(url);
}

static void
mm_get_users_by_ids_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{

	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost users list"),TRUE)) return;

	PurpleGroup *default_group = mm_get_or_create_default_group();
	MattermostUser *mm_user = NULL;
	GList *mm_users = user_data;
	GList *i = NULL;
	JsonArray *users = json_node_get_array(node);	
	guint j, len = json_array_get_length(users);

	if (len == 0) return;

	for (i=mm_users;i;i=i->next) {
		mm_user = i->data;
		for (j = 0; j < len; j++) {
			JsonObject *user = json_array_get_object_element(users,j);
			if (g_strcmp0(mm_user->user_id,json_object_get_string_member(user,"id")) == 0){
				mm_user->username = g_strdup(json_object_get_string_member(user, "username"));
				mm_user->nickname = g_strdup(json_object_get_string_member(user, "nickname"));
				mm_user->first_name = g_strdup(json_object_get_string_member(user, "first_name"));
				mm_user->last_name = g_strdup(json_object_get_string_member(user, "last_name"));
				mm_user->email = g_strdup(json_object_get_string_member(user, "email"));
				mm_user->locale = g_strdup(json_object_get_string_member(user, "locale"));
				mm_user->position = g_strdup(json_object_get_string_member(user, "position"));
				mm_user->alias = g_strdup(mm_get_alias(mm_user));
				mm_user->channel_approximate_view_time = mm_find_channel_approximate_view_time(ma, g_hash_table_lookup(ma->one_to_ones_rev,mm_user->username));
			}
		}
	}

	mm_users = g_list_sort(mm_users, mm_compare_users_by_alias_int);

	for (i=mm_users; i; i=i->next) {

		MattermostUser *mm_user = i->data;
		PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, mm_user->username);
		if (buddy == NULL) {
			buddy = purple_buddy_new(ma->account, mm_user->username, NULL);
			purple_blist_add_buddy(buddy, NULL, default_group, NULL);
		} else {
			MattermostChannel *tmpchannel = g_new0(MattermostChannel,1);
			tmpchannel->id = g_strdup(mm_user->room_id);
			tmpchannel->page_history = 0;
			mm_get_history_of_room(ma, tmpchannel, -1);
			//FIXME: GFREE THAT !
		}

		if (mm_user->user_id && mm_user->username) {
			g_hash_table_replace(ma->ids_to_usernames, g_strdup(mm_user->user_id), g_strdup(mm_user->username));
			g_hash_table_replace(ma->usernames_to_ids, g_strdup(mm_user->username), g_strdup(mm_user->user_id));
		}

		mm_set_user_blist(ma, mm_user, buddy);

		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "user_id", mm_user->user_id);
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "channel_approximate_view_time", g_strdup_printf("%" G_GINT64_FORMAT,(mm_user->channel_approximate_view_time)));

		//this is called for new buddies or on startup: set a flag to read history from server
		purple_blist_node_set_bool(PURPLE_BLIST_NODE(buddy), "seen", FALSE);

		if(purple_account_get_bool(ma->account, "use-alias", FALSE)) {
			gchar *alias = g_strdup(mm_get_alias(mm_user));
			purple_buddy_set_local_alias(buddy, alias);
			g_free(alias);
		}

		mm_get_avatar(ma,buddy);
		mm_refresh_statuses(ma, mm_user->user_id);

	}
	g_list_free_full(user_data, mm_g_free_mattermost_user);
}



void
mm_get_users_by_ids(MattermostAccount *ma, GList *ids)
{
	GList *i;
	gchar *url, *postdata;
	MattermostUser *mm_user;

	if (ids == NULL) {
		return;
	}

	JsonArray *data = json_array_new();

	for (i = ids; i; i = i->next) {
		mm_user = i->data;
		json_array_add_string_element(data, mm_user->user_id);
	}

	postdata = json_array_to_string(data);

	url = mm_build_url(ma,"/users/ids");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_get_users_by_ids_response, ids);

	json_array_unref(data);
	g_free(postdata);
	g_free(url);
}

static void 
mm_save_user_pref_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostUserPref *pref = user_data;
	g_free(pref);
	mm_check_mattermost_response(ma,node,_("Error"),_("Error saving Mattermost user preferences"),TRUE);
}

void
mm_save_user_pref(MattermostAccount *ma, MattermostUserPref *pref)
{
	JsonArray *data = json_array_new();
	JsonObject *pref_data = json_object_new();
	gchar *postdata, *url;
	
	json_object_set_string_member(pref_data, "user_id", pref->user_id);
	json_object_set_string_member(pref_data, "category", pref->category);
	json_object_set_string_member(pref_data, "name", pref->name);
	json_object_set_string_member(pref_data, "value", pref->value);

	json_array_add_object_element(data,pref_data);
	postdata = json_array_to_string(data);
	
	if (purple_strequal(pref->category,"direct_channel_show") || purple_strequal(pref->category,"group_channel_show")) {
		url = mm_build_url(ma,"/users/me/preferences");
		mm_fetch_url(ma, url, MATTERMOST_HTTP_PUT, postdata, -1, mm_save_user_pref_response, pref);
	}

	g_free(postdata);
	json_array_unref(data);
}

static void
mm_get_user_prefs_response(MattermostAccount *ma, JsonNode *node, gpointer userdata)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost user preferences"),TRUE)) return;

		JsonArray *arr = json_node_get_array(node);
		GList *prefs = json_array_get_elements(arr);
		GList *i;

		g_list_free(ma->user_prefs);

		for (i = prefs; i != NULL; i = i->next) {

			JsonNode *prefnode = i->data;
			JsonObject *tmppref = json_node_get_object(prefnode);

			MattermostUserPref *pref = g_new0(MattermostUserPref,1);
			pref->user_id = g_strdup(ma->self->user_id); // not really needed
			pref->category = g_strdup(json_object_get_string_member(tmppref, "category"));
			pref->name = g_strdup(json_object_get_string_member(tmppref, "name"));
			pref->value = g_strdup(json_object_get_string_member(tmppref, "value"));
			ma->user_prefs = g_list_prepend(ma->user_prefs,pref);
		}
}


static void
mm_get_user_prefs(MattermostAccount *ma)
{
//TODO: preference categories (v5 server):
//		 direct_channel_show { name:channel_id,value:bool}
//		 group_channel_show { name:channel_id,value:bool}
//		 tutorial_step { name:user_id,value:4 }
//		 last { name:channel,value:channel_id }
//		 display_settings { name:use_military_time,value:bool}
//		 				{ name:name_format,value:username} (or?)
//		 				{ name:selected_font,value:Open Sans} (or?)
//		 				{ name:channel_display_mode,value:full} (or?}
//		 				{ name:message_display,value:compact} (or?}
//		 				{.name:collapse_previews,value:bool}
//		 channel_approximate_view_time { name:channel_id,value:unixseconds}
//		 channel_open_time { name:channel_id,value:unixseconds}

	gchar *url;
	url = mm_build_url(ma,"/users/me/preferences");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_user_prefs_response, NULL);
	g_free(url);

}

static void
mm_get_client_config_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost client configuration"),TRUE)) return;

	JsonObject *response = json_node_get_object(node);

	if (json_object_get_string_member(response,"EnablePublicLink"), "true") {
		ma->client_config->public_link = TRUE; 
	} else {
		ma->client_config->public_link = FALSE;
	}

	if (json_object_get_string_member(response,"EnableCommands"), "true") {
		ma->client_config->enable_commands = TRUE;
	} else {
		ma->client_config->enable_commands = FALSE;
	}

	ma->client_config->site_name = g_strdup(json_object_get_string_member(response,"SiteName"));
	ma->client_config->support_email = g_strdup(json_object_get_string_member(response,"SupportEmail"));
	ma->client_config->server_version = g_strdup(json_object_get_string_member(response,"Version"));
	ma->client_config->site_url = g_strdup(json_object_get_string_member(response,"SiteURL"));
	ma->client_config->report_a_problem_link = g_strdup(json_object_get_string_member(response,"ReportAProblemLink"));
	ma->client_config->build_number = g_strdup(json_object_get_string_member(response,"BuildNumber"));
	ma->client_config->build_hash = g_strdup(json_object_get_string_member(response,"BuildHash"));
	ma->client_config->build_date = g_strdup(json_object_get_string_member(response,"BuildDate"));
	ma->client_config->enterprise_ready = g_strdup(json_object_get_string_member(response,"BuildEnterpriseReady"));
}

static void
mm_get_client_config(MattermostAccount *ma)
{
	gchar *url;
	//NOTE: MM 5.3 still does not implement 'new' format.
	url = mm_build_url(ma,"/config/client?format=old");

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_client_config_response, NULL);
	g_free(url);
}


static MattermostUser *
mm_user_from_json(MattermostAccount *ma, JsonObject *user)
{
	MattermostUser *mu = g_new0(MattermostUser, 1);	

	mu->user_id = g_strdup(json_object_get_string_member(user, "id"));
	mu->username = g_strdup(json_object_get_string_member(user, "username"));
	mu->first_name = g_strdup(json_object_get_string_member(user, "first_name"));
	mu->last_name = g_strdup(json_object_get_string_member(user, "last_name"));
	mu->nickname = g_strdup(json_object_get_string_member(user, "nickname"));
	mu->email = g_strdup(json_object_get_string_member(user, "email"));
	mu->position = g_strdup(json_object_get_string_member(user, "position"));
	mu->locale = g_strdup(json_object_get_string_member(user, "locale"));
	mu->alias = g_strdup(mm_get_alias(mu));
	mu->roles = mm_role_to_purple_flag(ma, json_object_get_string_member(user, "roles"));

	return mu;
}

static void 
mm_set_me(MattermostAccount *ma)
{
	if (!purple_account_get_private_alias(ma->account)) {
		purple_account_set_private_alias(ma->account, ma->self->username); 
	}

	purple_connection_set_display_name(ma->pc, ma->self->username);
	
	g_hash_table_replace(ma->ids_to_usernames, g_strdup(ma->self->user_id), g_strdup(ma->self->username));
	g_hash_table_replace(ma->usernames_to_ids, g_strdup(ma->self->username), g_strdup(ma->self->user_id));

}


static void
mm_me_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response;
	gboolean gitlabauth = FALSE;

	if (node == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Invalid or expired Gitlab cookie"));
		return;
	}

	response = json_node_get_object(node);

	if (json_object_get_int_member(response, "status_code") >= 400) {
		if (purple_account_get_bool(ma->account, "use-mmauthtoken", FALSE)) {
			gitlabauth = TRUE;
		}
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, g_strconcat(json_object_get_string_member(response, "message"), gitlabauth ? _("(Invalid or expired Gitlab cookie)") : "",NULL));
		return;
	}

	mm_g_free_mattermost_user(ma->self);
	ma->self = g_new0(MattermostUser, 1);

	if (!json_object_get_string_member(response, "id") || !json_object_get_string_member(response, "username")) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("User ID/Name not received from server"));
		return;
	}
	
	ma->self = mm_user_from_json(ma, response);	
	
	JsonObject *notify_props = json_object_get_object_member(response, "notify_props");

	if (purple_strequal(json_object_get_string_member(notify_props, "all"), "true")) {
		ma->mention_words = g_list_prepend(ma->mention_words,"@all");
	}

	if (purple_strequal(json_object_get_string_member(notify_props, "channel"), "true")) {
		ma->mention_words = g_list_prepend(ma->mention_words,"@channel");
	}

	if (purple_strequal(json_object_get_string_member(notify_props, "first_name"), "true")) {
		ma->mention_words = g_list_prepend(ma->mention_words,g_strconcat("@", ma->self->first_name, NULL));
		ma->mention_words = g_list_prepend(ma->mention_words, ma->self->first_name);
	}
	
	gchar **mention_keys; 
	mention_keys = g_strsplit_set(json_object_get_string_member(notify_props, "mention_keys"), ",", -1);
	gint i;
	for (i =0 ; mention_keys[i] != NULL; i++) {
		const gchar *mkey = mention_keys[i];
		ma->mention_words=g_list_prepend(ma->mention_words, g_strdup(mkey));
		if (mkey[0] != '@') {
			ma->mention_words=g_list_prepend(ma->mention_words, g_strconcat("@", mkey, NULL));
		}	
	}
	g_strfreev(mention_keys);

	gchar *regex = g_strdup("");

	GList *j;
	for (j = ma->mention_words; j != NULL; j=j->next) {
		const gchar *tmp = j->data;
		if (j != ma->mention_words) {
			regex = g_strconcat(regex, "|", tmp, NULL);
		} else {
			regex = g_strdup(tmp);
		}
	}

	if (ma->mention_all_regex) {
		g_regex_unref(ma->mention_all_regex);
	}
	ma->mention_all_regex = g_regex_new(MATTERMOST_MENTION_ALL_MATCH, G_REGEX_CASELESS|G_REGEX_DOTALL|G_REGEX_OPTIMIZE, G_REGEX_MATCH_NOTEMPTY, NULL);

	if (ma->mention_me_regex) {
		g_regex_unref(ma->mention_me_regex);
	}

	if (!purple_strequal(regex,"")) {		
		ma->mention_me_regex = g_regex_new(MATTERMOST_MENTION_ME_MATCH(regex), G_REGEX_CASELESS|G_REGEX_DOTALL|G_REGEX_OPTIMIZE, G_REGEX_MATCH_NOTEMPTY, NULL);
	} else {
		ma->mention_me_regex = NULL;
	}

	g_free(regex);

	//TODO: get avatar ?
	mm_get_user_prefs(ma);
	mm_get_client_config(ma);
	mm_set_me(ma);
	mm_start_socket(ma);

	mm_get_teams(ma);
}

static void
mm_get_me(MattermostAccount *ma)
{
	gchar *url;
	url = mm_build_url(ma,"/users/me");

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_me_response, NULL);
	g_free(url);
}


static void
mm_purple_message_file_send(MattermostAccount *ma, MattermostFile *mmfile, const gchar *anchor, gboolean isimage)
{
	PurpleMessageFlags msg_flags = (purple_strequal(mmfile->mmchlink->sender, ma->self->username) ? PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED : PURPLE_MESSAGE_RECV);
	
	if (isimage) msg_flags |= PURPLE_MESSAGE_IMAGES;
	
	if (g_hash_table_contains(ma->group_chats, mmfile->mmchlink->channel_id)) {
		purple_serv_got_chat_in(ma->pc, g_str_hash(mmfile->mmchlink->channel_id), mmfile->mmchlink->sender, msg_flags, anchor, mmfile->mmchlink->timestamp);
	} else {
		if (msg_flags == PURPLE_MESSAGE_RECV) {
			purple_serv_got_im(ma->pc, mmfile->mmchlink->sender, anchor, msg_flags, mmfile->mmchlink->timestamp);
		} else {
			const gchar *other_user = g_hash_table_lookup(ma->one_to_ones, mmfile->mmchlink->channel_id);
			// TODO null check
			PurpleIMConversation *imconv = purple_conversations_find_im_with_account(other_user, ma->account);
			PurpleMessage *pmsg = purple_message_new_outgoing(other_user, anchor, msg_flags);
			
			if (imconv == NULL) {
				imconv = purple_im_conversation_new(ma->account, other_user);
			}
			purple_message_set_time(pmsg, mmfile->mmchlink->timestamp);
			purple_conversation_write_message(PURPLE_CONVERSATION(imconv), pmsg);
			purple_message_destroy(pmsg);
		}
	}
}

static void
mm_process_message_image_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostFile *mmfile = user_data;
	PurpleImage *image;
	guint image_id;
	gsize response_len;
	gpointer response_dup;
	const gchar *response_str;
	gchar *anchor;

	JsonObject *response = json_node_get_object(node);

	response_str = g_dataset_get_data(node, "raw_body");
	response_len = json_object_get_int_member(response,"len");
	response_dup = g_memdup(response_str, response_len);

	image = purple_image_new_from_data(response_dup,response_len);
	image_id = purple_image_store_add(image);

	if (purple_account_get_bool(ma->account,"show-full-images", FALSE)) {
		anchor = g_strdup_printf("<img id='%d' src='%s' />", image_id, mmfile->uri);
	} else {
		anchor = g_strdup_printf("<a href='%s'>%s <img id='%d' src='%s' /></a>", mmfile->uri, _("[view full image]"), image_id, mmfile->uri);
	}

	mm_purple_message_file_send(ma, mmfile, anchor, TRUE);

	g_free(anchor);
	mm_g_free_mattermost_file(mmfile);
}

static void
mm_process_message_image(MattermostAccount *ma, MattermostFile *mmfile)
{
	gchar *url;

	if (mmfile->has_preview_image) {
		url=mm_build_url(ma,"/files/%s/preview", mmfile->id);
	} else if (purple_account_get_bool(ma->account,"show-full-images", FALSE)) {
		url=mm_build_url(ma,"/files/%s" , mmfile->id);
	} else {
		url=mm_build_url(ma,"/files/%s/thumbnail" , mmfile->id);
	}

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_process_message_image_response, mmfile);
	g_free(url);
}

static void
mm_file_metadata_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{

	JsonObject *response = json_node_get_object(node);
	MattermostFile *mmfile = user_data;
	gchar *anchor = NULL;

//todo: if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost file metadata"),TRUE)) return;
	if (json_object_get_int_member(response, "status_code") >= 400) {
		anchor = g_strdup(mmfile->uri);
	} else {
		mmfile->name = g_strdup(json_object_get_string_member(response, "name"));
		mmfile->mime_type = g_strdup(json_object_get_string_member(response, "mime_type"));
		mmfile->id = g_strdup(json_object_get_string_member(response, "id"));
		if (purple_strequal(json_object_get_string_member(response, "has_preview_image"),"true")) {
			mmfile->has_preview_image = TRUE;
		} else {
			mmfile->has_preview_image = FALSE;
		}
	}

// do we really support any image type ? ...
	if (g_str_has_prefix(mmfile->mime_type,"image/") && purple_account_get_bool(ma->account, "show-images", TRUE)) {
		mm_process_message_image(ma,mmfile);
		return;
	}

	//TODO: that file can have thumbnail, display it ? ...
	if (!mmfile->uri || !ma->client_config->public_link) {
		anchor = g_strconcat("[error: public links disabled on server, cannot get file: ",mmfile->name,"]",NULL);
	} else {
		if (!anchor) anchor = g_strconcat("<a href=\"", mmfile->uri, "\">", mmfile->name, "</a>", NULL);
	}

	mm_purple_message_file_send(ma, mmfile, anchor, FALSE);
	
	mm_g_free_mattermost_file(mmfile);
	g_free(anchor);
}


static void
mm_fetch_file_link_for_channel_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostChannelLink *mmchlink = user_data;
	MattermostFile *mmfile = g_new0(MattermostFile,1);
	mmfile->uri = g_strdup(json_object_get_string_member(json_node_get_object(node),"link"));
	mmfile->mmchlink = mmchlink;

	gchar *url;

	url = mm_build_url(ma,"/files/%s/info", mmfile->mmchlink->file_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_file_metadata_response, mmfile);

	g_free(url);
}

void
mm_fetch_file_link_for_channel(MattermostAccount *ma, const gchar *file_id, const gchar *channel_id, const gchar *username, gint64 timestamp)
{
	MattermostChannelLink *info = g_new0(MattermostChannelLink, 1);
	gchar *url;

	info->channel_id = g_strdup(channel_id);
	info->file_id = g_strdup(file_id);
	info->sender = g_strdup(username);
	info->timestamp = timestamp;

	url = mm_build_url(ma,"/files/%s/link", file_id);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_fetch_file_link_for_channel_response, info);

	g_free(url);
}

static void
mm_roomlist_get_list_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{

#define _MAX_COLS 33

	MatterMostTeamRoomlist *mmtrl = user_data;
	PurpleRoomlist *roomlist = mmtrl->roomlist;
	JsonArray *channels = json_node_get_array(node);
	guint i, len = json_array_get_length(channels);
	PurpleRoomlistRoom *team_category = NULL;
	const gchar *team_id = mmtrl->team_id;
	const gchar *team_name;

	team_name = g_strconcat(g_hash_table_lookup(ma->teams_display_names, team_id), " ", mmtrl->team_desc, NULL);

	team_category = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, team_name, NULL);
	purple_roomlist_room_add_field(roomlist, team_category, team_id);
	purple_roomlist_room_add(roomlist, team_category);

	for (i = 0; i < len; i++) {
		JsonObject *channel = json_array_get_object_element(channels, i);
		const gchar *room_type = json_object_get_string_member(channel, "type");

		if (*room_type == MATTERMOST_CHANNEL_DIRECT) {
			continue; // these are buddies - dont show empty 'rooms' in room list 
		}

		const gchar *id = json_object_get_string_member(channel, "id");
		const gchar *display_name = json_object_get_string_member(channel, "display_name");
		const gchar *name = json_object_get_string_member(channel, "name");
		const gchar *header = json_object_get_string_member(channel, "header");
		const gchar *purpose = json_object_get_string_member(channel, "purpose");
		const gchar *team_id = json_object_get_string_member(channel, "team_id");

		//FIXME: in v4 api team_id is NULL for group chats, that breaks the code in many places.
		//       should be rewritten.

		//if (team_id == NULL || strlen(team_id) == 0) {
		//	team_id = mm_get_first_team_id(ma);
		//}

		const gchar *team_name = g_hash_table_lookup(ma->teams, team_id);

		PurpleRoomlistRoom *room;
		const gchar *type_str;
		gchar *tmp_h = strlen(header) > _MAX_COLS ? g_strdup_printf("%.*s...", _MAX_COLS-3, header) : NULL;
		gchar *tmp_p = strlen(purpose) > _MAX_COLS ? g_strdup_printf("%.*s...", _MAX_COLS-3, purpose) : NULL;
		
		switch(*room_type) {
			case MATTERMOST_CHANNEL_OPEN: type_str = _("Open"); break;
			case MATTERMOST_CHANNEL_PRIVATE: type_str = _("Private"); break;
			case MATTERMOST_CHANNEL_GROUP: type_str = _("Group"); break;
			default:  type_str = _("Unknown"); break;
		}

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, name, team_category);

		purple_roomlist_room_add_field(roomlist, room, id);
		purple_roomlist_room_add_field(roomlist, room, team_id);
		purple_roomlist_room_add_field(roomlist, room, team_name);
		purple_roomlist_room_add_field(roomlist, room, name);
		purple_roomlist_room_add_field(roomlist, room, display_name);
		purple_roomlist_room_add_field(roomlist, room, type_str);
		purple_roomlist_room_add_field(roomlist, room, tmp_h ? tmp_h : header);
		purple_roomlist_room_add_field(roomlist, room, tmp_p ? tmp_p : purpose);

		purple_roomlist_room_add(roomlist, room);
		
		mm_set_group_chat(ma, team_id, name, id);//ALIAS ???
		
		g_hash_table_replace(ma->channel_teams, g_strdup(id), g_strdup(team_id));

		g_free(tmp_h);
		g_free(tmp_p);
	}

	//Only after last team
	ma->roomlist_team_count--;
	if (ma->roomlist_team_count <= 0) {
		purple_roomlist_set_in_progress(roomlist, FALSE);
		ma->roomlist_team_count = 0;
	}
	
	g_free(mmtrl->team_id);
	g_free(mmtrl->team_desc);
	g_free(mmtrl);

#undef _MAX_COLS
}


PurpleRoomlist *
mm_roomlist_get_list(PurpleConnection *pc)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;
	gchar *url;
	GList *teams, *i;

	roomlist = purple_roomlist_new(ma->account);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("ID"), "id", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Team ID"), "team_id", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Team Name"), "team_name", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Name"), "name", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Display Name"), "display_name", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Type"), "type", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Header"), "header", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Purpose"), "purpose", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);
	
	//Loop through teams and look for channels within each
	for(i = teams = g_hash_table_get_keys(ma->teams); i; i = i->next)
	{
		MatterMostTeamRoomlist *mmtrl;
		const gchar *team_id = i->data;

		ma->roomlist_team_count++;

		// Get a list of public channels the user has *not* yet joined
		mmtrl = g_new0(MatterMostTeamRoomlist, 1);
		mmtrl->team_id = g_strdup(team_id);
		mmtrl->team_desc = g_strdup(_(": More public channels"));
		mmtrl->roomlist = roomlist;
		url = mm_build_url(ma,"/teams/%s/channels", team_id); 
		mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_roomlist_get_list_response, mmtrl);
		g_free(url);
		
		ma->roomlist_team_count++;
	}
	
	return roomlist;
}

static void
mm_slash_command_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *cmd = user_data;
	mm_check_mattermost_response(ma,node,_("Error"),g_strconcat(_("Error executing Mattermost Slash Command (/"),cmd,")",NULL),TRUE);
}


PurpleCmdRet
mm_slash_command(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer userdata)
{
	PurpleConnection *pc = NULL;
	MattermostAccount *ma = NULL;
	const gchar *channel_id = NULL;
	JsonObject *data;
	gchar *postdata;
	gchar *url;
	gchar *params_str, *command;
	
	pc = purple_conversation_get_connection(conv);
	if (pc == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}
	ma = purple_connection_get_protocol_data(pc);
	if (ma == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}
	
	channel_id = purple_conversation_get_data(conv, "id");
	if (channel_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			channel_id = g_hash_table_lookup(ma->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			channel_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ma->group_chats_rev, channel_id)) {
				// Convert friendly name into id
				channel_id = g_hash_table_lookup(ma->group_chats_rev, channel_id);
			}
		}
	}
	if (channel_id == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}

	if (PURPLE_IS_IM_CONVERSATION(conv)) {
		purple_notify_error(pc, _("Error"), _("Not implemented."), 
														_("Slash commands not implemented (yet) for private channels."), purple_request_cpar_from_connection(pc));
		return PURPLE_CMD_RET_FAILED;
	}

	if (!ma->client_config->enable_commands) {
		purple_notify_error(pc, _("Error"), _("Custom Slash Commands are disabled on Mattermost server"), 
														_("(See: https://docs.mattermost.com/administration/config-settings.html#integrations)"), purple_request_cpar_from_connection(pc));
		return PURPLE_CMD_RET_FAILED;
	}

	params_str = g_strjoinv(" ", args);
	command = g_strconcat("/", cmd, " ", params_str ? params_str : "", NULL);

	g_free(params_str);

	data = json_object_new();
	json_object_set_string_member(data, "command", command);
	json_object_set_string_member(data, "channel_id", channel_id);
	postdata = json_object_to_string(data);

	url = mm_build_url(ma,"/commands/execute");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_slash_command_response, g_strdup(cmd));
	g_free(url);

	g_free(postdata);
	json_object_unref(data);

	return PURPLE_CMD_RET_OK;
}


static void 
mm_create_direct_channel_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	const gchar *user_id = user_data;
	JsonObject *response = json_node_get_object(node);
	const gchar *room_id;

	if (json_object_get_int_member(response, "status_code") >= 400) {
		purple_notify_error(ma->pc, _("Error"), _("Error creating Mattermost Channel"), json_object_get_string_member(response, "message"), purple_request_cpar_from_connection(ma->pc));
		return;
	}

	room_id = json_object_get_string_member(response, "id");

	if (room_id == NULL) {
		return;
	}

	PurpleBlistNode *bnode;
	gboolean found = FALSE;
	for (bnode = purple_blist_get_root(); bnode != NULL && !found; bnode = purple_blist_node_next(bnode, TRUE)) {
		if (!PURPLE_IS_BUDDY(bnode)) { continue; }
		if (purple_strequal(purple_blist_node_get_string(bnode, "user_id"), user_id)) {
			purple_blist_node_set_string(bnode, "room_id", room_id);
			found = TRUE;
		} 
	}
}

static void
mm_create_direct_channel(MattermostAccount *ma, PurpleBuddy *buddy) 
{
	gchar *url, *postdata;
	const gchar *user_id;
	JsonArray *data;

	if (purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "room_id")) {
		return;
	}

	data = json_array_new();

	user_id = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "user_id");
	json_array_add_string_element(data, user_id);
	json_array_add_string_element(data, ma->self->user_id);

	postdata = json_array_to_string(data);
	url = mm_build_url(ma,"/channels/direct");

	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_create_direct_channel_response, g_strdup(user_id));

	g_free(url);
	json_array_unref(data);
}

static void
mm_search_results_add_buddy(PurpleConnection *pc, GList *row, void *user_data)
{
	PurpleAccount *account = purple_connection_get_account(pc);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	gboolean usealias = FALSE;

	MattermostUser *mm_user=g_new0(MattermostUser,1);
	mm_user->username = g_strdup(g_list_nth_data(row, 0));
	mm_user->first_name = g_strdup(g_list_nth_data(row, 1));
	mm_user->last_name = g_strdup(g_list_nth_data(row, 2));
	mm_user->nickname = g_strdup(g_list_nth_data(row, 3));
	mm_user->email = g_strdup(g_list_nth_data(row, 4));
	mm_user->alias = g_strdup(mm_get_alias(mm_user));

	if (purple_account_get_bool(ma->account, "use-alias", FALSE)) {
		usealias = TRUE;
	} 

	if (!purple_blist_find_buddy(account, mm_user->username)) {
		purple_blist_request_add_buddy(account, mm_user->username, MATTERMOST_DEFAULT_BLIST_GROUP_NAME, usealias ? mm_user->alias : NULL); //NO room_id
		//TODO: get info here to fill in all buddy data ?
	}
	mm_g_free_mattermost_user(mm_user);
}

static void
mm_search_results_send_im(PurpleConnection *pc, GList *row, void *user_data)
{
	PurpleAccount *account = purple_connection_get_account(pc);
	const gchar *who = g_list_nth_data(row, 0);
	PurpleIMConversation *imconv;

	imconv = purple_conversations_find_im_with_account(who, account);
	if (imconv == NULL) {
		imconv = purple_im_conversation_new(account, who);
	}
	purple_conversation_present(PURPLE_CONVERSATION(imconv));
}


static void
mm_search_users_text_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *search_term = user_data;
	GList *users, *i;
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;

	// api docs says this should be an object response, but the api returns an array (v3?)
	if (json_node_get_node_type(node) == JSON_NODE_OBJECT) {
		JsonObject *obj = json_node_get_object(node);
		if (json_object_has_member(obj, "status_code")) {
			purple_notify_error(ma->pc, _("Search Error"), _("There was an error searching for the user"), json_object_get_string_member(obj, "message"), purple_request_cpar_from_connection(ma->pc));
			return;
		}

		users = json_object_get_values(obj);
	} else {
		JsonArray *arr = json_node_get_array(node);

		users = json_array_get_elements(arr);
	}

	if (users == NULL) {
		gchar *primary_text = g_strdup_printf(_("Your search for the user \"%s\" returned no results"), search_term);
		purple_notify_warning(ma->pc, _("No users found"), primary_text, "", purple_request_cpar_from_connection(ma->pc));
		g_free(primary_text);

		g_free(search_term);
		return;
	}

	results = purple_notify_searchresults_new();
	if (results == NULL)
	{
		g_list_free(users);
		// This UI can't show search results
		return;
	}

	/* columns: username, First Name, Last Name, Nickname, Email */
	column = purple_notify_searchresults_column_new(_("Username"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("First Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Last Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Nickname"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Email"));
	purple_notify_searchresults_column_add(results, column);

	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD, mm_search_results_add_buddy);
	//purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_INFO, mm_search_results_get_info);
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_IM, mm_search_results_send_im);

	for (i = users; i; i = i->next) {
		JsonNode *usernode = i->data;
		JsonObject *user = json_node_get_object(usernode);
		const gchar *username = json_object_get_string_member(user, "username");

		GList *row = NULL;

		row = g_list_append(row, g_strdup(username));
		row = g_list_append(row, g_strdup(json_object_get_string_member(user, "first_name")));
		row = g_list_append(row, g_strdup(json_object_get_string_member(user, "last_name")));
		row = g_list_append(row, g_strdup(json_object_get_string_member(user, "nickname")));
		row = g_list_append(row, g_strdup(json_object_get_string_member(user, "email")));

		purple_notify_searchresults_row_add(results, row);

		if (!g_hash_table_contains(ma->usernames_to_ids, username)) {
			const gchar *id = json_object_get_string_member(user, "id");
			g_hash_table_replace(ma->ids_to_usernames, g_strdup(id), g_strdup(username));
			g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(id));
		}
	}

	purple_notify_searchresults(ma->pc, NULL, search_term, NULL, results, NULL, NULL);

	g_list_free(users);
	g_free(search_term);
}


void
mm_search_users_text(MattermostAccount *ma, const gchar *text)
{
	JsonObject *obj = json_object_new();
	gchar *url;
	gchar *postdata;
	
	json_object_set_string_member(obj, "term", text);
	json_object_set_boolean_member(obj, "allow_inactive", TRUE);
	json_object_set_boolean_member(obj, "without_team", TRUE);

	postdata = json_object_to_string(obj);

	url = mm_build_url(ma,"/users/search");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_search_users_text_response, g_strdup(text));
	g_free(url);

	g_free(postdata);
	json_object_unref(obj);
}
//TODO: integrate with mm_get_users_by_ids() ?
static void
mm_add_buddy_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *user = json_node_get_object(node);
	PurpleBuddy *buddy = user_data;

	if (json_object_has_member(user, "status_code")) {
		// There was an error in the response, which generally means the buddy is invalid somehow
		const gchar *buddy_name = purple_buddy_get_name(buddy);
		PurpleIMConversation *imconv = purple_conversations_find_im_with_account(buddy_name, ma->account);
		
		if (imconv != NULL) {
			PurpleConversation *conv = PURPLE_CONVERSATION(imconv);
			purple_conversation_write_system_message(conv, _("Cannot sent message, invalid buddy"), PURPLE_MESSAGE_ERROR);
		} else {
			purple_notify_error(ma->pc, _("Add Buddy Error"), _("There was an error searching for the user"), json_object_get_string_member(user, "message"), purple_request_cpar_from_connection(ma->pc));
		}

		// bad user, delete
		purple_blist_remove_buddy(buddy);
		return;
	}

	MattermostUser *mm_user = mm_user_from_json(ma, user);

	g_hash_table_replace(ma->ids_to_usernames, g_strdup(mm_user->user_id), g_strdup(mm_user->username));
	g_hash_table_replace(ma->usernames_to_ids, g_strdup(mm_user->username), g_strdup(mm_user->user_id));

	mm_add_buddy(ma->pc, buddy, NULL, NULL);

	if (purple_account_get_bool(ma->account,"use-alias", FALSE)) {	
		purple_buddy_set_local_alias(buddy, mm_user->alias);
	}

	mm_g_free_mattermost_user(mm_user);
}


void
mm_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	const gchar *user_id = g_hash_table_lookup(ma->usernames_to_ids, buddy_name);

	if (purple_strequal(user_id,ma->self->user_id)) {
		purple_blist_remove_buddy(buddy);	
		return;
	}

	if (purple_str_has_suffix(buddy_name, MATTERMOST_BOT_LABEL)) {
		purple_blist_remove_buddy(buddy);
		return;
	}

	if (user_id == NULL) {
		gchar *url;

		//Search for user
		// if they've entered what we think is a username, sanitise it
		if (!strchr(buddy_name, ' ') && !strchr(buddy_name, '@')) {
			url = mm_build_url(ma,"/users/username/%s", buddy_name);
			mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_add_buddy_response, buddy);
			g_free(url);
		} else {
			// Doesn't look like a username, do a search
			mm_search_users_text(ma, buddy_name);
			purple_blist_remove_buddy(buddy);
		}

		return;
	}

	purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "user_id", user_id);

	mm_get_avatar(ma,buddy);

	mm_create_direct_channel(ma, buddy);

	MattermostUserPref *pref = g_new0(MattermostUserPref,1);
	pref->user_id = g_strdup(ma->self->user_id);
	pref->category = g_strdup("direct_channel_show");
	pref->name = g_strdup(user_id);
	pref->value = g_strdup("true");
	mm_save_user_pref(ma,pref);
	// free pref in callback

	mm_refresh_statuses(ma, user_id);
}

//FIXME: check server reply !
void
mm_chat_set_header_purpose(PurpleConnection *pc, int id, const char *topic, const gboolean isheader)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	JsonObject *data;
	gchar *postdata;
	gchar *url;
	const gchar *channel_id;

	chatconv = purple_conversations_find_chat(pc, id);
	if (chatconv == NULL) return;

	channel_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");

	data = json_object_new();
	json_object_set_string_member(data, "id", channel_id);

	if (isheader) {
		json_object_set_string_member(data, "header", topic);
	} else {
		json_object_set_string_member(data, "purpose", topic);
	}

	url = mm_build_url(ma,"/channels/%s", channel_id);

	postdata = json_object_to_string(data);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_PUT, postdata, -1, NULL, NULL);
	
	g_free(postdata);
	g_free(url);
}

static void
mm_coversation_send_image_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	const gchar *channel_id = user_data;

	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error uploading image file"),TRUE)) return;

	JsonObject *response = json_node_get_object(node);
	JsonArray *file_infos = json_object_get_array_member(response,"file_infos");
	guint i, len = json_array_get_length(file_infos);
	for (i=0; i < len ; i++) {
		JsonObject *file_info = json_node_get_object(json_array_get_element(file_infos, i));
		const gchar *file_id = json_object_get_string_member(file_info,"id");

		GList *file_ids = NULL;
		file_ids = g_list_append(file_ids,g_strdup(file_id));
		mm_conversation_send_message(ma, NULL, channel_id, "", file_ids);
	}
}
static void
mm_conversation_send_image(MattermostAccount *ma,const gchar *channel_id, PurpleImage *image)
{
	gchar *url, *postdata;
	const gchar *filename = purple_image_get_path(image);

	postdata = g_memdup(purple_image_get_data(image),purple_image_get_size(image));

	url = mm_build_url(ma,"/files?channel_id=%s&filename=%s",channel_id,filename);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, purple_image_get_size(image), mm_coversation_send_image_response, g_strdup(channel_id));

	g_free(url);
	g_free(postdata);
}

//FIXME: check server reply !
void
mm_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	const gchar *user_id;
	JsonObject *data;
	gchar *postdata;
	gchar *url;
	const gchar *channel_id;

	chatconv = purple_conversations_find_chat(pc, id);
	if (chatconv == NULL) {
		return;
	}

	channel_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (channel_id == NULL) {
		channel_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}

	user_id = g_hash_table_lookup(ma->usernames_to_ids, who);
	if (user_id == NULL) {
		//TODO search for user
		
		//  /users/search
		
		//"term", buddy_name
		//"allow_inactive", TRUE
		
		return;
	}

	data = json_object_new();
	json_object_set_string_member(data, "user_id", user_id);

	postdata = json_object_to_string(data);

	url = mm_build_url(ma,"/channels/%s/members", channel_id);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, NULL, NULL);

	g_free(postdata);
	g_free(url);
}

static void
mm_login_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response;

	if (node == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Bad username/password"));
		return;
	}
	
	response = json_node_get_object(node);
	
	if (g_hash_table_contains(ma->cookie_table, "MMAUTHTOKEN")) {
		g_free(ma->session_token);
		ma->session_token = g_strdup(g_hash_table_lookup(ma->cookie_table, "MMAUTHTOKEN"));
	} else if (json_object_has_member(response, "body")) {
		// Uh oh, error
		gchar *stripped = purple_markup_strip_html(json_object_get_string_member(response, "body"));
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, stripped);
		g_free(stripped);
		return;
	}
	
	if (json_object_get_int_member(response, "status_code") >= 400) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, json_object_get_string_member(response, "message"));
		return;
	}
	
	if (!json_object_get_string_member(response, "id") || !json_object_get_string_member(response, "username")) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("User ID/Name not received from server"));
		return;
	}

	mm_get_me(ma);
}

static void
mm_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type)
{
	PurpleConnection *pc;
	MattermostAccount *ma;
	const gchar *room_id;

	if (type != PURPLE_CONVERSATION_UPDATE_UNSEEN)
		return;

	pc = purple_conversation_get_connection(conv);
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return;

	if (g_strcmp0(purple_protocol_get_id(purple_connection_get_protocol(pc)), MATTERMOST_PLUGIN_ID))
		return;

	ma = purple_connection_get_protocol_data(pc);

	room_id = purple_conversation_get_data(conv, "id");

	if (PURPLE_IS_IM_CONVERSATION(conv)) {
		room_id = g_hash_table_lookup(ma->one_to_ones_rev, purple_conversation_get_name(conv));
		// new conversation: selecting IM in chat room people list on a non-buddy
		if (room_id == NULL) {
			// name of a new IM conv. == buddy username: better way to do it ?
			const gchar *username = purple_conversation_get_name(conv);
			PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, username);
			if (buddy == NULL) {
				buddy = purple_buddy_new(ma->account, username, NULL);
				purple_blist_add_buddy(buddy, NULL, mm_get_or_create_default_group(), NULL);
				mm_add_buddy(pc, buddy, NULL, NULL);
			}
			return;
		}
	} else {
		//FIXME	room_id = g_hash_table_lookup(ma->group_chats_rev, room_id);
		//TODO:  if (room_id) == NULL - create new group chat 
	}

	g_return_if_fail(room_id != NULL);
	
	mm_mark_room_messages_read(ma, room_id);
}


static void
mm_build_groups_from_blist(MattermostAccount *ma)
{
	PurpleBlistNode *node;

	for (node = purple_blist_get_root();
		node != NULL;
		node = purple_blist_node_next(node, TRUE)) {
		if (PURPLE_IS_CHAT(node)) {
			PurpleChat *chat = PURPLE_CHAT(node);

			if (purple_chat_get_account(chat) != ma->account) {
				continue;
			}

			GHashTable *components = purple_chat_get_components(chat);

			if (components != NULL) {
				mm_set_group_chat(ma, g_hash_table_lookup(components, "team_id") , g_hash_table_lookup(components, "name"), g_hash_table_lookup(components, "id"));
			} //TODO: else { ERROR }

		} else if (PURPLE_IS_BUDDY(node)) {
			const gchar *room_id;
			const gchar *user_id;
			const gchar *username;
			PurpleBuddy *buddy = PURPLE_BUDDY(node);
			if (purple_buddy_get_account(buddy) != ma->account) {
				continue;
			}
			
			username = purple_buddy_get_name(buddy);
			room_id = purple_blist_node_get_string(node, "room_id");
			user_id = purple_blist_node_get_string(node, "user_id");
			if (room_id != NULL) {
				g_hash_table_replace(ma->one_to_ones, g_strdup(room_id), g_strdup(username));
				g_hash_table_replace(ma->one_to_ones_rev, g_strdup(username), g_strdup(room_id));
			}
			if (user_id != NULL) {
				g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
				g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));
			}
		}
	}
}

void
mm_login(PurpleAccount *account)
{
	MattermostAccount *ma;
	PurpleConnection *pc = purple_account_get_connection(account);
	gchar **userparts;
	const gchar *username = purple_account_get_username(account);
	gchar *url;
	PurpleConnectionFlags pc_flags;
	const gchar *split_string = (char[2]) {MATTERMOST_SERVER_SPLIT_CHAR, '\0'};

	pc_flags = purple_connection_get_flags(pc);
	pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
	purple_connection_set_flags(pc, pc_flags);

	ma = g_new0(MattermostAccount, 1);
	purple_connection_set_protocol_data(pc, ma);
	ma->account = account;
	ma->pc = pc;
	ma->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->seq = 1;

	if (purple_account_get_string(account, "last_message_timestamp", NULL)) {
		const gchar *last_message_timestamp_str = purple_account_get_string(account, "last_message_timestamp", NULL);
		ma->last_load_last_message_timestamp = g_ascii_strtoll(last_message_timestamp_str, NULL, 10);
	} else {
		ma->last_load_last_message_timestamp = purple_account_get_int(account, "last_message_timestamp_high", 0);
		if (ma->last_load_last_message_timestamp != 0) {
			ma->last_load_last_message_timestamp = (ma->last_load_last_message_timestamp << 32) | ((guint64) purple_account_get_int(account, "last_message_timestamp_low", 0) & 0xFFFFFFFF);
		}
	}
	if (ma->last_load_last_message_timestamp < 0) {
		ma->last_load_last_message_timestamp = 0;
	}

	ma->client_config = g_new0(MattermostClientConfig,1);
	ma->client_config->public_link = FALSE;
	ma->client_config->enable_commands = FALSE;

	ma->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->group_chats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->group_chats_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->aliases = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->group_chats_creators = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
	ma->result_callbacks = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
	ma->usernames_to_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->ids_to_usernames = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->teams = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->teams_display_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->channel_teams = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->received_message_queue = g_queue_new();

	userparts = g_strsplit(username, split_string, 2);

	if (userparts[0] == NULL) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "No username supplied");
		return;
	}
	if (userparts[1] == NULL) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "No server supplied (use username|server)");
		return;
	}

	purple_connection_set_display_name(pc, userparts[0]);
	ma->username = g_strdup(userparts[0]);
	ma->server = g_strdup(userparts[1]);
	g_strfreev(userparts);

	ma->api_endpoint = g_strdup(MATTERMOST_API_EP);

	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);

	//Build the initial hash tables from the current buddy list
	mm_build_groups_from_blist(ma);

	//TODO check for two-factor-auth
	{
		JsonObject *data = json_object_new();
		gchar *postdata;
		
		if (purple_account_get_bool(ma->account, "use-mmauthtoken", FALSE)) {
			ma->session_token = g_strdup(purple_connection_get_password(pc));

			mm_get_me(ma);

		} else {
			json_object_set_string_member(data, "login_id", ma->username);
			json_object_set_string_member(data, "password", purple_connection_get_password(pc));
			json_object_set_string_member(data, "token", ""); //TODO 2FA
			
			postdata = json_object_to_string(data);
			
			url = mm_build_url(ma,"/users/login");
			mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_login_response, NULL);
			
			g_free(postdata);
			g_free(url);
		}
		json_object_unref(data);
	}

	if (!chat_conversation_typing_signal) {
		chat_conversation_typing_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing", purple_connection_get_protocol(pc), PURPLE_CALLBACK(mm_conv_send_typing), NULL);
	}
	if (!conversation_updated_signal) {
		conversation_updated_signal = purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", purple_connection_get_protocol(pc), PURPLE_CALLBACK(mm_mark_conv_seen), NULL);
	}
}

static void
mm_created_direct_message_send(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	PurpleMessage *msg = user_data;
	JsonObject *result;
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message;
	const gchar *room_id;
	PurpleBuddy *buddy;
	
	if (node == NULL) {
		purple_conversation_present_error(who, ma->account, _("Could not create conversation"));
		purple_message_destroy(msg);
		return;
	}
	result = json_node_get_object(node);

	if (json_object_get_int_member(result, "status_code") >= 400) {
		purple_notify_error(ma->pc, _("Error"), _("Error creating Mattermost Channel"), json_object_get_string_member(result, "message"), purple_request_cpar_from_connection(ma->pc));
		return;
	}

	message = purple_message_get_contents(msg);
	room_id = json_object_get_string_member(result, "id");
	buddy = purple_blist_find_buddy(ma->account, who);

	if (room_id != NULL && who != NULL) {
		g_hash_table_replace(ma->one_to_ones, g_strdup(room_id), g_strdup(who));
		g_hash_table_replace(ma->one_to_ones_rev, g_strdup(who), g_strdup(room_id));
	}

	if (buddy != NULL) {
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", room_id);
	}
	//API: user is MM global, still need a team_id to contact, why ? ..
	mm_conversation_send_message(ma, mm_get_first_team_id(ma), room_id, message, NULL);
}


int
mm_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	gchar *room_id = g_hash_table_lookup(ma->one_to_ones_rev, who);

	//API: user is MM global, still need team_id to contact, why ? ..
	const gchar *team_id = mm_get_first_team_id(ma); 
	
	if (room_id == NULL) {

		if (purple_str_has_suffix(who, MATTERMOST_BOT_LABEL)) {
			purple_notify_error(ma->pc, _("Error"), _("You cannot send instant message to a BOT"), _("(However you may be able to interact with it using \"/cmd command\" in a chat)"), purple_request_cpar_from_connection(ma->pc));
			//TODO: 'disable' im conv window ?
			return -1;
		}

		if (purple_strequal(who, ma->self->username)) {
			purple_notify_error(ma->pc, _("Error"), _("You cannot send instant message to yourself"), "", purple_request_cpar_from_connection(ma->pc));
			//TODO: 'disable' im conv window ? 
			return -1;
		}

		JsonArray *data;
		gchar *url, *postdata;
		const gchar *user_id = g_hash_table_lookup(ma->usernames_to_ids, who);
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif

		data = json_array_new();
		json_array_add_string_element(data, user_id);
		json_array_add_string_element(data, ma->self->user_id); 

		postdata = json_array_to_string(data);
		url = mm_build_url(ma,"/channels/direct");
		mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_created_direct_message_send, msg);
		g_free(url);

		g_free(postdata);
		json_array_unref(data);

		MattermostUserPref *pref = g_new0(MattermostUserPref, 1);
		pref->user_id = g_strdup(ma->self->user_id);
		pref->category = g_strdup("direct_channel_show");
		pref->name = g_strdup(user_id);
		pref->value = g_strdup("true");

		mm_save_user_pref(ma, pref);
		// free pref in callback
		return 1;
	}
	return mm_conversation_send_message(ma, team_id, room_id, message, NULL);
}

//FIXME: check errors ?
void
mm_chat_leave(PurpleConnection *pc, int id)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const gchar *channel_id; //, *team_id;
	PurpleChatConversation *chatconv;
	gchar *url;

	chatconv = purple_conversations_find_chat(pc, id);
	if (chatconv == NULL) {
		return;
	}
	
	channel_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (channel_id == NULL) {
		channel_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}

	url = mm_build_url(ma,"/channels/%s/members/%s", channel_id, ma->self->user_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_DELETE, NULL, -1, NULL, NULL);

	g_free(url);

}

static int
mm_conversation_find_imageid(const gchar *message)
{
	const gchar *img;

	if ((img = strstr(message, "<img ")) || (img = strstr(message, "<IMG "))) {
		const gchar *id;
		const gchar *close = strchr(img, '>');

		if (((id = strstr(img, "ID=\"")) || (id = strstr(img, "id=\""))) && id < close) {
			int imgid = atoi(id + 4);
			return imgid;
		}
	}
	return 0;
}


static void
mm_conversation_send_files(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, const gchar *message)
{	
	const gchar *msgpt = message;

	msgpt = g_strstr_len(message, strlen(message), "<img");
	if (!msgpt) msgpt = g_strstr_len(message, strlen(message), "<IMG");
	while (msgpt && strlen(msgpt)) {

		int imgid = mm_conversation_find_imageid(msgpt);

		PurpleImage *image = purple_image_store_get(imgid);
		if (image) {mm_conversation_send_image(ma, channel_id, image);}

		msgpt = g_strstr_len(msgpt, strlen(msgpt), ">");
		if (msgpt != NULL) { msgpt = msgpt + 1; }
	}
}

static void
mm_conversation_send_message_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	if (json_object_get_int_member(obj, "status_code") >= 400) {
		purple_notify_error(ma->pc, _("Error"), _("Error sending Message"), json_object_get_string_member(obj, "message"), purple_request_cpar_from_connection(ma->pc));
	}
}

gint
mm_conversation_send_message(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, const gchar *message, GList *file_ids)
{
	JsonObject *data = json_object_new();
	gchar *stripped;
	gchar *_id;
	gchar *postdata;
	gchar *url;
	JsonArray *tmparr;
	GList *file_id;

	_id = g_strdup_printf("%012XFFFF", g_random_int());
	json_object_set_string_member(data, "pending_post_id", _id);
	g_hash_table_insert(ma->sent_message_ids, _id, _id);

	json_object_set_string_member(data, "channel_id", channel_id);

	stripped = mm_html_to_markdown(message);
	json_object_set_string_member(data, "message", stripped);
	g_free(stripped);

	json_object_set_string_member(data, "user_id", ma->self->user_id);
	json_object_set_int_member(data, "create_at", 0);

	tmparr = json_array_new();

	if (file_ids) {	
		for (file_id = file_ids; file_id != NULL; file_id = file_id->next) {
			json_array_add_string_element(tmparr,file_id->data);
		}
		json_object_set_array_member(data, "file_ids", tmparr); 
	}

	postdata = json_object_to_string(data);

	url = mm_build_url(ma,"/posts");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_conversation_send_message_response, NULL); //todo look at callback

	if (!file_ids) mm_conversation_send_files(ma, team_id, channel_id, message);

	json_array_unref(tmparr);
	g_free(postdata);
	g_free(url);

	return 1;
}

