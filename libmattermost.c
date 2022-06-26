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
#include <json-glib/json-glib.h>
#include "glibcompat.h"

#include <purple.h>

#include "purplecompat.h"
#include "image-store.h"
#include "image.h"
#include "libmattermost-json.h"
#include "libmattermost-markdown.h"
#include "libmattermost-helpers.h"
#include "libmattermost.h"

static gint
mm_get_next_seq(MattermostAccount *ma)
{
	return ma->seq++;
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
mm_fetch_url(MattermostAccount *ma, const gchar *url, const guint optype, const gchar *postdata, const guint postdata_size, MattermostProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	MattermostProxyConnection *conn;
	PurpleHttpConnection *http_conn;

	account = ma->account;
	if (purple_account_is_disconnected(account)) return;

	conn = g_new0(MattermostProxyConnection, 1);
	conn->ma = ma;
	conn->callback = callback;
	conn->user_data = user_data;

	purple_debug_info("mattermost", "Fetching url %s\n", url);


	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", MATTERMOST_USERAGENT);
        purple_http_request_header_set(request, "X-Requested-With", "XMLHttpRequest");
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

}

const gchar *
mm_split_topic(gchar *str)
{
	gchar *p = g_strstr_len(str, -1, MATTERMOST_CHAT_TOPIC_SEP);
	if (p == NULL) return NULL;
	*p = '\0';
	return p + strlen(MATTERMOST_CHAT_TOPIC_SEP);
}

const gchar *
mm_make_topic(const gchar *header, const gchar *purpose, const gchar *old_topic)
{
	//TODO: limit len !
	const gchar *old_purpose = mm_split_topic((gchar *)old_topic);
	const gchar *old_header = old_topic;

	const gchar *topic = g_strconcat((header && *header) ? header : old_header, MATTERMOST_CHAT_TOPIC_SEP, (purpose && *purpose) ? purpose : old_purpose, NULL);

	return topic;
}

static void
mm_send_email_cb(PurpleBuddy *buddy)
{
	PurpleBlistNode *bnode = PURPLE_BLIST_NODE(buddy);
	const gchar *email = purple_blist_node_get_string(bnode, "email");
	const gchar *first_name = purple_blist_node_get_string(bnode, "first_name");
	const gchar *last_name = purple_blist_node_get_string(bnode, "last_name");
	GString *full_email = g_string_new("mailto:");

	if (first_name) {
		g_string_append_printf(full_email, "%s ", first_name);
	}
	if (last_name) {
		g_string_append_printf(full_email, "%s ", last_name);
	}

	g_string_append_printf(full_email, "<%s>", email);

	gchar *uri = g_string_free(full_email, FALSE);
	purple_notify_uri(purple_account_get_connection(purple_buddy_get_account(buddy)), uri);
	g_free(uri);
}

static GList *
mm_buddy_menu(PurpleBuddy *buddy)
{
	GList *menu = NULL;
	if (purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "email")) {
		PurpleMenuAction *action = purple_menu_action_new(_("Email Buddy"), PURPLE_CALLBACK(mm_send_email_cb), NULL, NULL);
		menu = g_list_append(menu, action);
	}
	return menu;
}

static GList *
mm_blist_node_menu(PurpleBlistNode *node)
{
	if(PURPLE_BUDDY(node)) {
		return mm_buddy_menu((PurpleBuddy *) node);
	}
	return NULL;
}

static const gchar *
mm_get_first_team_id(MattermostAccount *ma)
{
	GList *team_ids = g_hash_table_get_keys(ma->teams);
	const gchar *first_team_id = team_ids ? team_ids->data : NULL;

	g_list_free(team_ids);

	return first_team_id;
}

static void mm_get_user_prefs(MattermostAccount *ma);

PurpleGroup* mm_get_or_create_default_group();
static void mm_get_history_of_room(MattermostAccount *ma, MattermostChannel *channel, gint64 since);

static void mm_start_socket(MattermostAccount *ma);
static void mm_socket_write_json(MattermostAccount *ma, JsonObject *data);
static void mm_get_users_by_ids(MattermostAccount *ma, GList *ids);
static void mm_get_avatar(MattermostAccount *ma, PurpleBuddy *buddy);

static void mm_join_room(MattermostAccount *ma, MattermostChannel *channel);
static PurpleChatUserFlags mm_role_to_purple_flag(MattermostAccount *ma, const gchar *rolelist);

static void mm_get_channel_by_id(MattermostAccount *ma, const gchar *team_id, const gchar *id);
static void mm_mark_room_messages_read_timeout_response(MattermostAccount *ma, JsonNode *node, gpointer user_data);
static void mm_save_user_pref(MattermostAccount *ma, MattermostUserPref *pref);
static void mm_close(PurpleConnection *pc);
const gchar *
mm_get_alias(MattermostUser *mu)
{
	gchar *nickname = NULL;
	gchar *full_name = NULL;
	gchar *alias = NULL;

	if (mu->nickname && *mu->nickname) { nickname = g_strconcat(" (",mu->nickname,")",NULL); }
	full_name = g_strconcat(mu->first_name ? mu->first_name : "", (mu->first_name && *mu->first_name) ? " " : "", mu->last_name, nickname,  NULL);
    alias = g_strdup((full_name && *full_name) ? full_name : (mu->email && *mu->email) ? mu->email : NULL);

	g_free(nickname);
	g_free(full_name);

	return alias;
}

const gchar *
mm_get_chat_alias(MattermostAccount *ma, MattermostChannel *ch)
{
	gchar *alias = NULL;
	gchar *type = NULL;

	//FIXME: redo with some pattern matching.. this is ugly.
	if (ch->type && purple_strequal(ch->type,MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_GROUP))) {
		const gchar *tmpa = g_strjoinv("", g_strsplit(ch->display_name, ma->username, -1));
		const gchar *tmpb = g_strjoinv(",", g_strsplit(tmpa,", ",-1));
		const gchar *tmpc = g_strjoinv(",", g_strsplit(tmpb,",,",-1));
		if (g_str_has_prefix(tmpc,",")) {
			alias = g_strndup(tmpc+1,strlen(tmpc));
		} else {
			alias = g_strdup(tmpc);
		}
		return alias;
	}

	type = g_strconcat((ch->type && purple_strequal(ch->type,MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_PRIVATE))) ? MATTERMOST_CHANNEL_PRIVATE_VISUAL : "", NULL);

	alias = g_strconcat(type, ch->display_name, MATTERMOST_CHANNEL_SEPARATOR_VISUAL, g_hash_table_lookup(ma->teams_display_names, ch->team_id), NULL);

	g_free(type);

	return alias;
}
static void mm_set_group_chat(MattermostAccount *ma, const gchar *team_id, const gchar *channel_name, const gchar *channel_id);

// only non-changing values are channel_id and team_id !
// name and display_name for teams and channels can change
PurpleChat *
mm_purple_blist_find_chat(MattermostAccount *ma, const gchar *channel_id)
{
	PurpleBlistNode *bnode;
	for (bnode = purple_blist_get_root(); bnode != NULL; bnode = purple_blist_node_next(bnode, FALSE)) {
		if (!PURPLE_IS_CHAT(bnode)) continue;
		if (purple_chat_get_account(PURPLE_CHAT(bnode)) != ma->account) continue;

		GHashTable *components = purple_chat_get_components(PURPLE_CHAT(bnode));

		if (purple_strequal(g_hash_table_lookup(components, "id"), channel_id)) return PURPLE_CHAT(bnode);
	}
	return NULL;
}

void
mm_purple_blist_remove_chat(MattermostAccount *ma, const gchar *channel_id)
{
	PurpleBlistNode *bnode;
	for (bnode = purple_blist_get_root(); bnode != NULL; bnode = purple_blist_node_next(bnode, FALSE)) {
		if (!PURPLE_IS_CHAT(bnode)) continue;
		if (purple_chat_get_account(PURPLE_CHAT(bnode)) != ma->account) continue;

		GHashTable *components = purple_chat_get_components(PURPLE_CHAT(bnode));

		if (purple_strequal(g_hash_table_lookup(components, "id"), channel_id)) purple_blist_remove_chat(PURPLE_CHAT(bnode));
	}
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

gboolean
mm_idle_updater_timeout(gpointer data);

void
mm_set_status(PurpleAccount *account, PurpleStatus *status);

// when Pidgin is open and a new channel is joined then add it to the blist
static void
mm_add_joined_channel_to_blist(MattermostAccount *ma, MattermostChannel *mm_channel)
{
	if (mm_channel_is_hidden(ma, mm_channel->id)) {
		mm_g_free_mattermost_channel(mm_channel);
		return;
	}

	mm_set_group_chat(ma, mm_channel->team_id, mm_channel->name, mm_channel->id);
	PurpleChat *chat = mm_purple_blist_find_chat(ma, mm_channel->id);

	if (chat == NULL) {
		GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

		const gchar *alias;
		g_hash_table_insert(defaults, "team_id", g_strdup(mm_channel->team_id));
		g_hash_table_insert(defaults, "id", g_strdup(mm_channel->id));
		g_hash_table_insert(defaults, "creator_id", g_strdup(mm_channel->creator_id));
		g_hash_table_insert(defaults, "type", g_strdup(mm_channel->type));
		g_hash_table_insert(defaults, "display_name", g_strdup(mm_channel->display_name));

		alias = mm_get_chat_alias(ma, mm_channel);

		if (mm_channel->type && *(mm_channel->type) != MATTERMOST_CHANNEL_GROUP) {
			g_hash_table_insert(defaults, "name", g_strconcat(mm_channel->name, MATTERMOST_CHANNEL_SEPARATOR, g_hash_table_lookup(ma->teams, mm_channel->team_id), NULL));
		} else {
			g_hash_table_insert(defaults, "name", g_strdup(mm_channel->name));
		}

		chat = purple_chat_new(ma->account, alias, defaults);
		purple_blist_add_chat(chat, mm_get_or_create_default_group(), NULL);
		purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin", FALSE /*autojoin*/);
		purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-persistent", TRUE);

		purple_chat_set_alias(chat, alias);
		g_hash_table_replace(ma->group_chats, g_strdup(mm_channel->id), g_strdup(mm_channel->name));
		g_hash_table_replace(ma->group_chats_rev, g_strdup(mm_channel->name), g_strdup(mm_channel->id));
		g_hash_table_replace(ma->aliases, g_strdup(mm_channel->id), g_strdup(alias));
		if (mm_channel->creator_id) {
			g_hash_table_replace(ma->group_chats_creators, g_strdup(mm_channel->id), g_strdup(mm_channel->creator_id));
		}
	}

	const gchar *alias;
	alias = mm_get_chat_alias(ma, mm_channel);

	g_hash_table_replace(ma->aliases, g_strdup(mm_channel->id), g_strdup(alias));

	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(mm_channel->id));

	if (!chatconv && !purple_blist_node_get_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin")) {
		return;
	}

	PurpleChatConversation *conv = purple_serv_got_joined_chat(ma->pc, g_str_hash(mm_channel->id), alias);
	purple_conversation_set_data(PURPLE_CONVERSATION(conv), "id", g_strdup(mm_channel->id));
	purple_conversation_set_data(PURPLE_CONVERSATION(conv), "team_id", g_strdup(mm_channel->team_id));
	purple_conversation_set_data(PURPLE_CONVERSATION(conv), "name", g_strdup(mm_channel->name));
	purple_conversation_present(PURPLE_CONVERSATION(conv));
}

static void
mm_add_channels_to_blist(MattermostAccount *ma, JsonNode *node, gpointer user_data)
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
		mm_add_joined_channel_to_blist(ma, channel);

		PurpleChat *chat = mm_purple_blist_find_chat(ma, channel->id);
		// already called from mm_join_chat
		if (!purple_blist_node_get_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin")) mm_get_channel_by_id(ma, channel->team_id, channel->id);
	}

	mm_get_users_by_ids(ma,mm_users);

        // Is this the last team we are waiting to receive channels
        // for?  If so mark the connection as connected.
        ma->groupchat_team_count --;
        if (ma->groupchat_team_count == 0) {
          purple_connection_set_state(ma->pc, PURPLE_CONNECTION_CONNECTED);
          mm_set_status(ma->account, purple_presence_get_active_status(purple_account_get_presence(ma->account)));
          ma->idle_timeout = g_timeout_add_seconds(270, mm_idle_updater_timeout, ma->pc);
        }


}

static void
mm_get_open_channels_for_team(MattermostAccount *ma, const gchar *team_id)
{
	gchar *url;

	//FIXME: v4 API bug ? 'me' instead of user_id does not work here ? ...
	url = mm_build_url(ma,"/users/%s/teams/%s/channels", ma->self->user_id, team_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_add_channels_to_blist, g_strdup(team_id));
	g_free(url);
}

gboolean mm_idle_updater_timeout(gpointer data);


void mm_set_status(PurpleAccount *account, PurpleStatus *status);

static gchar *mm_purple_flag_to_role(PurpleChatUserFlags flags);

static PurpleNotifyUserInfo *
mm_user_info(MattermostUser *mu)
{
	PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
	purple_notify_user_info_add_pair_plaintext(user_info,_("Nickname"), mu->nickname);
	purple_notify_user_info_add_pair_plaintext(user_info,_("First Name"), mu->first_name);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Last Name"), mu->last_name);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Email address"), mu->email);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Position"), mu->position);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Locale"), mu->locale);
	purple_notify_user_info_add_section_break(user_info);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Username"), mu->username);
	purple_notify_user_info_add_pair_plaintext(user_info,_("User ID"), mu->user_id);

	gchar *rolelist = mm_purple_flag_to_role(mu->roles);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Roles"), rolelist);
	g_free(rolelist);

	return user_info;
}

static void
mm_about_server(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
	purple_notify_user_info_add_pair_plaintext(user_info,_("Server Version"), ma->client_config->server_version);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Site Name"), ma->client_config->site_name);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Site URL"), ma->client_config->site_url);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Support Email"), ma->client_config->support_email);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Report Problems"), ma->client_config->report_a_problem_link);

	purple_notify_user_info_add_section_break(user_info);

	if(ma->client_config->enable_commands) {
		purple_notify_user_info_add_pair_plaintext(user_info,_("Slash commands"),_("enabled"));
	} else {
		purple_notify_user_info_add_pair_plaintext(user_info,_("Slash commands"),_("disabled"));
	}

	if(ma->client_config->public_link) {
		purple_notify_user_info_add_pair_plaintext(user_info,_("Public file links"),_("enabled"));
	} else {
		purple_notify_user_info_add_pair_plaintext(user_info,_("Public file links"),_("disabled"));
	}

	purple_notify_user_info_add_section_break(user_info);

	purple_notify_user_info_add_pair_plaintext(user_info,_("Build number"), ma->client_config->build_number);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Build hash"), ma->client_config->build_hash);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Build date"), ma->client_config->build_date);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Enterprise ready"), ma->client_config->enterprise_ready);

	purple_notify_userinfo(ma->pc, _("Mattermost Server"), user_info, NULL, NULL);

	purple_notify_user_info_destroy(user_info);
}

static void
mm_about_commands(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();
	GList *i = NULL;
	MattermostCommand *cmd = NULL;
	for(i=ma->commands;i;i=i->next) {
		cmd = i->data;
		const gchar *info = g_strconcat("/",cmd->trigger," ",
				strlen(cmd->auto_complete_hint) ? g_strconcat(cmd->auto_complete_hint," | ",NULL) : " | ",
				strlen(cmd->auto_complete_desc) ? g_strconcat(cmd->auto_complete_desc," ",NULL) : "",
				( !strlen(cmd->auto_complete_desc) && strlen(cmd->description) ) ? g_strconcat(cmd->description," ",NULL) : " ",
				strlen(cmd->team_id) ? g_strconcat("[team only: ",g_hash_table_lookup(ma->teams, cmd->team_id),"]",NULL) : "",
				NULL);

		purple_notify_user_info_add_pair_plaintext(user_info,cmd->trigger, info);
	}
	purple_notify_userinfo(ma->pc, _("Mattermost Slash Commands"), user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);
}

static void
mm_about_myself(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleNotifyUserInfo *user_info = mm_user_info(ma->self);

	purple_notify_user_info_add_section_break(user_info);

	GList *team_names = g_hash_table_get_values(ma->teams);
	GList *team_name = NULL;

	for (team_name = team_names; team_name != NULL; team_name=team_name->next) {
		purple_notify_user_info_add_pair_plaintext(user_info,_("Team"), team_name->data);
	}
	g_list_free(team_names);

	purple_notify_user_info_add_section_break(user_info);

	GString *mention_keys = g_string_new(NULL);
	GList *i;

	for (i = ma->mention_words; i != NULL; i=i->next) {
		 g_string_append(mention_keys,i->data);
		 g_string_append(mention_keys,",");
	}

	gchar *tmp = g_string_free(mention_keys, FALSE);
	purple_notify_user_info_add_pair_plaintext(user_info,_("Mention"), tmp);


	purple_notify_userinfo(ma->pc, ma->self->username, user_info, NULL, NULL);

	purple_notify_user_info_destroy(user_info);

	g_free(tmp);
}

static void
mm_got_teams(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost teams"),TRUE)) { return; };

	JsonArray *teams = json_node_get_array(node);
	guint i, len = json_array_get_length(teams);

        // Set the counter so we know how many teams to wait for
        // before marking the connection as connected.
        ma->groupchat_team_count = len;
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
}


static void
mm_set_user_blist(MattermostAccount *ma, MattermostUser *mu, PurpleBuddy *buddy)
{
	PurpleBlistNode *bnode = PURPLE_BLIST_NODE(buddy);

	purple_blist_node_set_string(bnode, "nickname", mu->nickname);
	purple_blist_node_set_string(bnode, "first_name", mu->first_name);
	purple_blist_node_set_string(bnode, "last_name", mu->last_name);

	// room_id exists only if a direct channel has been created.
	if (mu->room_id && *mu->room_id) {
		purple_blist_node_set_string(bnode, "room_id", mu->room_id);
	}

	purple_blist_node_set_string(bnode, "email", mu->email);
	purple_blist_node_set_string(bnode, "locale", mu->locale);
	purple_blist_node_set_string(bnode, "position", mu->position);
	purple_blist_node_set_int(bnode, "roles", mu->roles);

	if(purple_account_get_bool(ma->account, "use-alias", FALSE)) {
		gchar *alias = g_strdup(mm_get_alias(mu));
		purple_buddy_set_local_alias(buddy, alias);
		g_free(alias);
	}

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

static void
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

static void
mm_add_user_to_channel_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostChannel *channel = user_data;
	JsonObject *obj = json_node_get_object(node);

	if (json_object_get_int_member(obj, "status_code") >= 400) {
		purple_notify_error(ma->pc, "Error", "Error joining channel", json_object_get_string_member(obj, "message"), purple_request_cpar_from_connection(ma->pc));
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel->id));
		if (chatconv) purple_conv_chat_left(chatconv);
		return;
	}

	if (mm_purple_blist_find_chat(ma, channel->id) == NULL) {
		PurpleChat *chat = NULL;
		GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
		const gchar *alias = mm_get_chat_alias(ma, channel);

		g_hash_table_insert(defaults, "team_id", g_strdup(channel->team_id));
		g_hash_table_insert(defaults, "id", g_strdup(channel->id));
		g_hash_table_insert(defaults, "type", g_strdup(channel->type));
		g_hash_table_insert(defaults, "creator_id", g_strdup(channel->creator_id));
		g_hash_table_insert(defaults,"display_name",g_strdup(channel->display_name));

		if (channel->type && *(channel->type) != MATTERMOST_CHANNEL_GROUP) {
			g_hash_table_insert(defaults, "name", g_strconcat(channel->name, MATTERMOST_CHANNEL_SEPARATOR, g_hash_table_lookup(ma->teams, channel->team_id), NULL));
		} else {
			g_hash_table_insert(defaults, "name", g_strdup(channel->name));
		}

		chat = purple_chat_new(ma->account, alias, defaults);
		purple_blist_add_chat(chat, mm_get_or_create_default_group(), NULL);

		mm_set_group_chat(ma, channel->team_id, channel->name, channel->id);

		purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-persistent", TRUE);
		purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-autojoin", FALSE /*autojoin*/);

		purple_chat_set_alias(chat, alias);

	}
	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel->id));
	if (chatconv != NULL) {
		purple_chat_conversation_set_topic(chatconv, NULL, mm_make_topic(channel->header, channel->purpose, purple_chat_conversation_get_topic(chatconv)));
	}
	mm_join_room(ma, channel);
}

static void
mm_add_user_to_channel(MattermostAccount *ma, MattermostChannel *channel)
{
	const gchar *user_id;
	JsonObject *data;
	gchar *postdata;
	gchar *url;

	data = json_object_new();
	user_id = ma->self->user_id;
	json_object_set_string_member(data, "user_id", user_id);

	postdata = json_object_to_string(data);

	url = mm_build_url(ma,"/channels/%s/members", channel->id);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_add_user_to_channel_response, channel);

	g_free(postdata);
	g_free(url);
}

static void
mm_get_channel_by_id_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting Mattermost channel information"),TRUE)) return;

	JsonObject *channel = json_node_get_object(node);
	const gchar *id = json_object_get_string_member(channel, "id");
	const gchar *name = json_object_get_string_member(channel, "name");
	const gchar *display_name = json_object_get_string_member(channel, "display_name");
	const gchar *type = json_object_get_string_member(channel, "type");
	const gchar *creator_id = json_object_get_string_member(channel, "creator_id");
	const gchar *team_id = user_data;
	const gchar *header = json_object_get_string_member(channel, "header");
	const gchar *purpose = json_object_get_string_member(channel, "purpose");

	const gchar *alias;
	//gboolean autojoin = purple_account_get_bool(ma->account, "use-autojoin", FALSE);

	if (creator_id && *creator_id) {
		g_hash_table_replace(ma->group_chats_creators, g_strdup(id), g_strdup(creator_id));
	}

	MattermostChannel *tmpchannel = g_new0(MattermostChannel,1);
	tmpchannel->id = g_strdup(id);
	tmpchannel->display_name = g_strdup(display_name);
	tmpchannel->type = g_strdup(type);
	tmpchannel->creator_id = g_strdup(creator_id);
	tmpchannel->name = g_strdup(name);
	tmpchannel->team_id = g_strdup(team_id);
	tmpchannel->header = g_strdup(header);
	tmpchannel->purpose = g_strdup(purpose);
	tmpchannel->channel_approximate_view_time = mm_find_channel_approximate_view_time(ma, tmpchannel->id);

	alias = mm_get_chat_alias(ma, tmpchannel);

	if (mm_purple_blist_find_chat(ma, id) == NULL) {
		// user is trying to join a new channel

		// add the new channel to blist
		mm_add_joined_channel_to_blist(ma, tmpchannel);

		// add user to the channel
		mm_add_user_to_channel(ma, tmpchannel);
	} else {
		// user is already present in the channel, we just open the chat conv
		purple_chat_set_alias(mm_purple_blist_find_chat(ma, id),alias);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(tmpchannel->id));
		if (chatconv != NULL) {
			purple_chat_conversation_set_topic(chatconv, NULL, mm_make_topic(header, purpose, purple_chat_conversation_get_topic(chatconv)));
		}
		mm_join_room(ma, tmpchannel);
	}
}


static void
mm_get_channel_by_id(MattermostAccount *ma, const gchar *team_id, const gchar *id)
{
	gchar *url;
	GList *tmpl;
	gboolean joined = FALSE;

	for(tmpl=ma->joined_channels;tmpl != NULL; tmpl=g_list_next(tmpl))
		if (purple_strequal(tmpl->data,id)) {
			joined = TRUE; continue;
		}

	// user list is lost when conv window is closed, we need to re-read data from MM
	// this is rather a workaround .. reimplement the workflow ? ...
	if (joined && purple_conv_chat_get_users(purple_conversations_find_chat(ma->pc, g_str_hash(id))) != NULL) {
		return; }
	if (!joined) ma->joined_channels = g_list_prepend(ma->joined_channels, g_strdup(id));

	url = mm_build_url(ma,"/channels/%s",id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_channel_by_id_response, g_strdup(team_id));
	g_free(url);
}


static void mm_refresh_statuses(MattermostAccount *ma, const gchar *id);



static MattermostUser *mm_user_from_json(MattermostAccount *ma, JsonObject *user);

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



static void
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
mm_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	const PurplePresence *presence = purple_buddy_get_presence(buddy);

	if(purple_presence_is_online(presence)) {
		_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("Status"),NULL,purple_status_get_name(purple_presence_get_active_status(presence)));
	}

	_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("Nickname"),"nickname",NULL);
	_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("First Name"),"first_name",NULL);
	_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("Last Name"),"last_name",NULL);
	_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("Email"),"email",NULL);
	_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("Position"),"position",NULL);
	_MM_TOOLTIP_LINE_ADD(buddy,user_info,_("Locale"),"locale",NULL);

	gchar *rolelist = mm_purple_flag_to_role(purple_blist_node_get_int(PURPLE_BLIST_NODE(buddy),"roles"));
	purple_notify_user_info_add_pair_plaintext(user_info,_("Roles"), rolelist);
	g_free(rolelist);
}

static void
mm_set_group_chat(MattermostAccount *ma, const gchar *team_id, const gchar *channel_name, const gchar *channel_id)
{
	g_hash_table_replace(ma->group_chats, g_strdup(channel_id), g_strdup(channel_name));
	g_hash_table_replace(ma->group_chats_rev, g_strdup(channel_name), g_strdup(channel_id));
	if (team_id) g_hash_table_replace(ma->channel_teams, g_strdup(channel_id), g_strdup(team_id));
}

static void
mm_remove_group_chat(MattermostAccount *ma, const gchar *channel_id)
{
	if (!g_hash_table_lookup(ma->group_chats, channel_id)) return;

	g_hash_table_remove(ma->group_chats_rev, g_hash_table_lookup(ma->group_chats, channel_id));
	g_hash_table_remove(ma->group_chats, channel_id);
	g_hash_table_remove(ma->channel_teams, channel_id);
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
mm_get_teams(MattermostAccount *ma)
{
	gchar *url;

	mm_start_socket(ma);

	url = mm_build_url(ma,"/users/me/teams");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_got_teams, NULL);

	g_free(url);
}

static void
mm_save_user_pref_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostUserPref *pref = user_data;
	g_free(pref);
	mm_check_mattermost_response(ma,node,_("Error"),_("Error saving Mattermost user preferences"),TRUE);
}

static void
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


//static void mm_chat_leave(PurpleConnection *pc, int id);
/*
static void
mm_remove_blist_by_id(MattermostAccount *ma, const gchar *id)
{
	if (mm_hash_table_contains(ma->ids_to_usernames, id)) {
		const gchar *user_name = g_hash_table_lookup(ma->ids_to_usernames, id);
		PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, user_name);
		if (buddy) {
			g_hash_table_remove(ma->ids_to_usernames, id);
			g_hash_table_remove(ma->usernames_to_ids, user_name);
			purple_blist_remove_buddy(buddy);
		}
		//TODO: leave imconversation ?
	} else {
		PurpleBlistNode *node;
		gboolean found = FALSE;
		for (node = purple_blist_get_root(); node != NULL && !found; node = purple_blist_node_next(node, TRUE)) {
			if (PURPLE_IS_CHAT(node) && purple_chat_get_account(PURPLE_CHAT(node)) == ma->account &&
				purple_strequal(purple_blist_node_get_string(node, "type"), MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_GROUP))) {

				found = TRUE;
			}
		}

		if (found && PURPLE_IS_CHAT(node)) {
			purple_blist_remove_chat(PURPLE_CHAT(node));
			mm_chat_leave(ma->pc, g_str_hash(id));
		}
			//TODO: leave chatconversation ?
			// 3.0 purple_chat_conversation_leave(chatconv);
	}
}
*/

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

void
mm_get_commands_for_team(MattermostAccount *ma,const gchar *team_id)
{
	gchar *url;

	url = mm_build_url(ma,"/commands?team_id=%s",team_id);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_get_commands_for_team_response, g_strdup(team_id));
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

static void
mm_me_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response;
	gboolean gitlabauth = FALSE;

	if (node == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Bad me response"));
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
mm_login_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response;

	if (node == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Bad login response"));
		return;
	}

	response = json_node_get_object(node);

	if (mm_hash_table_contains(ma->cookie_table, "MMAUTHTOKEN")) {
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



static PurpleChatUserFlags
mm_role_to_purple_flag(MattermostAccount *ma, const gchar *rolelist)
{
	PurpleChatUserFlags flags = PURPLE_CHAT_USER_NONE;
	gchar **roles = g_strsplit_set(rolelist, " ", -1);
	gint i;

	for(i = 0; roles[i]; i++) {
		const gchar *role = roles[i];

		// we are always channel_user
		if (purple_strequal(role, "channel_admin")) {
			flags |= PURPLE_CHAT_USER_OP;
		} else if (purple_strequal(role, "system_admin")) {
			flags |= PURPLE_CHAT_USER_FOUNDER;
		}
	}

	g_strfreev(roles);

	return flags;
}

static gchar *
mm_purple_flag_to_role(PurpleChatUserFlags flags)
{
	const gchar *cu_str = _("Channel User");
	const gchar *ca_str = _("Channel Administrator");
	const gchar *sa_str = _("System Administrator");
	gboolean ca = FALSE;
	gboolean sa = FALSE;

	// we are always channel_user
	if (flags & PURPLE_CHAT_USER_OP) {
		ca = TRUE;
	}
	if (flags & PURPLE_CHAT_USER_FOUNDER) {
		sa = TRUE;
	}

	return g_strjoin(", ", cu_str, ca ? ca_str : "", sa ? sa_str : "", NULL);
}

static void
mm_purple_message_file_send(MattermostAccount *ma, MattermostFile *mmfile, const gchar *anchor, gboolean isimage)
{
	PurpleMessageFlags msg_flags = (purple_strequal(mmfile->mmchlink->sender, ma->self->username) ? PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED : PURPLE_MESSAGE_RECV);

	if (isimage) msg_flags |= PURPLE_MESSAGE_IMAGES;

	if (mm_hash_table_contains(ma->group_chats, mmfile->mmchlink->channel_id)) {
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
		// get team_id for this channel, if possible
		const gchar *team_id = NULL;
		if (mmfile->mmchlink->channel_id) {
			team_id = g_hash_table_lookup(ma->channel_teams, mmfile->mmchlink->channel_id);
		}

		// if there is no channel id or the lookup failed, use first team_id
		if (!team_id || strlen(team_id) == 0) {
			team_id = mm_get_first_team_id(ma);
		}

		const gchar *team_name = g_hash_table_lookup(ma->teams, team_id);
		gchar *link_error_str = g_strconcat("[error: public links disabled on server, cannot get file: ",mmfile->name, NULL);
		if (team_name) {
			gchar *url = g_strconcat((purple_account_get_bool(ma->account, "use-ssl", TRUE)?"https://":"http://"), ma->server,"/", team_name, "/pl/", mmfile->mmchlink->post_id, NULL);
			anchor = g_strconcat(link_error_str, ", visit ","<a href=\"", url, "\">", url, "</a> to access the file]" , NULL);
			g_free(url);
		} else {
			anchor = g_strconcat(link_error_str, "]", NULL);
		}
		g_free(link_error_str);
	} else {
		if (!anchor) anchor = g_strconcat("<a href=\"", mmfile->uri, "\">", mmfile->name, "</a>", NULL);
	}

	mm_purple_message_file_send(ma, mmfile, anchor, FALSE);

	mm_g_free_mattermost_file(mmfile);
	g_free(anchor);
}


static void
mm_fetch_file_metadata(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MattermostChannelLink *mmchlink = user_data;
	MattermostFile *mmfile = g_new0(MattermostFile,1);
	mmfile->uri = g_strdup(json_object_get_string_member(json_node_get_object(node),"link"));
	mmfile->mmchlink = mmchlink;

	gchar *url;

	url = mm_build_url(ma,"/files/%s/info", mmfile->mmchlink->file_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_file_metadata_response, mmfile);

	g_free(url);

	if (!mmfile->uri) {
		mmfile->uri = mm_build_url(ma, "/files/%s", mmfile->mmchlink->file_id);
	}
}

static void
mm_fetch_file_link_for_channel(MattermostAccount *ma, const gchar *file_id, const gchar *channel_id, const gchar *post_id, const gchar *username, gint64 timestamp)
{
	MattermostChannelLink *info = g_new0(MattermostChannelLink, 1);
	gchar *url;

	info->channel_id = g_strdup(channel_id);
	info->file_id = g_strdup(file_id);
	info->post_id = g_strdup(post_id);
	info->sender = g_strdup(username);
	info->timestamp = timestamp;

	url = mm_build_url(ma,"/files/%s/link", file_id);

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_fetch_file_metadata, info);

	g_free(url);
}

static gboolean
mm_have_seen_message_id(MattermostAccount *ma, const gchar *message_id)
{
	guint message_hash = g_str_hash(message_id);
	gpointer message_hash_ptr = GINT_TO_POINTER(message_hash);

	if (g_queue_find(ma->received_message_queue, message_hash_ptr)) {
		return TRUE;
	}

	g_queue_push_head(ma->received_message_queue, message_hash_ptr);
	g_queue_pop_nth(ma->received_message_queue, 10);

	return FALSE;
}

static void mm_mark_room_messages_read(MattermostAccount *ma, const gchar *room_id);

static gchar *mm_process_attachment(JsonObject *attachment);

static gint64
mm_process_room_message(MattermostAccount *ma, JsonObject *post, JsonObject *data)
{
	const gchar *id = json_object_get_string_member(post, "id");
	const gchar *msg_text = json_object_get_string_member(post, "message");
	const gchar *channel_id = json_object_get_string_member(post, "channel_id");
	const gchar *msg_type = json_object_get_string_member(post, "type");
	const gchar *user_id = json_object_get_string_member(post, "user_id");
	const gchar *username = json_object_get_string_member(data, "sender_name");
	const gchar *channel_type = json_object_get_string_member(data, "channel_type");
	const gchar *type = json_object_get_string_member(post, "type");
	const gchar *pending_post_id = json_object_get_string_member(post, "pending_post_id");
	JsonObject *props = json_object_get_object_member(post, "props");
	const gchar *override_username = json_object_get_string_member(props, "override_username");
	const gchar *from_webhook = json_object_get_string_member(props, "from_webhook");
	gint64 update_at = json_object_get_int_member(post, "update_at");
	gint64 timestamp = update_at / 1000;
	gchar *use_username;

	gchar *attachments = NULL;

	// Strip '@' from username
	if (username && username[0] == '@') {
		username++;
	}

	if (purple_strequal(type, "slack_attachment")) {
		JsonArray *attchs = json_object_get_array_member(props, "attachments");
		guint i, len = json_array_get_length(attchs);
		gchar *tmpa1, *tmpa2;
		for (i=0; i < len ; i++) {
			JsonObject *attch = json_node_get_object(json_array_get_element(attchs, i));
			tmpa1 = g_strdup(attachments);
			tmpa2 = mm_process_attachment(attch);
			g_free(attachments);
			if (tmpa1) {
				attachments = g_strconcat(tmpa1, tmpa2, NULL);
			} else {
				attachments = g_strdup(tmpa2);
			}
			g_free(tmpa1);
			g_free(tmpa2);
		}
	}

	// ephemeral messages have update_at:0
	if (!timestamp) {
		gint64 create_at =  json_object_get_int_member(post, "create_at");
		timestamp = create_at / 1000;
		update_at = create_at;
	}

	PurpleMessageFlags msg_flags;

	if (username != NULL && !mm_hash_table_contains(ma->ids_to_usernames, user_id)) {
		g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
		g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));
	} else if (username == NULL) {
		username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
	}

	if (purple_strequal(from_webhook, "true") && override_username && *override_username) {
		use_username = g_strconcat(override_username, MATTERMOST_BOT_LABEL, NULL);
		msg_flags = PURPLE_MESSAGE_RECV;	// user_id for BOT is webhook owner ID .. t own BOTS as such too !
	} else {
		use_username = g_strdup(username);
		msg_flags = (purple_strequal(user_id, ma->self->user_id) ? PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED : PURPLE_MESSAGE_RECV);
	}

	if (use_username == NULL) {
		//we get here when reading history of a chat
		//but have not yet read user list for the channel
		//since this calls run in parallel
		//FIXME: or not ?
		use_username=g_strdup("[unknown]");
	}

	if (!mm_hash_table_contains(ma->channel_teams, channel_id)) {
		const gchar *team_id = json_object_get_string_member(data, "team_id");
		if (team_id != NULL) {
			g_hash_table_replace(ma->channel_teams, g_strdup(channel_id), g_strdup(team_id));
		}
	}

	if (g_str_has_prefix(msg_type, "system_")) {
		msg_flags |= PURPLE_MESSAGE_SYSTEM;
	}

	if (!mm_have_seen_message_id(ma, id) || json_object_get_int_member(post, "edit_at")) {
		// Dont display duplicate messages (eg where the server inspects urls to give icons/header/content)
		//  but do display edited messages

		// check we didn't send this ourselves
		if (msg_flags == PURPLE_MESSAGE_RECV || !g_hash_table_remove(ma->sent_message_ids, pending_post_id)) {
			gchar *msg_pre = mm_markdown_to_html(ma, msg_text);
			gchar *msg_post = g_regex_replace(ma->mention_me_regex, msg_pre, -1, 0, MATTERMOST_MENTION_ME_REPLACE, G_REGEX_MATCH_NOTEMPTY, NULL);
			gchar *message = g_regex_replace(ma->mention_all_regex, msg_post, -1, 0, MATTERMOST_MENTION_ALL_REPLACE, G_REGEX_MATCH_NOTEMPTY, NULL);

			if (!purple_strequal(msg_pre, msg_post)) {
				msg_flags |= PURPLE_MESSAGE_NICK;
			}

			g_free(msg_pre);
			g_free(msg_post);

			if (json_object_get_int_member(post, "delete_at")) {
				gchar *tmp = g_strconcat(_("Deleted : "), message, NULL);
				g_free(message);
				message = tmp;
			} else if (json_object_get_int_member(post, "edit_at")) {
				gchar *tmp = g_strconcat(_("Edited : "), message, NULL);
				g_free(message);
				message = tmp;
			}

			if (json_object_has_member(post, "file_ids")) {
				JsonArray *file_ids = json_object_get_array_member(post, "file_ids");
				guint i, len = json_array_get_length(file_ids);

				// pass post_id so that permalink to the post can be displayed in case of error
				const gchar *post_id = json_object_get_string_member(post, "id");

				for (i = 0; i < len; i++) {
					const gchar *file_id = json_array_get_string_element(file_ids, i);

					mm_fetch_file_link_for_channel(ma, file_id, channel_id, post_id, use_username, timestamp);
				}
			}

//FIXME JAREK: dont know the TEAM here

			if ((channel_type != NULL && *channel_type != MATTERMOST_CHANNEL_DIRECT) || mm_hash_table_contains(ma->group_chats, channel_id)) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));

				if (chatconv) {
					if (purple_strequal(msg_type, "system_header_change") || purple_strequal(msg_type, "system_purpose_change")) {
						const gchar *new_header = json_object_get_string_member(props, "new_header");
						const gchar *new_purpose = json_object_get_string_member(props, "new_purpose");
						const gchar *new_topic_who = json_object_get_string_member(props, "username");
						purple_chat_conversation_set_topic(chatconv, new_topic_who, mm_make_topic(new_header, new_purpose, purple_chat_conversation_get_topic(chatconv)));
					}

					// Group chat message
					gchar *msg_out = g_strconcat( message ? message : " " , attachments ? attachments : NULL, NULL);
					gchar *alias = g_hash_table_lookup(ma->aliases,channel_id);

					if (alias && chatconv) {
						purple_conversation_set_name(PURPLE_CONVERSATION(chatconv),alias);
					}

					purple_serv_got_chat_in(ma->pc, g_str_hash(channel_id), use_username, msg_flags, msg_out, timestamp);

					mm_get_channel_by_id(ma, g_hash_table_lookup(ma->channel_teams, channel_id), channel_id);

					g_free(msg_out);

					if (purple_conversation_has_focus(PURPLE_CONVERSATION(chatconv))) {
						mm_mark_room_messages_read(ma, channel_id);
					}
				} //TODO: else { ERROR } - we have received a group chat message for a chat we dont know about ?
			} else {
				if (msg_flags == PURPLE_MESSAGE_RECV) {
					gchar *msg_out = g_strconcat( message ? message : " " , attachments ? attachments : NULL, NULL);
					purple_serv_got_im(ma->pc, use_username, msg_out, msg_flags, timestamp);

					g_free(msg_out);

					if (channel_type && *channel_type == MATTERMOST_CHANNEL_DIRECT && !mm_hash_table_contains(ma->one_to_ones, channel_id)) {
						g_hash_table_replace(ma->one_to_ones, g_strdup(channel_id), g_strdup(username));
						g_hash_table_replace(ma->one_to_ones_rev, g_strdup(username), g_strdup(channel_id));
					}

					if (purple_conversation_has_focus(PURPLE_CONVERSATION(purple_conversations_find_im_with_account(username, ma->account)))) {
						mm_mark_room_messages_read(ma, channel_id);
					}

				} else {
					const gchar *other_user = g_hash_table_lookup(ma->one_to_ones, channel_id);
					// TODO null check
					PurpleIMConversation *imconv = purple_conversations_find_im_with_account(other_user, ma->account);
					PurpleMessage *pmsg = purple_message_new_outgoing(other_user, message, msg_flags);

					if (imconv == NULL) {
						imconv = purple_im_conversation_new(ma->account, other_user);
					}
					purple_message_set_time(pmsg, timestamp);
					purple_conversation_write_message(PURPLE_CONVERSATION(imconv), pmsg);
					purple_message_destroy(pmsg);
				}
			}

			g_free(message);
		}

	}

	g_free(use_username);
	g_free(attachments);

	return update_at;
}

static void
mm_got_hello_user_statuses(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{

	JsonObject *obj = json_node_get_object(node);
	JsonObject *data = json_object_get_object_member(obj, "data");
	GList *ids = json_object_get_members(data);
	GList *i;

	for (i = ids; i; i = i->next) {
		const gchar *user_id = i->data;
		const gchar *status = json_object_get_string_member(data, user_id);
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);

		if (username != NULL && status != NULL) {
			purple_protocol_got_user_status(ma->account, username, status, NULL);
		}
	}

	g_list_free(ids);
}

static void
mm_got_user_statuses_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{

	if (!mm_check_mattermost_response(ma,node,_("Error"),_("Error getting user statuses"),TRUE)) return;

	JsonArray *users = json_node_get_array(node);
	guint i, len = json_array_get_length(users);

	for (i = 0; i < len; i++) {
		JsonObject *user = json_array_get_object_element(users,i);
		const gchar *user_id = json_object_get_string_member(user, "user_id");
		const gchar *status = json_object_get_string_member(user, "status");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);

		if (username != NULL && status != NULL) {
			purple_protocol_got_user_status(ma->account, username, status, NULL);
		}
	}
}

static void
mm_refresh_statuses(MattermostAccount *ma, const gchar *id)
{
	JsonArray *user_ids;
	gchar *url;
	gchar *postdata;
	user_ids = json_array_new();

	if (id != NULL) {
		json_array_add_string_element(user_ids, id);
	} else {
		GSList *buddies = purple_find_buddies(ma->account, NULL);
		GSList *buddy_it = buddies;
		while(buddy_it != NULL){
			PurpleBuddy *buddy = buddy_it->data;
			const gchar *buddy_name = purple_buddy_get_name(buddy);
			const gchar *user_id = g_hash_table_lookup(ma->usernames_to_ids, buddy_name);
			json_array_add_string_element(user_ids, user_id);

			buddy_it = g_slist_next(buddy_it);
		}
		g_slist_free(buddies);
	}
	guint len = json_array_get_length(user_ids);
	if(len == 0){
		return;
	}
	postdata = json_array_to_string(user_ids);

	url = mm_build_url(ma,"/users/status/ids");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_got_user_statuses_response, NULL);
}


static gchar *
mm_process_attachment(JsonObject *attachment)
{
//TODO: sanitze input strings !
//TODO: libpurple xhtml-im parser is .. fragile .. easy to get output not htmlized ...

	gchar *msg_top = NULL;
	gchar *msg_fields = NULL;
	gchar *message = NULL;

	//fallback
	const gchar *color = json_object_get_string_member(attachment, "color");
	const gchar *pretext = json_object_get_string_member(attachment, "pretext");
	const gchar *text = json_object_get_string_member(attachment, "text");
	const gchar *author_name = json_object_get_string_member(attachment, "author_name");
	//const gchar *author_icon = json_object_get_string_member(attachment, "author_icon");
	const gchar *author_link = json_object_get_string_member(attachment,"author_link");
	const gchar *title = json_object_get_string_member(attachment, "title");
	const gchar *title_link = json_object_get_string_member(attachment, "title_link");
	// following are not implemented in MM 3.09 (yet?)
	const gchar *image_url = json_object_get_string_member(attachment, "image_url");
	//const gchar *thumb_url = json_object_get_string_member(attachment, "thumb_url");
	//const gchar *footer = json_object_get_string_member(attachment, "footer");
	//const gchar *footer_icon = json_object_get_string_member(attachment, "footer_icon");
	//const gint64 *ts = json_object_get_int_member(attachment, "ts");

	JsonArray *fields = json_object_get_array_member(attachment, "fields");
	guint fields_len = json_array_get_length(fields);

	GList *flds_list = NULL;
	guint i;

	for (i = 0; i < fields_len; i++) {
		MattermostAttachmentField *fld_cont = g_new0(MattermostAttachmentField, 1);
		JsonObject *field = json_node_get_object(json_array_get_element(fields, i));

		fld_cont->title = g_strdup(json_object_get_string_member(field, "title"));
		fld_cont->value = g_strdup(json_object_get_string_member(field, "value"));
		//fld_cont-> short : we cannot format in multi-column (easily..)
		flds_list = g_list_append(flds_list, fld_cont);
	}

	//TODO: symbolic color names .. and checking

	if (!color) {
		color = "#FFFFFF";
	}

	msg_top = g_strconcat(
		MM_ATT_BREAK, MM_ATT_TEXT(pretext),
		MM_ATT_LINE,
		MM_ATT_BORDER(color), MM_ATT_AUTHOR(author_name,author_link),
		MM_ATT_BORDER(color), MM_ATT_TITLE(title,title_link),
		MM_ATT_BORDER(color), MM_ATT_TEXT(text),
		MM_ATT_BORDER(color), MM_ATT_IMAGE(image_url),
		NULL);

	GList *j;
	gchar *tmpl1 = NULL;
	gchar *tmpl2 = NULL;

	for (j=flds_list; j != NULL; j=j->next) {
		MattermostAttachmentField *af = j->data;
		tmpl1 = g_strdup(msg_fields);
		g_free(msg_fields);
		tmpl2 = g_strconcat(
			MM_ATT_BORDER(color), MM_ATT_FTITLE(af->title),
			MM_ATT_BORDER(color), MM_ATT_TEXT(af->value),
			NULL);
		if (tmpl1) {
			msg_fields = g_strconcat(tmpl1, tmpl2, NULL);
		} else {
			msg_fields = g_strdup(tmpl2);
		}
		g_free(tmpl1);
		g_free(tmpl2);
	}

	message = g_strconcat(msg_top, msg_fields ? msg_fields : " ", MM_ATT_LINE, NULL);
	g_free(msg_top);
	g_free(msg_fields);
	g_list_free_full(flds_list, mm_g_free_mattermost_attachment_field);

	return message;
}

static gint64
mm_get_channel_approximate_view_time(MattermostAccount *ma, const gchar *id)
{
	gchar *tmptime = NULL;

	PurpleChat *chat = mm_purple_blist_find_chat(ma, id);
	if (chat) {
		tmptime = g_strdup(purple_blist_node_get_string(PURPLE_BLIST_NODE(chat), "channel_approximate_view_time"));
	} else {
		PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, g_hash_table_lookup(ma->one_to_ones,id));
		if (buddy) {
			tmptime = g_strdup(purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "channel_approximate_view_time"));
		}
	}

	// If "tmptime" is null it means a new channel is added to Pidgin which was not existing before
	if(!tmptime) {
		g_free(tmptime);
		return MATTERMOST_NEW_CHANNEL_FOUND;
	}

	gint64 viewtime = g_ascii_strtoll(tmptime, NULL, 10);
	purple_debug_info("alphatest maxx2", "%s\n", tmptime);
	g_free(tmptime);
	return viewtime;
}


static void
mm_process_msg(MattermostAccount *ma, JsonNode *element_node)
{
	//JsonObject *response = NULL;
	JsonObject *obj = json_node_get_object(element_node);

	const gchar *event = json_object_get_string_member(obj, "event");
	const gchar *status = json_object_get_string_member(obj, "status");
	JsonObject *data = json_object_get_object_member(obj, "data");
	JsonObject *broadcast = json_object_get_object_member(obj, "broadcast");
	mm_get_or_create_default_group();

	if (event == NULL) {
		gint seq_reply = json_object_get_int_member(obj, "seq_reply");
		MattermostProxyConnection *proxy = g_hash_table_lookup(ma->result_callbacks, GINT_TO_POINTER(seq_reply));

		if (proxy != NULL) {
			if (proxy->callback != NULL) {
				proxy->callback(ma, element_node, proxy->user_data);
			}
			g_hash_table_remove(ma->result_callbacks, GINT_TO_POINTER(seq_reply));
		}
	}

	if (purple_strequal(event, "posted") || purple_strequal(event, "post_edited") || purple_strequal(event, "ephemeral_message")) {
		JsonParser *post_parser = json_parser_new();
		const gchar *post_str = json_object_get_string_member(data, "post");

		if (json_parser_load_from_data(post_parser, post_str, -1, NULL)) {
			JsonObject *post = json_node_get_object(json_parser_get_root(post_parser));
			const gchar *channel_id = json_object_get_string_member(post, "channel_id");
			const gchar *user_id =  mm_data_or_broadcast_string("user_id");
			const gchar *team_id = json_object_get_string_member(post, "team_id");

			// detect posts with reactions (update time is larger than edit) and ignore them
			if (purple_strequal(event, "post_edited") && json_object_get_int_member(post, "update_at") > json_object_get_int_member(post, "edit_at")) {
				// do nothing
			} else
			//type system_join_channel, channel_id is ""
			if (!purple_strequal(channel_id, "") && purple_strequal(ma->self->user_id, user_id)) {
				mm_get_channel_by_id(ma, team_id, channel_id);

			} else if (!purple_strequal(channel_id, "") && g_hash_table_lookup(ma->group_chats, channel_id)) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
				if (!chatconv) {
					PurpleChat *chat = mm_purple_blist_find_chat(ma,channel_id);
						if (chat) {
							GHashTable *components = purple_chat_get_components(chat);
							gchar *team_id = g_hash_table_lookup(components, "team_id");
							gchar *channel_id = g_hash_table_lookup(components, "id");
							gchar *type = g_hash_table_lookup(components, "type");
							gchar *display_name = g_hash_table_lookup(components, "display_name");
							const gchar *alias;

							MattermostChannel *tmpchannel = g_new0(MattermostChannel,1);
							tmpchannel->id = g_strdup(channel_id);
							tmpchannel->team_id = g_strdup(team_id);
							tmpchannel->display_name = g_strdup(display_name);
							tmpchannel->type = g_strdup(type);

							alias = mm_get_chat_alias(ma,tmpchannel);

							PurpleChatConversation *conv = purple_serv_got_joined_chat(ma->pc, g_str_hash(channel_id), alias);
							purple_conversation_set_data(PURPLE_CONVERSATION(conv), "id", g_strdup(channel_id));
							purple_conversation_set_data(PURPLE_CONVERSATION(conv), "team_id", g_strdup(team_id));
							purple_conversation_set_data(PURPLE_CONVERSATION(conv), "name", g_strdup(alias));
							purple_conversation_set_data(PURPLE_CONVERSATION(conv), "display_name", g_strdup(display_name));
							purple_conversation_present(PURPLE_CONVERSATION(conv));
						}
				}
			}

			// If a new channel is joined then first show the last 60 messages and then channel joined message
			if (!purple_strequal(channel_id, "") && mm_get_channel_approximate_view_time(ma, channel_id) != MATTERMOST_NEW_CHANNEL_FOUND) {
				mm_process_room_message(ma, post, data);
			}
		}
		g_object_unref(post_parser);
	} else if (purple_strequal(event, "typing")) {
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *user_id = mm_data_or_broadcast_string("user_id");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);

		if (mm_hash_table_contains(ma->group_chats, channel_id)) {
			// This is a group conversation
			PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
			if (chatconv != NULL) {
				PurpleChatUser *cb = purple_chat_conversation_find_user(chatconv, username);
				PurpleChatUserFlags cbflags;

				if (cb == NULL) {
					// Getting notified about a buddy we dont know about yet
					//TODO add buddy
					return;
				}
				cbflags = purple_chat_user_get_flags(cb);

				//if (is_typing)
					cbflags |= PURPLE_CHAT_USER_TYPING;
				//else //TODO
				//	cbflags &= ~PURPLE_CHAT_USER_TYPING;

				purple_chat_user_set_flags(cb, cbflags);
			}
		} else {
			purple_serv_got_typing(ma->pc, username, 15, PURPLE_IM_TYPING);
		}

	} else if (purple_strequal(event, "status_change")) {
		const gchar *user_id = json_object_get_string_member(data, "user_id");
		const gchar *status = json_object_get_string_member(data, "status");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
		if (username != NULL && status != NULL) {
			purple_protocol_got_user_status(ma->account, username, status, NULL);
		}
	} else if (purple_strequal(event, "user_added")) {
		const gchar *user_id = mm_data_or_broadcast_string("user_id");
		const gchar *team_id = json_object_get_string_member(data, "team_id");
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));

		if (chatconv != NULL) {
			if (!purple_chat_conversation_has_left(chatconv))
				//FIXME: we can end up here with username == NULL and segfault pidgin.
				if (username)
					purple_chat_conversation_add_user(chatconv, username, NULL, PURPLE_CHAT_USER_NONE, FALSE);
		} else if (purple_strequal(user_id, ma->self->user_id)) {
			mm_get_channel_by_id(ma, team_id, channel_id);
		}

	} else if (purple_strequal(event, "user_removed")) {
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *user_id = mm_data_or_broadcast_string("user_id");

		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
		if (chatconv != NULL) {
			purple_chat_conversation_remove_user(chatconv, username, NULL);
		}

		if (purple_strequal(user_id, ma->self->user_id)) {
			if (mm_hash_table_contains(ma->group_chats, channel_id)) {
				PurpleChat *chat = mm_purple_blist_find_chat(ma, channel_id);
				if (chat) {
					PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
					if (chatconv) purple_chat_conversation_leave(chatconv);
					mm_remove_group_chat(ma, channel_id);
					//FIXME twice ? mm_remove_group_chat(ma, channel_id);
					purple_blist_remove_chat(chat);
				}
			}
		}
	} else if (purple_strequal(event, "preferences_changed") && purple_strequal(mm_data_or_broadcast_string("user_id"), ma->self->user_id)) {
		GList *users = json_array_get_elements(json_array_from_string(json_node_get_string(json_object_get_member(data, "preferences"))));
		GList *user = NULL;
		GList *mm_users = NULL;
		for (user = users; user != NULL; user = user->next) {
			JsonObject *object = json_node_get_object(user->data);
			const gchar *id = json_object_get_string_member(object, "name");
			if (purple_strequal(json_object_get_string_member(object, "category"), "direct_channel_show")) {
				if (purple_strequal(json_object_get_string_member(object, "value"), "false")) {
					if (mm_hash_table_contains(ma->ids_to_usernames, id)) {
						const gchar *user_name = g_hash_table_lookup(ma->ids_to_usernames, id);
						PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, user_name);
						if (buddy) {
							// don't remove conversation if any: direct channel is not destroyed so it is reuseable.
							g_hash_table_remove(ma->ids_to_usernames, id);
							g_hash_table_remove(ma->usernames_to_ids, user_name);
							purple_blist_remove_buddy(buddy);
						}
					}
				} else {
					MattermostUser *mm_user = g_new0(MattermostUser,1);
					mm_user->user_id=g_strdup(id);
					mm_users = g_list_prepend(mm_users, mm_user);
				}
			}
			if (purple_strequal(json_object_get_string_member(object, "category"), "group_channel_show")) {
				if (purple_strequal(json_object_get_string_member(object, "value"), "false")) {
					if (mm_hash_table_contains(ma->group_chats, id)) {
						PurpleChat *chat = mm_purple_blist_find_chat(ma, id);
						if (chat) {
							// don't remove conversation if any: group channel is not destroyed so it is reuseable.
							mm_remove_group_chat(ma, id);
							purple_blist_remove_chat(chat);
						}
					}
				} else {
					// not efficient: one callback per channel:
					// but no API to do it on multiple channels at once ? ...
					const gchar *team_id = json_object_get_string_member(data, "team_id");
					mm_get_channel_by_id(ma, team_id, id);
				}
			}
		}
		mm_get_users_by_ids(ma, mm_users);
		g_list_free(users);
	} else if (purple_strequal(event, "channel_created") && purple_strequal(mm_data_or_broadcast_string("user_id"), ma->self->user_id)) {
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *team_id = json_object_get_string_member(data, "team_id");
		mm_get_channel_by_id(ma, team_id, channel_id);
	} else if (purple_strequal(event, "channel_deleted")) {
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		if (mm_hash_table_contains(ma->group_chats, channel_id)) {
			PurpleChat *chat = mm_purple_blist_find_chat(ma, channel_id);
			if (chat) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
				if (chatconv) purple_chat_conversation_leave(chatconv);
				mm_remove_group_chat(ma, channel_id);
				purple_blist_remove_chat(chat);
			}
		}
//	} else if (purple_strequal(event, "channel_converted")) {
//		//TODO: implement: remove & add to blist again (see above) or just change type ?
//	} else if (purple_strequal(event, "channel_updated")) {
//		//TODO: implement
	} else if (purple_strequal(event, "channel_viewed")) {
		//we have marked it viewed already with purple_conversation_has_focus()
	} else if (purple_strequal(event, "hello")) {
		mm_refresh_statuses(ma, NULL);
	} else if (purple_strequal(event, "user_updated")) {
	//TODO: implement reusing (partsof) mm_get_users_by_ids_response()
	//	{"event":"user_updated","data":{"user":
	//	{	"id":"XXXXX","create_at":XXXX,"update_at":XXXX ,"delete_at":0,
	//	"username":"aaa","auth_data":"","auth_service":"","email":"aa@aa.oo","nickname":"AA",
	//	"first_name":"AAA","last_name":"AAA","position":"CCC","roles":"system_user",
	//	"last_picture_update": XXXXX,"locale":"en",
	//	"timezone":{"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}}},"broadcast":
	//	{"omit_users":null,"user_id":"","channel_id":"","team_id":""},"seq":5}
	}	else if (event) {
		// can be one of: https://api.mattermost.com/#tag/WebSocket
		purple_debug_info("mattermost", "unhandled event %s [%s]\n", event,json_object_to_string(obj));
	} else if (purple_strequal(status,"OK")) {
		//TODO: this can be a reply to client sending 'user_typing', 'get_statuses' or 'get_statuses_by_ids'
		//      we dont know since would need to track seq number... so assume it was one of statuses replies...
		JsonNode *tmpjsonnode=json_node_new(JSON_NODE_OBJECT);
		json_node_set_object(tmpjsonnode,obj);
		mm_got_hello_user_statuses(ma, tmpjsonnode, NULL);
		json_node_free(tmpjsonnode);
	} else if (status) {
		//TODO: this will be FAIL status in reply to 'user_typing', 'get_statuses' or 'get_statuses_by_ids'
		//      we dont know since would need to track seq number... so just ignore it..
		purple_debug_info("mattermost", "unhandled status %s [%s]\n", status,json_object_to_string(obj));
	} else {
		purple_debug_info("mattermost", "unhandled message [%s]\n", json_object_to_string(obj));
	}
}


#undef	mm_data_or_broadcast_string

PurpleGroup *
mm_get_or_create_default_group()
{
	PurpleGroup *mm_group = NULL;

	mm_group = purple_blist_find_group(MATTERMOST_DEFAULT_BLIST_GROUP_NAME);
	if (!mm_group)
	{
		mm_group = purple_group_new(MATTERMOST_DEFAULT_BLIST_GROUP_NAME);
		purple_blist_add_group(mm_group, NULL);
	}

	return mm_group;
}

static void
mm_roomlist_got_list(MattermostAccount *ma, JsonNode *node, gpointer user_data)
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

static gchar *
mm_roomlist_serialize(PurpleRoomlistRoom *room) {
	GList *fields = purple_roomlist_room_get_fields(room);

	const gchar *id = g_list_nth_data(fields, 0);
	const gchar *team_id = g_list_nth_data(fields, 1);
	const gchar *team_name = g_list_nth_data(fields, 2);
	const gchar *name = g_list_nth_data(fields, 3);

	//TODO: add alias ?
	return g_strconcat(team_id, "^", id, "^", name, MATTERMOST_CHANNEL_SEPARATOR, team_name, NULL); //FIXME: need proper separator - unique !
}

//roomlist_deserialize
static GHashTable *
mm_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

	if (chatname != NULL)
	{
		gchar **chat_parts = g_strsplit_set(chatname, "^", 3); //FIXME: need proper separator - unique !

		if (chat_parts[0]) {
			g_hash_table_insert(defaults, "team_id", g_strdup(chat_parts[0]));
			if (chat_parts[1]) {
				g_hash_table_insert(defaults, "id", g_strdup(chat_parts[1]));
				if (chat_parts[2]) {
					g_hash_table_insert(defaults, "name", g_strdup(chat_parts[2]));
				}
			}
		}
		//TODO: add alias ?
		g_strfreev(chat_parts);
	} else {
		g_hash_table_insert(defaults, "team_id", g_strdup(mm_get_first_team_id(purple_connection_get_protocol_data(pc))));
	}

	return defaults;
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

		// Get a list of public channels the user has *not* yet joined
		mmtrl = g_new0(MatterMostTeamRoomlist, 1);
		mmtrl->team_id = g_strdup(team_id);
		mmtrl->team_desc = g_strdup(_(": More public channels"));
		mmtrl->roomlist = roomlist;
		url = mm_build_url(ma,"/teams/%s/channels", team_id);
		mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_roomlist_got_list, mmtrl);
		g_free(url);

		ma->roomlist_team_count++;
	}

	return roomlist;
}


void
mm_set_idle(PurpleConnection *pc, int time)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const gchar *channel_id = "";

	if (time < 20) {
		channel_id = ma->last_channel_id;
	}

	mm_mark_room_messages_read(ma, channel_id);
}

gboolean
mm_idle_updater_timeout(gpointer data)
{
	PurpleConnection *pc = data;
	PurpleAccount *account = purple_connection_get_account(pc);
	PurplePresence *presence = purple_account_get_presence(account);
	time_t idle_time = purple_presence_get_idle_time(presence);

	if (idle_time > 0) {
		idle_time -= time(NULL);
	}

	mm_set_idle(pc, idle_time);

	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	mm_refresh_statuses(ma,NULL);

	return TRUE;
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
	if(ma->self == NULL){
		purple_debug_error("mattermost","Mattermost Account is NULL");
		return;
	}
	json_object_set_string_member(data, "user_id", ma->self->user_id);
	postdata = json_object_to_string(data);
	url = mm_build_url(ma,"/users/%s/status", ma->self->user_id);
	mm_fetch_url(ma, url, MATTERMOST_HTTP_PUT, postdata, -1, NULL, NULL);
	g_free(url);

	g_free(postdata);
	json_object_unref(data);
	g_free(setstatus);
}

static void
mm_restart_channel(MattermostAccount *ma)
{
	purple_connection_set_state(ma->pc, PURPLE_CONNECTION_CONNECTING);
	mm_start_socket(ma);
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

static guint mm_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, MattermostAccount *ma);
static gulong chat_conversation_typing_signal = 0;
static void mm_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type);
static gulong conversation_updated_signal = 0;

void
mm_login(PurpleAccount *account)
{
	MattermostAccount *ma;
	PurpleConnection *pc = purple_account_get_connection(account);
	gchar **userparts;
	gchar **serverparts;
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

        serverparts = g_strsplit(userparts[1], "/", 2);
        if( serverparts[0] == NULL ) {
		purple_connection_error(pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "No server supplied (use username|server)");
		return;
        }

	purple_connection_set_display_name(pc, userparts[0]);
	ma->username = g_strdup(userparts[0]);
	ma->server = g_strdup(serverparts[0]);
	g_strfreev(userparts);
        if( serverparts[1] == NULL ) {
	        ma->api_endpoint = g_strdup(MATTERMOST_API_EP);
        }
        else {
	        ma->api_endpoint = g_strconcat("/", serverparts[1], MATTERMOST_API_EP, NULL);
        }
	g_strfreev(serverparts);

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
mm_close(PurpleConnection *pc)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);

	g_return_if_fail(ma != NULL);

	mm_set_status(ma->account, purple_presence_get_active_status(purple_account_get_presence(ma->account)));

	if(ma->idle_timeout > 0){
		g_source_remove(ma->idle_timeout);
	}
	if(ma->read_messages_timeout > 0){
		g_source_remove(ma->read_messages_timeout);
	}

	purple_proxy_connect_cancel_with_handle(pc);
	if (ma->websocket != NULL) purple_ssl_close(ma->websocket);
	if (ma->websocket_inpa) purple_input_remove(ma->websocket_inpa);
	if (ma->websocket_fd >= 0) close(ma->websocket_fd);

	g_hash_table_remove_all(ma->one_to_ones);
	g_hash_table_unref(ma->one_to_ones);
	g_hash_table_remove_all(ma->one_to_ones_rev);
	g_hash_table_unref(ma->one_to_ones_rev);
	g_hash_table_remove_all(ma->group_chats);
	g_hash_table_unref(ma->group_chats);
	g_hash_table_remove_all(ma->aliases);
	g_hash_table_unref(ma->aliases);
	g_hash_table_remove_all(ma->group_chats_creators);
	g_hash_table_unref(ma->group_chats_creators);
	g_hash_table_remove_all(ma->sent_message_ids);
	g_hash_table_unref(ma->sent_message_ids);
	g_hash_table_remove_all(ma->result_callbacks);
	g_hash_table_unref(ma->result_callbacks);
	g_hash_table_remove_all(ma->usernames_to_ids);
	g_hash_table_unref(ma->usernames_to_ids);
	g_hash_table_remove_all(ma->ids_to_usernames);
	g_hash_table_unref(ma->ids_to_usernames);
	g_hash_table_remove_all(ma->teams);
	g_hash_table_unref(ma->teams);
	g_hash_table_remove_all(ma->teams_display_names);
	g_hash_table_unref(ma->teams_display_names);
	g_hash_table_remove_all(ma->channel_teams);
	g_hash_table_unref(ma->channel_teams);
	g_queue_free(ma->received_message_queue);

	while (ma->http_conns) {
		purple_http_conn_cancel(ma->http_conns->data);
		ma->http_conns = g_slist_delete_link(ma->http_conns, ma->http_conns);
	}

	while (ma->pending_writes) {
		json_object_unref(ma->pending_writes->data);
		ma->pending_writes = g_slist_delete_link(ma->pending_writes, ma->pending_writes);
	}

	mm_g_free_mattermost_user(ma->self);
	mm_g_free_mattermost_client_config(ma->client_config);

	g_hash_table_destroy(ma->cookie_table); ma->cookie_table = NULL;
	g_free(ma->last_channel_id); ma->last_channel_id = NULL;
	g_free(ma->current_channel_id); ma->current_channel_id = NULL;
	g_free(ma->username); ma->username = NULL;
	g_free(ma->server); ma->server = NULL;
	g_free(ma->api_endpoint); ma->api_endpoint = NULL;
	g_free(ma->frame); ma->frame = NULL;
	g_free(ma->session_token); ma->session_token = NULL;
	g_free(ma->channel); ma->channel = NULL;
	g_regex_unref(ma->mention_me_regex); ma->mention_me_regex = NULL;
	g_regex_unref(ma->mention_all_regex); ma->mention_all_regex = NULL;
	g_free(ma);
}


//static void mm_start_polling(MattermostAccount *ma);

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
mm_socket_read(MattermostAccount *ma, gpointer buffer, size_t len)
{
	if (ma->websocket) {
		return purple_ssl_read(ma->websocket, buffer, len);
	}

	return read(ma->websocket_fd, buffer, len);
}

static size_t
mm_socket_write(MattermostAccount *ma, gconstpointer buffer, size_t len)
{
	if (ma->websocket) {
		return purple_ssl_write(ma->websocket, buffer, len);
	}

	return write(ma->websocket_fd, buffer, len);
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

/* takes ownership of data parameter */
static void
mm_socket_write_json(MattermostAccount *ma, JsonObject *data)
{
	gchar *str;

	if (ma->websocket == NULL && ma->websocket_fd <= 0) {
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
mm_socket_got_data_nonssl(gpointer userdata, gint fd, PurpleInputCondition cond)
{
	mm_socket_got_data(userdata, NULL, cond);
}

static void
mm_socket_send_headers(MattermostAccount *ma)
{
	gchar *websocket_header;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy

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
                                                        "X-Requested-With: XMLHttpRequest\r\n"
							"Authorization: Bearer %s\r\n"
							//"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
							"\r\n", ma->api_endpoint, ma->server,
							websocket_key, ma->session_token);

	mm_socket_write(ma, websocket_header, strlen(websocket_header));

	g_free(websocket_header);
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

static void
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


static void
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

static void
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

static GList *
mm_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Name");
	pce->identifier = "name";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Channel ID");
	pce->identifier = "id";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Team ID");
	pce->identifier = "team_id";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

static gchar *
mm_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL) {
		return NULL;
	}

	temp = g_hash_table_lookup(data, "name");

	if (temp == NULL) {
		temp = g_hash_table_lookup(data, "id");
	}

	if (temp == NULL) {
		return NULL;
	}

	return g_strdup(temp);
}


static void mm_get_users_of_room(MattermostAccount *ma, MattermostChannel *channel);

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

		if (!mm_hash_table_contains(ma->ids_to_usernames, user_id)) {
			g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
			g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));

			if (chatconv == NULL && mm_hash_table_contains(ma->one_to_ones, channel->id)) {
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

static void mm_get_history_of_room(MattermostAccount *ma, MattermostChannel *channel, gint64 since);

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

	// do not show updates (such as reactions). only edits, new posts and deletes
	// We don't need this now, as in a channel we are fetching last 60 messages where post "create_at" time could be lesser than channel joined time "since"
	// for (i = len - 1; i >= 0; i--) {
	// 	const gchar *post_id = json_array_get_string_element(order, i);
	// 	JsonObject *post = json_object_get_object_member(posts, post_id);

	// 	const gint64 since = mm_get_channel_approximate_view_time(ma, channel->id);
	// 	if (json_object_get_int_member(post, "create_at") < since && json_object_get_int_member(post, "edit_at") < since && json_object_get_int_member(post, "delete_at") < since) {
	// 		json_array_remove_element(order, i);
	// 	}
	// }
	len = json_array_get_length(order);

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

// 'since' does follow the page size
if (len == MATTERMOST_HISTORY_PAGE_SIZE && channel->page_history < MATTERMOST_MAX_PAGES) {
		channel->page_history = channel->page_history + 1;

		mm_get_history_of_room(ma, channel, -1); // FIXME: that should be parametrized !
	} else {
		channel->page_history = MATTERMOST_MAX_PAGES;
		// history will be stored in purple log, even if channel not read now, avoid re-reading later.
		mm_mark_room_messages_read_timeout_response(ma, NULL, channel->id);

		mm_g_free_mattermost_channel(channel);
	}
// for now we could just tell user...

}

static void
mm_get_history_of_room(MattermostAccount *ma, MattermostChannel *channel, gint64 since)
{
	gchar *url;

	if (channel->page_history == MATTERMOST_MAX_PAGES) return;
	if (!channel->id) return;

	if (since < 0) {
		const gchar *channel_id = channel->id;
		since = mm_get_channel_approximate_view_time(ma, channel_id);
	}

	if (since == MATTERMOST_NEW_CHANNEL_FOUND) {
		// If a new channel is joined then fetch last 60 messages
		url = mm_build_url(ma,"/channels/%s/posts?page=0&per_page=%s", channel->id, g_strdup_printf("%i",MATTERMOST_HISTORY_PAGE_SIZE));
	} else {
		url = mm_build_url(ma,"/channels/%s/posts?page=%s&per_page=%s&since=%" G_GINT64_FORMAT "", channel->id, g_strdup_printf("%i",channel->page_history), g_strdup_printf("%i", MATTERMOST_HISTORY_PAGE_SIZE), since);
	}

	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_got_history_of_room, channel);
	g_free(url);
}

static void
mm_join_room(MattermostAccount *ma, MattermostChannel *channel)
{
	mm_set_group_chat(ma, channel->team_id, channel->name, channel->id);
	mm_get_users_of_room(ma, channel);
}


static void
mm_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const gchar *id = g_hash_table_lookup(chatdata, "id");
	const gchar *name = g_hash_table_lookup(chatdata, "name");
	const gchar *team_id = g_hash_table_lookup(chatdata, "team_id");
	const gchar *type = g_hash_table_lookup(chatdata, "type");
	const gchar *creator_id = g_hash_table_lookup(chatdata, "creator_id");

	guint id_hash;
	PurpleChatConversation *chatconv;

	if (id == NULL && name == NULL) {
		//What do?
		return;
	}

	if (id == NULL) {
		id = g_hash_table_lookup(ma->group_chats_rev, name);
	}
	//TODO use the api look up name info from the id
	if (id == NULL) {
		return;
	}

	id_hash = g_str_hash(id);
	chatconv = purple_conversations_find_chat(ma->pc, id_hash);

	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}

	const gchar *alias = g_hash_table_lookup(ma->aliases,id);

	chatconv = purple_serv_got_joined_chat(pc, id_hash, alias);//ALIAS ?

	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_strdup(id));
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "team_id", g_strdup(team_id));
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "name", g_strdup(name));
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "type", g_strdup(type));
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "creator_id", g_strdup(creator_id));
	purple_conversation_present(PURPLE_CONVERSATION(chatconv));

	mm_get_channel_by_id(ma,team_id,id);
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

static void
mm_mark_room_messages_read(MattermostAccount *ma, const gchar *room_id)
{
	g_free(ma->current_channel_id);
	ma->current_channel_id = g_strdup(room_id);

	g_source_remove(ma->read_messages_timeout);
	ma->read_messages_timeout = g_timeout_add_seconds(1, mm_mark_room_messages_read_timeout, ma);
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

static guint
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

static guint
mm_send_typing(PurpleConnection *pc, const gchar *who, PurpleIMTypingState state)
{
	PurpleConversation *conv;

	conv = PURPLE_CONVERSATION(purple_conversations_find_im_with_account(who, purple_connection_get_account(pc)));
	g_return_val_if_fail(conv, -1);

	return mm_conv_send_typing(conv, state, NULL);
}


static gint
mm_conversation_send_message(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, const gchar *message, GList *file_ids);

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

//FIXME: merge two funcs below.

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

static gint
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

	//url = mm_build_url(ma,"/teams/%s/channels/%s/posts/create", team_id, channel_id);
	url = mm_build_url(ma,"/posts");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_conversation_send_message_response, NULL); //todo look at callback

	if (!file_ids) mm_conversation_send_files(ma, team_id, channel_id, message);

	json_array_unref(tmparr);
	g_free(postdata);
	g_free(url);

	return 1;
}

static gint
mm_chat_send(PurpleConnection *pc, gint id,
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv = purple_conversations_find_chat(pc, id);
	const gchar *room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	const gchar *team_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "team_id");
	gint ret = 0;

	// this should not happen.
	g_return_val_if_fail(room_id, -1);
//g_return_val_if_fail(team_id, -1);  // it IS NULL for group channel.

	ret = mm_conversation_send_message(ma, team_id, room_id, mm_purple_xhtml_im_to_html_parse(ma, message), NULL);

	if (ret > 0) {
		gchar *message_out = mm_markdown_to_html(ma, message);
		purple_serv_got_chat_in(pc, g_str_hash(room_id), ma->self->username, PURPLE_MESSAGE_SEND, message_out, time(NULL));
		g_free(message_out);
	}
	return ret;
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

static int
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


static void
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
mm_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	mm_chat_set_header_purpose(pc, id, topic, TRUE);
}


void
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

void
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
mm_got_add_buddy_search(MattermostAccount *ma, JsonNode *node, gpointer user_data)
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

		if (!mm_hash_table_contains(ma->usernames_to_ids, username)) {
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

	postdata = json_object_to_string(obj);

	url = mm_build_url(ma,"/users/search");
	mm_fetch_url(ma, url, MATTERMOST_HTTP_POST, postdata, -1, mm_got_add_buddy_search, g_strdup(text));
	g_free(url);

	g_free(postdata);
	json_object_unref(obj);
}

void
mm_search_users(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);

	purple_request_input(pc, _("Search for users..."),
					_("Search for users..."),
					NULL,
					NULL, FALSE, FALSE, NULL,
					_("_Search"), G_CALLBACK(mm_search_users_text),
					_("_Cancel"), NULL,
					purple_request_cpar_from_connection(pc),
					ma);

}


void
mm_roomlist_show(PurpleProtocolAction *action)
{
	PurpleConnection *pc = purple_protocol_action_get_connection(action);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	purple_roomlist_show_with_account(ma->account);
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

//TODO: integrate with mm_get_users_by_ids() ?
static void
mm_got_add_buddy_user(MattermostAccount *ma, JsonNode *node, gpointer user_data)
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


static void
mm_got_avatar(MattermostAccount *ma, JsonNode *node, gpointer user_data)
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
	mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_got_avatar, (gpointer) buddy_name);
	g_free(url);
}


static void
mm_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	// Do nothing to stop the remove+add behaviour
}


static void
mm_fake_group_rename(PurpleConnection *pc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
	// Do nothing to stop the remove+add behaviour
}


static void
mm_remove_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	MattermostUserPref *pref = g_new0(MattermostUserPref,1);
	pref->user_id = g_strdup(ma->self->user_id);
	pref->category = g_strdup("direct_channel_show");
	pref->name = g_strdup(purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "user_id"));
	pref->value = g_strdup("false");
	mm_save_user_pref(ma, pref);
	// free pref in callback
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
			mm_fetch_url(ma, url, MATTERMOST_HTTP_GET, NULL, -1, mm_got_add_buddy_user, buddy);
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

static const char *
mm_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "mattermost";
}

static GList *
mm_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "online", "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, "away", "Away", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "offline", "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, "dnd", "Busy", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, "invisible", "Invisible", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static GHashTable *
mm_get_account_text_table(PurpleAccount *unused)
{
	GHashTable *table;

	table = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(table, "login_label", (gpointer)_("Email or AD/LDAP Username..."));

	return table;
}

static GList *
mm_add_account_options(GList *account_options)
{
	PurpleAccountOption *option;

	option = purple_account_option_bool_new(N_("Use SSL/HTTPS"), "use-ssl", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(N_("Password is Gitlab cookie"), "use-mmauthtoken", FALSE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(N_("Interpret (subset of) markdown"), "use-markdown", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(N_("Auto generate buddies aliases"), "use-alias", FALSE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(N_("Show images in messages"), "show-images", TRUE);
	account_options = g_list_append(account_options, option);

	//FIXME: this one shall depend on above one !
	option = purple_account_option_bool_new(N_("Show full images in messages"), "show-full-images", FALSE);
	account_options = g_list_append(account_options, option);

	return account_options;
}

static PurpleCmdRet
mm_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = NULL;
	int id = -1;

	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));

	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;

	mm_chat_leave(pc, id);

	return PURPLE_CMD_RET_OK;
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

static GList *
mm_actions(
#if !PURPLE_VERSION_CHECK(3, 0, 0)
PurplePlugin *plugin, gpointer context
#else
PurpleConnection *pc
#endif
)
{
	GList *m = NULL;
	PurpleProtocolAction *act;

	act = purple_protocol_action_new(_("Search for Users..."), mm_search_users);
	m = g_list_append(m, act);

	act = purple_protocol_action_new(_("Room List"), mm_roomlist_show);
	m = g_list_append(m, act);

	act = purple_protocol_action_new(_("About Myself"), mm_about_myself);
	m = g_list_append(m, act);

	act = purple_protocol_action_new(_("Server Info"), mm_about_server);
	m = g_list_append(m, act);

	act = purple_protocol_action_new(_("Slash Commands"), mm_about_commands);
	m = g_list_append(m, act);

	return m;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{

	mm_purple_xhtml_im_html_init();

	// we do not want the server to initiate channel leave, we do it ourselves.
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_cmd_leave,
						_("leave:  Leave the channel"), NULL);

	return TRUE;

}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);

	return TRUE;
}

// Purple2 Plugin Load Functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

// Normally set in core.c in purple3
void _purple_socket_init(void);
void _purple_socket_uninit(void);

static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();

	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();

	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{
	// PurpleAccountOption *option;
	// PurplePluginInfo *info = plugin->info;
	// PurplePluginProtocolInfo *prpl_info = info->extra_info;
	//purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(mm_uri_handler), NULL);

	PurpleAccountUserSplit *split;
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);

	split = purple_account_user_split_new(_("Server"), MATTERMOST_DEFAULT_SERVER, MATTERMOST_SERVER_SPLIT_CHAR);
	prpl_info->user_splits = g_list_append(prpl_info->user_splits, split);

	info = plugin->info;
	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}
	info->actions = mm_actions;
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	#if PURPLE_MINOR_VERSION >= 8
		//prpl_info->add_buddy_with_invite = mm_add_buddy;
	#endif

	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_IM_IMAGE;
	prpl_info->protocol_options = mm_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;

	prpl_info->get_account_text_table = mm_get_account_text_table;
	prpl_info->list_icon = mm_list_icon;
	prpl_info->set_status = mm_set_status;
	prpl_info->set_idle = mm_set_idle;
	prpl_info->status_types = mm_status_types;
	prpl_info->chat_info = mm_chat_info;
	prpl_info->chat_info_defaults = mm_chat_info_defaults;
	prpl_info->login = mm_login;
	prpl_info->close = mm_close;
	prpl_info->send_im = mm_send_im;
	prpl_info->send_typing = mm_send_typing;
	prpl_info->join_chat = mm_join_chat;
	prpl_info->get_chat_name = mm_get_chat_name;
	prpl_info->chat_invite = mm_chat_invite;
	prpl_info->chat_send = mm_chat_send;
	prpl_info->set_chat_topic = mm_chat_set_topic;
	prpl_info->add_buddy = mm_add_buddy_no_message;
	prpl_info->remove_buddy = mm_remove_buddy;
	prpl_info->group_buddy = mm_fake_group_buddy;
	prpl_info->rename_group = mm_fake_group_rename;
	prpl_info->blist_node_menu = mm_blist_node_menu;
	prpl_info->get_info = mm_get_info;
	prpl_info->tooltip_text = mm_tooltip_text;

	prpl_info->roomlist_get_list = mm_roomlist_get_list;
	prpl_info->roomlist_room_serialize = mm_roomlist_serialize;
}


static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,            // type
	NULL,                              // ui_requirement
	0,                                 // flags
	NULL,                              // dependencies
	PURPLE_PRIORITY_DEFAULT,           // priority
	MATTERMOST_PLUGIN_ID,              // id
	"Mattermost",                      // name
	MATTERMOST_PLUGIN_VERSION,         // version
	N_("Mattermost Protocol Plugin."), // summary
	N_("Adds Mattermost protocol support to libpurple."), // description
	"Eion Robb <eion@robbmob.com>",    // author
	MATTERMOST_PLUGIN_WEBSITE,         // homepage
	libpurple2_plugin_load,            // load
	libpurple2_plugin_unload,          // unload
	NULL,                              // destroy
	NULL,                              // ui_info
	NULL,                              // extra_info
	NULL,                              // prefs_info
	NULL,                              // actions
	NULL,                              // padding
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(mattermost, plugin_init, info);

#else
//Purple 3 plugin load functions

static void
mm_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;
	PurpleAccountUserSplit *split;

	info->id = MATTERMOST_PLUGIN_ID;
	info->name = "Mattermost";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_IM_IMAGE;
	info->account_options = mm_add_account_options(info->account_options);

	split = purple_account_user_split_new(_("Server"), MATTERMOST_DEFAULT_SERVER, MATTERMOST_SERVER_SPLIT_CHAR);
	info->user_splits = g_list_append(info->user_splits, split);
}

static void
mm_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = mm_login;
	prpl_info->close = mm_close;
	prpl_info->status_types = mm_status_types;
	prpl_info->list_icon = mm_list_icon;
}


static void
mm_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = mm_send_im;
	prpl_info->send_typing = mm_send_typing;
}

static void
mm_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = mm_chat_send;
	prpl_info->info = mm_chat_info;
	prpl_info->info_defaults = mm_chat_info_defaults;
	prpl_info->join = mm_join_chat;
	prpl_info->get_name = mm_get_chat_name;
	prpl_info->invite = mm_chat_invite;
	prpl_info->set_topic = mm_chat_set_topic;
}


static void
mm_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->add_buddy = mm_add_buddy;
	prpl_info->remove_buddy = mm_remove_buddy;
	prpl_info->group_buddy = mm_fake_group_buddy;
	prpl_info->rename_group = mm_fake_group_rename;
	prpl_info->set_status = mm_set_status;
	prpl_info->set_idle = mm_set_idle;
	prpl_info->get_info = mm_get_info;
}


static void
mm_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_actions = mm_actions;
	prpl_info->get_account_text_table = mm_get_account_text_table;
	prpl_info->blist_node_menu = mm_blist_node_menu;
	prpl_info->tooltip_text = mm_tooltip_text;

}


static void
mm_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	prpl_info->get_list = mm_roomlist_get_list;
	prpl_info->room_serialize = mm_roomlist_serialize;
}


static PurpleProtocol *mm_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	MattermostProtocol, mm_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  mm_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  mm_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  mm_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  mm_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  mm_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	mm_protocol_register_type(plugin);
	mm_protocol = purple_protocols_add(MATTERMOST_TYPE_PROTOCOL, error);
	if (!mm_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(mm_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          MATTERMOST_PLUGIN_ID,
		"name",        "Mattermost",
		"version",     MATTERMOST_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Mattermost Protocol Plugin."),
		"description", N_("Adds Mattermost protocol support to libpurple."),
		"website",     MATTERMOST_PLUGIN_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(mattermost, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
