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
#include "libmattermost-msgprocess.h"
#include "libmattermost-mmrequests.h"

gulong chat_conversation_typing_signal = 0;
gulong conversation_updated_signal = 0;


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

static void
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



void
mm_remove_group_chat(MattermostAccount *ma, const gchar *channel_id)
{
	if (!g_hash_table_lookup(ma->group_chats, channel_id)) return;

	g_hash_table_remove(ma->group_chats_rev, g_hash_table_lookup(ma->group_chats, channel_id));
	g_hash_table_remove(ma->group_chats, channel_id);
	g_hash_table_remove(ma->channel_teams, channel_id);
}


void
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





static void 
mm_close(PurpleConnection *pc)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);

	g_return_if_fail(ma != NULL);

	mm_set_status(ma->account, purple_presence_get_active_status(purple_account_get_presence(ma->account)));

	g_source_remove(ma->idle_timeout);
	g_source_remove(ma->read_messages_timeout);

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

	mm_get_channel_by_id(ma, id);
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
mm_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	mm_chat_set_header_purpose(pc, id, topic, TRUE);
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
