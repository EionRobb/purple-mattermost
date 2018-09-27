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

#include "libmattermost.h"
#include "libmattermost-json.h"
#include "libmattermost-msgprocess.h"
#include "libmattermost-helpers.h"
#include "libmattermost-markdown.h"

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

static void
mm_process_msg_user_typing(MattermostAccount *ma, const gchar *user_id, const gchar *channel_id)
{
	if (!strlen(user_id) || !strlen(channel_id)) {
		// debug error
		return;
	}

	const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);

	if (g_hash_table_contains(ma->group_chats, channel_id)) {
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
}


static void
mm_process_msg_seq_reply(MattermostAccount *ma, gint64 seq_reply, JsonNode *element_node)
{
	if (!seq_reply) 
		return;

	MattermostProxyConnection *proxy = g_hash_table_lookup(ma->result_callbacks, GINT_TO_POINTER(seq_reply));

	if (proxy != NULL) {
		if (proxy->callback != NULL) {
			proxy->callback(ma, element_node, proxy->user_data);
		}
		g_hash_table_remove(ma->result_callbacks, GINT_TO_POINTER(seq_reply));
	}
}

static void
mm_process_msg_user_added(MattermostAccount *ma, const gchar *user_id, const gchar *channel_id)
{
	const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));

	if (chatconv != NULL) {
		if (!purple_chat_conversation_has_left(chatconv))
			//FIXME: we can end up here with username == NULL and segfault pidgin.
			if (username) 
				purple_chat_conversation_add_user(chatconv, username, NULL, PURPLE_CHAT_USER_NONE, FALSE);
		} else if (purple_strequal(user_id, ma->self->user_id)) {
			mm_get_channel_by_id(ma, channel_id);
		}
}

static void
mm_process_msg_user_removed(MattermostAccount *ma, const gchar *user_id, const gchar *channel_id)
{
	const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));

	if (chatconv != NULL) {
		purple_chat_conversation_remove_user(chatconv, username, NULL);
	}

	if (purple_strequal(user_id, ma->self->user_id)) {
		if (g_hash_table_contains(ma->group_chats, channel_id)) {
			PurpleChat *chat = mm_purple_blist_find_chat(ma, channel_id);
			if (chat) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
				if (chatconv) 
					purple_chat_conversation_leave(chatconv);
				mm_remove_group_chat(ma, channel_id);
				purple_blist_remove_chat(chat);
			}
		}
	}
}

static void
mm_process_msg_channel_deleted(MattermostAccount *ma, const gchar *channel_id)
{
	if (g_hash_table_contains(ma->group_chats, channel_id)) {
		PurpleChat *chat = mm_purple_blist_find_chat(ma, channel_id);
		if (chat) {
			PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
			if (chatconv) 
				purple_chat_conversation_leave(chatconv);
			mm_remove_group_chat(ma, channel_id);
			purple_blist_remove_chat(chat);
		}
	}
}

static void
mm_process_msg_status_change(MattermostAccount *ma, const gchar *user_id, JsonObject *data)
{
	const gchar *status = json_object_get_string_member(data, "status");
	const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);

	//FIXME: CHECK THE status itself ! 		
	if (username != NULL && status != NULL) {
			purple_protocol_got_user_status(ma->account, username, status, NULL);
	}
}

static void
mm_process_msg_preferences_changed(MattermostAccount *ma, JsonObject *data)
{
	GList *users = json_array_get_elements(json_array_from_string(json_node_get_string(json_object_get_member(data, "preferences"))));
	GList *user = NULL;
	GList *mm_users = NULL;
	for (user = users; user != NULL; user = user->next) {
		JsonObject *object = json_node_get_object(user->data);
		const gchar *id = json_object_get_string_member(object, "name");

		if (purple_strequal(json_object_get_string_member(object, "category"), "direct_channel_show")) {
			if (purple_strequal(json_object_get_string_member(object, "value"), "false")) {				
				if (g_hash_table_contains(ma->ids_to_usernames, id)) {
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
				if (g_hash_table_contains(ma->group_chats, id)) {
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
				mm_get_channel_by_id(ma, id);
			}
		}
	}
	
	mm_get_users_by_ids(ma, mm_users);
	g_list_free(users);
}

static void
mm_process_msg_posted(MattermostAccount *ma, const gchar *user_id, const gchar *post_str, JsonObject *data)
{
	JsonParser *post_parser = json_parser_new();

	if (json_parser_load_from_data(post_parser, post_str, -1, NULL)) {
		JsonObject *post = json_node_get_object(json_parser_get_root(post_parser));
		const gchar *channel_id = json_object_get_string_member(post, "channel_id");
			
		//type system_join_channel, channel_id is ""		
		if (!purple_strequal(channel_id,"") && purple_strequal(ma->self->user_id, user_id)) {
			mm_get_channel_by_id(ma, channel_id);
		} else if (!purple_strequal(channel_id,"") && g_hash_table_lookup(ma->group_chats, channel_id)) {
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

		if (!purple_strequal(channel_id,"")) 
			mm_process_room_message(ma, post, data);

	}
	
	g_object_unref(post_parser);
}

void
mm_process_msg(MattermostAccount *ma, JsonNode *element_node)
{
	JsonObject *obj = json_node_get_object(element_node);

	const gchar *event = json_object_get_string_member(obj, "event");
	const gchar *status = json_object_get_string_member(obj, "status");
	JsonObject *data = json_object_get_object_member(obj, "data");
	JsonObject *broadcast = json_object_get_object_member(obj, "broadcast");

	// Status: this can be reply to user_typing , get_statuses, get_statuses_by_id
	if (event == NULL) {
		mm_process_msg_seq_reply(ma, json_object_get_int_member(obj, "seq_reply"), element_node);

		if (purple_strequal(status,"OK")) { 
			JsonNode *tmpjsonnode=json_node_new(JSON_NODE_OBJECT);
			json_node_set_object(tmpjsonnode,obj);
			mm_got_hello_user_statuses(ma, tmpjsonnode, NULL);
			json_node_free(tmpjsonnode);
		} else {
			purple_debug_info("mattermost", "unhandled status %s [%s]\n", status,json_object_to_string(obj));
		}
		return;
	}

	const gchar *user_id = mm_data_or_broadcast_string("user_id");
	const gchar *channel_id = mm_data_or_broadcast_string("channel_id");

	// Event
	// a message: most frequent activity on channel...

	if (purple_strequal(event, "posted") || 
			purple_strequal(event, "post_edited") || 
			purple_strequal(event, "ephemeral_message")) {
		//channel id here ?
		mm_process_msg_posted(ma, user_id, json_object_get_string_member(data, "post"), data);
		return;
	}

	if (purple_strequal(event, "channel_viewed")) {
		//we have marked it viewed already with purple_conversation_has_focus()
		return;
	}

	if (purple_strequal(event, "channel_converted")) {
		//TODO: implement: remove & add to blist again (see above) or just change type ?
		return;
	}

	if (purple_strequal(event, "channel_updated")) {
		//TODO: implement
		return;
	}

	// User related events

	if (purple_strequal(event, "typing")) {
		mm_process_msg_user_typing(ma, user_id, channel_id);
		return;
	}

	if (purple_strequal(event, "user_added")) {
		mm_process_msg_user_added(ma, user_id, channel_id);
		return;
	}

	if (purple_strequal(event, "user_removed")) {
		mm_process_msg_user_removed(ma, user_id, channel_id);
	}

	if (purple_strequal(event, "user_updated")) {
	//TODO: implement reusing (partsof) mm_get_users_by_ids_response()
	//	{"event":"user_updated","data":{"user": 
	//	{	"id":"XXXXX","create_at":XXXX,"update_at":XXXX ,"delete_at":0,
	//	"username":"aaa","auth_data":"","auth_service":"","email":"aa@aa.oo","nickname":"AA",
	//	"first_name":"AAA","last_name":"AAA","position":"CCC","roles":"system_user",
	//	"last_picture_update": XXXXX,"locale":"en",
	//	"timezone":{"automaticTimezone":"","manualTimezone":"","useAutomaticTimezone":"true"}}},"broadcast":
	//	{"omit_users":null,"user_id":"","channel_id":"","team_id":""},"seq":5}	
		return;
	}

	if (purple_strequal(event, "status_change")) {
		mm_process_msg_status_change(ma, user_id, data);
		return;
	}

	//Channel related events

	if (purple_strequal(event, "channel_created") && 
			purple_strequal(user_id, ma->self->user_id)) {
		mm_get_channel_by_id(ma, channel_id);
		return;
	}

	if (purple_strequal(event, "channel_deleted")) {
		mm_process_msg_channel_deleted(ma, channel_id);
		return;
	}

	// Other events

	if (purple_strequal(event, "preferences_changed") && 
			purple_strequal(user_id, ma->self->user_id)) {
		mm_process_msg_preferences_changed(ma, data);
		return;
	}

	// Check this: MM 5.X server does not seem to send hello anymore ?
	if (purple_strequal(event, "hello")) {
		mm_refresh_statuses(ma, NULL); 
		return;
	}
 
	if (event) {
		// can be one of: https://api.mattermost.com/#tag/WebSocket
		purple_debug_info("mattermost", "unhandled event '%s' [%s]\n", event,json_object_to_string(obj)); 
		return;
	} 

	purple_debug_info("mattermost", "unhandled message [%s]\n", json_object_to_string(obj));
}


#undef	mm_data_or_broadcast_string

gint64
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

	if (username != NULL && !g_hash_table_contains(ma->ids_to_usernames, user_id)) {
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

	if (!g_hash_table_contains(ma->channel_teams, channel_id)) {
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
		
			if (json_object_get_int_member(post, "edit_at")) {
				gchar *tmp = g_strconcat(_("Edited: "), message, NULL);
				g_free(message);
				message = tmp;
			}
			
			if (json_object_has_member(post, "file_ids")) {
				JsonArray *file_ids = json_object_get_array_member(post, "file_ids");
				guint i, len = json_array_get_length(file_ids);
				
				for (i = 0; i < len; i++) {
					const gchar *file_id = json_array_get_string_element(file_ids, i);
					
					mm_fetch_file_link_for_channel(ma, file_id, channel_id, use_username, timestamp);
				}
			}

//FIXME JAREK: dont know the TEAM here

			if ((channel_type != NULL && *channel_type != MATTERMOST_CHANNEL_DIRECT) || g_hash_table_contains(ma->group_chats, channel_id)) {
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

					mm_get_channel_by_id(ma, channel_id);
						
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

					if (channel_type && *channel_type == MATTERMOST_CHANNEL_DIRECT && !g_hash_table_contains(ma->one_to_ones, channel_id)) {
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


