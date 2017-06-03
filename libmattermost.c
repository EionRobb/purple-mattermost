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

// Glib
#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */

static gboolean
g_str_insensitive_equal(gconstpointer v1, gconstpointer v2)
{
	return (g_ascii_strcasecmp(v1, v2) == 0);
}
static guint
g_str_insensitive_hash(gconstpointer v)
{
	guint hash;
	gchar *lower_str = g_ascii_strdown(v, -1);
	
	hash = g_str_hash(lower_str);
	g_free(lower_str);
	
	return hash;
}


// GNU C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include <json-glib/json-glib.h>
// Supress overzealous json-glib 'critical errors'
#define json_object_has_member(JSON_OBJECT, MEMBER) \
	(JSON_OBJECT ? json_object_has_member(JSON_OBJECT, MEMBER) : FALSE)
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)

#define json_array_get_length(JSON_ARRAY) \
	(JSON_ARRAY ? json_array_get_length(JSON_ARRAY) : 0)

static gchar *
json_object_to_string(JsonObject *obj)
{
	JsonNode *node;
	gchar *str;
	JsonGenerator *generator;
	
	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, obj);
	
	// a json string ...
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, NULL);
	g_object_unref(generator);
	json_node_free(node);
	
	return str;
}


#include <purple.h>
#if PURPLE_VERSION_CHECK(3, 0, 0)
#include <http.h>
#endif

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif

#define MATTERMOST_PLUGIN_ID "prpl-eionrobb-mattermost"
#ifndef MATTERMOST_PLUGIN_VERSION
#define MATTERMOST_PLUGIN_VERSION "1.1"
#endif
#define MATTERMOST_PLUGIN_WEBSITE "https://github.com/EionRobb/mattermost-libpurple"

#define MATTERMOST_USERAGENT "libpurple"

#define MATTERMOST_BUFFER_DEFAULT_SIZE 40960

#define MATTERMOST_DEFAULT_SERVER ""
#define MATTERMOST_SERVER_SPLIT_CHAR '|'

#define MATTERMOST_DEFAULT_BLIST_GROUP_NAME  _("Mattermost")


// Purple2 compat functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

#define purple_connection_error                 purple_connection_error_reason
#define purple_connection_get_protocol          purple_connection_get_prpl
#define PURPLE_CONNECTION_CONNECTING       PURPLE_CONNECTING
#define PURPLE_CONNECTION_CONNECTED        PURPLE_CONNECTED
#define PURPLE_CONNECTION_FLAG_HTML        PURPLE_CONNECTION_HTML
#define PURPLE_CONNECTION_FLAG_NO_BGCOLOR  PURPLE_CONNECTION_NO_BGCOLOR
#define PURPLE_CONNECTION_FLAG_NO_FONTSIZE PURPLE_CONNECTION_NO_FONTSIZE
#define PURPLE_CONNECTION_FLAG_NO_IMAGES   PURPLE_CONNECTION_NO_IMAGES
#define purple_connection_set_flags(pc, f)      ((pc)->flags = (f))
#define purple_connection_get_flags(pc)         ((pc)->flags)
#define purple_blist_find_group        purple_find_group
#define purple_protocol_get_id  purple_plugin_get_id
#define PurpleProtocolChatEntry  struct proto_chat_entry
#define PurpleChatConversation             PurpleConvChat
#define PurpleIMConversation               PurpleConvIm
#define purple_conversations_find_chat_with_account(id, account) \
		PURPLE_CONV_CHAT(purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, id, account))
#define purple_chat_conversation_has_left     purple_conv_chat_has_left
#define PurpleConversationUpdateType          PurpleConvUpdateType
#define PURPLE_CONVERSATION_UPDATE_UNSEEN     PURPLE_CONV_UPDATE_UNSEEN
#define PURPLE_IS_IM_CONVERSATION(conv)       (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM)
#define PURPLE_IS_CHAT_CONVERSATION(conv)     (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
#define PURPLE_CONVERSATION(chatorim)         (chatorim == NULL ? NULL : chatorim->conv)
#define PURPLE_IM_CONVERSATION(conv)          PURPLE_CONV_IM(conv)
#define PURPLE_CHAT_CONVERSATION(conv)        PURPLE_CONV_CHAT(conv)
#define purple_conversation_present_error     purple_conv_present_error
#define purple_serv_got_joined_chat(pc, id, name)  PURPLE_CONV_CHAT(serv_got_joined_chat(pc, id, name))
#define purple_conversations_find_chat(pc, id)  PURPLE_CONV_CHAT(purple_find_chat(pc, id))
#define purple_serv_got_chat_in                    serv_got_chat_in
#define purple_serv_got_chat_left                  serv_got_chat_left
#define purple_chat_conversation_add_user     purple_conv_chat_add_user
#define purple_chat_conversation_add_users    purple_conv_chat_add_users
#define purple_chat_conversation_remove_user  purple_conv_chat_remove_user
#define purple_chat_conversation_get_topic    purple_conv_chat_get_topic
#define purple_chat_conversation_set_topic    purple_conv_chat_set_topic
#define PurpleChatUserFlags  PurpleConvChatBuddyFlags
#define PURPLE_CHAT_USER_NONE     PURPLE_CBFLAGS_NONE
#define PURPLE_CHAT_USER_OP       PURPLE_CBFLAGS_OP
#define PURPLE_CHAT_USER_FOUNDER  PURPLE_CBFLAGS_FOUNDER
#define PURPLE_CHAT_USER_TYPING   PURPLE_CBFLAGS_TYPING
#define PURPLE_CHAT_USER_AWAY     PURPLE_CBFLAGS_AWAY
#define PURPLE_CHAT_USER_HALFOP   PURPLE_CBFLAGS_HALFOP
#define PURPLE_CHAT_USER_VOICE    PURPLE_CBFLAGS_VOICE
#define PURPLE_CHAT_USER_TYPING   PURPLE_CBFLAGS_TYPING
#define PurpleChatUser  PurpleConvChatBuddy
static inline PurpleChatUser *
purple_chat_conversation_find_user(PurpleChatConversation *chat, const char *name)
{
	PurpleChatUser *cb = purple_conv_chat_cb_find(chat, name);
	
	if (cb != NULL) {
		g_dataset_set_data(cb, "chat", chat);
	}
	
	return cb;
}
#define purple_chat_user_get_flags(cb)     purple_conv_chat_user_get_flags(g_dataset_get_data((cb), "chat"), (cb)->name)
#define purple_chat_user_set_flags(cb, f)  purple_conv_chat_user_set_flags(g_dataset_get_data((cb), "chat"), (cb)->name, (f))
#define purple_chat_user_set_alias(cb, a)  (g_free((cb)->alias), (cb)->alias = g_strdup(a))
#define PurpleIMTypingState	PurpleTypingState
#define PURPLE_IM_NOT_TYPING	PURPLE_NOT_TYPING
#define PURPLE_IM_TYPING	PURPLE_TYPING
#define PURPLE_IM_TYPED		PURPLE_TYPED
#define purple_conversation_get_connection      purple_conversation_get_gc
#define purple_conversation_write_system_message(conv, message, flags)  purple_conversation_write((conv), NULL, (message), ((flags) | PURPLE_MESSAGE_SYSTEM), time(NULL))
#define purple_chat_conversation_get_id         purple_conv_chat_get_id
#define PURPLE_CMD_FLAG_PROTOCOL_ONLY  PURPLE_CMD_FLAG_PRPL_ONLY
#define PURPLE_IS_BUDDY                PURPLE_BLIST_NODE_IS_BUDDY
#define PURPLE_IS_CHAT                 PURPLE_BLIST_NODE_IS_CHAT
#define purple_chat_get_name_only      purple_chat_get_name
static inline void
purple_chat_set_alias(PurpleChat *chat, const char *alias)
{
	PurpleBlistUiOps *ops = purple_blist_get_ui_ops();
	char *new_alias = purple_utf8_strip_unprintables(alias);
	char *old_alias = chat->alias;

	if (purple_strequal(old_alias, new_alias)) {
		g_free(new_alias);
		return;
	}
	
	if ((new_alias != NULL) && (*new_alias != '\0')) {
		chat->alias = new_alias;
	} else {
		chat->alias = NULL;
		g_free(new_alias); /* could be "\0" */
	}
	
	if (ops) {
		if (ops->save_node)
			ops->save_node((PurpleBlistNode*) chat);
		if (ops->update)
			ops->update(purple_get_blist(), (PurpleBlistNode *)chat);
	}

	purple_signal_emit(purple_blist_get_handle(), "blist-node-aliased", chat, old_alias);
	g_free(old_alias);
}

#define purple_blist_find_buddy        purple_find_buddy
#define purple_serv_got_alias                      serv_got_alias
#define purple_account_set_private_alias    purple_account_set_alias
#define purple_account_get_private_alias    purple_account_get_alias
#define purple_protocol_got_user_status		purple_prpl_got_user_status
#define purple_serv_got_im                         serv_got_im
#define purple_serv_got_typing                     serv_got_typing
#define purple_conversations_find_im_with_account(name, account)  \
		PURPLE_CONV_IM(purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account))
#define purple_im_conversation_new(account, from) PURPLE_CONV_IM(purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from))
#define PurpleMessage  PurpleConvMessage
#define purple_message_set_time(msg, time)  ((msg)->when = (time))
#define purple_conversation_write_message(conv, msg)  purple_conversation_write(conv, msg->who, msg->what, msg->flags, msg->when)
static inline PurpleMessage *
purple_message_new_outgoing(const gchar *who, const gchar *contents, PurpleMessageFlags flags)
{
	PurpleMessage *message = g_new0(PurpleMessage, 1);
	
	message->who = g_strdup(who);
	message->what = g_strdup(contents);
	message->flags = flags;
	message->when = time(NULL);
	
	return message;
}
static inline void
purple_message_destroy(PurpleMessage *message)
{
	g_free(message->who);
	g_free(message->what);
	g_free(message);
}

#define purple_message_get_recipient(message)  (message->who)
#define purple_message_get_contents(message)   (message->what)

#undef purple_notify_error
#define purple_notify_error(handle, title, primary, secondary, cpar)   \
	purple_notify_message((handle), PURPLE_NOTIFY_MSG_ERROR, (title), \
						(primary), (secondary), NULL, NULL)
#undef purple_notify_warning
#define purple_notify_warning(handle, title, primary, secondary, cpar)   \
	purple_notify_message((handle), PURPLE_NOTIFY_MSG_WARNING, (title), \
						(primary), (secondary), NULL, NULL)
#define purple_notify_user_info_add_pair_html  purple_notify_user_info_add_pair

#define purple_request_cpar_from_connection(a)  purple_connection_get_account(a), NULL, NULL

#define PurpleProtocolAction                           PurplePluginAction
#define purple_protocol_action_get_connection(action)  ((PurpleConnection *) (action)->context)
#define purple_protocol_action_new                     purple_plugin_action_new
#define purple_protocol_get_id                         purple_plugin_get_id

#define purple_account_privacy_deny_add     purple_privacy_deny_add
#define purple_account_privacy_deny_remove  purple_privacy_deny_remove
#define PurpleHttpConnection  PurpleUtilFetchUrlData
#define purple_buddy_set_name  purple_blist_rename_buddy
#if	!PURPLE_VERSION_CHECK(2, 12, 0)
#	define PURPLE_MESSAGE_REMOTE_SEND  0x10000
#endif

#else
// Purple3 helper functions
#define purple_conversation_set_data(conv, key, value)  g_object_set_data(G_OBJECT(conv), key, value)
#define purple_conversation_get_data(conv, key)         g_object_get_data(G_OBJECT(conv), key)
#define purple_message_destroy          g_object_unref
#define purple_chat_user_set_alias(cb, alias)  g_object_set((cb), "alias", (alias), NULL)
#define purple_chat_get_alias(chat)  g_object_get_data(G_OBJECT(chat), "alias")
#define purple_protocol_action_get_connection(action)  ((action)->connection)

//TODO remove this when dx adds this to the PurpleMessageFlags enum
#define PURPLE_MESSAGE_REMOTE_SEND  0x10000
#endif



typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	gchar *self_user_id;
	gchar *self_username;
	
	gchar *current_channel_id;
	gchar *last_channel_id;
	guint read_messages_timeout;
	gint64 last_message_timestamp;
	gint64 last_load_last_message_timestamp;
	guint idle_timeout;
	
	gchar *username;
	gchar *server;
	
	PurpleSslConnection *websocket;
	guint websocket_inpa;
	gint websocket_fd;
	
	gboolean websocket_header_received;
	gboolean sync_complete;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;
	
	gint seq; //incrementing counter
	gint roomlist_team_count;
	
	GHashTable *one_to_ones;      // A store of known room_id's -> username's
	GHashTable *one_to_ones_rev;  // A store of known usernames's -> room_id's
	GHashTable *group_chats;      // A store of known multi-user room_id's -> room name's
	GHashTable *group_chats_rev;  // A store of known multi-user room name's -> room_id's
	GHashTable *sent_message_ids; // A store of message id's that we generated from this instance
	GHashTable *result_callbacks; // Result ID -> Callback function
	GHashTable *usernames_to_ids; // username -> user id
	GHashTable *ids_to_usernames; // user id -> username
	GHashTable *teams;            // A list of known team_id's -> team names
	GHashTable *channel_teams;    // A list of channel_id -> team_id to know what team a channel is in
	GQueue *received_message_queue; // A store of the last 10 received message id's for de-dup

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
	GSList *pending_writes;
} MattermostAccount;

typedef void (*MattermostProxyCallbackFunc)(MattermostAccount *ma, JsonNode *node, gpointer user_data);

typedef struct {
	MattermostAccount *ma;
	MattermostProxyCallbackFunc callback;
	gpointer user_data;
} MattermostProxyConnection;



//#include <mkdio.h>
extern char markdown_version[];
int mkd_line(char *, int, char **, int);

#define MKD_NOLINKS	0x00000001	/* don't do link processing, block <a> tags  */
#define MKD_NOIMAGE	0x00000002	/* don't do image processing, block <img> */
#define MKD_NOPANTS	0x00000004	/* don't run smartypants() */
#define MKD_NOHTML	0x00000008	/* don't allow raw html through AT ALL */
#define MKD_STRICT	0x00000010	/* disable SUPERSCRIPT, RELAXED_EMPHASIS */
#define MKD_TAGTEXT	0x00000020	/* process text inside an html tag; no
					 * <em>, no <bold>, no html or [] expansion */
#define MKD_NO_EXT	0x00000040	/* don't allow pseudo-protocols */
#define MKD_NOEXT	MKD_NO_EXT	/* ^^^ (aliased for user convenience) */
#define MKD_CDATA	0x00000080	/* generate code for xml ![CDATA[...]] */
#define MKD_NOSUPERSCRIPT 0x00000100	/* no A^B */
#define MKD_NORELAXED	0x00000200	/* emphasis happens /everywhere/ */
#define MKD_NOTABLES	0x00000400	/* disallow tables */
#define MKD_NOSTRIKETHROUGH 0x00000800	/* forbid ~~strikethrough~~ */
#define MKD_TOC		0x00001000	/* do table-of-contents processing */
#define MKD_1_COMPAT	0x00002000	/* compatibility with MarkdownTest_1.0 */
#define MKD_AUTOLINK	0x00004000	/* make http://foo.com link even without <>s */
#define MKD_SAFELINK	0x00008000	/* paranoid check for link protocol */
#define MKD_NOHEADER	0x00010000	/* don't process header blocks */
#define MKD_TABSTOP	0x00020000	/* expand tabs to 4 spaces */
#define MKD_NODIVQUOTE	0x00040000	/* forbid >%class% blocks */
#define MKD_NOALPHALIST	0x00080000	/* forbid alphabetic lists */
#define MKD_NODLIST	0x00100000	/* forbid definition lists */
#define MKD_EXTRA_FOOTNOTE 0x00200000	/* enable markdown extra-style footnotes */
#define MKD_NOSTYLE	0x00400000	/* don't extract <style> blocks */
#define MKD_NODLDISCOUNT 0x00800000	/* disable discount-style definition lists */
#define	MKD_DLEXTRA	0x01000000	/* enable extra-style definition lists */
#define MKD_FENCEDCODE	0x02000000	/* enabled fenced code blocks */
#define MKD_IDANCHOR	0x04000000	/* use id= anchors for TOC links */
#define MKD_GITHUBTAGS	0x08000000	/* allow dash and underscore in element names */
#define MKD_URLENCODEDANCHOR 0x10000000 /* urlencode non-identifier chars instead of replacing with dots */
#define MKD_LATEX	0x40000000	/* handle embedded LaTeX escapes */

#define MKD_EMBED	MKD_NOLINKS|MKD_NOIMAGE|MKD_TAGTEXT

static gchar *
mm_markdown_to_html(const gchar *markdown)
{
	static char *markdown_str = NULL;
	int markdown_len;
	int flags = MKD_NOPANTS | MKD_NODIVQUOTE | MKD_NODLIST;
	static gboolean markdown_version_checked = FALSE;
	static gboolean markdown_version_safe = FALSE;
	
	if (markdown == NULL) {
		return NULL;
	}
	
	if (!markdown_version_checked) {
		gchar **markdown_version_split = g_strsplit_set(	markdown_version, ". ", -1);
		gchar *last_part;
		guint i = 0;

		do {
			last_part = markdown_version_split[i++];
		} while (markdown_version_split[i] != NULL);
		
		if (!purple_strequal(last_part, "DEBUG")) {
			markdown_version_safe = TRUE;
		} else {
			gint major, minor, micro;
			major = atoi(markdown_version_split[0]);
			if (major > 2) {
				markdown_version_safe = TRUE;
			} else if (major == 2) {
				minor = atoi(markdown_version_split[1]);
				if (minor > 2) {
					markdown_version_safe = TRUE;
				} else if (minor == 2) {
					micro = atoi(markdown_version_split[2]);
					if (micro > 2) {
						markdown_version_safe = TRUE;
					}
				}
			}
		}
		
		g_strfreev(markdown_version_split);
		markdown_version_checked = TRUE;
	}
	
	if (markdown_str != NULL) {
		// if libmarkdown is pre-2.2.2 and we're using amalloc, don't free()
		if (markdown_version_safe) {
			free(markdown_str);
		}
	}
	
	markdown_len = mkd_line((char *)markdown, strlen(markdown), &markdown_str, flags);

	if (markdown_len < 0) {
		return NULL;
	}
	
	return g_strndup(markdown_str, markdown_len);
}



static void
mm_markup_anchor_parse_text(GMarkupParseContext *context, const gchar *text, gsize text_len, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	g_string_prepend_len(output, text, text_len);
}

static GMarkupParser mm_markup_anchor_parser = {
	NULL,
	NULL,
	mm_markup_anchor_parse_text,
	NULL,
	NULL
};

static void
mm_markdown_parse_start_element(GMarkupParseContext *context, const gchar *element_name, const gchar **attribute_names, const gchar **attribute_values, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	switch(g_str_hash(element_name)) {
		case 0x2b607: case 0x2b5e7: //B
			g_string_append(output, "**");
			break;
		case 0x2b60e: case 0x2b5ee: //I
		case 0x5977b7: case 0x597377: //EM
			g_string_append_c(output, '_');
			break;
		case 0x597759: case 0x597319: //BR
			g_string_append_c(output, '\n');
			break;
		case 0xb8869ba: case 0xb87dd5a: //DEL
		case 0x2b618: case 0x2b5f8: //S
		case 0x1c93af97: case 0xcf9972d7: //STRIKE
			g_string_append(output, "~~");
			break;
		case 0x2b606: case 0x2b5e6: //A
		{
			const gchar **name_cursor = attribute_names;
			const gchar **value_cursor = attribute_values;
			GString *href_string = g_string_new("](");
			
			while (*name_cursor) {
				if (g_ascii_strncasecmp(*name_cursor, "href", -1) == 0) {
					g_string_append(href_string, *value_cursor);
					break;
				}
				name_cursor++;
				value_cursor++;
			}
		
			g_string_append_c(output, '[');
			g_markup_parse_context_push(context, &mm_markup_anchor_parser, href_string);
			break;
		}
	}
	
}

static void
mm_markdown_parse_end_element(GMarkupParseContext *context, const gchar *element_name, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	switch(g_str_hash(element_name)) {
		case 0x2b607: case 0x2b5e7: //B
			g_string_append(output, "**");
			break;
		case 0x2b60e: case 0x2b5ee: //I
		case 0x5977b7: case 0x597377: //EM
			g_string_append_c(output, '_');
			break;
		case 0xb8869ba: case 0xb87dd5a: //DEL
		case 0x2b618: case 0x2b5f8: //S
		case 0x1c93af97: case 0xcf9972d7: //STRIKE
			g_string_append(output, "~~");
			break;
		case 0x2b606: case 0x2b5e6: //A
		{
			GString *href_string = g_markup_parse_context_pop(context);
			g_string_append_printf(output, "%s)", href_string->str);
			g_string_free(href_string, TRUE);
			break;
		}
	}
	
}

static void
mm_markdown_parse_text(GMarkupParseContext *context, const gchar *text, gsize text_len, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	g_string_append_len(output, text, text_len);
}

static GMarkupParser mm_markup_markdown_parser = {
	mm_markdown_parse_start_element,
	mm_markdown_parse_end_element,
	mm_markdown_parse_text,
	NULL,
	NULL
};

static gchar *
mm_html_to_markdown(const gchar *html)
{
	GString *output = g_string_new(NULL);
	GMarkupParseContext *context;
	
	context = g_markup_parse_context_new(&mm_markup_markdown_parser, G_MARKUP_TREAT_CDATA_AS_TEXT, output, NULL);
	g_markup_parse_context_parse(context, "<html>", -1, NULL);	
	g_markup_parse_context_parse(context, html, -1, NULL);	
	g_markup_parse_context_parse(context, "</html>", -1, NULL);	
	g_markup_parse_context_end_parse(context, NULL);
	g_markup_parse_context_free(context);
	
	return g_string_free(output, FALSE);
}



static gint
mm_get_next_seq(MattermostAccount *ma)
{
	return ma->seq++;
}

static gint
mm_get_next_seq_callback(MattermostAccount *ma, MattermostProxyCallbackFunc callback, gpointer user_data)
{
	gint seq = mm_get_next_seq(ma);
	MattermostProxyConnection *proxy = g_new0(MattermostProxyConnection, 1);
	
	proxy->ma = ma;
	proxy->callback = callback;
	proxy->user_data = user_data;
	
	g_hash_table_insert(ma->result_callbacks, GINT_TO_POINTER(seq), proxy);
	
	return seq;
}

gchar *
mm_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end)
{
	const gchar *chunk_start, *chunk_end;
	g_return_val_if_fail(haystack && start && end, NULL);
	
	if (len > 0) {
		chunk_start = g_strstr_len(haystack, len, start);
	} else {
		chunk_start = strstr(haystack, start);
	}
	g_return_val_if_fail(chunk_start, NULL);
	chunk_start += strlen(start);
	
	if (len > 0) {
		chunk_end = g_strstr_len(chunk_start, len - (chunk_start - haystack), end);
	} else {
		chunk_end = strstr(chunk_start, end);
	}
	g_return_val_if_fail(chunk_end, NULL);
	
	return g_strndup(chunk_start, chunk_end - chunk_start);
}

#if PURPLE_VERSION_CHECK(3, 0, 0)
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

#else
static void
mm_update_cookies(MattermostAccount *ma, const gchar *headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	int header_len;

	g_return_if_fail(headers != NULL);

	header_len = strlen(headers);

	/* look for the next "Set-Cookie: " */
	/* grab the data up until ';' */
	cookie_start = headers;
	while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) && (cookie_start - headers) < header_len)
	{
		cookie_start += 14;
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
#endif

static void
mm_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
mm_cookies_to_string(MattermostAccount *ma)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ma->cookie_table, (GHFunc)mm_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void
mm_response_callback(PurpleHttpConnection *http_conn, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
	const gchar *error_message = purple_http_response_get_error(response);
#else
gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
#endif
	const gchar *body;
	gsize body_len;
	MattermostProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();
	
	conn->ma->http_conns = g_slist_remove(conn->ma->http_conns, http_conn);

#if !PURPLE_VERSION_CHECK(3, 0, 0)
	mm_update_cookies(conn->ma, url_text);
	
	body = g_strstr_len(url_text, len, "\r\n\r\n");
	body = body ? body + 4 : body;
	body_len = len - (body - url_text);
#else
	mm_update_cookies(conn->ma, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

	body = url_text;
	body_len = len;
#endif
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
mm_fetch_url(MattermostAccount *ma, const gchar *url, const gchar *postdata, MattermostProxyCallbackFunc callback, gpointer user_data)
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

#if PURPLE_VERSION_CHECK(3, 0, 0)
	
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
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		purple_http_request_set_contents(request, postdata, -1);
	}
	
	http_conn = purple_http_request(ma->pc, request, mm_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL)
		ma->http_conns = g_slist_prepend(ma->http_conns, http_conn);

#else
	GString *headers;
	gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
	int port;
	purple_url_parse(url, &host, &port, &path, &user, &password);
	
	headers = g_string_new(NULL);
	
	//Use the full 'url' until libpurple can handle path's longer than 256 chars
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), path);
	//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
	g_string_append_printf(headers, "Connection: close\r\n");
	g_string_append_printf(headers, "Host: %s\r\n", host);
	g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: " MATTERMOST_USERAGENT "\r\n");
	g_string_append_printf(headers, "Cookie: %s\r\n", cookies);
	if (ma->session_token) {
		g_string_append_printf(headers, "Authorization: Bearer %s\r\n", ma->session_token);
	}

	if (postdata) {
		purple_debug_info("mattermost", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			g_string_append(headers, "Content-Type: application/json\r\n");
		} else {
			g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
		}
		g_string_append_printf(headers, "Content-Length: %" G_GSIZE_FORMAT "\r\n", strlen(postdata));
		g_string_append(headers, "\r\n");

		g_string_append(headers, postdata);
	} else {
		g_string_append(headers, "\r\n");
	}

	g_free(host);
	g_free(path);
	g_free(user);
	g_free(password);

	http_conn = purple_util_fetch_url_request_len_with_account(ma->account, url, FALSE, MATTERMOST_USERAGENT, TRUE, headers->str, TRUE, 6553500, mm_response_callback, conn);
	
	if (http_conn != NULL)
		ma->http_conns = g_slist_prepend(ma->http_conns, http_conn);

	g_string_free(headers, TRUE);
#endif

	g_free(cookies);
}

static const gchar *
mm_get_first_team_id(MattermostAccount *ma)
{
	GList *team_ids = g_hash_table_get_keys(ma->teams);
	const gchar *first_team_id = team_ids ? team_ids->data : NULL;
	
	g_list_free(team_ids);
	
	return first_team_id;
}

PurpleGroup* mm_get_or_create_default_group();
static void mm_get_history_of_room(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, gint64 since);
static void mm_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message);

static void mm_start_socket(MattermostAccount *ma);
static void mm_socket_write_json(MattermostAccount *ma, JsonObject *data);

static void
mm_add_channels_to_blist(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *team_id = user_data;
	JsonArray *channels = json_node_get_array(node);
	guint i, len = json_array_get_length(channels);
	PurpleGroup *default_group = mm_get_or_create_default_group();
			
	for (i = 0; i < len; i++) {
		JsonObject *channel = json_array_get_object_element(channels, i);
		const gchar *id = json_object_get_string_member(channel, "id");
		const gchar *name = json_object_get_string_member(channel, "display_name");
		const gchar *room_type = json_object_get_string_member(channel, "type");
		
		if (room_type && *room_type == 'D') {
			if (!g_hash_table_contains(ma->one_to_ones, id)) {
				gchar **buddy_names = g_strsplit(json_object_get_string_member(channel, "name"), "__", 2);
				gchar *user_id = NULL;
				gchar *username = NULL;
				PurpleBuddy *buddy = NULL;
				
				if (purple_strequal(buddy_names[0], ma->self_user_id)) {
					user_id = buddy_names[1];
				} else {
					user_id = buddy_names[0];
				}
				if (user_id != NULL) {
					username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
					if (username != NULL) {
						buddy = purple_blist_find_buddy(ma->account, username);
						if (buddy == NULL) {
							buddy = purple_buddy_new(ma->account, username, NULL);
							purple_blist_add_buddy(buddy, NULL, default_group, NULL);
							mm_add_buddy(ma->pc, buddy, NULL, NULL);
						}
						
						purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", id);
						g_hash_table_replace(ma->one_to_ones, g_strdup(id), g_strdup(username));
						g_hash_table_replace(ma->one_to_ones_rev, g_strdup(username), g_strdup(id));
					}
				}
				
				g_strfreev(buddy_names);
				
				//TODO if buddy is still NULL, look for details by channel_id
			}
			
			//fetch offline history
			mm_get_history_of_room(ma, team_id, id, ma->last_load_last_message_timestamp);
		} else {
			if (!g_hash_table_contains(ma->group_chats, id)) {
				PurpleChat *chat = NULL;
				GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
				
				g_hash_table_insert(defaults, "team_id", g_strdup(team_id));
				g_hash_table_insert(defaults, "id", g_strdup(id));
				g_hash_table_insert(defaults, "name", g_strdup(name));
				
				chat = purple_chat_new(ma->account, name, defaults);
				purple_blist_add_chat(chat, default_group, NULL);
				
				purple_blist_node_set_string(PURPLE_BLIST_NODE(chat), "room_id", id);
				g_hash_table_replace(ma->group_chats, g_strdup(id), g_strdup(name));
				g_hash_table_replace(ma->group_chats_rev, g_strdup(name), g_strdup(id));
				
				purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-persistent", TRUE);
			}
		}
	}
		
	g_free(team_id);
}

static void
mm_get_open_channels_for_team(MattermostAccount *ma, const gchar *team_id)
{
	gchar *url;
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/", team_id);
	mm_fetch_url(ma, url, NULL, mm_add_channels_to_blist, g_strdup(team_id));
	g_free(url);
}

gboolean mm_idle_updater_timeout(gpointer data);

static void
mm_got_teams(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response = json_node_get_object(node);
	GList *teams = json_object_get_values(response);
	GList *i;
	
	for (i = teams; i; i = i->next) {
		JsonNode *member = i->data;
		JsonObject *team = json_node_get_object(member);
		
		const gchar *team_id = json_object_get_string_member(team, "id");
		const gchar *display_name = json_object_get_string_member(team, "display_name");
		
		g_hash_table_replace(ma->teams, g_strdup(team_id), g_strdup(display_name));
		
		mm_get_open_channels_for_team(ma, team_id);
	}
	
	g_list_free(teams);
	
	purple_connection_set_state(ma->pc, PURPLE_CONNECTION_CONNECTED);
	
	// Update our idleness every 4.5 minutes
	ma->idle_timeout = purple_timeout_add_seconds(270, mm_idle_updater_timeout, ma->pc);
}


static void
mm_info_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
        JsonObject *user = json_node_get_object(node);
        PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();

        PurpleBuddy *buddy = user_data;
        const gchar *nickname;
        const gchar *first_name;
        const gchar *last_name;
        const gchar *email;

        nickname = json_object_get_string_member(user, "nickname");
        if (nickname && *nickname) {
                purple_notify_user_info_add_pair_plaintext(user_info,"Nickname", nickname);
        }

        first_name = json_object_get_string_member(user, "first_name");
        if (first_name && *first_name) {
                purple_notify_user_info_add_pair_plaintext(user_info,"First Name", first_name);
        }

        last_name = json_object_get_string_member(user, "last_name");
        if (last_name && *last_name) {
                purple_notify_user_info_add_pair_plaintext(user_info,"Last Name", last_name);
        }

        email = json_object_get_string_member(user, "email");
        if (email && *email) {
                purple_notify_user_info_add_pair_plaintext(user_info,"Email address", email);
        }

        purple_notify_userinfo(ma->pc, purple_buddy_get_name(buddy), user_info, NULL, NULL);

        purple_notify_user_info_destroy(user_info);
}

static void
mm_get_info(PurpleConnection *pc,const gchar *username)
{
        MattermostAccount *ma = purple_connection_get_protocol_data(pc);
        PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, username);
        gchar *url;

        if (buddy == NULL) {
                buddy = purple_buddy_new(ma->account, username, NULL);
        }

        url = mm_build_url(ma, "/api/v3/users/name/%s", username);
        mm_fetch_url(ma, url, NULL, mm_info_response, buddy);
        g_free(url);
}


static void 
mm_set_me(MattermostAccount *ma)
{

	if (!purple_account_get_private_alias(ma->account)) {
		purple_account_set_private_alias(ma->account, ma->self_username); 
	}

	purple_connection_set_display_name(ma->pc, ma->self_username);
	
	g_hash_table_replace(ma->ids_to_usernames, g_strdup(ma->self_user_id), g_strdup(ma->self_username));
	g_hash_table_replace(ma->usernames_to_ids, g_strdup(ma->self_username), g_strdup(ma->self_user_id));
 
}

static void
mm_get_teams(MattermostAccount *ma)
{
	gchar *url;

	mm_start_socket(ma);

	url = mm_build_url(ma, "/api/v3/teams/all");
	mm_fetch_url(ma, url, NULL, mm_got_teams, NULL);
	g_free(url);
	
}
static void
mm_me_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response;

        if (node == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Invalid or expired Gitlab cookie");
		return;
	}

        response = json_node_get_object(node);

        if (json_object_get_int_member(response, "status_code") >= 400) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, g_strconcat(json_object_get_string_member(response, "message"),"(Invalid or expired Gitlab cookie)",NULL));
	        return;
        }

        g_free(ma->self_user_id);
	ma->self_user_id = g_strdup(json_object_get_string_member(response, "id"));
	g_free(ma->self_username);
	ma->self_username = g_strdup(json_object_get_string_member(response, "username"));
        
	if (!ma->self_user_id || !ma->self_username) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "User ID/Name not received from server");
		return;
	}
	
        mm_set_me(ma);
	mm_get_teams(ma);

}

static void
mm_login_response(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *response;

	if (node == NULL) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Bad username/password");
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
	
	g_free(ma->self_user_id);
	ma->self_user_id = g_strdup(json_object_get_string_member(response, "id"));
	g_free(ma->self_username);
	ma->self_username = g_strdup(json_object_get_string_member(response, "username"));
	
	if (!ma->self_user_id || !ma->self_username) {
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "User ID/Name not received from server");
		return;
	}

	mm_set_me(ma);
	mm_get_teams(ma);
	
}

static PurpleChatUserFlags
mm_role_to_purple_flag(MattermostAccount *ma, const gchar *rolelist)
{
	PurpleChatUserFlags flags = PURPLE_CHAT_USER_NONE;
	gchar **roles = g_strsplit_set(rolelist, " ", -1);
	gint i;
	
	for(i = 0; roles[i]; i++) {
		const gchar *role = roles[i];
		
		if (purple_strequal(role, "channel_user")) {
			
		} else if (purple_strequal(role, "channel_admin")) {
			flags |= PURPLE_CHAT_USER_OP;
		}
	}
	
	g_strfreev(roles);
	
	return flags;
}

typedef struct {
	gchar *channel_id;
	gchar *file_id;
	gchar *sender;
	gint64 timestamp;
} MattermostChannelLink;

static void
mm_got_link_for_channel(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	const gchar *url = json_node_get_string(node);
	MattermostChannelLink *info = user_data;
	PurpleMessageFlags msg_flags = (purple_strequal(info->sender, ma->self_username) ? PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED : PURPLE_MESSAGE_RECV);
	
	if (g_hash_table_contains(ma->group_chats, info->channel_id)) {
		purple_serv_got_chat_in(ma->pc, g_str_hash(info->channel_id), info->sender, msg_flags, url, info->timestamp);
	} else {
		if (msg_flags == PURPLE_MESSAGE_RECV) {
			purple_serv_got_im(ma->pc, info->sender, url, msg_flags, info->timestamp);
		} else {
			const gchar *other_user = g_hash_table_lookup(ma->one_to_ones, info->channel_id);
			// TODO null check
			PurpleIMConversation *imconv = purple_conversations_find_im_with_account(other_user, ma->account);
			PurpleMessage *pmsg = purple_message_new_outgoing(other_user, url, msg_flags);
			
			if (imconv == NULL) {
				imconv = purple_im_conversation_new(ma->account, other_user);
			}
			purple_message_set_time(pmsg, info->timestamp);
			purple_conversation_write_message(PURPLE_CONVERSATION(imconv), pmsg);
			purple_message_destroy(pmsg);
		}
	}
	
	g_free(info->channel_id);
	g_free(info->file_id);
	g_free(info->sender);
	g_free(info);
}

static void
mm_fetch_file_link_for_channel(MattermostAccount *ma, const gchar *file_id, const gchar *channel_id, const gchar *username, gint64 timestamp)
{
	MattermostChannelLink *info = g_new0(MattermostChannelLink, 1);
	gchar *url;
	
	info->channel_id = g_strdup(channel_id);
	info->file_id = g_strdup(file_id);
	info->sender = g_strdup(username);
	info->timestamp = timestamp;
	
	url = mm_build_url(ma, "/api/v3/files/%s/get_public_link", file_id);
	
	mm_fetch_url(ma, url, NULL, mm_got_link_for_channel, info);
	
	g_free(url);
}


static gint64 mm_get_room_last_timestamp(MattermostAccount *ma, const gchar *room_id);
static void mm_set_room_last_timestamp(MattermostAccount *ma, const gchar *room_id, gint64 last_timestamp);

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
	const gchar *pending_post_id = json_object_get_string_member(post, "pending_post_id");
	const gchar *room_name = g_hash_table_lookup(ma->group_chats, channel_id);
	gint64 update_at = json_object_get_int_member(post, "update_at");
	gint64 timestamp = update_at / 1000;
	PurpleMessageFlags msg_flags = (purple_strequal(user_id, ma->self_user_id) ? PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_REMOTE_SEND | PURPLE_MESSAGE_DELAYED : PURPLE_MESSAGE_RECV);
	
	if (username != NULL && !g_hash_table_contains(ma->ids_to_usernames, user_id)) {
		g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
		g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));
	} else if (username == NULL) {
		username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
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
			gchar *message = mm_markdown_to_html(msg_text);
			
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
					
					mm_fetch_file_link_for_channel(ma, file_id, channel_id, username, timestamp);
				}
			}
			
			if ((channel_type != NULL && *channel_type != 'D') || g_hash_table_contains(ma->group_chats, channel_id)) {
				PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
				// PurpleChatUser *cb;
				
				if (room_name == NULL) {
					PurpleChat *chat = purple_blist_find_chat(ma->account, channel_id);
					
					room_name = json_object_get_string_member(data, "channel_display_name");
					
					g_hash_table_replace(ma->group_chats, g_strdup(channel_id), g_strdup(room_name));
					g_hash_table_replace(ma->group_chats_rev, g_strdup(room_name), g_strdup(channel_id));
					
					if (chat != NULL) {
						GHashTable *defaults = purple_chat_get_components(chat);
						g_hash_table_insert(defaults, "name", g_strdup(room_name));
						
						purple_chat_set_alias(chat, room_name);
					}
				}
				if (chatconv == NULL) {
					chatconv = purple_conversations_find_chat_with_account(room_name, ma->account);
				}
				if (chatconv == NULL) {
					chatconv = purple_conversations_find_chat_with_account(channel_id, ma->account);
				}
				
				if (purple_strequal(msg_type, "system_header_change")) {
					JsonObject *props = json_object_get_object_member(post, "props");
					const gchar *new_topic = json_object_get_string_member(props, "new_header");
					const gchar *new_topic_who = json_object_get_string_member(props, "username");
					
					purple_chat_conversation_set_topic(chatconv, new_topic_who, new_topic);
				}
				
				// Group chat message
				purple_serv_got_chat_in(ma->pc, g_str_hash(channel_id), username, msg_flags, message, timestamp);
				
				if (purple_conversation_has_focus(PURPLE_CONVERSATION(chatconv))) {
					mm_mark_room_messages_read(ma, channel_id);
				}
				
			} else {
				if (msg_flags == PURPLE_MESSAGE_RECV) {
					purple_serv_got_im(ma->pc, username, message, msg_flags, timestamp);
					
					if (channel_type && *channel_type == 'D' && !g_hash_table_contains(ma->one_to_ones, channel_id)) {
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

// Helper function for picking from either 'data' or 'broadcast', since values can be in either depending on who added/removed
#define	mm_data_or_broadcast_string(a) (json_object_has_member(data, (a)) ? json_object_get_string_member(data, (a)) : json_object_get_string_member(broadcast, (a)))

static void
mm_process_msg(MattermostAccount *ma, JsonNode *element_node)
{
	//JsonObject *response = NULL;
	JsonObject *obj = json_node_get_object(element_node);

	const gchar *event = json_object_get_string_member(obj, "event");
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
	
	if (purple_strequal(event, "posted") || purple_strequal(event, "post_edited")) {
		gint64 last_message_timestamp;
		JsonParser *post_parser = json_parser_new();
		const gchar *post_str = json_object_get_string_member(data, "post");
		
		if (json_parser_load_from_data(post_parser, post_str, -1, NULL)) {
			JsonObject *post = json_node_get_object(json_parser_get_root(post_parser));
			const gchar *channel_id = json_object_get_string_member(post, "channel_id");
			
			last_message_timestamp = mm_process_room_message(ma, post, data);
			
			mm_set_room_last_timestamp(ma, channel_id, last_message_timestamp);
		}
		g_object_unref(post_parser);
	} else if (purple_strequal(event, "typing")) {		
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *user_id = mm_data_or_broadcast_string("user_id");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
		
		if (g_hash_table_contains(ma->group_chats, channel_id)) {
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
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
		
		if (chatconv != NULL) {
			purple_chat_conversation_add_user(chatconv, username, NULL, PURPLE_CHAT_USER_NONE, FALSE);
		} else if (purple_strequal(user_id, ma->self_user_id) && !g_hash_table_contains(ma->group_chats, channel_id)) {
			const gchar *team_id = mm_data_or_broadcast_string("team_id");
			PurpleChat *chat = NULL;
			GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
			
			g_hash_table_insert(defaults, "team_id", g_strdup(team_id));
			g_hash_table_insert(defaults, "id", g_strdup(channel_id));
			
			chat = purple_chat_new(ma->account, channel_id, defaults);
			purple_blist_add_chat(chat, mm_get_or_create_default_group(), NULL);
			
			purple_blist_node_set_string(PURPLE_BLIST_NODE(chat), "room_id", channel_id);
			g_hash_table_replace(ma->group_chats, g_strdup(channel_id), NULL);
			
			purple_blist_node_set_bool(PURPLE_BLIST_NODE(chat), "gtk-persistent", TRUE);
		}
		
	} else if (purple_strequal(event, "user_removed")) {
		const gchar *channel_id = mm_data_or_broadcast_string("channel_id");
		const gchar *user_id = mm_data_or_broadcast_string("user_id");
		const gchar *username = g_hash_table_lookup(ma->ids_to_usernames, user_id);
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
		if (chatconv != NULL) {
			purple_chat_conversation_remove_user(chatconv, username, NULL);
			
			if (purple_strequal(user_id, ma->self_user_id)) {
				purple_serv_got_chat_left(ma->pc, g_str_hash(channel_id));
				g_hash_table_remove(ma->group_chats, channel_id);
				purple_blist_remove_chat(purple_blist_find_chat(ma->account, channel_id));
			}
		}
		
	} else if (purple_strequal(event, "hello")) {
		JsonObject *data_inside;
		//JsonArray *user_ids;
		
		data = json_object_new();
		data_inside = json_object_new();
		
		//json_object_set_string_member(data_inside, "user_ids", user_ids);
			
		json_object_set_string_member(data, "action", "get_statuses");
		json_object_set_object_member(data, "data", data_inside);
		json_object_set_int_member(data, "seq", mm_get_next_seq_callback(ma, mm_got_hello_user_statuses, NULL));
		
		mm_socket_write_json(ma, data);
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

typedef struct {
	PurpleRoomlist *roomlist;
	gchar *team_id;
} MatterMostTeamRoomlist;

static void
mm_roomlist_got_list(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	MatterMostTeamRoomlist *mmtrl = user_data;
	PurpleRoomlist *roomlist = mmtrl->roomlist;
	JsonArray *channels = json_node_get_array(node);
	guint i, len = json_array_get_length(channels);
	PurpleRoomlistRoom *team_category = NULL;
	const gchar *team_id = mmtrl->team_id;
	const gchar *team_name;
	
	team_name = g_hash_table_lookup(ma->teams, team_id);
	
	team_category = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, team_name, NULL);
	purple_roomlist_room_add_field(roomlist, team_category, team_id);
	purple_roomlist_room_add(roomlist, team_category);
			
	for (i = 0; i < len; i++) {
		JsonObject *channel = json_array_get_object_element(channels, i);
		const gchar *id = json_object_get_string_member(channel, "id");
		const gchar *name = json_object_get_string_member(channel, "display_name");
		const gchar *room_type = json_object_get_string_member(channel, "type");
		PurpleRoomlistRoom *room;
		const gchar *type_str;
		
		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, name, team_category);
		
		purple_roomlist_room_add_field(roomlist, room, id);
		purple_roomlist_room_add_field(roomlist, room, name);
		if (room_type == NULL) {
			room_type = "";
		}
		switch(*room_type) {
			case 'O': type_str = _("Open"); break;
			case 'P': type_str = _("Private"); break;
			case 'D': type_str = _("Direct"); break;
			case 'G': type_str = _("Group"); break;
			default:  type_str = _("Unknown"); break;
		}
		purple_roomlist_room_add_field(roomlist, room, type_str);
		
		purple_roomlist_room_add(roomlist, room);
		
		g_hash_table_replace(ma->group_chats, g_strdup(id), g_strdup(name));
		g_hash_table_replace(ma->group_chats_rev, g_strdup(name), g_strdup(id));
		
		g_hash_table_replace(ma->channel_teams, g_strdup(id), g_strdup(team_id));
	}
	
	//Only after last team
	ma->roomlist_team_count--;
	if (ma->roomlist_team_count <= 0) {
		purple_roomlist_set_in_progress(roomlist, FALSE);
		ma->roomlist_team_count = 0;
	}
	
	g_free(mmtrl->team_id);
	g_free(mmtrl);
}

static gchar *
mm_roomlist_serialize(PurpleRoomlistRoom *room) {
	GList *fields = purple_roomlist_room_get_fields(room);
	const gchar *id = (const gchar *) fields->data;
	const gchar *name = (const gchar *) fields->next->data;
	
	PurpleRoomlistRoom *team_category = purple_roomlist_room_get_parent(room);
	GList *team_fields = purple_roomlist_room_get_fields(team_category);
	const gchar *team_id = (const gchar *) team_fields->data;
	
	return g_strconcat(team_id, "/", id, "/", name, NULL);
}

//roomlist_deserialize
static GHashTable *
mm_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	
	if (chatname != NULL)
	{
		gchar **chat_parts = g_strsplit_set(chatname, "/", 3);
		
		if (chat_parts[0]) {
			g_hash_table_insert(defaults, "team_id", g_strdup(chat_parts[0]));
			if (chat_parts[1]) {
				g_hash_table_insert(defaults, "id", g_strdup(chat_parts[1]));
				if (chat_parts[2]) {
					g_hash_table_insert(defaults, "name", g_strdup(chat_parts[2]));
				}
			}
		}
		
		g_strfreev(chat_parts);
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

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Name"), "name", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Type"), "t", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);
	
	//Loop through teams and look for channels within each
	for(i = teams = g_hash_table_get_keys(ma->teams); i; i = i->next)
	{
		MatterMostTeamRoomlist *mmtrl;
		const gchar *team_id = i->data;
		
		// Get a list of channels the user has already joined
		mmtrl = g_new0(MatterMostTeamRoomlist, 1);
		mmtrl->team_id = g_strdup(team_id);
		mmtrl->roomlist = roomlist;
		
		url = mm_build_url(ma, "/api/v3/teams/%s/channels/", team_id);
		mm_fetch_url(ma, url, NULL, mm_roomlist_got_list, mmtrl);
		g_free(url);
		
		ma->roomlist_team_count++;
		
		
		// Get a list of channels the user has *not* yet joined
		mmtrl = g_new0(MatterMostTeamRoomlist, 1);
		mmtrl->team_id = g_strdup(team_id);
		mmtrl->roomlist = roomlist;
		
		url = mm_build_url(ma, "/api/v3/teams/%s/channels/more/0/9999", team_id);
		mm_fetch_url(ma, url, NULL, mm_roomlist_got_list, mmtrl);
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
	
	return TRUE;
}

void
mm_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const char *status_id = purple_status_get_id(status);
	JsonObject *data;
	const gchar *team_id = mm_get_first_team_id(ma);
	gchar *cmd = g_strconcat("/", status_id, NULL);
	gchar *postdata, *url;
	
	data = json_object_new();
	json_object_set_string_member(data, "command", cmd);
	json_object_set_string_member(data, "channel_id", "");
	postdata = json_object_to_string(data);
	
	url = mm_build_url(ma, "/api/v3/teams/%s/commands/execute", team_id);
	mm_fetch_url(ma, url, postdata, NULL, NULL);
	g_free(url);
	
	g_free(postdata);
	json_object_unref(data);
	g_free(cmd);
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
			const gchar *room_id;
			const gchar *team_id;
			const gchar *name;
			PurpleChat *chat = PURPLE_CHAT(node);
			if (purple_chat_get_account(chat) != ma->account) {
				continue;
			}
			
			name = purple_chat_get_name(chat);
			room_id = purple_blist_node_get_string(node, "room_id");
			team_id = purple_blist_node_get_string(node, "team_id");
			if (name == NULL || room_id == NULL || team_id == NULL || purple_strequal(name, room_id)) {
				GHashTable *components = purple_chat_get_components(chat);
				if (components != NULL) {
					if (room_id == NULL) {
						room_id = g_hash_table_lookup(components, "id");
					}
					if (name == NULL || purple_strequal(name, room_id)) {
						name = g_hash_table_lookup(components, "name");
					}
					if (team_id == NULL) {
						team_id = g_hash_table_lookup(components, "team_id");
					}
				}
			}
			if (room_id != NULL) {
				g_hash_table_replace(ma->group_chats, g_strdup(room_id), name ? g_strdup(name) : NULL);
			}
			if (name != NULL) {
				g_hash_table_replace(ma->group_chats_rev, g_strdup(name), room_id ? g_strdup(room_id) : NULL);
			}
			if (team_id != NULL) {
				g_hash_table_replace(ma->channel_teams, g_strdup(room_id), g_strdup(team_id));
			}
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
	
	ma->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->group_chats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->group_chats_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
	ma->result_callbacks = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
	ma->usernames_to_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->ids_to_usernames = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ma->teams = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
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
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);

	//Build the initial hash tables from the current buddy list
	mm_build_groups_from_blist(ma);
	
	//TODO check for two-factor-auth
	{
		JsonObject *data = json_object_new();
		gchar *postdata;
		
		if (purple_account_get_bool(ma->account, "use-mmauthtoken", FALSE)) {
			ma->session_token = g_strdup(purple_connection_get_password(pc));

			url = mm_build_url(ma, "/api/v3/users/me");
			mm_fetch_url(ma, url, NULL, mm_me_response, NULL);

		} else {
			json_object_set_string_member(data, "login_id", ma->username);
			json_object_set_string_member(data, "password", purple_connection_get_password(pc));
			json_object_set_string_member(data, "token", ""); //TODO 2FA
		
			postdata = json_object_to_string(data);
		
			url = mm_build_url(ma, "/api/v3/users/login");
			mm_fetch_url(ma, url, postdata, mm_login_response, NULL);
		
			g_free(postdata);
		}
		json_object_unref(data);
		g_free(url);	

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
	
	purple_timeout_remove(ma->idle_timeout);
	purple_timeout_remove(ma->read_messages_timeout);
	
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
	g_hash_table_remove_all(ma->channel_teams);
	g_hash_table_unref(ma->channel_teams);
	g_queue_free(ma->received_message_queue);

	while (ma->http_conns) {
#	if !PURPLE_VERSION_CHECK(3, 0, 0)
		purple_util_fetch_url_cancel(ma->http_conns->data);
#	else
		purple_http_conn_cancel(ma->http_conns->data);
#	endif
		ma->http_conns = g_slist_delete_link(ma->http_conns, ma->http_conns);
	}

	while (ma->pending_writes) {
		json_object_unref(ma->pending_writes->data);
		ma->pending_writes = g_slist_delete_link(ma->pending_writes, ma->pending_writes);
	}
	
	g_hash_table_destroy(ma->cookie_table); ma->cookie_table = NULL;
	g_free(ma->last_channel_id); ma->last_channel_id = NULL;
	g_free(ma->current_channel_id); ma->current_channel_id = NULL;
	g_free(ma->username); ma->username = NULL;
	g_free(ma->server); ma->server = NULL;
	g_free(ma->frame); ma->frame = NULL;
	g_free(ma->session_token); ma->session_token = NULL;
	g_free(ma->channel); ma->channel = NULL;
	g_free(ma->self_user_id); ma->self_user_id = NULL;
	g_free(ma->self_username); ma->self_username = NULL;
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
			purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
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
	gchar *cookies;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy
	
	cookies = mm_cookies_to_string(ma);
	
	websocket_header = g_strdup_printf("GET /api/v3/users/websocket HTTP/1.1\r\n"
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
							"\r\n", ma->server,
							websocket_key, cookies, ma->session_token);
	
	mm_socket_write(ma, websocket_header, strlen(websocket_header));
	
	g_free(websocket_header);
	g_free(cookies);
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
		purple_connection_error(ma->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Couldn't connect to gateway");
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
	const gchar *channel_id, *team_id;
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
	team_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "team_id");
	if (!team_id) {
		team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	}
	if (!team_id) {
		//Uh oh!
		team_id = mm_get_first_team_id(ma);
	}
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/%s/leave", team_id, channel_id);
	mm_fetch_url(ma, url, "", NULL, NULL);
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
	const gchar *team_id, *channel_id;
	
	chatconv = purple_conversations_find_chat(pc, id);
	if (chatconv == NULL) {
		return;
	}
	
	channel_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (channel_id == NULL) {
		channel_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}
	team_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "team_id");
	if (!team_id) {
		team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	}
	if (!team_id) {
		//Uh oh!
		team_id = mm_get_first_team_id(ma);
	}
	
	user_id = g_hash_table_lookup(ma->usernames_to_ids, who);
	if (user_id == NULL) {
		//TODO search for user
		
		//  /api/v3/users/search
		
		//"term", buddy_name
		//"allow_inactive", TRUE
		
		return;
	}
	
	data = json_object_new();
	json_object_set_string_member(data, "user_id", user_id);
	
	postdata = json_object_to_string(data);
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/%s/add", team_id, channel_id);
	
	mm_fetch_url(ma, url, postdata, NULL, NULL);
	
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
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Channel ID");
	pce->identifier = "id";
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Team ID");
	pce->identifier = "team_id";
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
mm_got_users_of_room(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *channel_id = user_data;
	PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
	JsonObject *obj = json_node_get_object(node);
	PurpleGroup *default_group = mm_get_or_create_default_group();
	
	if (!json_object_has_member(obj, "status_code")) {
		GList *users = json_object_get_values(obj);
		GList *i;
		GList *users_list = NULL, *flags_list = NULL;
		
		for (i = users; i; i = i->next) {
			JsonNode *user_node = i->data;
			JsonObject *user = json_node_get_object(user_node);
			const gchar *user_id = json_object_get_string_member(user, "id");
			const gchar *username = json_object_get_string_member(user, "username");
			const gchar *roles = json_object_get_string_member(user, "roles");
			
			if (!g_hash_table_contains(ma->ids_to_usernames, user_id)) {
				g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
				g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));
				
				if (chatconv == NULL && g_hash_table_contains(ma->one_to_ones, channel_id)) {
					//Probably a direct message, add them to the buddy list
					PurpleBuddy *buddy = purple_blist_find_buddy(ma->account, username);
					if (buddy == NULL) {
						buddy = purple_buddy_new(ma->account, username, json_object_get_string_member(user, "nickname"));
						purple_blist_add_buddy(buddy, NULL, default_group, NULL);
						mm_add_buddy(ma->pc, buddy, NULL, NULL);
					}
					
					purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", channel_id);
				}
			}
			
			if (chatconv != NULL) {
				users_list = g_list_prepend(users_list, g_strdup(username));
				flags_list = g_list_prepend(flags_list, GINT_TO_POINTER(mm_role_to_purple_flag(ma, roles)));
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
		g_list_free(users);
	}
	
	if (ma->last_load_last_message_timestamp > 0) {
		// Fetch offline history
		mm_get_history_of_room(ma, NULL, channel_id, -1);
	}
	
	g_free(channel_id);
}

static void
mm_get_users_of_room(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id)
{
	gchar *url;

	if (team_id == NULL) {
		team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	}
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/%s/users/0/9999", team_id, channel_id);
	mm_fetch_url(ma, url, NULL, mm_got_users_of_room, g_strdup(channel_id));
	g_free(url);
}

static void
mm_got_history_of_room(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *channel_id = user_data;
	JsonObject *obj = json_node_get_object(node);
	JsonObject *posts = json_object_get_object_member(obj, "posts");
	JsonArray *order = json_object_get_array_member(obj, "order");
	gint64 last_message_timestamp = 0;
	gint i, len = json_array_get_length(order);
	
	for (i = len - 1; i >= 0; i--) {
		const gchar *post_id = json_array_get_string_element(order, i);
		JsonObject *post = json_object_get_object_member(posts, post_id);
		
		last_message_timestamp = mm_process_room_message(ma, post, NULL);
	}
	
	if (last_message_timestamp > 0) {
		mm_set_room_last_timestamp(ma, channel_id, last_message_timestamp);
	}
	
	g_free(channel_id);
}


	// libpurple can't store a 64bit int on a 32bit machine, so convert to something more usable instead (puke)
	//  also needs to work cross platform, in case the accounts.xml is being shared (double puke)

static gint64
mm_get_room_last_timestamp(MattermostAccount *ma, const gchar *room_id)
{
	guint64 last_message_timestamp = ma->last_load_last_message_timestamp;
	PurpleBlistNode *blistnode = NULL;
	
	if (g_hash_table_contains(ma->group_chats, room_id)) {
		//twas a group chat
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ma->account, g_hash_table_lookup(ma->group_chats, room_id)));
		if (blistnode == NULL) {
			blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ma->account, room_id));
		}
	} else {
		//is a direct message
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(ma->account, g_hash_table_lookup(ma->one_to_ones, room_id)));
	}
	if (blistnode != NULL) {
		const gchar *last_message_timestamp_str = purple_blist_node_get_string(blistnode, "last_message_timestamp");
		gint64 last_room_timestamp = 0;
		
		if (last_message_timestamp_str) {
			last_room_timestamp = g_ascii_strtoll(last_message_timestamp_str, NULL, 10);
		} else {
			last_room_timestamp = purple_blist_node_get_int(blistnode, "last_message_timestamp_high");
			if (last_room_timestamp != 0) {
				last_room_timestamp = (last_room_timestamp << 32) | ((guint64) purple_blist_node_get_int(blistnode, "last_message_timestamp_low") & 0xFFFFFFFF);
			}
		}
		if (last_room_timestamp != 0) {
			ma->last_message_timestamp = MAX(ma->last_message_timestamp, last_room_timestamp);
			return last_room_timestamp;
		}
	}
	
	return last_message_timestamp;
}

static void
mm_get_history_of_room(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, gint64 since)
{
	gchar *url;

	if (team_id == NULL) {
		team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	}
	
	if (since < 0) {
		since = mm_get_room_last_timestamp(ma, channel_id);
	}
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/%s/posts/since/%" G_GINT64_FORMAT, team_id, channel_id, since);
	mm_fetch_url(ma, url, NULL, mm_got_history_of_room, g_strdup(channel_id));
	g_free(url);
}

static void
mm_set_room_last_timestamp(MattermostAccount *ma, const gchar *room_id, gint64 last_timestamp)
{
	PurpleBlistNode *blistnode = NULL;
	gchar *last_message_timestamp_str;
	
	if (last_timestamp < 0) {
		return;
	}
	
	if (g_hash_table_contains(ma->group_chats, room_id)) {
		//twas a group chat
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ma->account, g_hash_table_lookup(ma->group_chats, room_id)));
		if (blistnode == NULL) {
			blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ma->account, room_id));
		}
	} else {
		//is a direct message
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(ma->account, g_hash_table_lookup(ma->one_to_ones, room_id)));
	}
	if (blistnode != NULL) {
		last_message_timestamp_str = g_strdup_printf("%" G_GINT64_FORMAT, last_timestamp);
		purple_blist_node_set_string(blistnode, "last_message_timestamp", last_message_timestamp_str);
		g_free(last_message_timestamp_str);
	}
	
	if (last_timestamp <= ma->last_message_timestamp) {
		return;
	}
	
	ma->last_message_timestamp = last_timestamp;	
	last_message_timestamp_str = g_strdup_printf("%" G_GINT64_FORMAT, last_timestamp);
	purple_account_set_string(ma->account, "last_message_timestamp", last_message_timestamp_str);
	g_free(last_message_timestamp_str);
	
}

static void
mm_got_room_info(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	gchar *channel_id = user_data;
	
	if (!json_object_has_member(obj, "status_code")) {
		JsonObject *channel = json_object_get_object_member(obj, "channel");
		const gchar *channel_name = json_object_get_string_member(channel, "display_name");
		PurpleChatConversation *chatconv = purple_conversations_find_chat(ma->pc, g_str_hash(channel_id));
		
		if (!g_hash_table_contains(ma->group_chats, channel_id)) {
			g_hash_table_replace(ma->group_chats, g_strdup(channel_id), g_strdup(channel_name));
			g_hash_table_replace(ma->group_chats_rev, g_strdup(channel_name), g_strdup(channel_id));
		}
		
		if (chatconv != NULL) {
			const gchar *topic = json_object_get_string_member(channel, "header");
			purple_chat_conversation_set_topic(chatconv, NULL, topic);
		}
	}
	
	g_free(channel_id);
}

static void
mm_join_room(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id)
{
	gchar *url;
	
	if (team_id == NULL) {
		team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	}
	
	// Fetch offline history
	// but first, get users in room (will fetch offline history after)
	mm_get_users_of_room(ma, team_id, channel_id);
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/%s/", team_id, channel_id);
	mm_fetch_url(ma, url, NULL, mm_got_room_info, g_strdup(channel_id));
	g_free(url);
}


static void mm_join_chat(PurpleConnection *pc, GHashTable *chatdata);


static void
mm_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const gchar *id;
	const gchar *name;
	const gchar *team_id;
	PurpleChatConversation *chatconv = NULL;
	
	id = g_hash_table_lookup(chatdata, "id");
	name = g_hash_table_lookup(chatdata, "name");
	team_id = g_hash_table_lookup(chatdata, "team_id");
	
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
	
	if (name == NULL) {
		name = g_hash_table_lookup(ma->group_chats, id);
	}
	if (team_id == NULL) {
		team_id = g_hash_table_lookup(ma->channel_teams, id);
	}
	
	if (name != NULL) {
		chatconv = purple_conversations_find_chat_with_account(name, ma->account);
	}
	if (chatconv == NULL) {
		chatconv = purple_conversations_find_chat_with_account(id, ma->account);
	}
	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}
	
	chatconv = purple_serv_got_joined_chat(pc, g_str_hash(id), name ? name : id);
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_strdup(id));
	
	if (team_id != NULL) {
		purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "team_id", g_strdup(team_id));
	}
	
	purple_conversation_present(PURPLE_CONVERSATION(chatconv));
	
	if (!g_hash_table_contains(ma->group_chats, id)) {
		g_hash_table_replace(ma->group_chats, g_strdup(id), name ? g_strdup(name) : NULL);
	}
	if (name != NULL && !g_hash_table_contains(ma->group_chats_rev, name)) {
		g_hash_table_replace(ma->group_chats_rev, g_strdup(name), id ? g_strdup(id) : NULL);
	}
	if (team_id != NULL && !g_hash_table_contains(ma->channel_teams, id)) {
		g_hash_table_replace(ma->channel_teams, g_strdup(id), g_strdup(team_id));
	}
	
	mm_join_room(ma, team_id, id);
}

static gboolean
mm_mark_room_messages_read_timeout(gpointer userdata)
{
	MattermostAccount *ma = userdata;
	JsonObject *obj;
	gchar *url;
	gchar *postdata;
	const gchar *team_id = NULL;
	const gchar *room_id = ma->current_channel_id;

	if (room_id != NULL) {
		team_id = g_hash_table_lookup(ma->channel_teams, room_id);
	}
	
	if (!team_id || !*team_id) {
		team_id = mm_get_first_team_id(ma);
	}
	
	if (!team_id || !*team_id) {
		return FALSE;
	}
	
	obj = json_object_new();
	json_object_set_string_member(obj, "channel_id", room_id);
	json_object_set_string_member(obj, "prev_channel_id", ma->last_channel_id);
	postdata = json_object_to_string(obj);
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/view", team_id);
	mm_fetch_url(ma, url, postdata, NULL, NULL);
	
	g_free(postdata);
	g_free(url);
	json_object_unref(obj);
	
	g_free(ma->last_channel_id);
	ma->last_channel_id = g_strdup(room_id);
	
	return FALSE;
}

static void
mm_mark_room_messages_read(MattermostAccount *ma, const gchar *room_id)
{
	g_free(ma->current_channel_id);
	ma->current_channel_id = g_strdup(room_id);
	
	purple_timeout_remove(ma->read_messages_timeout);
	ma->read_messages_timeout = purple_timeout_add_seconds(1, mm_mark_room_messages_read_timeout, ma);
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
	if (room_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			room_id = g_hash_table_lookup(ma->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			room_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ma->group_chats_rev, room_id)) {
				// Convert friendly name into id
				room_id = g_hash_table_lookup(ma->group_chats_rev, room_id);
			}
		}
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
	if (room_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			room_id = g_hash_table_lookup(ma->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			room_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ma->group_chats_rev, room_id)) {
				// Convert friendly name into id
				room_id = g_hash_table_lookup(ma->group_chats_rev, room_id);
			}
		}
	}
	g_return_val_if_fail(room_id, -1); //TODO create new conversation for this new person
	
	
	
	data = json_object_new();
	data_inside = json_object_new();
	
	json_object_set_string_member(data_inside, "channel_id", room_id);
	json_object_set_string_member(data_inside, "parent_id", ""); //TODO what is this?
		
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
mm_conversation_send_message(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, const gchar *message)
{
	JsonObject *data = json_object_new();
	gchar *stripped;
	gchar *_id;
	gchar *postdata;
	gchar *url;
	
	_id = g_strdup_printf("%012XFFFF", g_random_int());
	json_object_set_string_member(data, "pending_post_id", _id);
	g_hash_table_insert(ma->sent_message_ids, _id, _id);
	
	json_object_set_string_member(data, "channel_id", channel_id);
	
	stripped = mm_html_to_markdown(message);
	json_object_set_string_member(data, "message", stripped);
	g_free(stripped);
	
	json_object_set_string_member(data, "user_id", ma->self_user_id);
	json_object_set_int_member(data, "create_at", 0);
	
	postdata = json_object_to_string(data);
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/%s/posts/create", team_id, channel_id);
	mm_fetch_url(ma, url, postdata, NULL, NULL); //todo look at callback
	
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
	
	MattermostAccount *ma;
	const gchar *room_id;
	PurpleChatConversation *chatconv;
	gint ret;
	const gchar *team_id;
	
	ma = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (!room_id) {
		// Fix for a race condition around the chat data and serv_got_joined_chat()
		room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		if (g_hash_table_lookup(ma->group_chats_rev, room_id)) {
			// Convert friendly name into id
			room_id = g_hash_table_lookup(ma->group_chats_rev, room_id);
		}
		g_return_val_if_fail(room_id, -1);
	}
	g_return_val_if_fail(g_hash_table_contains(ma->group_chats, room_id), -1); //TODO rejoin room?
	
	team_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "team_id");
	if (!team_id) {
		team_id = g_hash_table_lookup(ma->channel_teams, room_id);
	}
	if (!team_id) {
		//Uh oh!
		team_id = mm_get_first_team_id(ma);
	}
	
	ret = mm_conversation_send_message(ma, team_id, room_id, message);
	if (ret > 0) {
		purple_serv_got_chat_in(pc, g_str_hash(room_id), ma->self_username, PURPLE_MESSAGE_SEND, message, time(NULL));
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
		//TODO write error message to window
		//json_object_get_string_member(result, "message")
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
	
	mm_conversation_send_message(ma, mm_get_first_team_id(ma), room_id, message);
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
	const gchar *team_id = mm_get_first_team_id(ma);
	
	if (room_id == NULL) {
		JsonObject *data;
		gchar *url, *postdata;
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif
		
		data = json_object_new();
		
		json_object_set_string_member(data, "user_id", g_hash_table_lookup(ma->usernames_to_ids, who));
		
		postdata = json_object_to_string(data);
		url = mm_build_url(ma, "/api/v3/teams/%s/channels/create_direct", team_id);
		mm_fetch_url(ma, url, postdata, mm_created_direct_message_send, msg);
		g_free(url);
		
		g_free(postdata);
		json_object_unref(data);
		
		return 1;
	}
	
	return mm_conversation_send_message(ma, team_id, room_id, message);
}


static void
mm_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	PurpleChatConversation *chatconv;
	JsonObject *data;
	gchar *postdata;
	gchar *url;
	const gchar *team_id, *channel_id;
	
	chatconv = purple_conversations_find_chat(pc, id);
	if (chatconv == NULL) {
		return;
	}
	
	channel_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (channel_id == NULL) {
		channel_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}
	team_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "team_id");
	if (!team_id) {
		team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	}
	if (!team_id) {
		//Uh oh!
		team_id = mm_get_first_team_id(ma);
	}
	
	data = json_object_new();
	json_object_set_string_member(data, "channel_id", channel_id);
	json_object_set_string_member(data, "channel_header", topic);
	
	postdata = json_object_to_string(data);
	
	url = mm_build_url(ma, "/api/v3/teams/%s/channels/update_header", team_id);
	
	mm_fetch_url(ma, url, postdata, NULL, NULL);
	
	g_free(postdata);
	g_free(url);
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

// void
// mm_search_results_get_info(PurpleConnection *pc, GList *row, void *user_data)
// {
	// mm_get_info(pc, g_list_nth_data(row, 0));
// }

void
mm_search_results_add_buddy(PurpleConnection *pc, GList *row, void *user_data)
{
	PurpleAccount *account = purple_connection_get_account(pc);
	const gchar *username = g_list_nth_data(row, 0);
	const gchar *first_name = g_list_nth_data(row, 1);
	const gchar *last_name = g_list_nth_data(row, 2);
	const gchar *nickname = g_list_nth_data(row, 3);
	gchar *full_name;
	
	if (!purple_blist_find_buddy(account, username)) {
		purple_blist_request_add_buddy(account, username, MATTERMOST_DEFAULT_BLIST_GROUP_NAME, nickname);
	}
	
	full_name = g_strconcat(first_name ? first_name : "", (first_name && *first_name) ? " " : "", last_name, NULL);
	if (*full_name) {
		purple_serv_got_alias(pc, username, full_name);
	}
	g_free(full_name);
}

static void
mm_got_add_buddy_search(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	gchar *search_term = user_data;
	GList *users, *i;
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	
	// api docs says this should be an object response, but the api returns an array
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
	
	/* columns: username, First Name, Last Name */
	column = purple_notify_searchresults_column_new(_("Username"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("First Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Last Name"));
	purple_notify_searchresults_column_add(results, column);
	column = purple_notify_searchresults_column_new(_("Nickname"));
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
	postdata = json_object_to_string(obj);
	
	url = mm_build_url(ma, "/api/v3/users/search");
	mm_fetch_url(ma, url, postdata, mm_got_add_buddy_search, g_strdup(text));
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

static void
mm_got_add_buddy_user(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	JsonObject *user = json_node_get_object(node);
	PurpleBuddy *buddy = user_data;
	const gchar *user_id;
	const gchar *username;
	const gchar *nickname;
	const gchar *first_name;
	const gchar *last_name;
	gchar *full_name;
	
	if (json_object_has_member(user, "status_code")) {
		// bad user, delete
		purple_blist_remove_buddy(buddy);
		return;
	}
	
	user_id = json_object_get_string_member(user, "id");
	username = json_object_get_string_member(user, "username");
	
	g_hash_table_replace(ma->ids_to_usernames, g_strdup(user_id), g_strdup(username));
	g_hash_table_replace(ma->usernames_to_ids, g_strdup(username), g_strdup(user_id));
	
	mm_add_buddy(ma->pc, buddy, NULL, NULL);
	
	nickname = json_object_get_string_member(user, "nickname");
	if (nickname && *nickname) {
		purple_serv_got_private_alias(ma->pc, username, nickname);
	}
	
	first_name = json_object_get_string_member(user, "first_name");
	last_name = json_object_get_string_member(user, "last_name");
	full_name = g_strconcat(first_name ? first_name : "", (first_name && *first_name) ? " " : "", last_name, NULL);
	if (*full_name) {
		purple_serv_got_alias(ma->pc, username, full_name);
	}
	g_free(full_name);
}

static void
mm_got_avatar(MattermostAccount *ma, JsonNode *node, gpointer user_data)
{
	if (node != NULL) {
		JsonObject *response = json_node_get_object(node);
		PurpleBuddy *buddy = user_data;
		const gchar *response_str;
		gsize response_len;
		gpointer response_dup;
		
		response_str = g_dataset_get_data(node, "raw_body");
		response_len = json_object_get_int_member(response, "len");
		response_dup = g_memdup(response_str, response_len);
		
		purple_buddy_icons_set_for_user(ma->account, purple_buddy_get_name(buddy), response_dup, response_len, NULL);
	}
}

static void
mm_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message)
{
	MattermostAccount *ma = purple_connection_get_protocol_data(pc);
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	const gchar *user_id = g_hash_table_lookup(ma->usernames_to_ids, buddy_name);
	gchar *avatar_url;
	
	if (user_id == NULL) {
		gchar *url;
		
		//Search for user
		// if they've entered what we think is a username, sanitise it
		if (!strchr(buddy_name, ' ') && !strchr(buddy_name, '@')) {
			url = mm_build_url(ma, "/api/v3/users/name/%s", buddy_name);
			mm_fetch_url(ma, url, NULL, mm_got_add_buddy_user, buddy);
			g_free(url);
		} else {
			// Doesn't look like a username, do a search
			mm_search_users_text(ma, buddy_name);
			purple_blist_remove_buddy(buddy);
		}
		
		return;
	}
	
	//avatar at https://{server}/api/v3/users/{username}/image
	avatar_url = mm_build_url(ma, "/api/v3/users/%s/image", user_id);
	mm_fetch_url(ma, avatar_url, NULL, mm_got_avatar, buddy);
	g_free(avatar_url);
	
	purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "user_id", user_id);
	
	// Refresh status
	{
		JsonObject *obj;
		JsonObject *data;
		JsonArray *user_ids;
		
		obj = json_object_new();
		data = json_object_new();
		user_ids = json_array_new();
		
		json_array_add_string_element(user_ids, user_id);
		json_object_set_array_member(data, "user_ids", user_ids);
			
		json_object_set_string_member(obj, "action", "get_statuses_by_ids");
		json_object_set_object_member(obj, "data", data);
		json_object_set_int_member(obj, "seq", mm_get_next_seq_callback(ma, mm_got_hello_user_statuses, NULL));
		
		mm_socket_write_json(ma, obj);
	}
	
	return;
}

#if !PURPLE_VERSION_CHECK(3, 0, 0)
static void
mm_add_buddy_no_message(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	mm_add_buddy(pc, buddy, group, NULL);
}
#endif


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
	
	// option = purple_account_option_bool_new(N_("Auto-add buddies to the buddy list"), "auto-add-buddy", FALSE);
	// account_options = g_list_append(account_options, option);
	
	option = purple_account_option_bool_new(N_("Use SSL/HTTPS"), "use-ssl", TRUE);
	account_options = g_list_append(account_options, option);

	option = purple_account_option_bool_new(N_("Password is Gitlab cookie"), "use-mmauthtoken", FALSE);
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

static PurpleCmdRet
mm_cmd_topic(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	PurpleChatConversation *chatconv = NULL;
	
	pc = purple_conversation_get_connection(conv);
	chatconv = PURPLE_CHAT_CONVERSATION(conv);
	id = purple_chat_conversation_get_id(chatconv);
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;

	if (!args || !args[0]) {
		gchar *buf;
		const gchar *topic = purple_chat_conversation_get_topic(chatconv);

		if (topic) {
			gchar *tmp, *tmp2;
			tmp = g_markup_escape_text(topic, -1);
			tmp2 = purple_markup_linkify(tmp);
			buf = g_strdup_printf(_("current topic is: %s"), tmp2);
			g_free(tmp);
			g_free(tmp2);
		} else {
			buf = g_strdup(_("No topic is set"));
		}
		
		purple_conversation_write_system_message(conv, buf, PURPLE_MESSAGE_NO_LOG);
		
		g_free(buf);
		return PURPLE_CMD_RET_OK;
	}
	
	mm_chat_set_topic(pc, id, args ? args[0] : NULL);
	
	return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet
mm_slash_command(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, gpointer userdata)
{
	PurpleConnection *pc = NULL;
	MattermostAccount *ma = NULL;
	const gchar *channel_id = NULL;
	const gchar *team_id = NULL;
	JsonObject *data;
	gchar *postdata;
	gchar *url;
	gchar *params_str, *original_msg;
	
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
	
	team_id = g_hash_table_lookup(ma->channel_teams, channel_id);
	if (team_id == NULL) {
		return PURPLE_CMD_RET_FAILED;
	}
	
	params_str = g_strjoinv(" ", args);
	original_msg = g_strconcat("/", cmd, " ", params_str, NULL);
	g_free(params_str);
	
	data = json_object_new();
	json_object_set_string_member(data, "command", original_msg);
	json_object_set_string_member(data, "channel_id", channel_id);
	postdata = json_object_to_string(data);
	
	url = mm_build_url(ma, "/api/v3/teams/%s/commands/execute", team_id);
	mm_fetch_url(ma, url, postdata, NULL, NULL);
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

	act = purple_protocol_action_new(_("Search for friends..."), mm_search_users);
	m = g_list_append(m, act);

	return m;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	
	purple_cmd_register("invite_people", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command,
						_("invite_people <username>:  Invite user to join channel"), NULL);
						
	purple_cmd_register("join", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command,
						_("join <name>:  Join a channel"), NULL);
						
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_cmd_leave,
						_("leave:  Leave the channel"), NULL);
	
	purple_cmd_register("part", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_cmd_leave,
						_("part:  Leave the channel"), NULL);
	
	purple_cmd_register("me", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command,
						_("me <action>:  Display action text"), NULL);
	
	purple_cmd_register("msg", "ws", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command,
						_("msg <username> <message>:  Direct message someone"), NULL);
	
	purple_cmd_register("topic", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_cmd_topic,
						_("topic <description>:  Set the channel topic description"), NULL);
	
	purple_cmd_register("echo", "sw", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command,
						_("echo message <delay>:  Post a message as yourself, optionally adding a delay"), NULL);
	
	purple_cmd_register("shrug", "s", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_IM |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						MATTERMOST_PLUGIN_ID, mm_slash_command,
						_("shrug message:  Post a message as yourelf followed by 'shrug'"), NULL);
	
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
static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
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
	
	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
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
	prpl_info->get_info = mm_get_info;
	
	prpl_info->roomlist_get_list = mm_roomlist_get_list;
	prpl_info->roomlist_room_serialize = mm_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL,          // type
	NULL,                            // ui_requirement
	0,                               // flags 
	NULL,                            // dependencies 
	PURPLE_PRIORITY_DEFAULT,         // priority
	MATTERMOST_PLUGIN_ID,            // id
	"Mattermost",                    // name
	MATTERMOST_PLUGIN_VERSION,       // version
	"",                              // summary
	"",                              // description
	"Eion Robb <eion@robbmob.com>",  // author
	MATTERMOST_PLUGIN_WEBSITE,       // homepage
	libpurple2_plugin_load,          // load
	libpurple2_plugin_unload,        // unload
	NULL,                            // destroy
	NULL,                            // ui_info
	NULL,                            // extra_info
	NULL,                            // prefs_info
	NULL,                            // actions
	NULL,                            // padding
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(mattermost, plugin_init, info);

#else
//Purple 3 plugin load functions


G_MODULE_EXPORT GType mm_protocol_get_type(void);
#define MATTERMOST_TYPE_PROTOCOL			(mm_protocol_get_type())
#define MATTERMOST_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), MATTERMOST_TYPE_PROTOCOL, MattermostProtocol))
#define MATTERMOST_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), MATTERMOST_TYPE_PROTOCOL, MattermostProtocolClass))
#define MATTERMOST_IS_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), MATTERMOST_TYPE_PROTOCOL))
#define MATTERMOST_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), MATTERMOST_TYPE_PROTOCOL))
#define MATTERMOST_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), MATTERMOST_TYPE_PROTOCOL, MattermostProtocolClass))

typedef struct _MattermostProtocol
{
	PurpleProtocol parent;
} MattermostProtocol;

typedef struct _MattermostProtocolClass
{
	PurpleProtocolClass parent_class;
} MattermostProtocolClass;

static void
mm_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;
	PurpleAccountUserSplit *split;

	info->id = MATTERMOST_PLUGIN_ID;
	info->name = "Mattermost";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
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
	prpl_info->set_status = mm_set_status;
	prpl_info->set_idle = mm_set_idle;
}

static void 
mm_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_actions = mm_actions;
	prpl_info->get_account_text_table = mm_get_account_text_table;
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
		"summary",     N_("Mattermost Protocol Plugins."),
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
