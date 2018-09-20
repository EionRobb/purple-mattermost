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

#ifndef _LIBMATTERMOST_H_
#define _LIBMATTERMOST_H_

#include <purple.h>
#include "purplecompat.h"

#define MATTERMOST_PLUGIN_ID "prpl-eionrobb-mattermost"
#ifndef MATTERMOST_PLUGIN_VERSION
#define MATTERMOST_PLUGIN_VERSION "1.1"
#endif
#define MATTERMOST_PLUGIN_WEBSITE "https://github.com/EionRobb/mattermost-libpurple"

#define MATTERMOST_USERAGENT "libpurple"
#define MATTERMOST_API_EP "/api/v4"

#define MATTERMOST_BUFFER_DEFAULT_SIZE 40960
#define MATTERMOST_USER_PAGE_SIZE 200 // 200 is MAX. in paged queries (and default)
#define MATTERMOST_HISTORY_PAGE_SIZE 60 // 200 is MAX in paged queries (60 is default)
#define MATTERMOST_MAX_PAGES 10 // that is 2000 users or posts in paged queries

#define MATTERMOST_DEFAULT_SERVER ""
#define MATTERMOST_SERVER_SPLIT_CHAR '|'

#define MATTERMOST_CHANNEL_SEPARATOR_VISUAL " / "
#define MATTERMOST_CHANNEL_PRIVATE_VISUAL  "[P] "
#define MATTERMOST_CHANNEL_SEPARATOR "---"
#define MATTERMOST_CHANNEL_OPEN 'O'
#define MATTERMOST_CHANNEL_PRIVATE 'P'
#define MATTERMOST_CHANNEL_DIRECT 'D'
#define MATTERMOST_CHANNEL_GROUP 'G'
#define MATTERMOST_CHANNEL_TYPE_STRING(t) (gchar[2]) { t, '\0' }

#define MATTERMOST_MENTION_ME_MATCH(m) (g_strconcat("(?<MNTWRD>", m, ")(?<MNTSEP>([[:^alnum:]\r\n]|$))", NULL)) 
#define MATTERMOST_MENTION_ME_REPLACE "<u><b>\\g<MNTWRD></b></u>\\g<MNTSEP>"
#define MATTERMOST_MENTION_ALL_MATCH "(?<MNTWRD>(@|#)[a-z0-9]+)(?<MNTSEP>([[:^alnum:]\r\n]|$))"
#define MATTERMOST_MENTION_ALL_REPLACE "<u>\\g<MNTWRD></u>\\g<MNTSEP>" //MM does not use underline

// need some string which is unlikely in channel header/purpose
#define MATTERMOST_CHAT_TOPIC_SEP "\n----- ---- --- -- -\n"

#define MATTERMOST_DEFAULT_BLIST_GROUP_NAME  _("Mattermost")

#define MATTERMOST_BOT_LABEL " [BOT]"

#define MATTERMOST_HTTP_GET    0
#define MATTERMOST_HTTP_PUT    1
#define MATTERMOST_HTTP_POST   2
#define MATTERMOST_HTTP_DELETE 3

#define _MM_BLIST_SET(b,u,p,s) \
{ \
	if (s) { \
		purple_blist_node_set_string(PURPLE_BLIST_NODE(b), p, s); \
	} else { \
		const gchar *v = json_object_get_string_member(u,p); \
		if (v && *v) { \
			purple_blist_node_set_string(PURPLE_BLIST_NODE(b), p, v); \
		} \
	} \
}

#define _MM_TOOLTIP_LINE_ADD(b,u,d,p,o) \
{ \
	if (o) { \
		purple_notify_user_info_add_pair_plaintext(u,d,o); \
	} else { \
		const gchar *v = purple_blist_node_get_string(PURPLE_BLIST_NODE(b),p); \
		if (v && *v) { \
			purple_notify_user_info_add_pair_plaintext(u,d,v); \
		} \
	} \
}

// Helper function for picking from either 'data' or 'broadcast', since values can be in either depending on who added/removed
#define	mm_data_or_broadcast_string(a) (json_object_has_member(data, (a)) ? json_object_get_string_member(data, (a)) : json_object_get_string_member(broadcast, (a)))

#if !PURPLE_VERSION_CHECK(3, 0, 0)
#ifndef PurpleChatUserFlags
#define PurpleChatUserFlags  PurpleConvChatBuddyFlags
#endif
#endif

typedef struct {
	gchar *user_id;
	gchar *room_id;
	gchar *username;
	gchar *nickname;
	gchar *first_name;
	gchar *last_name;
	gchar *email;	
	gchar *alias;
	gchar *position;
	gchar *locale;
	PurpleChatUserFlags roles;
	gint64 channel_approximate_view_time;
} MattermostUser;

typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	
	MattermostUser *self;

	gchar *current_channel_id;
	gchar *last_channel_id;
	guint read_messages_timeout;
	gint64 last_message_timestamp;
	gint64 last_load_last_message_timestamp;
	guint idle_timeout;
	
	gchar *username;
	gchar *server;
	gchar *api_endpoint;
	
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
	GHashTable *aliases;          // A store of known display names -> room id's
	GHashTable *group_chats_rev;  // A store of known multi-user room name's -> room_id's
	GHashTable *group_chats_creators; // chat_id -> creator_id
	GHashTable *sent_message_ids; // A store of message id's that we generated from this instance
	GHashTable *result_callbacks; // Result ID -> Callback function
	GHashTable *usernames_to_ids; // username -> user id
	GHashTable *ids_to_usernames; // user id -> username
	GHashTable *teams;            // A list of known team_id's -> team names
	GHashTable *teams_display_names; // an descriptive names too.
	GHashTable *channel_teams;    // A list of channel_id -> team_id to know what team a channel is in
	GQueue *received_message_queue; // A store of the last 10 received message id's for de-dup
	
	GList *user_prefs;            // all user preferences read from server
	GList *joined_channels;       // all channels for which we performed mm_join_room and have not left;
	GList *mention_words;         // terms set up in MM account settings which trigger notifications.
	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
	GSList *pending_writes;

	GRegex *mention_me_regex;
	GRegex *mention_all_regex;

} MattermostAccount;

#include <glib.h>
#include <json-glib/json-glib.h>

typedef void (*MattermostProxyCallbackFunc)(MattermostAccount *ma, JsonNode *node, gpointer user_data);

#include <purple.h>

#if PURPLE_VERSION_CHECK(3, 0, 0)

typedef struct _MattermostProtocol
{
	PurpleProtocol parent;
} MattermostProtocol;

typedef struct _MattermostProtocolClass
{
	PurpleProtocolClass parent_class;
} MattermostProtocolClass;

G_MODULE_EXPORT GType mm_protocol_get_type(void);
#define MATTERMOST_TYPE_PROTOCOL			(mm_protocol_get_type())
#define MATTERMOST_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), MATTERMOST_TYPE_PROTOCOL, MattermostProtocol))
#define MATTERMOST_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), MATTERMOST_TYPE_PROTOCOL, MattermostProtocolClass))
#define MATTERMOST_IS_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), MATTERMOST_TYPE_PROTOCOL))
#define MATTERMOST_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), MATTERMOST_TYPE_PROTOCOL))
#define MATTERMOST_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), MATTERMOST_TYPE_PROTOCOL, MattermostProtocolClass))

#endif

typedef struct {
	PurpleRoomlist *roomlist;
	gchar *team_id;
	gchar *team_desc;
} MatterMostTeamRoomlist;

typedef struct {
	gchar *title;
	gchar *value;
	// short
} MattermostAttachmentField;

typedef struct {
	MattermostAccount *ma;
	MattermostProxyCallbackFunc callback;
	gpointer user_data;
} MattermostProxyConnection;

typedef struct {
	gchar *id;
	gchar *team_id;
	gchar *name;
	gchar *type;
	gchar *display_name;
	gchar *header;
	gchar *purpose;	
	gchar *creator_id;
	gint64 channel_approximate_view_time;
	gint page_users; //FIXME: this is for getting paged replies from server, should be NOT here.
	gint page_history; //FIXME: this is for getting paged replies from server, should be NOT here.
} MattermostChannel;

typedef struct {
	gchar *user_id;
	gchar *category;
	gchar *name;
	gchar *value;
} MattermostUserPref;

typedef struct {
	gchar *channel_id;
	gchar *file_id;
	gchar *sender;
	gint64 timestamp;
} MattermostChannelLink;

typedef struct {
		gchar *id;
//	gchar *user_id;
//	gchar *post_id;
	gchar *name;
//	gchar *extension;
//	gint64 size;
		gchar *mime_type;
//	gint width;
//	gint height;
	gboolean has_preview_image;
	gchar *uri;
	MattermostChannelLink *mmchlink;
} MattermostFile;

typedef struct {
	GRegex *regex;
	gchar *find;
	gchar *repl;
} MattermostRegexElement;

void mm_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char *message);

#endif /* _LIBMATTERMOST_H_ */
