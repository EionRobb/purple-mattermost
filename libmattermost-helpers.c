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

#include <glib.h>
#include "libmattermost.h"
#include "libmattermost-helpers.h"

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

gboolean
g_str_insensitive_equal(gconstpointer v1, gconstpointer v2)
{
	return (g_ascii_strcasecmp(v1, v2) == 0);
}

guint
g_str_insensitive_hash(gconstpointer v)
{
	guint hash;
	gchar *lower_str = g_ascii_strdown(v, -1);
	
	hash = g_str_hash(lower_str);
	g_free(lower_str);
	
	return hash;
}

void
mm_g_free_mattermost_user(gpointer a)
{
	MattermostUser *u = a;
	if (!u) return;
	g_free(u->user_id);
	g_free(u->room_id);
	g_free(u->username);
	g_free(u->nickname);
	g_free(u->first_name);
	g_free(u->last_name);
	g_free(u->email);
	g_free(u->alias);
	g_free(u->position);
	g_free(u->locale);
	g_free(u);
}

void
mm_g_free_mattermost_channel(gpointer a)
{
	MattermostChannel *c = a;
	if (!c) return;
	g_free(c->id);
	g_free(c->team_id);
	g_free(c->name);
	g_free(c->display_name);
	g_free(c->type);
	g_free(c->header);
	g_free(c->purpose);
	g_free(c->creator_id);
}

void
mm_g_free_mattermost_channel_link(gpointer a)
{
	MattermostChannelLink *l = a;
	g_free(l->channel_id);
	g_free(l->file_id);
	g_free(l->sender);
	g_free(l);
}

void
mm_g_free_mattermost_file(gpointer a)
{
	MattermostFile *f = a;
	g_free(f->id);
//	g_free(f->user_id);
//	g_free(f->post_id);
	g_free(f->name);
//	g_free(f->extension);
	g_free(f->mime_type);
	g_free(f->uri);
	mm_g_free_mattermost_channel_link(f->mmchlink);
	g_free(f);
}

void mm_g_free_mattermost_attachment_field(gpointer f) 
{
	MattermostAttachmentField *af = f;
	if (!af) return;
	g_free(af->title);
	g_free(af->value);
	g_free(af);
}

void
mm_g_free_mattermost_client_config(gpointer a)
{
	MattermostClientConfig *cc = a;
	if (!cc) return;
	g_free(cc->site_name);
	g_free(cc->support_email);
	g_free(cc->site_url);
	g_free(cc->server_version);
	g_free(cc->build_number);
	g_free(cc->build_hash);
	g_free(cc->build_date);
	g_free(cc->enterprise_ready);
	g_free(cc->report_a_problem_link);
	g_free(cc);
}

void
mm_g_free_mattermost_command(gpointer a)
{
	MattermostCommand *c = a;
	if (!c) return;
	g_free(c->trigger);
	g_free(c->team_id);
	g_free(c->display_name);
	g_free(c->description);
	g_free(c->auto_complete_hint);
	g_free(c->auto_complete_desc);
	g_free(c);
}

int
mm_compare_cmd_int(gconstpointer a, gconstpointer b)
{
	const MattermostCommand *c1 = a;
	const MattermostCommand *c2 = b;
	if (!g_strcmp0(c1->trigger,c2->trigger) &&
			!g_strcmp0(c1->team_id,c2->team_id)) return 0;

	return -1;
}

int
mm_compare_cmd_2_int(gconstpointer a, gconstpointer b)
{
	const MattermostCommand *c1 = a;
	const MattermostCommand *c2 = b;

	gint res = g_strcmp0(c1->trigger,c2->trigger);

	if (res < 0) { return -1;}
	if (res > 0) { return 1;}

	return 0;
}

int
mm_compare_users_by_id_int(gconstpointer a, gconstpointer b)
{
	const MattermostUser *p1 = a;
	const MattermostUser *p2 = b;
	if (!g_strcmp0(p1->user_id,p2->user_id)) return 0;

	return -1;
}

int 
mm_compare_channels_by_id_team_id_int(gconstpointer a, gconstpointer b)
{
	const MattermostChannel *p1 = a;
	const MattermostChannel *p2 = b;

	if (!g_strcmp0(p1->id,p2->id) && !g_strcmp0(p1->team_id,p2->team_id)) return 0;

	return -1;
}

int 
mm_compare_channels_by_id_int(gconstpointer a, gconstpointer b)
{
	const MattermostChannel *p1 = a;
	const MattermostChannel *p2 = b;

	if (!g_strcmp0(p1->id,p2->id)) return 0;

	return -1;
}

int
mm_compare_channels_by_display_name_int(gconstpointer a, gconstpointer b)
{
        const MattermostChannel *p1 = a;
        const MattermostChannel *p2 = b;

        gint res = g_strcmp0(p1->display_name,p2->display_name);

        if (res < 0) { return 1;}
        if (res > 0) { return -1;}

        return 0;
}

int
mm_compare_channels_by_type_int(gconstpointer a, gconstpointer b)
{
	const MattermostChannel *p1 = a;
	const MattermostChannel *p2 = b;

	const gchar *p = MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_PRIVATE);
	const gchar *o = MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_OPEN);
	const gchar *g = MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_GROUP);
//const gchar *d = MATTERMOST_CHANNEL_TYPE_STRING(MATTERMOST_CHANNEL_DIRECT);

	if (purple_strequal(p1->type, p2->type)) return 0;
	if (purple_strequal(p1->type,g)) return -1;
	if (purple_strequal(p2->type,g)) return 1;
	if (purple_strequal(p1->type,p) && purple_strequal(p2->type,o)) return -1;
	return 1;
}

int mm_compare_users_by_alias_int(gconstpointer a, gconstpointer b)
{
	const MattermostUser *u1 = a;
	const MattermostUser *u2 = b;

	return g_strcmp0(u1->alias, u2->alias);
}

int
mm_compare_prefs_int(gconstpointer a, gconstpointer b)
{
	const MattermostUserPref *p1 = a;
	const MattermostUserPref *p2 = b;

	if (!(g_strcmp0(p1->user_id,p2->user_id) &&
		g_strcmp0(p1->category,p2->category) &&
		g_strcmp0(p1->name,p2->name))) {
		return 0;
	} 
	return -1;
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

gchar *
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

gchar *
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

static void
mm_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

gchar *
mm_cookies_to_string(MattermostAccount *ma)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ma->cookie_table, (GHFunc)mm_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

PurpleChatUserFlags
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

gchar *
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

void
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

PurpleNotifyUserInfo *
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

void
mm_set_group_chat(MattermostAccount *ma, const gchar *team_id, const gchar *channel_name, const gchar *channel_id)
{
	g_hash_table_replace(ma->group_chats, g_strdup(channel_id), g_strdup(channel_name));
	g_hash_table_replace(ma->group_chats_rev, g_strdup(channel_name), g_strdup(channel_id));
	if (team_id) g_hash_table_replace(ma->channel_teams, g_strdup(channel_id), g_strdup(team_id));
}

const gchar *
mm_get_first_team_id(MattermostAccount *ma)
{
	GList *team_ids = g_hash_table_get_keys(ma->teams);
	const gchar *first_team_id = team_ids ? team_ids->data : NULL;
	
	g_list_free(team_ids);
	
	return first_team_id;
}

gint
mm_get_next_seq(MattermostAccount *ma)
{
	return ma->seq++;
}

gint
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
