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

#ifndef _LIBMATTERMOST_HELPERS_H_
#define _LIBMATTERMOST_HELPERS_H_

#include <glib.h>

gboolean g_str_insensitive_equal(gconstpointer v1, gconstpointer v2);
guint g_str_insensitive_hash(gconstpointer v);

void mm_g_free_mattermost_user(gpointer a);
void mm_g_free_mattermost_channel(gpointer a);
void mm_g_free_mattermost_file(gpointer a);
void mm_g_free_mattermost_attachment_field(gpointer f);
void mm_g_free_mattermost_client_config(gpointer a);
void mm_g_free_mattermost_command(gpointer a);

int mm_compare_channels_by_display_name_int(gconstpointer a, gconstpointer b);
int mm_compare_channels_by_type_int(gconstpointer a, gconstpointer b);
int mm_compare_users_by_alias_int(gconstpointer a, gconstpointer b);
int	mm_compare_cmd_int(gconstpointer a, gconstpointer b);
int	mm_compare_cmd_2_int(gconstpointer a, gconstpointer b);

#include "libmattermost.h"

gchar *mm_get_alias(MattermostUser *mu);
gchar *mm_get_chat_alias(MattermostAccount *ma, MattermostChannel *ch);
const gchar *mm_make_topic(const gchar *header, const gchar *purpose, const gchar *old_topic);
gchar *mm_cookies_to_string(MattermostAccount *ma);

PurpleChatUserFlags mm_role_to_purple_flag(MattermostAccount *ma, const gchar *rolelist);
gchar *mm_purple_flag_to_role(PurpleChatUserFlags flags);

PurpleGroup *mm_get_or_create_default_group(void);
void mm_set_user_blist(MattermostAccount *ma, MattermostUser *mu, PurpleBuddy *buddy);
PurpleNotifyUserInfo *mm_user_info(MattermostUser *mu);

void mm_set_group_chat(MattermostAccount *ma, const gchar *team_id, const gchar *channel_name, const gchar *channel_id);
const gchar *mm_get_first_team_id(MattermostAccount *ma);

gint mm_get_next_seq(MattermostAccount *ma);
gint mm_get_next_seq_callback(MattermostAccount *ma, MattermostProxyCallbackFunc callback, gpointer user_data);

#endif /* _LIBMATTERMOST_HELPERS_H_ */
