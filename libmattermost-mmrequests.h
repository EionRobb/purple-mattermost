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

#ifndef _LIBMATTERMOST_MMREQUESTS_H_
#define _LIBMATTERMOST_MMREQUESTS_H_

#include "libmattermost.h"
#include <purple.h>
#include "purplecompat.h"

void mm_get_info(PurpleConnection *pc,const gchar *username);
PurpleRoomlist *mm_roomlist_get_list(PurpleConnection *pc);
void mm_chat_set_header_purpose(PurpleConnection *pc, int id, const char *topic, const gboolean isheader);
void mm_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who);
void mm_chat_leave(PurpleConnection *pc, int id);
void mm_login(PurpleAccount *account);

gint mm_conversation_send_message(MattermostAccount *ma, const gchar *team_id, const gchar *channel_id, const gchar *message, GList *file_ids);
guint mm_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, MattermostAccount *ma);

int mm_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags);
#endif

void mm_search_users_text(MattermostAccount *ma, const gchar *text);
void mm_save_user_pref(MattermostAccount *ma, MattermostUserPref *pref);
void mm_set_status(PurpleAccount *account, PurpleStatus *status);

#endif /* _LIBMATTERMOST_MMREQUEST_H_ */
