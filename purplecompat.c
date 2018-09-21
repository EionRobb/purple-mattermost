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
#include "libmattermost.h"

#if !PURPLE_VERSION_CHECK(3, 0, 0)

inline PurpleChatUser *
purple_chat_conversation_find_user(PurpleChatConversation *chat, const char *name)
{
	PurpleChatUser *cb = purple_conv_chat_cb_find(chat, name);

	if (cb != NULL) {
		g_dataset_set_data(cb, "chat", chat);
	}

	return cb;
}

inline void
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

inline PurpleMessage *
purple_message_new_outgoing(const gchar *who, const gchar *contents, PurpleMessageFlags flags)
{
	PurpleMessage *message = g_new0(PurpleMessage, 1);
	
	message->who = g_strdup(who);
	message->what = g_strdup(contents);
	message->flags = flags;
	message->when = time(NULL);
	
	return message;
}

inline void
purple_message_destroy(PurpleMessage *message)
{
	g_free(message->who);
	g_free(message->what);
	g_free(message);
}

void
mm_add_buddy_no_message(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	mm_add_buddy(pc, buddy, group, NULL);
}

#endif
