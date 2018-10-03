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

#ifndef _LIBMATTERMOST_MSGPROCESS_H_
#define _LIBMATTERMOST_MSGPROCESS_H_

// Markdown to imhtml
#define MM_ATT_LINE "<hr>"
#define MM_ATT_BREAK "<br>"
#define MM_ATT_BORDER(c) "<font back=\"", color, "\" color=\"", color, "\">I</font> "
#define MM_ATT_AUTHOR(a,l)  "<a href=\"", l, "\"><b>", a, "</b></a><br>"
#define MM_ATT_TITLE(t,l) "<a href=\"", l, "\"><font size=\"5\"><b>", t, "</b></font></a> <br>"
#define MM_ATT_FTITLE(t) "<b>", t, "</b><br>"
#define MM_ATT_IMAGE(i) "<a href=\"", i, "\">", i, "</a><br>"
#define MM_ATT_TEXT(t) "<span>", t, "</span><br>"

// Helper function for picking from either 'data' or 'broadcast', since values can be in either depending on who added/removed
#define	mm_data_or_broadcast_string(a) (json_object_has_member(data, (a)) ? json_object_get_string_member(data, (a)) : json_object_get_string_member(broadcast, (a)))

void mm_process_msg(MattermostAccount *ma, JsonNode *node);
gint64 mm_process_room_message(MattermostAccount *ma, JsonObject *post, JsonObject *data);

#endif /* _LIBMATTERMOST_MSGPROCESS_H_ */
