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

int mm_compare_channels_by_display_name_int(gconstpointer a, gconstpointer b);
int mm_compare_channels_by_type_int(gconstpointer a, gconstpointer b);
int mm_compare_users_by_alias_int(gconstpointer a, gconstpointer b);

#endif /* _LIBMATTERMOST_HELPERS_H_ */
