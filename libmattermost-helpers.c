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
	g_free(l->post_id);
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
