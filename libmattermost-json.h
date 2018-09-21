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

#ifndef _LIBMATTERMOST_JSON_H_
#define _LIBMATTERMOST_JSON_H_

#include <glib.h>
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

gchar *json_object_to_string(JsonObject *obj);
gchar *json_array_to_string(JsonArray *array);
JsonArray *json_array_from_string(const gchar *str);

#endif /* _LIBMATTERMOST_JSON_H_ */
