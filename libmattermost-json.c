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
#include <json-glib/json-glib.h>
#include "libmattermost-json.h"

gchar *
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

gchar *
json_array_to_string(JsonArray *array)
{
	JsonNode *node;
	gchar *str;
	JsonGenerator *generator;

	node = json_node_new(JSON_NODE_ARRAY);
	json_node_set_array(node, array);

	// a json string ...
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, NULL);
	g_object_unref(generator);
	json_node_free(node);
	
	return str;
}

JsonArray *
json_array_from_string(const gchar *str)
{
	JsonParser *parser = json_parser_new();
	if (json_parser_load_from_data(parser, str, -1, NULL)) {
		return json_node_get_array(json_parser_get_root(parser));
	}
	return NULL;
}
