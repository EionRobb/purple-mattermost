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
#include "libmattermost.h"
#include "libmattermost-markdown.h"

//#include <mkdio.h>
extern char markdown_version[];
int mkd_line(char *, int, char **, int);

static MattermostRegexElement mm_rev_regexes[MM_MAX_REV_REGEX]={
	// (inline) code block, bold, italic, strikethrough -> pass
	// no underline in html5, font size 1,2 - ignored.
	// line break 
	{
	.find = "<br>",
	.repl = "\n",
	.regex = NULL,
	},
	// title1 
	{
	.find = "<font size=\"7\">(.*)</font>",
	.repl = " # \\1",
	.regex = NULL,
	},
	// title2 
	{
	.find = "<font size=\"6\">(.*)</font>",
	.repl = " ## \\1",
	.regex = NULL,
	},
	// title3
	{
	.find = "<font size=\"5\">(.*)</font>",
	.repl = " ### \\1",
	.regex = NULL,
	},
	// title4 
	{
	.find = "<font size=\"4\">(.*)</font>",
	.repl = " #### \\1",
	.regex = NULL,
	},
	// horizontal line
	{
	.find = "<hr>",
	.repl = "\n---\n",
	.regex = NULL,
	},
	// blockquote
	{
	.find = "^ *&gt;(.*)$",
	.repl = ">\\1",
	.regex = NULL,
	},
};



static MattermostRegexElement mm_regexes[MM_MAX_REGEX]={
	// line break 
	{
	.find = "<br>",
	.repl = "\n",
	.regex = NULL,
	},
	// (inline) code block 
	{
	.find = "<code>(.*)</code>",
	.repl = "<font back=\"#E1E1E1\">\\1</font>",
	.regex = NULL,
	},
	// title1
	{
	.find = "^ *# +(.*)($|<br>)",
	.repl = "<font size=\"7\"><b>\\1</b></font>",
	.regex = NULL,
	},
	// title2
	{
	.find = "^ *## +(.*)$",
	.repl = "<font size=\"6\"><b>\\1</b></font>",
	.regex = NULL,
	},
	// title3
	{
	.find = "^ *### +(.*)$",
	.repl = "<font size=\"5\"><b>\\1</b></font>",
	.regex = NULL,
	},
	// title4-6 (normal font size is 3)
	{
	.find = "^ *#####?#? +(.*)$",
	.repl = "<font size=\"4\"<b>\\1</b></font>",
	.regex = NULL,
	},
	// horizontal line
	{	
	.find = "^ *(-|_|\\*){3,}$",
	.repl = "<hr>",
	.regex = NULL,
	},
	// blockquote
	{
	.find = "^ *(&gt;|>)(.*)$",
	.repl = "<font size=\"6\"><b>\"</b></font>\\2", //0x93 ?
	.regex = NULL,
	},
	// strikethrough
	{
	.find = "<del>(.*)</del>",
	.repl = "<s>\\1</s>",
	.regex = NULL,
	},
};

void 
mm_purple_xhtml_im_html_init(void)
{
	gint i;

	for (i=0;i< MM_MAX_REGEX; i++) {
		mm_regexes[i].regex = g_regex_new(mm_regexes[i].find, G_REGEX_CASELESS|G_REGEX_DOTALL|G_REGEX_OPTIMIZE|G_REGEX_MULTILINE|G_REGEX_UNGREEDY, G_REGEX_MATCH_NOTEMPTY, NULL);
	}
	for (i=0;i< MM_MAX_REV_REGEX; i++) {
		mm_rev_regexes[i].regex = g_regex_new(mm_rev_regexes[i].find, G_REGEX_CASELESS|G_REGEX_DOTALL|G_REGEX_OPTIMIZE|G_REGEX_MULTILINE|G_REGEX_UNGREEDY, G_REGEX_MATCH_NOTEMPTY, NULL);
	}

}

gchar *
mm_purple_html_to_xhtml_im_parse(MattermostAccount *ma, const gchar *html)
{
	gint i;
	gchar *input = NULL;
	gchar *output = NULL;

	if(!purple_account_get_bool(ma->account, "use-markdown", TRUE)) {
		return g_strdup(html);
	}
 
	if (html == NULL) {
		return NULL;
	}

	input = g_strdup(html);
	for (i=0;i< MM_MAX_REGEX; i++) {
		output = g_regex_replace(mm_regexes[i].regex, input, -1, 0, mm_regexes[i].repl, G_REGEX_MATCH_NOTEMPTY, NULL);
		g_free(input);
		input = g_strdup(output);
		g_free(output);
	}
	
	return g_strdup(input);
}

gchar *
mm_purple_xhtml_im_to_html_parse(MattermostAccount *ma, const gchar *xhtml_im)
{
	gint i;
	gchar *input = NULL;
	gchar *output = NULL;

	if(!purple_account_get_bool(ma->account, "use-markdown", TRUE)) {
		return g_strdup(xhtml_im);
	}

	if (xhtml_im == NULL) {
		return NULL;
	}

	input = g_strdup(xhtml_im);
	for (i=0;i< MM_MAX_REV_REGEX; i++) {
		output = g_regex_replace(mm_rev_regexes[i].regex, input, -1, 0, mm_rev_regexes[i].repl, G_REGEX_MATCH_NOTEMPTY, NULL);
		g_free(input);
		input = g_strdup(output);
		g_free(output);
	}

	return g_strdup(input);
}

gchar *
mm_markdown_to_html(MattermostAccount *ma, const gchar *markdown)
{
	static char *markdown_str = NULL;
	int markdown_len;
	int flags = MKD_NOPANTS | MKD_NODIVQUOTE | MKD_NODLIST;
	static gboolean markdown_version_checked = FALSE;
	static gboolean markdown_version_safe = TRUE;
	
	if (markdown == NULL) {
		return NULL;
	}
	
	if (!markdown_version_checked) {
		gchar **markdown_version_split = g_strsplit_set(markdown_version, ". ", -1);
		gint major, minor, micro;

		major = atoi(markdown_version_split[0]);
		if (major > 2) {
			markdown_version_checked = TRUE;
		} else if (major == 2) {
			minor = atoi(markdown_version_split[1]);
			if (minor > 2) {
				markdown_version_checked = TRUE;
			} else if (minor == 2) {
				micro = atoi(markdown_version_split[2]);
				if (micro > 2) {
					markdown_version_checked = TRUE;
				}
			}
		}
		
		if (!markdown_version_checked) {
			guint i;
			for(i = 0; markdown_version_split[i]; i++) {
				if (purple_strequal(markdown_version_split[i], "DEBUG")) {
					markdown_version_safe = FALSE;
					break;
				}
			}
			markdown_version_checked = TRUE;
		}
		
		g_strfreev(markdown_version_split);
	}
	
	if (markdown_str != NULL) {
		// if libmarkdown is pre-2.2.2 and we're using amalloc, don't free()
		if (markdown_version_safe) {
			free(markdown_str);
		}
	}
	
	markdown_len = mkd_line((char *)markdown, strlen(markdown), &markdown_str, flags);

	if (markdown_len < 0) {
		return NULL;
	}

	return mm_purple_html_to_xhtml_im_parse(ma, g_strndup(markdown_str, markdown_len));
}



static void
mm_markup_anchor_parse_text(GMarkupParseContext *context, const gchar *text, gsize text_len, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	g_string_prepend_len(output, text, text_len);
}

static GMarkupParser mm_markup_anchor_parser = {
	NULL,
	NULL,
	mm_markup_anchor_parse_text,
	NULL,
	NULL
};

static void
mm_markdown_parse_start_element(GMarkupParseContext *context, const gchar *element_name, const gchar **attribute_names, const gchar **attribute_values, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	switch(g_str_hash(element_name)) {
		case 0x2b607: case 0x2b5e7: //B
			g_string_append(output, "**");
			break;
		case 0x2b60e: case 0x2b5ee: //I
		case 0x5977b7: case 0x597377: //EM
			g_string_append_c(output, '_');
			break;
		case 0x597759: case 0x597319: //BR
			g_string_append_c(output, '\n');
			break;
		case 0xb8869ba: case 0xb87dd5a: //DEL
		case 0x2b618: case 0x2b5f8: //S
		case 0x1c93af97: case 0xcf9972d7: //STRIKE
			g_string_append(output, "~~");
			break;
		case 0x2b606: case 0x2b5e6: //A
		{
			const gchar **name_cursor = attribute_names;
			const gchar **value_cursor = attribute_values;
			GString *href_string = g_string_new("](");
			
			while (*name_cursor) {
				if (g_ascii_strncasecmp(*name_cursor, "href", -1) == 0) {
					g_string_append(href_string, *value_cursor);
					break;
				}
				name_cursor++;
				value_cursor++;
			}
		
			g_string_append_c(output, '[');
			g_markup_parse_context_push(context, &mm_markup_anchor_parser, href_string);
			break;
		}
	}
	
}

static void
mm_markdown_parse_end_element(GMarkupParseContext *context, const gchar *element_name, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	switch(g_str_hash(element_name)) {
		case 0x2b607: case 0x2b5e7: //B
			g_string_append(output, "**");
			break;
		case 0x2b60e: case 0x2b5ee: //I
		case 0x5977b7: case 0x597377: //EM
			g_string_append_c(output, '_');
			break;
		case 0xb8869ba: case 0xb87dd5a: //DEL
		case 0x2b618: case 0x2b5f8: //S
		case 0x1c93af97: case 0xcf9972d7: //STRIKE
			g_string_append(output, "~~");
			break;
		case 0x2b606: case 0x2b5e6: //A
		{
			GString *href_string = g_markup_parse_context_pop(context);
			g_string_append_printf(output, "%s)", href_string->str);
			g_string_free(href_string, TRUE);
			break;
		}
	}
	
}

static void
mm_markdown_parse_text(GMarkupParseContext *context, const gchar *text, gsize text_len, gpointer user_data, GError **error)
{
	GString *output = user_data;
	
	g_string_append_len(output, text, text_len);
}

static GMarkupParser mm_markup_markdown_parser = {
	mm_markdown_parse_start_element,
	mm_markdown_parse_end_element,
	mm_markdown_parse_text,
	NULL,
	NULL
};

gchar *
mm_html_to_markdown(const gchar *html)
{
	GString *output = g_string_new(NULL);
	GMarkupParseContext *context;
	
	context = g_markup_parse_context_new(&mm_markup_markdown_parser, G_MARKUP_TREAT_CDATA_AS_TEXT, output, NULL);
	g_markup_parse_context_parse(context, "<html>", -1, NULL);	
	g_markup_parse_context_parse(context, html, -1, NULL);	
	g_markup_parse_context_parse(context, "</html>", -1, NULL);	
	g_markup_parse_context_end_parse(context, NULL);
	g_markup_parse_context_free(context);
	
	return g_string_free(output, FALSE);
}





