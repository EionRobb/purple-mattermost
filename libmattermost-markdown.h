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

#ifndef _LIBMATTERMOST_MARKDOWN_H_
#define _LIBMATTERMOST_MARKDOWN_H_

// Markdown to imhtml
#define MM_ATT_LINE "<hr>"
#define MM_ATT_BREAK "<br>"
#define MM_ATT_BORDER(c) "<font back=\"", color, "\" color=\"", color, "\">I</font> "
#define MM_ATT_AUTHOR(a,l)  "<a href=\"", l, "\"><b>", a, "</b></a><br>"
#define MM_ATT_TITLE(t,l) "<a href=\"", l, "\"><font size=\"5\"><b>", t, "</b></font></a> <br>"
#define MM_ATT_FTITLE(t) "<b>", t, "</b><br>"
#define MM_ATT_IMAGE(i) "<a href=\"", i, "\">", i, "</a><br>"
#define MM_ATT_TEXT(t) "<span>", t, "</span><br>"

//#include <mkdio.h>

#define MKD_NOLINKS	0x00000001	/* don't do link processing, block <a> tags  */
#define MKD_NOIMAGE	0x00000002	/* don't do image processing, block <img> */
#define MKD_NOPANTS	0x00000004	/* don't run smartypants() */
#define MKD_NOHTML	0x00000008	/* don't allow raw html through AT ALL */
#define MKD_STRICT	0x00000010	/* disable SUPERSCRIPT, RELAXED_EMPHASIS */
#define MKD_TAGTEXT	0x00000020	/* process text inside an html tag; no
					 * <em>, no <bold>, no html or [] expansion */
#define MKD_NO_EXT	0x00000040	/* don't allow pseudo-protocols */
#define MKD_NOEXT	MKD_NO_EXT	/* ^^^ (aliased for user convenience) */
#define MKD_CDATA	0x00000080	/* generate code for xml ![CDATA[...]] */
#define MKD_NOSUPERSCRIPT 0x00000100	/* no A^B */
#define MKD_NORELAXED	0x00000200	/* emphasis happens /everywhere/ */
#define MKD_NOTABLES	0x00000400	/* disallow tables */
#define MKD_NOSTRIKETHROUGH 0x00000800	/* forbid ~~strikethrough~~ */
#define MKD_TOC		0x00001000	/* do table-of-contents processing */
#define MKD_1_COMPAT	0x00002000	/* compatibility with MarkdownTest_1.0 */
#define MKD_AUTOLINK	0x00004000	/* make http://foo.com link even without <>s */
#define MKD_SAFELINK	0x00008000	/* paranoid check for link protocol */
#define MKD_NOHEADER	0x00010000	/* don't process header blocks */
#define MKD_TABSTOP	0x00020000	/* expand tabs to 4 spaces */
#define MKD_NODIVQUOTE	0x00040000	/* forbid >%class% blocks */
#define MKD_NOALPHALIST	0x00080000	/* forbid alphabetic lists */
#define MKD_NODLIST	0x00100000	/* forbid definition lists */
#define MKD_EXTRA_FOOTNOTE 0x00200000	/* enable markdown extra-style footnotes */
#define MKD_NOSTYLE	0x00400000	/* don't extract <style> blocks */
#define MKD_NODLDISCOUNT 0x00800000	/* disable discount-style definition lists */
#define	MKD_DLEXTRA	0x01000000	/* enable extra-style definition lists */
#define MKD_FENCEDCODE	0x02000000	/* enabled fenced code blocks */
#define MKD_IDANCHOR	0x04000000	/* use id= anchors for TOC links */
#define MKD_GITHUBTAGS	0x08000000	/* allow dash and underscore in element names */
#define MKD_URLENCODEDANCHOR 0x10000000 /* urlencode non-identifier chars instead of replacing with dots */
#define MKD_LATEX	0x40000000	/* handle embedded LaTeX escapes */

#define MKD_EMBED	MKD_NOLINKS|MKD_NOIMAGE|MKD_TAGTEXT

#define MM_MAX_REV_REGEX 7
#define MM_MAX_REGEX 9

#include "libmattermost.h"

gchar *mm_html_to_markdown(const gchar *html);
gchar *mm_markdown_to_html(MattermostAccount *ma, const gchar *markdown);
gchar *mm_purple_html_to_xhtml_im_parse(MattermostAccount *ma, const gchar *html);
gchar *mm_purple_xhtml_im_to_html_parse(MattermostAccount *ma, const gchar *xhtml_im);
void mm_purple_xhtml_im_html_init(void);

#endif /* _LIBMATTERMOST_MARKDOWN_H_ */
