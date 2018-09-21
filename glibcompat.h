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

#ifndef _GLIBCOMPAT_H_
#define _GLIBCOMPAT_H_

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */


#if !GLIB_CHECK_VERSION(2, 28, 0)
gint64
g_get_real_time()
{
	GTimeVal val;
	
	g_get_current_time (&val);
	
	return (((gint64) val.tv_sec) * 1000000) + val.tv_usec;
}
#endif /* 2.28.0 */

#endif /*_GLIBCOMPAT_H_*/
