/* $%BEGINLICENSE%$
 Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include <glib.h>

#include "glib-ext.h"

#if GLIB_CHECK_VERSION(2, 16, 0)

#define TV(t,s,us) do { t.tv_sec=s; t.tv_usec=us; } while(0)

void t_ge_gtimeval_diff() {
	GTimeVal old = {0,0};
	GTimeVal new = {0,0};
	gint64 diff = 0;

	TV(old, 10, 100);

	TV(new, 10, 100);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, 0);

	TV(new, 10, 101);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, 1);

	TV(new, 10, 99);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, -1);

	TV(new, 12, 100);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, 2 * G_USEC_PER_SEC);

	TV(new, 12, 101);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, 2 * G_USEC_PER_SEC + 1);

	TV(new, 12, 99);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, 2 * G_USEC_PER_SEC - 1);

	TV(new, 8, 100);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, -2 * G_USEC_PER_SEC);

	TV(new, 8, 101);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, -2 * G_USEC_PER_SEC + 1);

	TV(new, 8, 99);
	ge_gtimeval_diff(&old, &new, &diff);
	g_assert_cmpint(diff, ==, -2 * G_USEC_PER_SEC - 1);
}

void t_wildcard_string_match1(void)
{
	g_assert( wildcard_string_match1("a", "a") == TRUE );
	g_assert( wildcard_string_match1("a", "b") == FALSE );
	g_assert( wildcard_string_match1("abc", "abc") == TRUE );
	g_assert( wildcard_string_match1("abc", "abcd") == FALSE );
	g_assert( wildcard_string_match1("", "") == TRUE );
	g_assert( wildcard_string_match1("", "a") == FALSE );
	g_assert( wildcard_string_match1("a", "") == FALSE );
	g_assert( wildcard_string_match1("", "abc") == FALSE );
	g_assert( wildcard_string_match1("abc", "") == FALSE );

	g_assert( wildcard_string_match1("%"      , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("%%"     , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("%%%"    , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("_"      , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("__"     , "a"   ) == FALSE );
	g_assert( wildcard_string_match1("___"    , "a"   ) == FALSE );
	g_assert( wildcard_string_match1("_%"     , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("_%%"    , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("%_"     , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("%%_"    , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("%_%"    , "a"   ) == TRUE );
	g_assert( wildcard_string_match1("%"      , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("%%"     , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("%%%"    , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("%%%%"   , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("_"      , "abc" ) == FALSE );
	g_assert( wildcard_string_match1("__"     , "abc" ) == FALSE );
	g_assert( wildcard_string_match1("___"    , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("%___"   , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("___%"   , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("%___%"  , "abc" ) == TRUE );
	g_assert( wildcard_string_match1("%____%" , "abc" ) == FALSE );

	g_assert( wildcard_string_match1("abc%efg", "abcefg") == TRUE );
	g_assert( wildcard_string_match1("abc%efg", "abcdefg") == TRUE );
	g_assert( wildcard_string_match1("abc%efg", "abcddefg") == TRUE );
	g_assert( wildcard_string_match1("%efg", "abcddefg") == TRUE );
	g_assert( wildcard_string_match1("%efg", "abcddefg") == TRUE );

	g_assert( wildcard_string_match1("a_c%e_g", "abcefg") == TRUE );
	g_assert( wildcard_string_match1("a_c%e_g", "abcdefg") == TRUE );
	g_assert( wildcard_string_match1("a_c%e_g", "axcdeyg") == TRUE );
	g_assert( wildcard_string_match1("a_c%e_g", "abcefg") == TRUE );
	g_assert( wildcard_string_match1("a_c%e_g", "abcddefg") == TRUE );
	g_assert( wildcard_string_match1("a_c%e_g", "axcddeyg") == TRUE );
	g_assert( wildcard_string_match1("____%efg", "abcdefg") == TRUE );

	g_assert( wildcard_string_match1("%c%d", "abcd") == TRUE );
	g_assert( wildcard_string_match1("%_c%d", "abcd") == TRUE );

	g_assert( wildcard_string_match1("%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("%.%.%.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("%.%.%.%.%", "X.X.X.X") == FALSE );
	g_assert( wildcard_string_match1("X.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("X.%.%.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("X.X.%.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("X.X.X.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("X.X.X.X", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match1("X.%.%.%", "X.X.X.X") == FALSE );
	g_assert( wildcard_string_match1("X.X.X.X", "X.X.X.X") == FALSE );

	return;
}

void t_wildcard_string_match(void)
{
	g_assert( wildcard_string_match("a", "a") == TRUE );
	g_assert( wildcard_string_match("a", "b") == FALSE );
	g_assert( wildcard_string_match("abc", "abc") == TRUE );
	g_assert( wildcard_string_match("abc", "abcd") == FALSE );
	g_assert( wildcard_string_match("", "") == TRUE );
	g_assert( wildcard_string_match("", "a") == FALSE );
	g_assert( wildcard_string_match("a", "") == FALSE );
	g_assert( wildcard_string_match("", "abc") == FALSE );
	g_assert( wildcard_string_match("abc", "") == FALSE );

	g_assert( wildcard_string_match("%"      , "a"   ) == TRUE );
	g_assert( wildcard_string_match("%%"     , "a"   ) == TRUE );
	g_assert( wildcard_string_match("%%%"    , "a"   ) == TRUE );
	g_assert( wildcard_string_match("%"      , "abc" ) == TRUE );
	g_assert( wildcard_string_match("%%"     , "abc" ) == TRUE );
	g_assert( wildcard_string_match("%%%"    , "abc" ) == TRUE );
	g_assert( wildcard_string_match("%%%%"   , "abc" ) == TRUE );

	g_assert( wildcard_string_match("abc%efg", "abcefg") == TRUE );
	g_assert( wildcard_string_match("abc%efg", "abcdefg") == TRUE );
	g_assert( wildcard_string_match("abc%efg", "abcddefg") == TRUE );
	g_assert( wildcard_string_match("%efg", "abcddefg") == TRUE );
	g_assert( wildcard_string_match("%efg", "abcddefg") == TRUE );
	g_assert( wildcard_string_match("%c%d", "abcd") == TRUE );

	g_assert( wildcard_string_match("%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("%.%.%.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("%.%.%.%.%", "X.X.X.X") == FALSE );
	g_assert( wildcard_string_match("X.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("X.%.%.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("X.X.%.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("X.X.X.%", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("X.X.X.X", "X.X.X.X") == TRUE );
	g_assert( wildcard_string_match("X.%.%.%", "X.X.X.X") == FALSE );
	g_assert( wildcard_string_match("X.X.X.X", "X.X.X.X") == FALSE );

	return;
}

void t_time_us_to_str(void)
{
	struct tm tm;
	time_t t;
	//GTimeVal tv;
	guint64 time_us = 0;
	GString *s = NULL;
	GString *str = NULL;
	s = g_string_sized_new(sizeof("2014-01-01T00:00:00.000000Z"));
	str = g_string_sized_new(sizeof("2014-01-01T00:00:00.000000Z"));

	g_string_assign(s, "2014-03-01T12:34:56.100001");
	strptime("2014-03-01 12:34:56", "%Y-%m-%d %H:%M:%S", &tm);
	t = mktime(&tm);
	//tv.tv_sec = t;
	//tv.tv_usec = 100001;
	//time_us = tv.tv_sec * 1000000 + tv.tv_usec;
	time_us = t * 1000000 + 100001;
	time_us_to_str(time_us, str);
	printf("time_t: %llu, time_us: %ld, new_str: %s, old_str: %s\n", (long long unsigned int)t, time_us, str->str, s->str);
	g_assert(g_string_equal(str, s) == TRUE);

	g_string_assign(s, "2012-10-18T22:31:51.103401");
	strptime("2012-10-18 22:31:51", "%Y-%m-%d %H:%M:%S", &tm);
	t = mktime(&tm);
	//tv.tv_sec = t;
	//tv.tv_usec = 100001;
	//time_us = tv.tv_sec * 1000000 + tv.tv_usec;
	time_us = t * 1000000 + 103401;
	time_us_to_str(time_us, str);
	printf("time_t: %llu, time_us: %ld, new_str: %s, old_str: %s\n", (long long unsigned int)t, time_us, str->str, s->str);
	g_assert(g_string_equal(str, s) == TRUE);

	return;
}


int main(int argc, char **argv) {
	gint r = 0;
	//chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

//	log = chassis_log_new();
//	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
//	g_log_set_default_handler(chassis_log_func, log);
//	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/glib_ext", t_ge_gtimeval_diff);
	g_test_add_func("/core/wildcard_string_match1", t_wildcard_string_match1);
	g_test_add_func("/core/wildcard_string_match", t_wildcard_string_match);
	g_test_add_func("/core/time_us_to_str", t_time_us_to_str);

	r = g_test_run();

	//chassis_log_free(log);

	return r;
}
#else
int main() {
	return 77;
}
#endif
