/* $%BEGINLICENSE%$
 Copyright (c) 2009, Oracle and/or its affiliates. All rights reserved.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "chassis-keyfile.h"

#define C(x) x, sizeof(x) - 1

static void t_chassis_keyfile_to_options(void) {
	GKeyFile *f;
	GError *gerr = NULL;
	gint number_dest = 0;
	char *string_dest = NULL;
	GOptionEntry options[] = {
		{ "number", 'n', 0, G_OPTION_ARG_INT, NULL, "foo", "bar" },
		{ "string", 's', 0, G_OPTION_ARG_STRING, NULL, "foo", "bar" },

		{ NULL, 0, 0, 0, NULL, NULL, NULL }
	};

	options[0].arg_data = &number_dest;
	options[1].arg_data = &string_dest;

	f = g_key_file_new();

	g_assert_cmpint(TRUE, ==, g_key_file_load_from_data(f, C("[group]\n"
		"number = 1\n" 
		"string = \"abc\\n\"\n"), G_KEY_FILE_NONE, &gerr));
	g_assert(gerr == NULL);
	g_assert_cmpint(TRUE, ==, g_key_file_has_group(f, "group"));

	/* reset the dest-field to make sure they are not skipped */
	number_dest = 0;
	string_dest = NULL;

	g_assert_cmpint(TRUE, ==, chassis_keyfile_to_options_with_error(f, "group", options, &gerr));
	g_assert(gerr == NULL);
	g_assert_cmpint(number_dest, ==, 1);
	g_assert_cmpstr(string_dest, ==, "\"abc\n\"");

#if 0
	/* reset the dest-field to make sure they are not skipped */
	number_dest = 0;
	string_dest = NULL;

	g_assert_cmpint(0, ==, chassis_keyfile_to_options(f, "group", options));
	g_assert_cmpint(number_dest, ==, 1);
	g_assert_cmpstr(string_dest, ==, "\"abc\n\"");
#endif

	g_key_file_free(f);
}

/**
 * test that we detect invalid strings and 
 */
static void t_chassis_keyfile_invalid_string_value(void) {
	GKeyFile *f;
	GError *gerr = NULL;
	gint number_dest = 0;
	char *string_dest = NULL;
	GOptionEntry options[] = {
		{ "number", 'n', 0, G_OPTION_ARG_INT, NULL, "foo", "bar" },
		{ "string", 's', 0, G_OPTION_ARG_STRING, NULL, "foo", "bar" },

		{ NULL, 0, 0, 0, NULL, NULL, NULL }
	};

	options[0].arg_data = &number_dest;
	options[1].arg_data = &string_dest;

	f = g_key_file_new();

	/* \a is not allowed in strings according to
	 * http://standards.freedesktop.org/desktop-entry-spec/desktop-entry-spec-1.0.html
	 */
	g_assert_cmpint(TRUE, ==, g_key_file_load_from_data(f, C("[group]\n"
		"number = 1\n" 
		"string = \"\\a\"\n"), G_KEY_FILE_NONE, &gerr));
	g_assert(gerr == NULL);
	g_assert_cmpint(TRUE, ==, g_key_file_has_group(f, "group"));

	/* reset the dest-field to make sure they are not skipped */
	number_dest = 0;
	string_dest = NULL;

	g_assert_cmpint(FALSE, ==, chassis_keyfile_to_options_with_error(f, "group", options, &gerr));
	g_assert(gerr != NULL);
	g_clear_error(&gerr);

#if 0
	/* reset the dest-field to make sure they are not skipped */
	number_dest = 0;
	string_dest = NULL;
	g_assert_cmpint(-1, ==, chassis_keyfile_to_options(f, "group", options));
#endif

	g_key_file_free(f);
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/chassis/keyfile/to_options", t_chassis_keyfile_to_options);
	g_test_add_func("/chassis/keyfile/invalid_string_value", t_chassis_keyfile_invalid_string_value);

	return g_test_run();
}

