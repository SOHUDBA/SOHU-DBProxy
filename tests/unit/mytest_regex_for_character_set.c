/*
 * mytest_regex_for_character_set.c
 *
 *  Created on: 2013-6-4
 *      Author: jinxuanhou
 */

#include <chassis-regex.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <signal.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#endif /* WIN32 */

#include <glib.h>
#include <glib/gstdio.h> /* for g_unlink */

#include "chassis-mainloop.h"
#include "chassis-regex.h"

#define C(x) x, sizeof(x) - 1
#define S(x) x, strlen(x)

charset_regex *regex;

void test_charset_collation_mapping() {
	/** 验证常用的字符集的编码是正确的 */
	g_assert(0 == strcmp("latin1", charset_dic[8]));
	g_assert(0 == g_ascii_strncasecmp(collation_dic[8], C("latin1")));

	g_assert(0 == strcmp("utf8", charset_dic[33]));
	g_assert(0 == g_ascii_strncasecmp(collation_dic[33], C("utf8")));

	/** 验证常用的字符集的校验是正确的 */
	g_assert(0 == strcmp("utf8_bin", collation_dic[83]));
	g_assert(0 == strcmp("utf8", charset_dic[83]));

	/** 验证字符集和相应的校验是对应关系式正确的 */
	int index = 0;
	for (index = 0; index <= 253; index++) {
		if (charset_dic[index]) {
			g_assert(collation_dic[index]);
			g_assert(0 == g_ascii_strncasecmp(collation_dic[index], S(charset_dic[index])));
		}
	}

	/** 验证字符集对应的默认的校验是正确的 */
	for (index = 0; distinct_sets[index] != NULL; index++) {
		if(distinct_sets[index][0] == '\0') {
			break;
		}

		g_assert(distinct_collations[index]);
		printf("%d: collation ----- %s; charset -----%s \n",index, distinct_collations[index], distinct_sets[index]);
		g_assert(0 == g_ascii_strncasecmp(distinct_collations[index], S(distinct_sets[index])));
	}
}

void test_is_set_names_true() {
	gboolean ret = FALSE;
	ret = is_set_names(regex, "/**/set names gbk/**/");
	g_assert_cmpint(ret, ==, TRUE);
	ret = is_set_names(regex, "/**/SET NAMES GBK/**/");
	g_assert_cmpint(ret, ==, TRUE);
	ret = is_set_names(regex, "Set Names\n utf8");
	g_assert_cmpint(ret, ==, TRUE);
	ret = is_set_names(regex, "set /**/names gbk");
	g_assert_cmpint(ret, ==, TRUE);
	ret = is_set_names(regex, "set /**/names");
	g_assert_cmpint(ret, ==, TRUE);
}

void test_is_set_names_false() {
	gboolean ret = TRUE;
	ret = is_set_names(regex, "/**/et names gbk/**/");
	g_assert_cmpint(ret, ==, FALSE);
	ret = is_set_names(regex, "SET Name");
	g_assert_cmpint(ret, ==, FALSE);
	ret = is_set_names(regex, "setnames");
	g_assert_cmpint(ret, ==, FALSE);
}

void test_is_set_client_charset_true() {
	gboolean ret = FALSE;

	ret = is_set_client_charset(regex, "set character_set_client = gbk");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_set_client_charset(regex, "SET CHARACTER_SET_CLIENT = gbk");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_set_client_charset(regex, "/* test**/SET CHARACTER_SET_CLIENT = gbk");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_set_client_charset(regex, "SeT \n CHaracter_SET_CLIENT    =    \n gbk");
	g_assert_cmpint(ret, ==, TRUE);
}

void test_is_set_client_charset_false() {
	gboolean ret = FALSE;

	ret = is_set_client_charset(regex, "ste character_set_client = gbk");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_set_client_charset(regex, "SET charac_SET_CLIENT = gbk");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_set_client_charset(regex, "/* test**/SET CHARACTER _SET_CLIENT = gbk");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_set_client_charset(regex, "S eT \n CHaracter_SET_CLIENT    =    \n gbk");
	g_assert_cmpint(ret, ==, FALSE);
}

void test_set_other_character_true() {
	gboolean ret = FALSE;
	ret = is_set_connect_charset(regex, "set character_set_connection = utf8");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_set_connect_charset(regex, "SET CHARACTER_SET_CONNECTION = utf8");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_set_results_charset(regex, "set character_set_results = latin1");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_set_results_charset(regex, "SET CHARACTER_SET_RESULTS= dasdsdd");
	g_assert_cmpint(ret, ==, TRUE);
}

void test_set_other_character_false() {
	gboolean ret = TRUE;
	ret = is_set_connect_charset(regex, "et character_set_connection = utf8");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_set_connect_charset(regex, "SET CHACTER_SET_CONNECTION = utf8");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_set_results_charset(regex, "set charaer_set_results = latin1");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_set_results_charset(regex, "SET CHARACTER_SETESULTS= dasdsdd");
	g_assert_cmpint(ret, ==, FALSE);
}

int main(int argc, char **argv) {
	regex = charset_regex_new();


	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");


	g_test_add_func("/core/test_charset_collation_mapping",test_charset_collation_mapping);
	g_test_add_func("/core/test_is_set_names_true",test_is_set_names_true);
	g_test_add_func("/core/test_is_set_names_false",test_is_set_names_false);
	g_test_add_func("/core/test_is_set_client_charset_true",test_is_set_client_charset_true);
	g_test_add_func("/core/test_is_set_client_charset_false",test_is_set_client_charset_false);
	g_test_add_func("/core/test_set_other_character_true",test_set_other_character_true);
	g_test_add_func("/core/test_set_other_character_false",test_set_other_character_false);

	return g_test_run();
}

/*eof*/
