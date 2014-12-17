/*
 * mytest_para_limit_process_check.c
 *
 *  Created on: 2013-9-27
 *      Author: jinxuanhou
 */

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

#include "network-para-exec-limit.h"
#include "network-para-exec-process.h"


#define C(x) x, sizeof(x) - 1

#define START_TEST(x) void (x)(void)
#define END_TEST

/** sql并行限制规则的添加，包括四种不同种类的sql并行限制类别的添加 */
START_TEST(test_add_sql_para_rule) {

	/**0. 条件准备 */
	para_exec_limit_rules * rules = para_exec_limit_rules_new();
	char *user_name = "test";
	char *db_name = "test";
	char *sql = NULL;

	para_exec_limit *ret = NULL;
	para_exec_limit_type limit_type;
	para_exec_sql_type sql_type;
	gint limit_para;
	gboolean limit_switch;

	/**1. 添加个别的基于某条语句的规则 */
	sql = g_strdup("select a, bb #dshfjsd \n ,ccc from test where id in (1, 2)");
	limit_type = PARA_EXEC_INDIVIDUAL;
	sql_type = PARA_SQL_SINGLE;
	limit_para = 123;
	limit_switch = TRUE;

	ret = add_sql_para_rule(rules, user_name,db_name, sql, limit_type,
			sql_type, limit_para, limit_switch);

	g_assert(ret);
	g_assert_cmpint(ret->limit_para, ==, limit_para);
	g_assert_cmpint(ret->limit_switch, ==, limit_switch);
	g_free(sql);
	sql = NULL;

	/**2. 添加个别的基于某类语句的规则 */
	sql = g_strdup("select a, bb #dshfjsd \n ,ccc from test where id in (1, 2)");
	limit_type = PARA_EXEC_INDIVIDUAL;
	sql_type = PARA_SQL_TEMPLATE;
	limit_para = 124;
	limit_switch = TRUE;

	ret = add_sql_para_rule(rules, user_name,db_name, sql, limit_type,
			sql_type, limit_para, limit_switch);

	g_assert(ret);
	g_assert_cmpint(ret->limit_para, ==, limit_para);
	g_assert_cmpint(ret->limit_switch, ==, limit_switch);
	g_free(sql);
	sql = NULL;

	/**3. 添加个别的基于某类语句的规则 */
	sql = g_strdup("select a, bb #dshfjsd \n ,ccc from test where id in (1, 2)");
	limit_type = PARA_EXEC_GLOBAL;
	sql_type = PARA_SQL_SINGLE;
	limit_para = 125;
	limit_switch = TRUE;

	ret = add_sql_para_rule(rules, user_name,db_name, sql, limit_type,
			sql_type, limit_para, limit_switch);

	g_assert(ret);
	g_assert_cmpint(ret->limit_para, ==, limit_para);
	g_assert_cmpint(ret->limit_switch, ==, limit_switch);
	g_free(sql);
	sql = NULL;

	/**4. 添加个别的基于某类语句的规则 */
	sql = g_strdup("select a, bb #dshfjsd \n ,ccc from test where id in (1, 2)");
	limit_type = PARA_EXEC_GLOBAL;
	sql_type = PARA_SQL_TEMPLATE;
	limit_para = 126;
	limit_switch = TRUE;

	ret = add_sql_para_rule(rules, user_name,db_name, sql, limit_type,
			sql_type, limit_para, limit_switch);

	g_assert(ret);
	g_assert_cmpint(ret->limit_para, ==, limit_para);
	g_assert_cmpint(ret->limit_switch, ==, limit_switch);
	g_free(sql);
	sql = NULL;

}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/test_add_sql_para_rule",test_add_sql_para_rule);

	return g_test_run();
}

