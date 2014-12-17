/*
 * mytest_sql_security_manage.c
 *
 *  Created on: 2013-7-30
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

#include "network-security-sqlmode.h"


#if GLIB_CHECK_VERSION(2, 16, 0)

#define C(x) x, sizeof(x) - 1

#define START_TEST(x) void (x)(void)
#define END_TEST

START_TEST(test_add_sql_security_rule) {
	user_db_sql_rule_table *rules = user_db_sql_rule_table_new();
	g_assert(rules);

	/** 添加一个单条语句的限制规则，并查找、修改、再查找 */
	char *sql = g_strdup("select * from test # just a test");
	char *dbname = g_strdup("test");
	char *user = g_strdup("test");
	security_model_type type = SQL_SINGLE;
	security_action action = ACTION_BLOCK;
	gboolean is_disabled = FALSE;

	sql_security_rule* rule = add_sql_security_rule(
			rules,
			sql,
			dbname,
			user,
			type,
			action,
			is_disabled);

	g_assert(rule);
	g_assert(FALSE == rule->is_disabled);
	g_assert(rule->action == ACTION_BLOCK);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from test");

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			rules,
			NULL,
			"select \t *  \n from `test` -- just a test",
			"test",
			"test"));

	g_assert(set_action_sql_security_rule(
			rules,
			"SElect * From Test",
			"test",
			"test",
			SQL_SINGLE,
			ACTION_WARNING));

	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			rules,
			NULL,
			"selECT       \t *  \n from TEST/* just a test*/",
			"test",
			"test"));

	g_assert(set_switch_sql_security_rule(
			rules,
			"select * from `test`",
			"test",
			"test",
			SQL_SINGLE,
			TRUE));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
				rules,
				NULL,
				"selECT*from TEST/*! just a test*/",
				"test",
				"test"));

	g_assert(del_sql_security_rule(
			rules,
			"select * from test",
			"test",
			"test",
			SQL_SINGLE));

	g_free(sql);
	g_free(dbname);
	g_free(user);

	/** 再添加一条某类的sql限制规则 */
	sql = g_strdup("select a, b, c FROM `test` where id in (1, 2, 3, 4)");
	dbname = g_strdup("test");
	user = g_strdup("test");
	type = SQL_TEMPLATE;
	action = ACTION_BLOCK;
	is_disabled = FALSE;

	rule = add_sql_security_rule(
			rules,
			sql,
			dbname,
			user,
			type,
			action,
			is_disabled);

	g_assert(rule);
	g_assert(FALSE == rule->is_disabled);
	g_assert(rule->action == ACTION_BLOCK);
	g_assert_cmpstr(rule->sql_content->str, ==, "select a, b, c from test where id in (N)");

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
				rules,
				NULL,
				"select \t  a, b, c  \n from `test` where id in (1, 2, 3, 4, 5 , '123123') -- just a test",
				"test",
				"test"));

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
				rules,
				NULL,
				"select \t  a, b, c  \n from `test` WHERE id in (1) -- just a test",
				"test",
				"test"));

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
				rules,
				NULL,
				"select \t  a, b, c \n from `test` where id in ('123123') -- just a test",
				"test",
				"test"));

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
				rules,
				NULL,
				"select \t  a, b, c \n from `test` where id in (1, select * from help) -- just a test",
				"test",
				"test"));


	g_free(sql);
	g_free(dbname);
	g_free(user);

} END_TEST

START_TEST(test_del_sql_security_rule) {
	user_db_sql_rule_table *rules = user_db_sql_rule_table_new();
	g_assert(rules);

	/** 添加一个单条语句的限制规则，并查找、修改、再查找 */
	char *sql = g_strdup("select * from test # just a test");
	char *dbname = g_strdup("test");
	char *user = g_strdup("test");
	security_model_type type = SQL_SINGLE;
	security_action action = ACTION_BLOCK;
	gboolean is_disabled = FALSE;

	sql_security_rule* rule = add_sql_security_rule(
			rules,
			sql,
			dbname,
			user,
			type,
			action,
			is_disabled);

	g_assert(rule);
	g_assert(!rule->is_disabled);
	g_assert(rule->action == ACTION_BLOCK);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from test");

	g_free(sql);
	g_free(dbname);
	g_free(user);

	/** 添加一个单条语句的规则， select a, b, c from test where id in (A)*/
	sql = g_strdup("SELect a,b,    c from    test      where id in ('A')");
	dbname = g_strdup("test");
	user = g_strdup("test");
	type = SQL_SINGLE;
	action = ACTION_BLOCK;
	is_disabled = FALSE;

	rule = add_sql_security_rule(
			rules,
			sql,
			dbname,
			user,
			type,
			action,
			is_disabled);
	g_assert(rule);
	g_assert(FALSE == rule->is_disabled);
	g_assert(rule->action == ACTION_BLOCK);
	g_assert_cmpstr(rule->sql_content->str, ==, "select a, b, c from test where id in ('A')");

	/** 查询sql限制字典 */
	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			rules,
			NULL,
			"select \t *  \n from `test` -- just a test",
			"test",
			"test"));

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,     #aaaaaa\n b,     c    from test where id in ('A')",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a, b, c from test where id in ('a')",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a, c from test where id in ('A')",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,b, c from test where id in (1, 2)",
			"test",
			"test"));

	g_free(sql);
	g_free(dbname);
	g_free(user);

	/** 再添加一条某类的sql限制规则 */
	sql = g_strdup("select a, b, c FROM `test` where id in (1, 2, 3, 4)");
	dbname = g_strdup("test");
	user = g_strdup("test");
	type = SQL_TEMPLATE;
	action = ACTION_WARNING;
	is_disabled = FALSE;

	rule = add_sql_security_rule(
			rules,
			sql,
			dbname,
			user,
			type,
			action,
			is_disabled);
	g_assert(rule);
	g_assert(FALSE == rule->is_disabled);
	g_assert(rule->action == ACTION_WARNING);
	g_assert_cmpstr(rule->sql_content->str, ==, "select a, b, c from test where id in (N)");

	g_free(sql);
	g_free(dbname);
	g_free(user);
	/** 重新查询限制词典 */
	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			rules,
			NULL,
			"select \t *  \n from `test` -- just a test",
			"test",
			"test"));

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,     #aaaaaa\n b,     c    from test where id in ('A')",
			"test",
			"test"));

	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			rules,
			NULL,
			"select a, b, c from test where id in ('a')",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a, c from test where id in ('A')",
			"test",
			"test"));

	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,b, c from test where id in (1, 2)",
			"test",
			"test"));

	/** 删除sql限制语句 */
	g_assert(del_sql_security_rule(
				rules,
				"select a,b,c from `test` where id in ('A')",
				"test",
				"test",
				SQL_SINGLE));
	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,     #aaaaaa\n b,     c    from test where id in ('A')",
			"test",
			"test"));

	/** 再删除一条sql限制 */
	g_assert(del_sql_security_rule(
					rules,
					"select a,b,c from `test` where id in ('A')",
					"test",
					"test",
					SQL_TEMPLATE));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,     #aaaaaa\n b,     c    from test where id in ('A')",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a, b, c from test where id in ('a')",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			rules,
			NULL,
			"select a,b, c from test where id in (1, 2)",
			"test",
			"test"));

} END_TEST

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/test_add_sql_security_rule", test_add_sql_security_rule);
	g_test_add_func("/core/test_del_sql_security_rule", test_del_sql_security_rule);
	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */




