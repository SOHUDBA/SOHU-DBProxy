/*
 * mytest_sql_normalization.c
 *
 *  Created on: 2013-7-26
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

#include "network-sql-normalization.h"


#if GLIB_CHECK_VERSION(2, 16, 0)
extern void merge_multi_value_for_in(char *query_sql);
#define C(x) x, sizeof(x) - 1

#define START_TEST(x) void (x)(void)
#define END_TEST

START_TEST(test_merge_multi_value_for_in) {
	char *sql = g_strdup("select * from a.b where id in (?)");
	merge_multi_value_for_in(sql);

	g_assert_cmpstr(sql, ==, "select * from a.b where id in (N)");


	sql = g_strdup("select * from a.b where id in (?, ?, ?, ?)");
	merge_multi_value_for_in(sql);

	g_assert_cmpstr(sql, ==, "select * from a.b where id in (N)");

	sql = g_strdup("select * from a.b where id in (?, select id from a where id in (?, ?))");
	merge_multi_value_for_in(sql);

	g_assert_cmpstr(sql, ==, "select * from a.b where id in (N)");

	sql = g_strdup("select * from a.b where id in (select id from test where name in (?, ?, ?, ?))");
	merge_multi_value_for_in(sql);

	g_assert_cmpstr(sql, ==, "select * from a.b where id in (select id from test where name in (N))");

	sql = g_strdup("select a, b from a where id in (?, ?");
	merge_multi_value_for_in(sql);

	g_assert_cmpstr(sql, ==, "select a, b from a where id in (N)");
} END_TEST

START_TEST(test_sql_normalize_with_token_TEMPLATE) {
	/** 绑定变量替换掉 */
	char *sql = g_strdup("select a,b,c from `test`.`test` where name = 'test'");
	char *sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where name = ?");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select a,b,c from `test`.`test` where name = 'test' AND age = 19 and sex = 'female'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where name = ? and age = ? and sex = ?");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select a,b,c from `test`.`test` where name = 'test' AND age = 19 and class in (select class from test.class where class = 'class2')");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where name = ? and age = ? and class in (select class from test.class where class = ?)");
	g_free(sql);
	g_free(sql_normalized);

	/** 开头的空格去掉 */
	sql = g_strdup("       select a from `test`.`test`");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test");
	g_free(sql);
	g_free(sql_normalized);

	/** 语句中多个空着合并成一个空格 */
	sql = g_strdup("select       a   from `test`.`test`     ");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test");
	g_free(sql);
	g_free(sql_normalized);

	/** 去掉注释 ,包括三种形式的注释 */
	// 1. #注释
	sql = g_strdup("select   #aaaaaaaa \n    a  from  `test`.`test`     ");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select   #aaaaaaaa \n    a   from `test`.`test` where id = '#test_id'   ");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where id = ?");
	g_free(sql);
	g_free(sql_normalized);

	// 2. -- 注释
	sql = g_strdup("select   -- aaaaaaaa \n    a  from  `test`.`test` where test_id = '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = ?");
	g_free(sql);
	g_free(sql_normalized);

	// 3. /* */ 或 /*! */  注释
	sql = g_strdup("select     a  from      `test`.`test` /*	aaaaa\n badds \nsdfasdf */where test_id = '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = ?");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select     a   from      `test`/*!aaadddd*/.`test` /*	aaaaa\n badds \nsdfasdf */where test_id = '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = ?");
	g_free(sql);
	g_free(sql_normalized);

	/** 去掉换行符 */
	sql = g_strdup("select \n \r \t    a   from `test`.`test` /*	aaaaa\n badds \nsdfasdf */where test_id = \n	 '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = ?");
	g_free(sql);
	g_free(sql_normalized);

	/** 统一为小写 */
	sql = g_strdup("SELECT A,#aaaa\n B, C FROM /* \n*/ `TEST`.`TEST` WHERE ID = 'JJJJJ'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where id = ?");
	g_free(sql);
	g_free(sql_normalized);

	/** 将`db`.`table`的'`'符号去掉*/
	sql = g_strdup("SElect A,#aaaa\n B, C FROM /* \n*/ `TEST`.`TEST` WHERE ID = 'JJJJJ'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where id = ?");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("SElect A,#aaaa\n B, -- sdfadfd\n C FROM /* \n*/ `TEST` WHERE ID = 'JJJJJ'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test where id = ?");
	g_free(sql);
	g_free(sql_normalized);

	/** 将in (1, 2, 3, 4, 5)转换成in (N) */
	sql = g_strdup("SElect A,#aaaa\n B, -- sdfadfd\n C FROM /* \n*/ `TEST` WHERE ID in ('JJJJJ', 'aaa', 1, 2,3,4)");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test where id in (N)");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("SElect A,#aaaa\n B, -- sdfadfd\n C FROM /* \n*/ `TEST` WHERE ID in (select * from name where name in (1,2,3,4,5))");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test where id in (select * from name where name in (N))");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("update table set aa=12 where id in (1,2,2,2)");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "update table set aa = ? where id in (N)");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("update table set aa=12 where id in (1,2,2,");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	g_assert_cmpstr(sql_normalized, ==, "update table set aa = ? where id in (N)");
	g_free(sql);
	g_free(sql_normalized);

} END_TEST

START_TEST(test_sql_normalize_with_token_SINGLE) {
	/** 绑定变量不能做替换 */
	char *sql = g_strdup("select a,b,c from `test`.`test` where name = 'test'");
	char *sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where name = 'test'");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select a,b,c from `test`.`test` where name = 'test' AND age = 19 and sex = 'female'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where name = 'test' and age = 19 and sex = 'female'");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select a,b,c from `test`.`test` where name = 'test' AND age = 19 and class in (select class from test.class where class = 'class2')");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where name = 'test' and age = 19 and class in (select class from test.class where class = 'class2')");
	g_free(sql);
	g_free(sql_normalized);

	/** 开头的空格去掉 */
	sql = g_strdup("       select a from `test`.`test`");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test");
	g_free(sql);
	g_free(sql_normalized);

	/** 语句中多个空着合并成一个空格 */
	sql = g_strdup("select       a   from `test`.`test`     ");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test");
	g_free(sql);
	g_free(sql_normalized);

	/** 去掉注释 ,包括三种形式的注释 */
	// 1. #注释
	sql = g_strdup("select   #aaaaaaaa \n    a  from  `test`.`test`     ");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select   #aaaaaaaa \n    a   from `test`.`test` where id = '#test_id'   ");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where id = '#test_id'");
	g_free(sql);
	g_free(sql_normalized);

	// 2. -- 注释
	sql = g_strdup("select   -- aaaaaaaa \n    a  from  `test`.`test` where test_id = '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = '--test--'");
	g_free(sql);
	g_free(sql_normalized);

	// 3. /* */ 或 /*! */  注释
	sql = g_strdup("select     a  from      `test`.`test` /*	aaaaa\n badds \nsdfasdf */where test_id = '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = '--test--'");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("select     a   from      `test`/*!aaadddd*/.`test` /*	aaaaa\n badds \nsdfasdf */where test_id = '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = '--test--'");
	g_free(sql);
	g_free(sql_normalized);

	/** 去掉换行符 */
	sql = g_strdup("select \n \r \t    a   from `test`.`test` /*	aaaaa\n badds \nsdfasdf */where test_id = \n	 '--test--'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a from test.test where test_id = '--test--'");
	g_free(sql);
	g_free(sql_normalized);

	/** 统一为小写，但是查询的字符串不做转换 */
	sql = g_strdup("SELECT A,#aaaa\n B, C FROM /* \n*/ `TEST`.`TEST` WHERE ID = 'JJJJJ'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where id = 'JJJJJ'");
	g_free(sql);
	g_free(sql_normalized);

	/** 将`db`.`table`的'`'符号去掉*/
	sql = g_strdup("SElect A,#aaaa\n B, C FROM /* \n*/ `TEST`.`TEST` WHERE ID = 'JJJJJ'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test.test where id = 'JJJJJ'");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("SElect A,#aaaa\n B, -- sdfadfd\n C FROM /* \n*/ `TEST` WHERE ID = 'JJJJJ'");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test where id = 'JJJJJ'");
	g_free(sql);
	g_free(sql_normalized);

	/** 将in (1, 2, 3, 4, 5)不能转换 */
	sql = g_strdup("SElect A,#aaaa\n B, -- sdfadfd\n C FROM /* \n*/ `TEST` WHERE ID in ('JJJJJ', 'aaa', 1, 2,3,4)");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test where id in ('JJJJJ', 'aaa', 1, 2, 3, 4)");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("SElect A,#aaaa\n B, -- sdfadfd\n C FROM /* \n*/ `TEST` WHERE ID in (select * from name where name in (1,2,3,4,5))");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "select a, b, c from test where id in (select * from name where name in (1, 2, 3, 4, 5))");
	g_free(sql);
	g_free(sql_normalized);

	sql = g_strdup("update table set aa=12 where id in (1,2,2,2)");
	sql_normalized = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	g_assert_cmpstr(sql_normalized, ==, "update table set aa = 12 where id in (1, 2, 2, 2)");
	g_free(sql);
	g_free(sql_normalized);

} END_TEST


int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/test_merge_multi_value_for_in",test_merge_multi_value_for_in);
	g_test_add_func("/core/test_sql_normalize_with_token_TEMPLATE",test_sql_normalize_with_token_TEMPLATE);

	g_test_add_func("/core/test_sql_normalize_with_token_SINGLE",test_sql_normalize_with_token_SINGLE);
	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */

