/*
 * mytest_sql_statistics.c
 *
 *  Created on: 2013年9月30日
 *      Author: zhenfan
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
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

#include "network-sql-statistics.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1

#define START_TEST(x) void (x)(void)
#define END_TEST

typedef struct test_data {
	const char *user_dbname;
	const char *sql;
	gdouble running_time;
} test_data;

static void my_g_strfreev (gchar **str_array){
	if (str_array) {
		int i;

		for (i = 0; str_array[i] != NULL; i++)
			g_free (str_array[i]);

		g_free (str_array);
	}
}

// 和admin中的函数基本一致，入参不同
static GPtrArray *construct_showqueryresponsetime_rows(time_section_index *tmi, const gchar *username, const gchar *dbname) {
	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();
	guint index;
	
	time_section_statistics *time_section_stat = NULL;
	
	GList *user_db_list = NULL;
	GList *user_db_list_tmp = NULL;
	GString *user_db_key = NULL;
	
	GList *sql_list = NULL;
	GList *sql_list_tmp = NULL;
	GString *sql_key = NULL;
	
	sql_info_table *sql_info_v = NULL;
	statistics_info *info = NULL;
	
	gchar *tmp_buffer = g_new0(gchar, 32);
	gchar **user_db_split_array = NULL;
	
	for (index = 0; index < tmi->time_section_statistics_array->len; index++) {
		// 找到对应section的hash_table
		time_section_stat = tmi->time_section_statistics_array->pdata[index];
		g_rw_lock_reader_lock(&time_section_stat->table_lock);
		// 取出key链表并进行遍历
		user_db_list = g_hash_table_get_keys(time_section_stat->user_db_sql_info_table);
		user_db_list_tmp = user_db_list;
		// 对于每一个user_db的组合字符串进行遍历
		while (user_db_list_tmp) {
			user_db_key = (GString *)(user_db_list_tmp->data);
			if (user_db_key) {
				sql_info_v = g_hash_table_lookup(time_section_stat->user_db_sql_info_table, user_db_key);
				user_db_split_array = g_strsplit(user_db_key->str, "_", 2);
				// 判断username是否符合
				if (NULL != username) {
					if (0 != strcmp(user_db_split_array[0], username)) {
						my_g_strfreev(user_db_split_array);
						user_db_list_tmp = user_db_list_tmp->next;
						continue;
					}
				}
				if (NULL != dbname) {
					if (0 != strcmp(user_db_split_array[1], dbname)) {
						my_g_strfreev(user_db_split_array);
						user_db_list_tmp = user_db_list_tmp->next;
						continue;
					}
				}
				g_rw_lock_reader_lock(&sql_info_v->table_lock);
				sql_list = g_hash_table_get_keys(sql_info_v->sql_info_table);
				sql_list_tmp = sql_list;
				while (sql_list_tmp) {
					sql_key = (GString *)(sql_list_tmp->data);
					if (sql_key) {
						info = g_hash_table_lookup(sql_info_v->sql_info_table, sql_key);
						if (info) {
							/** 构造一行新的数据单元 */
							row = g_ptr_array_new();
							
							/** 添加time列 */
							sprintf(tmp_buffer, "%lf~%lf", time_section_stat->section.lower_bound, time_section_stat->section.upper_bound);
							g_ptr_array_add(row, g_strdup(tmp_buffer));
							
							/** 添加user列 */
							g_ptr_array_add(row,
									g_strdup(user_db_split_array[0]));
							
							/** 添加db列 */
							g_ptr_array_add(row,
									g_strdup(user_db_split_array[1]));
							
							/** 添加sql列*/
							g_ptr_array_add(row,
									g_strdup(sql_key->str));
							
							/** 添加count列*/
							sprintf(tmp_buffer, "%d", info->execute_count);
							g_ptr_array_add(row, g_strdup(tmp_buffer));
							
							/** 添加total列*/
							sprintf(tmp_buffer, "%lf", info->accumulate_time);
							g_ptr_array_add(row, g_strdup(tmp_buffer));
							
							//添加到结果集中
							g_ptr_array_add(rows, row);
						}
					}
					sql_list_tmp = sql_list_tmp->next;
				}
				g_list_free(sql_list);			
				g_rw_lock_reader_unlock(&sql_info_v->table_lock);
				my_g_strfreev(user_db_split_array);
			}
			user_db_list_tmp = user_db_list_tmp->next;	
		}
		g_list_free(user_db_list);
		g_rw_lock_reader_unlock(&time_section_stat->table_lock);
	}
	g_free(tmp_buffer);
	tmp_buffer = NULL;
	return rows;
}

static void destroy_rows(GPtrArray *rows) {
	if (!rows)
		return;

	guint i = 0;
	guint j = 0;
	GPtrArray *row = NULL;
	if (rows) {
		for (i = 0; i < rows->len; i++) {
			row = rows->pdata[i];

			for (j = 0; j < row->len; j++) {
				g_free(row->pdata[j]);
			}

			g_ptr_array_free(row, TRUE);
		}
		g_ptr_array_free(rows, TRUE);
		rows = NULL;
	}
}

START_TEST(test_get_section_index_by_running_time) {
	gint index, i;
	double time_10[] = {1.2e-7, 3.3e-6, 2.2e-5, 1.2e-4, 8e-3, 0.04, 0.3, 
						 1.3, 13, 130, 1.4e3, 1.5e4, 1.5e5, 1.5e6, 1.5e7,
						 1.5e8, 1.5e9, 0.00000000009, 0.000000012, 0.01, 0.1, 1, 10};
	for (i = 0; i < 23; i++) {
		index = get_section_index_by_running_time(10, time_10[i]);
		if (i == 15) {
			g_assert_cmpint(index, ==, 14);
		} else if (i == 16) {
			g_assert_cmpint(index, ==, 14);
		} else if (i == 17) {
			g_assert_cmpint(index, ==, 0);
		} else if (i == 18) {
			g_assert_cmpint(index, ==, 0);
		} else if (i == 19) {
			g_assert_cmpint(index, ==, 4);
		} else if (i == 20) {
			g_assert_cmpint(index, ==, 5);
		} else if (i == 21) {
			g_assert_cmpint(index, ==, 6);
		} else if (i == 22) {
			g_assert_cmpint(index, ==, 7);
		} else {
			g_assert_cmpint(index, ==, i);
		}
	}
	
	double time_2[] = {1.2 / pow(2, 20), 1.2 / pow(2, 19), 1.2 / pow(2, 18), 1.2 / pow(2, 17), 1.2 / pow(2, 16), 1.2 / pow(2, 15), 
					   1.2 / pow(2, 14), 1.2 / pow(2, 13), 1.2 / pow(2, 12), 1.2 / pow(2, 11), 1.2 / pow(2, 10), 1.2 / pow(2, 9),
					   1.2 / pow(2, 8), 1.2 / pow(2, 7), 1.2 / pow(2, 6), 1.2 / pow(2, 5), 1.2 / pow(2, 4), 1.2 / pow(2, 3),
					   1.2 / pow(2, 2), 1.2 / 2, 1.2, 1.2 * 2, 1.2 * pow(2, 2), 1.2 * pow(2, 3), 
					   1.2 * pow(2, 4), 1.2 * pow(2, 5), 1.2 * pow(2, 6), 1.2 * pow(2, 7), 1.2 * pow(2, 8), 1.2 * pow(2, 9), 
					   1.2 * pow(2, 10), 1.2 * pow(2, 11), 1.2 * pow(2, 12), 1.2 * pow(2, 13), 1.2 * pow(2, 14), 1.2 * pow(2, 15), 
					   1.2 * pow(2, 16), 1.2 * pow(2, 17), 1.2 * pow(2, 18), 1.2 * pow(2, 19), 1.2 * pow(2, 20), 1.2 * pow(2, 21), 
					   1.2 * pow(2, 22), 1.2 * pow(2, 23), 1.2 * pow(2, 24), 1.2 * pow(2, 25), 
					   1.2 * pow(2, 26), 1.2 * pow(2, 27), 1.2 / pow(2, 21), 1.2 / pow(2, 22), 0.25, 0.5, 1, 2};
	for (i = 0; i < 54; i++) {
		index = get_section_index_by_running_time(2, time_2[i]);
		if (i == 46) {
			g_assert_cmpint(index, ==, 45);
		} else if (i == 47) {
			g_assert_cmpint(index, ==, 45);
		} else if (i == 48) {
			g_assert_cmpint(index, ==, 0);
		} else if (i == 49) {
			g_assert_cmpint(index, ==, 0);
		} else if (i == 50) {
			g_assert_cmpint(index, ==, 17);
		} else if (i == 51) {
			g_assert_cmpint(index, ==, 18);
		} else if (i == 52) {
			g_assert_cmpint(index, ==, 19);
		} else if (i == 53) {
			g_assert_cmpint(index, ==, 20);
		} else {
			g_assert_cmpint(index, ==, i);
		}
	}
} END_TEST

START_TEST(test_insert_show_user_db_sql_info) {
	gint index;
	guint i;
	// 只需要测试以10为底的时间slot，以2为底的同理
	test_data data[] = {
		// 同一个index slot中 index=5
		{"test_test", "select * from table_a where a = 3", 0.023},
		{"test_test", "select * from table_a where a = 333", 0.011},
		{"test_test", "select * from table_a where b = 4", 0.033},	
		{"test_test1", "select 1 from table_a where a = 222", 0.034},
		// 同一个index slot中 index=6
		{"test_test", "select 1 from table_a where a = 333 and b = 222", 1},
		{"test_test", "select 1 from table_a where a = 222 and b = 333", 0.34},
		{"test_test1", "select 1 from table_a where a = 222", 0.24},
		{"test_test1", "select 1 from table_a where a = 222", 0.2},
		// 同一个index slot中 index=8
		{"test_test", "select 1 from table_a where a = 333 and b = 222", 22.33},
		{"test_test", "select 1 from table_a where a = 222 and b = 333", 33.22},
		{"test_test1", "select 1 from table_a where a = 222", 100},
		{"test1_test1", "select 1 from table_a where a = 222", 44.22},
	};
	// 初始化
	time_section_index *tmi = time_section_index_new(10);
	for (i = 0; i < sizeof(data) / sizeof(test_data); i++) {
		index = get_section_index_by_running_time(tmi->base, data[i].running_time);
		char *sql_normalized = sql_normalize_with_token(data[i].sql, NORMALIZE_FOR_TEMPLATE);
		insert_info_to_user_db_sql_info(
				tmi->time_section_statistics_array->pdata[index], 
				data[i].user_dbname,
				sql_normalized,
				data[i].running_time,
				TRUE);
		g_free(sql_normalized);
	}
	
	GPtrArray *rows = construct_showqueryresponsetime_rows(tmi, NULL, NULL);
	g_assert(rows->len == 8);
	destroy_rows(rows);
	
	rows = construct_showqueryresponsetime_rows(tmi, "test", NULL);
	g_assert(rows->len == 7);
	destroy_rows(rows);
	
	rows = construct_showqueryresponsetime_rows(tmi, NULL, "test1");
	g_assert(rows->len == 4);
	destroy_rows(rows);	
	
	rows = construct_showqueryresponsetime_rows(tmi, "test1", "test1");
	g_assert(rows->len == 1);
	destroy_rows(rows);
	
	g_assert(get_user_db_sql_info_count((time_section_statistics *)(tmi->time_section_statistics_array->pdata[5])) == 3);
	g_assert(get_user_db_sql_info_count((time_section_statistics *)(tmi->time_section_statistics_array->pdata[6])) == 2);
	g_assert(get_user_db_sql_info_count((time_section_statistics *)(tmi->time_section_statistics_array->pdata[8])) == 3);
	g_assert(get_sql_statistics_record_count(tmi) == 8);
} END_TEST

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/test_get_section_index_by_running_time", test_get_section_index_by_running_time);
	g_test_add_func("/core/test_insert_show_user_db_sql_info", test_insert_show_user_db_sql_info);

	//g_test_add_func("/core/test_sql_normalize_with_token_SINGLE",test_sql_normalize_with_token_SINGLE);
	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */


