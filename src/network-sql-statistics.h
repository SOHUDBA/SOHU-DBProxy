/*
 * network-sql-statistics.c
 *
 *  Created on: 2013年9月23日
 *      Author: zhenfan
 */

#ifndef NETWORK_SQL_STATISTICS_C_
#define NETWORK_SQL_STATISTICS_C_

#include <glib.h>
#include "glib-ext.h"
#include "chassis-mainloop.h"
#include "network-exports.h"
#include "network-sql-normalization.h"

typedef struct {
	guint execute_count; // 执行次数
	gdouble accumulate_time; // 累计执行时（单位us）
	gdouble min_time; // 最小执行时间
	gdouble max_time; // 最大执行时间
} statistics_info;

typedef struct {
	guint base; // 区间底数
	gint lower_exp; // 区间下限指数
	gint upper_exp; // 区间上限指数
	gdouble lower_bound; // 区间下限
	gdouble upper_bound; // 区间上限
} time_section;

typedef struct {
	GHashTable *sql_info_table;// <sql, info>;
	GRWLock table_lock;
} sql_info_table;

typedef struct {
	gdouble total_time; // 所有的语句的执行时间
	guint total_count;
	time_section section; // 区间信息
	GHashTable *user_db_sql_info_table;// <username_db, GHashTable<sql,info>>;
	GRWLock table_lock;
} time_section_statistics;

struct time_section_index {
	guint base;// 时间区间索引的底数
	gint array_len; 
	GPtrArray *time_section_statistics_array; // 区间统计信息列表, 每个元素是&time_section_statistic;
	guint sql_staitistics_record_count;
};

NETWORK_API time_section_statistics* time_section_statistics_new();
NETWORK_API void time_section_statistics_free(time_section_statistics* table);
NETWORK_API void g_hash_table_time_section_statistics_free(gpointer data);
NETWORK_API gint get_user_db_sql_info_count(time_section_statistics *table);
NETWORK_API gboolean insert_info_to_user_db_sql_info(
		time_section_statistics *table,
		const char *user_db_name,
		const char *normalized_sql,
		gdouble running_time,
		gboolean is_under_limit);

NETWORK_API time_section_index *time_section_index_new(guint base);
NETWORK_API void time_section_index_free(time_section_index *tmi);
NETWORK_API gint get_sql_statistics_record_count(time_section_index *tmi);

NETWORK_API int get_section_index_by_running_time(guint base, gdouble time);
NETWORK_API void get_normalized_sql(const char *sql, const GPtrArray *tokens, GString *normalized_sql, normalize_type type);

/************************************************************/
/**             下面是关于sql直方图统计的Thread检测部分                             **/
/************************************************************/

struct sql_statistics_thread_t {
	GThread *thr;
	struct event_base *event_base;
	chassis *chas;
};

NETWORK_API sql_statistics_thread_t *sql_statistics_thread_new(void);
NETWORK_API void sql_statistics_thread_free(sql_statistics_thread_t *sql_statistics_thread);
NETWORK_API void sql_statistics_thread_init(sql_statistics_thread_t *sql_statistics_thread, chassis *chas);
NETWORK_API void sql_statistics_thread_start(sql_statistics_thread_t *sql_statistics_thread);
NETWORK_API void *sql_statistics_thread_loop(sql_statistics_thread_t *sql_statistics_thread);

#endif /* NETWORK_SQL_STATISTICS_C_ */
