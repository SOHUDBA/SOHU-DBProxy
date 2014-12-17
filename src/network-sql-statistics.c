/*
 * network-sql-statistics.c
 *
 *  Created on: 2013年9月23日
 *      Author: zhenfan
 */
#include <math.h>
#include <errno.h>
#include <glib.h>

#include "glib-ext.h"
#include "network-sql-statistics.h"
#include "network-sql-normalization.h"

#define SECTION_BASE_10 DEFAULT_SECTION_BASE
#define SECTION_10_ARRAY_LEN 15
#define SECTION_BASE_2 2u
#define SECTION_2_ARRAY_LEN 46

/**
 * statistics_info的构造函数
 * @return statistics_info对象
 */
static statistics_info *statistics_info_new() {
	statistics_info *stat_info = NULL;
	stat_info = g_new0(statistics_info, 1);
	stat_info->execute_count = 0;
	stat_info->accumulate_time = 0.0;
	stat_info->max_time = 0.0;
	stat_info->min_time = 0.0;
	return stat_info;
}

/**
 * statistics_info的析构函数
 * @param statistics_info对象
 */
static void statistics_info_free(statistics_info *stat_info) {
	if (NULL != stat_info) {
		g_free(stat_info);
		stat_info = NULL;
	}
}

/**
 * statistics_info的析构函数封装，用在g_hash_table_new_full指定成员的析构函数
 * @param gpointer
 */
static void g_hash_table_statistics_info_free(gpointer data) {
	statistics_info_free((statistics_info *)data);
}

/**
 * sql_info_table 构造函数
 * @return sql_info_table对象
 */
static sql_info_table* sql_info_table_new() {
	sql_info_table *table = g_new0(sql_info_table, 1);
	table->sql_info_table = g_hash_table_new_full(g_hash_table_string_hash, 
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_statistics_info_free);
	g_rw_lock_init(&table->table_lock);
	return table;
}

/**
 * sql_info_table 析构函数
 * @param sql_info_table对象
 */
static void sql_info_table_free(sql_info_table* table) {
	if (NULL != table) {
		g_rw_lock_writer_lock(&table->table_lock);
		g_hash_table_destroy(table->sql_info_table);
		table->sql_info_table = NULL;
		g_rw_lock_writer_unlock(&table->table_lock);
		g_rw_lock_clear(&table->table_lock);
		g_free(table);
		table = NULL;
	}
}

/**
 * sql_info_table 析构函数封装，用在g_hash_table_new_full指定成员的析构函数
 * @param gpointer
 */
static void g_hash_table_sql_info_table_free(gpointer data) {
	sql_info_table_free((sql_info_table*)data);
}

/**
 * 在已有的hashtable中新建一条normalized_sql的记录
 * @param sql_info_table对象
 * @param normalized_sql
 * @param running_time
 * @return 新建的statistics_info对象
 */
static statistics_info* insert_info_to_sql_info(
		sql_info_table *table,
		const char *normalized_sql,
		gdouble running_time
		) {
	if (NULL == table || NULL == normalized_sql) {
		return NULL;
	}

	statistics_info *info = statistics_info_new();
	info->accumulate_time = running_time;
	info->execute_count = 1;

	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&table->table_lock);
	g_hash_table_insert(table->sql_info_table, sql_key, info);
	g_rw_lock_writer_unlock(&table->table_lock);

	return info;
}

/**
 * 在已有的hashtable中找到normalized_sql的记录，如果存在更新记录，如果不存在调用insert_info_to_sql_info
 * @param sql_info_table对象
 * @param normalized_sql
 * @param running_time
 * @return 成功TRUE，失败FALSE
 */
static gboolean accumulate_time_to_sql_info(
		sql_info_table *table,
		const char *normalized_sql,
		gdouble running_time,
		gboolean is_under_limit) {
	if (NULL == table || NULL == normalized_sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	statistics_info *info = NULL;
	g_rw_lock_reader_lock(&table->table_lock);
	// 查找是否有匹配的normalized_sql
	info = g_hash_table_lookup(table->sql_info_table, sql_key);
	g_rw_lock_reader_unlock(&table->table_lock);
	
	if (NULL != info) { // 如果存在，更新其值
		info->accumulate_time += running_time;
		info->execute_count++;
		ret = TRUE;
	} else { // 如果不存在，插入一条新的normalized_sql记录
		if (is_under_limit) {
			insert_info_to_sql_info(table, normalized_sql, running_time);
			ret = TRUE;
		}
	}
	g_string_free(sql_key, TRUE);

	return ret;
}

/**
 * time_section_statistics 构造函数，这是最外层的hashtable结构
 * @param base sql统计的基底
 * @param lower_exp 指数下届
 * @param upper_exp 指数上届
 * @return time_section_statistics对象
 */
time_section_statistics* time_section_statistics_new(guint base, gint lower_exp, gint upper_exp) {
	time_section_statistics *table = g_new0(time_section_statistics, 1);
	table->user_db_sql_info_table = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_sql_info_table_free);
	table->total_time = 0.0;
	table->total_count = 0;
	g_rw_lock_init(&table->table_lock);
	table->section.base = base;
	table->section.lower_exp = lower_exp;
	table->section.upper_exp = upper_exp;
	if (lower_exp == G_MININT32)
		table->section.lower_bound = 0;
	else
		table->section.lower_bound = pow(table->section.base, lower_exp);
	table->section.upper_bound = pow(table->section.base, upper_exp);
	return table;
}

/**
 * time_section_statistics 析构函数
 * @param time_section_statistics对象
 */
void time_section_statistics_free(time_section_statistics* table) {
	if (NULL != table) {
		g_rw_lock_writer_lock(&table->table_lock);
		g_hash_table_destroy(table->user_db_sql_info_table);
		table->user_db_sql_info_table = NULL;
		g_rw_lock_writer_unlock(&table->table_lock);
		g_rw_lock_clear(&table->table_lock);
		g_free(table);
		table = NULL;
	}
}

/**
 * time_section_statistics 析构函数封装，用在time_section_index_free释放成员变量
 * @param gpointer
 */
void g_hash_table_time_section_statistics_free(gpointer data) {
	time_section_statistics_free((time_section_statistics *)data);
}

/**
 * 计算user_db_sql_info hashtable中的记录条数，用于内存控制
 * @param time_section_statistics对象
 */
gint get_user_db_sql_info_count(time_section_statistics *table) {
	gint count = 0;
	GList *head = NULL;
	GList *cur = NULL;
	sql_info_table *cur_sql_info_table = NULL;
	
	g_rw_lock_reader_lock(&table->table_lock);
	// 每一个head是sql_info_table结构
	head = g_hash_table_get_values(table->user_db_sql_info_table);
	cur = head;
	while (cur != NULL) {
		cur_sql_info_table = (sql_info_table *)cur->data;
		count += g_hash_table_size(cur_sql_info_table->sql_info_table);
		cur = cur->next;
	}
	g_rw_lock_reader_unlock(&table->table_lock);
	// 将链表内存释放
	g_list_free(head);
	return count;
}

/**
 * 指定user_db_name 插入一条sql记录
 * @note 如果这条user_db_name已有记录，只更新已有的sql_info hashtable
 *       如果这条user_db_name无记录，创建一个sql_info hashtable
 * @param time_section_statistics对象
 * @param user_db_name
 * @param normalized_sql
 * @param running_time
 * @return 成功TRUE 失败FALSE
 */
gboolean insert_info_to_user_db_sql_info(
		time_section_statistics *table,
		const char *user_db_name,
		const char *normalized_sql,
		gdouble running_time,
		gboolean is_under_limit) {
	if (NULL == table || NULL == user_db_name || NULL == normalized_sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	GString *user_db_key = g_string_new(user_db_name);
	sql_info_table* sql_info_table_v = NULL;
	
	g_rw_lock_writer_lock(&table->table_lock);
	sql_info_table_v = g_hash_table_lookup(table->user_db_sql_info_table, user_db_key);
	if (NULL == sql_info_table_v) {
		sql_info_table_v = sql_info_table_new();
		GString *user_db_key_used = g_string_new(user_db_name);
		g_hash_table_insert(table->user_db_sql_info_table, user_db_key_used, sql_info_table_v);
	}
	g_rw_lock_writer_unlock(&table->table_lock);
	ret = accumulate_time_to_sql_info(
			sql_info_table_v,
			normalized_sql,
			running_time,
			is_under_limit);

	g_string_free(user_db_key, TRUE);
	return ret;
}

/**
 * 创建time_section_statistics的索引
 * @note 以10为基底 数组长度为15
 *       以2为基底 数组长度为46
 * @param base sql统计基底
 * @return time_section_index对象
 */
time_section_index *time_section_index_new(guint base) {
	gint i, pivot, lower_exp, upper_exp;
	time_section_index *tmi = g_new0(time_section_index, 1);
	if (SECTION_BASE_10 != base && SECTION_BASE_2 != base)
		base = DEFAULT_SECTION_BASE;
	tmi->base = base;
	if (SECTION_BASE_10 == base) {
		tmi->array_len = SECTION_10_ARRAY_LEN;
	} else if(SECTION_BASE_2 == base) {
		tmi->array_len = SECTION_2_ARRAY_LEN;
	}
	tmi->time_section_statistics_array = g_ptr_array_sized_new(tmi->array_len);
	tmi->sql_staitistics_record_count = 0;
	for (i = 0; i < tmi->array_len; i++) {
		if (SECTION_BASE_10 == tmi->base) {
			pivot = SECTION_10_ARRAY_LEN / 2 - 1;
			if (i == 0) 
				lower_exp = G_MININT32;
			else
				lower_exp = i - pivot - 1;
			upper_exp = i - pivot;
			g_ptr_array_add(tmi->time_section_statistics_array, time_section_statistics_new(tmi->base, lower_exp, upper_exp));
		} else if (SECTION_BASE_2 == tmi->base) {
			pivot = SECTION_2_ARRAY_LEN / 2 - 4;
			if (i == 0)
				lower_exp = G_MININT32;
			else
				lower_exp = i - pivot - 1;
			upper_exp = i - pivot;
			g_ptr_array_add(tmi->time_section_statistics_array, time_section_statistics_new(tmi->base, lower_exp, upper_exp));
		}
	}
	return tmi;
}

/**
 * time_section_index 析构函数
 * @param time_section_index对象
 */
void time_section_index_free(time_section_index *tmi) {
	guint i;
	if (NULL != tmi) {
		if (NULL != tmi->time_section_statistics_array) {
			for (i = 0; i < tmi->time_section_statistics_array->len; i++) {
				g_hash_table_time_section_statistics_free(tmi->time_section_statistics_array->pdata[i]);
			}
			g_ptr_array_free(tmi->time_section_statistics_array, TRUE);
		}
		g_free(tmi);
	}
}

/**
 * 获取sql限制中所有区间的标准化sql记录数
 * @param time_section_index对象
 */
gint get_sql_statistics_record_count(time_section_index *tmi) {
	guint i;
	gint count = 0;
	time_section_statistics *tss = NULL;
	if (NULL != tmi) {
		if (NULL != tmi->time_section_statistics_array) {
			for (i = 0; i < tmi->time_section_statistics_array->len; i++) {
				tss = (time_section_statistics *)tmi->time_section_statistics_array->pdata[i];
				count += get_user_db_sql_info_count(tss);
			}
		}
	}
	return count;
}

/**
 * 计算以10为底的time归属区间
 * @param time
 */
static int get_10_index_by_running_time(gdouble time) {
    int n = 0, index, pivot;
	pivot = SECTION_10_ARRAY_LEN / 2 - 1;
    if (time <= 1.0) {
		do {
			n++;
			time *= 10;
		} while (time <= 1.0 && n <= pivot);
		index = pivot + 1- n;
    } else if (time > 1.0) {
		do {
			n++;
			time /= 10;
		} while (time > 1.0 && n < SECTION_10_ARRAY_LEN - 1 - pivot);
		index = pivot + n;
	}
    return index;
}

/**
 * 计算以2为底的time归属区间
 * @param time
 */
static int get_2_index_by_running_time(gdouble time) {
    int n = 0, index, pivot;
	pivot = SECTION_2_ARRAY_LEN / 2 - 4;
    if (time <= 1.0) {
		do {
			n++;
			time *= 2;
		} while (time <= 1.0 && n <= pivot);
		index = pivot + 1 - n;
    } else if (time > 1.0) {
		do {
			n++;
			time /= 2;
		} while (time > 1.0 && n < SECTION_2_ARRAY_LEN - 1 - pivot);
		index = pivot + n;
	}
    return index;
}

/**
 * 计算以base为底的time归属区间
 * @param base
 * @param time
 */
int get_section_index_by_running_time(guint base, gdouble time) {
	if (SECTION_BASE_10 != base && SECTION_BASE_2 != base)
		base = DEFAULT_SECTION_BASE;
	if (SECTION_BASE_10 == base) 
		return get_10_index_by_running_time(time);
	else
		return get_2_index_by_running_time(time);
}

void get_normalized_sql(const char *sql, const GPtrArray *tokens, GString *normalized_sql, normalize_type type) {
	char *normalized_sql_in_use = NULL;
	if (0 == normalized_sql->len) {
		normalized_sql_in_use = sql_normalize_with_token_dispatch(tokens, sql, type);
		g_string_append(normalized_sql, normalized_sql_in_use);
	}
	if (NULL != normalized_sql_in_use) {
		g_free(normalized_sql_in_use);
	}
}

/************************************************************/
/**             下面是关于sql直方图统计的Thread检测部分                             **/
/************************************************************/
/**
 * 创建sql统计内存检测线程数据结构(不起线程)
 */
sql_statistics_thread_t *sql_statistics_thread_new(void) {
	sql_statistics_thread_t *sql_statistics_thread;
	sql_statistics_thread = g_new0(sql_statistics_thread_t, 1);
	return sql_statistics_thread;
}


/**
 * 销毁sql统计内存检测线程
 */
void sql_statistics_thread_free(sql_statistics_thread_t *sql_statistics_thread) {
	gboolean is_thread = FALSE;

	if (!sql_statistics_thread)
		return;

	is_thread = (sql_statistics_thread->thr != NULL);

	g_debug("join sql statistics thread");
	if (sql_statistics_thread->thr)
		g_thread_join(sql_statistics_thread->thr);

	g_debug("free sql statistics event base");
	if (is_thread && sql_statistics_thread->event_base)
		event_base_free(sql_statistics_thread->event_base);

	g_free(sql_statistics_thread);

	return;
}


/**
 * 初始化sql统计内存检测
 * 初始化事件base
 */
void sql_statistics_thread_init(sql_statistics_thread_t *sql_statistics_thread, chassis *chas) {
	sql_statistics_thread->event_base = event_base_new();
	sql_statistics_thread->chas = chas;
	return;
}


/**
 * 启动sql统计内存检测线程
 */
void sql_statistics_thread_start(sql_statistics_thread_t *sql_statistics_thread) {
	GError *gerr = NULL;
	g_message("%s: starting a sql statistics thread", G_STRLOC);
	sql_statistics_thread->thr = g_thread_try_new("sql statistics",
			(GThreadFunc) sql_statistics_thread_loop,
			sql_statistics_thread, &gerr);
	if (gerr) {
		g_critical("%s: %s", G_STRLOC, gerr->message);
		g_error_free(gerr);
		gerr = NULL;
	}
	return;
}

/**
 * sql统计内存检测线程主循环
 *
 */
void *sql_statistics_thread_loop(sql_statistics_thread_t *sql_statistics_thread) {

	while (!chassis_is_shutdown()) {
		GTimeVal begin_time;
		GTimeVal end_time;
#define SQL_STATISTICS_SLEEP_SECONDS 5
		guint sleep_seconds = SQL_STATISTICS_SLEEP_SECONDS;

		g_get_current_time(&begin_time);
		
		chassis *chas = sql_statistics_thread->chas;
		/* 计算当前sql统计中的sql条数 */
		if (chas->is_sql_statistics && (chas->tmi->sql_staitistics_record_count < chas->sql_staitistics_record_limit)) {
			chas->tmi->sql_staitistics_record_count = get_sql_statistics_record_count(chas->tmi);
			g_debug("%s: sql_statistics_thread_loop counts sql_staitistics_record_count (%d)",
									G_STRLOC, chas->tmi->sql_staitistics_record_count);
		}

		g_get_current_time(&end_time);

		/* Sleep */
		//g_message("going to sleep for %d seconds", sleep_seconds);
		while ((begin_time.tv_sec + sleep_seconds > end_time.tv_sec)
				&& !chassis_is_shutdown()) {
			struct timeval timeout;
			int rr;
			timeout.tv_sec = 1;
			timeout.tv_usec = 0;
			g_assert(event_base_loopexit(sql_statistics_thread->event_base,&timeout) == 0);
			rr = event_base_dispatch(sql_statistics_thread->event_base);
			if (rr == -1) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if (errno == EINTR)
					continue;
				g_critical(
						"%s: leaving sql_statistics_thread_loop sleep early, errno != EINTR was: %s (%d)",
						G_STRLOC, g_strerror(errno), errno);
				break;
			}
			g_get_current_time(&end_time);
			/*g_debug("begin_time: %d, end_time: %d", begin_time.tv_sec, end_time.tv_sec);*/
		}
	} /* end of while() */

	g_message("sql statistics thread is shutdown");
	return NULL;
} /* end of connection_scaler_thread_loop() */
