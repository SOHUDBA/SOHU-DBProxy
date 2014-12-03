/*
 * network-query-rate.c
 *
 *  Created on: 2014-4-3
 *      Author: jinxuanhou
 */

#include "string.h"
#include "network-query-rate.h"


/** 统计查询语句条数时，分为读端口语句条数、写端口语句条数以及错误语句的条数 */

/** 创建统计变量 */
query_rate_statistic * query_rate_statistic_new() {
	query_rate_statistic * r_static = g_new0(query_rate_statistic,1);

	r_static->rate_statistic_lock = &r_static->_rate_statistic_lock;
	g_mutex_init(r_static->rate_statistic_lock);

	r_static->is_banned = FALSE;
	memset(r_static->query_accumulated_num, 0, PROXY_TYPE_NO*sizeof(gint64));
	memset(r_static->query_accumulated_error_num, 0, PROXY_TYPE_NO*sizeof(gint64));

	g_get_current_time(&r_static->update_time);

	return r_static;
}

/** 销毁统计变量 */
void query_rate_statistic_free(query_rate_statistic *query_rate) {
	if (NULL == query_rate) {
		return;
	}

	if (query_rate->rate_statistic_lock) {
		g_mutex_clear(query_rate->rate_statistic_lock);
		query_rate->rate_statistic_lock = NULL;
	}

	g_free(query_rate);
}

/** hash key 销毁函数 */
void g_hash_table_query_rate_statistic_free(gpointer data) {
	if (NULL != data) {
		query_rate_statistic_free((query_rate_statistic *)data);
	}
}

/** 统计hash表构造函数 */
query_rate_list *query_rate_list_new() {
	query_rate_list * r_list = g_new0(query_rate_list, 1);

	r_list->list_lock = &r_list->_list_lock;
	g_mutex_init(r_list->list_lock);

	r_list->query_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_query_rate_statistic_free);

	return r_list;
}

/** 统计hash销毁函数  */
void query_rate_list_free(query_rate_list *query_rate) {
	if (NULL == query_rate) {
		return;
	}

	g_mutex_lock(query_rate->list_lock);
	g_hash_table_destroy(query_rate->query_list);
	g_mutex_unlock(query_rate->list_lock);

	if (NULL != query_rate->list_lock) {
		g_mutex_clear(query_rate->list_lock);
		query_rate->list_lock = NULL;
	}

	g_free(query_rate);
}

/** 添加对某个用户的sql执行累计统计量 */
query_rate_statistic* insert_query_rate(
		query_rate_list *query_rate_list, const char *username,
		gint64 * query_accumulated_num,
		gint64 * query_accumulated_error_num,
		gboolean is_banned) {
	if (NULL == query_rate_list){
		return NULL;
	}

	if (NULL == username) {
		return NULL;
	}

	if (NULL == query_accumulated_num){
		return NULL;
	}

	if (NULL == query_accumulated_error_num) {
		return NULL;
	}

	query_rate_statistic * value = query_rate_statistic_new();
	value->is_banned = is_banned;
	memcpy(value->query_accumulated_num, query_accumulated_num, PROXY_TYPE_NO*sizeof(gint64));
	memcpy(value->query_accumulated_error_num, query_accumulated_error_num, PROXY_TYPE_NO*sizeof(gint64));

	GString *key = g_string_new(username);

	g_mutex_lock(query_rate_list->list_lock);
	g_hash_table_insert(query_rate_list->query_list, key, value);
	g_mutex_unlock(query_rate_list->list_lock);

	return value;
}

/** 将用户的sql累计执行数增加1 */
gint64 query_rate_inc(
		query_rate_list *query_rate_list, const char *username,
		proxy_rw type
		) {
	gint64 last_num = -1;
	if (NULL == query_rate_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	GString *key = g_string_new(username);
	g_mutex_lock(query_rate_list->list_lock);
	query_rate_statistic *pre_statistic = g_hash_table_lookup(query_rate_list->query_list,
			key);
	if (NULL == pre_statistic) {
		pre_statistic = query_rate_statistic_new();
		pre_statistic->is_banned = FALSE;
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_rate_list->query_list, key_used, pre_statistic);
	}
	g_mutex_unlock(query_rate_list->list_lock);

	if (NULL != pre_statistic) {
		g_mutex_lock(pre_statistic->rate_statistic_lock);
		last_num = pre_statistic->query_accumulated_num[type];
		pre_statistic->query_accumulated_num[type]++;
		g_mutex_unlock(pre_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);

	return last_num;
}

/** 将用户的sql累计错误执行数增加1 */
gint64 query_error_rate_inc(
		query_rate_list *query_rate_list, const char *username,
		proxy_rw type
		) {
	gint64 last_num = -1;
	if (NULL == query_rate_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	GString *key = g_string_new(username);
	g_mutex_lock(query_rate_list->list_lock);
	query_rate_statistic *pre_statistic = g_hash_table_lookup(query_rate_list->query_list,
			key);
	if (NULL == pre_statistic) {
		pre_statistic = query_rate_statistic_new();
		pre_statistic->is_banned = FALSE;
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_rate_list->query_list, key_used, pre_statistic);
	}
	g_mutex_unlock(query_rate_list->list_lock);

	if (NULL != pre_statistic) {
		g_mutex_lock(pre_statistic->rate_statistic_lock);
		last_num = pre_statistic->query_accumulated_error_num[type];
		pre_statistic->query_accumulated_error_num[type]++;
		g_mutex_unlock(pre_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);

	return last_num;
}



/** 修改某个用户的sql累计执行统计值 */
gint64 modify_query_rate_num(
		query_rate_list *query_rate_list, const char *username,
		gint64 query_accumulated_num, proxy_rw type) {

	if (NULL == query_rate_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (query_accumulated_num < 0) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	gint64 last_num = -1;

	GString *key = g_string_new(username);
	query_rate_statistic *pre_statistic = NULL;
	g_mutex_lock(query_rate_list->list_lock);
	pre_statistic = g_hash_table_lookup(query_rate_list->query_list,
			key);
	if (NULL == pre_statistic) {
		pre_statistic = query_rate_statistic_new();
		pre_statistic->is_banned = FALSE;
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_rate_list->query_list, key_used, pre_statistic);
	}
	g_mutex_unlock(query_rate_list->list_lock);

	if (NULL != pre_statistic) {
		g_mutex_lock(pre_statistic->rate_statistic_lock);
		last_num = pre_statistic->query_accumulated_num[type];
		pre_statistic->query_accumulated_num[type] = query_accumulated_num;
		g_mutex_unlock(pre_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);

	return last_num;
}

/** 修改某个用户的sql累计执行统计值 */
gint64 modify_query_error_rate_num(
		query_rate_list *query_rate_list, const char *username,
		gint64 query_accumulated_error_num, proxy_rw type) {

	if (NULL == query_rate_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (query_accumulated_error_num < 0) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	gint64 last_num = -1;

	GString *key = g_string_new(username);
	query_rate_statistic *pre_statistic = NULL;
	g_mutex_lock(query_rate_list->list_lock);
	pre_statistic = g_hash_table_lookup(query_rate_list->query_list,
			key);
	if (NULL == pre_statistic) {
		pre_statistic = query_rate_statistic_new();
		pre_statistic->is_banned = FALSE;
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_rate_list->query_list, key_used, pre_statistic);
	}
	g_mutex_unlock(query_rate_list->list_lock);

	if (NULL != pre_statistic) {
		g_mutex_lock(pre_statistic->rate_statistic_lock);
		last_num = pre_statistic->query_accumulated_error_num[type];
		pre_statistic->query_accumulated_error_num[type] = query_accumulated_error_num;
		g_mutex_unlock(pre_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);

	return last_num;
}

/** 将用户对应的统计量清除 */
gboolean delete_query_rate(
		query_rate_list *query_rate_list, const char *username) {
	if (NULL == query_rate_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	gboolean result = FALSE;
	GString *key = g_string_new(username);
	g_mutex_lock(query_rate_list->list_lock);
	result = g_hash_table_remove(query_rate_list->query_list, key);
	g_mutex_unlock(query_rate_list->list_lock);

	g_string_free(key, TRUE);

	return result;
}

/** 修改某个用户的状态*/
gboolean modify_query_rate_switch(
		query_rate_list *query_rate_list, const char *username,
		gboolean is_banned) {
	if (NULL == query_rate_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	GString *key = g_string_new(username);

	query_rate_statistic *pre_statistic = NULL;

	g_mutex_lock(query_rate_list->list_lock);
	pre_statistic = g_hash_table_lookup(query_rate_list->query_list, key);
	if (NULL == pre_statistic) {
		pre_statistic = query_rate_statistic_new();
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_rate_list->query_list, key_used, pre_statistic);
	}
	g_mutex_unlock(query_rate_list->list_lock);

	if (pre_statistic) {
		g_mutex_lock(pre_statistic->rate_statistic_lock);
		pre_statistic->is_banned = is_banned;
		g_get_current_time(&pre_statistic->update_time);
		g_mutex_unlock(pre_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);
	return TRUE;
}

/** 查询某个用户的累计执行条数 */
gint64 get_query_rate_num(
		query_rate_list *query_rate_list,
		const char *username) {
	if (NULL == query_rate_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	query_rate_statistic *tmp_statistic = NULL;
	gint64 result = -1;
	GString *key = g_string_new(username);

	g_mutex_lock(query_rate_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_rate_list->query_list, key);
	g_mutex_unlock(query_rate_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->rate_statistic_lock);
		int index = 0;
		result = 0;
		for (index = 0; index < PROXY_TYPE_NO; index++) {
			result += tmp_statistic->query_accumulated_num[index];
		}
		g_mutex_unlock(tmp_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的累计error执行条数 */
gint64 get_query_error_rate_num(
		query_rate_list *query_rate_list,
		const char *username) {
	if (NULL == query_rate_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	query_rate_statistic *tmp_statistic = NULL;
	gint64 result = -1;
	GString *key = g_string_new(username);

	g_mutex_lock(query_rate_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_rate_list->query_list, key);
	g_mutex_unlock(query_rate_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->rate_statistic_lock);
		int index = 0;
		result = 0;
		for (index = 0; index < PROXY_TYPE_NO; index++) {
			result += tmp_statistic->query_accumulated_error_num[index];
		}
		g_mutex_unlock(tmp_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的是否被禁用  */
gboolean get_query_rate_switch(
		query_rate_list *query_rate_list, const char *username
		) {
	if (NULL == query_rate_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	gboolean result = FALSE;
	GString *key = g_string_new(username);

	query_rate_statistic *pre_statistic = NULL;

	g_mutex_lock(query_rate_list->list_lock);
	pre_statistic = g_hash_table_lookup(query_rate_list->query_list, key);
	g_mutex_unlock(query_rate_list->list_lock);

	if (pre_statistic) {
		g_mutex_lock(pre_statistic->rate_statistic_lock);
		result = pre_statistic->is_banned;
		g_mutex_unlock(pre_statistic->rate_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}
