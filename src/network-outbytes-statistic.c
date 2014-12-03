/*
 * network-outbytes-statistic.c
 *
 *  Created on: 2014-4-4
 *      Author: jinxuanhou
 */

#include <string.h>
#include "network-outbytes-statistic.h"

query_outbytes_statistic * query_outbytes_statistic_new() {
	query_outbytes_statistic * in_statistic = g_new0(query_outbytes_statistic, 1);
	in_statistic->outbytes_statistic_lock = &in_statistic->_outbytes_statistic_lock;
	g_mutex_init(in_statistic->outbytes_statistic_lock);
	in_statistic->is_banned = FALSE;
	memset(in_statistic->query_accumulated_outbytes, 0, PROXY_TYPE_NO*sizeof(gint64));
	g_get_current_time(&in_statistic->update_time);

	return in_statistic;
}

void query_outbytes_statistic_free(query_outbytes_statistic *query_outbytes) {
	if (NULL == query_outbytes) {
		return;
	}

	if (query_outbytes->outbytes_statistic_lock) {
		g_mutex_clear(query_outbytes->outbytes_statistic_lock);
		query_outbytes->outbytes_statistic_lock = NULL;
	}

	g_free(query_outbytes);
}


void g_hash_table_query_outbytes_statistic_free(gpointer data) {
	if (NULL != data) {
		query_outbytes_statistic_free((query_outbytes_statistic *)data);
	}
}

query_outbytes_list *query_outbytes_list_new() {
	query_outbytes_list * in_list = g_new0(query_outbytes_list, 1);

	in_list->list_lock = &in_list->_list_lock;
	g_mutex_init(in_list->list_lock);

	in_list->query_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_query_outbytes_statistic_free);

	return in_list;
}


void query_outbytes_list_free(query_outbytes_list *query_outbytes) {
	if (NULL == query_outbytes) {
		return;
	}

	g_mutex_lock(query_outbytes->list_lock);
	g_hash_table_destroy(query_outbytes->query_list);
	g_mutex_unlock(query_outbytes->list_lock);

	g_mutex_clear(query_outbytes->list_lock);

	g_free(query_outbytes);
}


gint64 query_outbytes_inc(
		query_outbytes_list *query_outbytes_list, const char *username,
		gint64 incre,
		proxy_rw type
		) {
	if (NULL == query_outbytes_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	query_outbytes_statistic *tmp_statistic = NULL;
	gint64 pre_bytes = 0;
	GString *key = g_string_new(username);

	g_mutex_lock(query_outbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_outbytes_list->query_list, key);
	if (NULL == tmp_statistic) {
		tmp_statistic = query_outbytes_statistic_new();
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_outbytes_list->query_list, key_used, tmp_statistic);
	}
	g_mutex_unlock(query_outbytes_list->list_lock);

	g_mutex_lock(tmp_statistic->outbytes_statistic_lock);
	pre_bytes = tmp_statistic->query_accumulated_outbytes[type];
	tmp_statistic->query_accumulated_outbytes[type]+=incre;
	g_mutex_unlock(tmp_statistic->outbytes_statistic_lock);

	g_string_free(key, TRUE);

	return pre_bytes;
}

gboolean query_outbytes_reset(query_outbytes_list *query_outbytes_list,
		const char *username, proxy_rw type) {
	if (NULL == query_outbytes_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	query_outbytes_statistic *tmp_statistic = NULL;
	gint64 pre_bytes = 0;
	GString *key = g_string_new(username);

	g_mutex_lock(query_outbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_outbytes_list->query_list, key);
	g_mutex_unlock(query_outbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->outbytes_statistic_lock);
		pre_bytes = tmp_statistic->query_accumulated_outbytes[type];
		tmp_statistic->query_accumulated_outbytes[type] = 0;
		g_mutex_unlock(tmp_statistic->outbytes_statistic_lock);
	}

	g_string_free(key, TRUE);
	return pre_bytes;
}

/** 将用户对应的统计量清除 */
gboolean delete_query_outbytes(
		query_outbytes_list *query_outbytes_list,
		const char *username) {
	if (NULL == query_outbytes_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_outbytes_list->list_lock);
	result = g_hash_table_remove(query_outbytes_list->query_list, key);
	g_mutex_unlock(query_outbytes_list->list_lock);

	g_string_free(key, TRUE);
	return result;
}

/** 修改某个用户的状态*/
gboolean modify_query_outbytes_switch(
		query_outbytes_list *query_outbytes_list, const char *username,
		gboolean is_banned) {
	if (NULL == query_outbytes_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	query_outbytes_statistic *tmp_statistic = NULL;
	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_outbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_outbytes_list->query_list, key);
	if (NULL == tmp_statistic) {
		tmp_statistic = query_outbytes_statistic_new();
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_outbytes_list->query_list, key_used, tmp_statistic);
	}
	g_mutex_unlock(query_outbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->outbytes_statistic_lock);
		tmp_statistic->is_banned = is_banned;
		g_get_current_time(&tmp_statistic->update_time);
		g_mutex_unlock(tmp_statistic->outbytes_statistic_lock);
		result = TRUE;
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的累计执行条数 */
gint64 get_query_outbytes_num_total(
		query_outbytes_list *query_outbytes_list, const char *username
		) {
	if (NULL == query_outbytes_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	query_outbytes_statistic *tmp_statistic = NULL;
	gint64 result = -1;
	GString *key = g_string_new(username);

	g_mutex_lock(query_outbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_outbytes_list->query_list, key);
	g_mutex_unlock(query_outbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->outbytes_statistic_lock);
		int index = 0;
		result = 0;
		for (index = 0; index < PROXY_TYPE_NO; index++) {
			result += tmp_statistic->query_accumulated_outbytes[index];
		}
		g_mutex_unlock(tmp_statistic->outbytes_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的是否被禁用  */
gboolean get_query_outbytes_switch(
		query_outbytes_list *query_outbytes_list, const char *username
		) {
	if (NULL == query_outbytes_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	query_outbytes_statistic *tmp_statistic = NULL;
	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_outbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_outbytes_list->query_list, key);
	g_mutex_unlock(query_outbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->outbytes_statistic_lock);
		result = tmp_statistic->is_banned;
		g_mutex_unlock(tmp_statistic->outbytes_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}
