/*
 * network-inbytes-statistic.c
 *
 *  Created on: 2014-4-4
 *      Author: jinxuanhou
 */
#include <string.h>
#include <network-inbytes-statistic.h>

query_inbytes_statistic * query_inbytes_statistic_new() {
	query_inbytes_statistic * in_statistic = g_new0(query_inbytes_statistic, 1);
	in_statistic->inbytes_statistic_lock = &in_statistic->_inbytes_statistic_lock;
	g_mutex_init(in_statistic->inbytes_statistic_lock);
	in_statistic->is_banned = FALSE;
	memset(in_statistic->query_accumulated_inbytes, 0, PROXY_TYPE_NO*sizeof(gint64));
	g_get_current_time(&in_statistic->update_time);

	return in_statistic;
}

void query_inbytes_statistic_free(query_inbytes_statistic *query_inbytes) {
	if (NULL == query_inbytes) {
		return;
	}

	if (query_inbytes->inbytes_statistic_lock) {
		g_mutex_clear(query_inbytes->inbytes_statistic_lock);
		query_inbytes->inbytes_statistic_lock = NULL;
	}

	g_free(query_inbytes);
}


void g_hash_table_query_inbytes_statistic_free(gpointer data) {
	if (NULL != data) {
		query_inbytes_statistic_free((query_inbytes_statistic *)data);
	}
}

query_inbytes_list *query_inbytes_list_new() {
	query_inbytes_list * in_list = g_new0(query_inbytes_list, 1);

	in_list->list_lock = &in_list->_list_lock;
	g_mutex_init(in_list->list_lock);

	in_list->query_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_query_inbytes_statistic_free);

	return in_list;
}


void query_inbytes_list_free(query_inbytes_list *query_inbytes) {
	if (NULL == query_inbytes) {
		return;
	}

	g_mutex_lock(query_inbytes->list_lock);
	g_hash_table_destroy(query_inbytes->query_list);
	g_mutex_unlock(query_inbytes->list_lock);

	g_mutex_clear(query_inbytes->list_lock);

	g_free(query_inbytes);
}


gint64 query_inbytes_inc(
		query_inbytes_list *query_inbytes_list, const char *username,
		gint64 incre,
		proxy_rw type
		) {
	if (NULL == query_inbytes_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	query_inbytes_statistic *tmp_statistic = NULL;
	gint64 pre_bytes = 0;
	GString *key = g_string_new(username);

	g_mutex_lock(query_inbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_inbytes_list->query_list, key);
	if (NULL == tmp_statistic) {
		tmp_statistic = query_inbytes_statistic_new();
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_inbytes_list->query_list, key_used, tmp_statistic);
	}
	g_mutex_unlock(query_inbytes_list->list_lock);

	g_mutex_lock(tmp_statistic->inbytes_statistic_lock);
	pre_bytes = tmp_statistic->query_accumulated_inbytes[type];
	tmp_statistic->query_accumulated_inbytes[type]+=incre;
	g_mutex_unlock(tmp_statistic->inbytes_statistic_lock);

	g_string_free(key, TRUE);

	return pre_bytes;
}

gboolean query_inbytes_reset(query_inbytes_list *query_inbytes_list,
		const char *username, proxy_rw type) {
	if (NULL == query_inbytes_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	if (type >= PROXY_TYPE_NO) {
		return -1;
	}

	query_inbytes_statistic *tmp_statistic = NULL;
	gint64 pre_bytes = 0;
	GString *key = g_string_new(username);

	g_mutex_lock(query_inbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_inbytes_list->query_list, key);
	g_mutex_unlock(query_inbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->inbytes_statistic_lock);
		pre_bytes = tmp_statistic->query_accumulated_inbytes[type];
		tmp_statistic->query_accumulated_inbytes[type] = 0;
		g_mutex_unlock(tmp_statistic->inbytes_statistic_lock);
	}

	g_string_free(key, TRUE);
	return pre_bytes;
}

/** 将用户对应的统计量清除 */
gboolean delete_query_inbytes(
		query_inbytes_list *query_inbytes_list,
		const char *username) {
	if (NULL == query_inbytes_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_inbytes_list->list_lock);
	result = g_hash_table_remove(query_inbytes_list->query_list, key);
	g_mutex_unlock(query_inbytes_list->list_lock);

	g_string_free(key, TRUE);
	return result;
}

/** 修改某个用户的状态*/
gboolean modify_query_inbytes_switch(
		query_inbytes_list *query_inbytes_list, const char *username,
		gboolean is_banned) {
	if (NULL == query_inbytes_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	query_inbytes_statistic *tmp_statistic = NULL;
	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_inbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_inbytes_list->query_list, key);
	if (NULL == tmp_statistic) {
		tmp_statistic = query_inbytes_statistic_new();
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_inbytes_list->query_list, key_used, tmp_statistic);
	}
	g_mutex_unlock(query_inbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->inbytes_statistic_lock);
		tmp_statistic->is_banned = is_banned;
		g_get_current_time(&tmp_statistic->update_time);
		g_mutex_unlock(tmp_statistic->inbytes_statistic_lock);
		result = TRUE;
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的累计执行条数 */
gint64 get_query_inbytes_num_total(
		query_inbytes_list *query_inbytes_list, const char *username
		) {
	if (NULL == query_inbytes_list) {
		return -1;
	}

	if (NULL == username) {
		return -1;
	}

	query_inbytes_statistic *tmp_statistic = NULL;
	gint64 result = -1;
	GString *key = g_string_new(username);

	g_mutex_lock(query_inbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_inbytes_list->query_list, key);
	g_mutex_unlock(query_inbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->inbytes_statistic_lock);
		int index = 0;
		result = 0;
		for (index = 0; index < PROXY_TYPE_NO; index++) {
			result += tmp_statistic->query_accumulated_inbytes[index];
		}
		g_mutex_unlock(tmp_statistic->inbytes_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的是否被禁用  */
gboolean get_query_inbytes_switch(
		query_inbytes_list *query_inbytes_list, const char *username
		) {
	if (NULL == query_inbytes_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	query_inbytes_statistic *tmp_statistic = NULL;
	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_inbytes_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_inbytes_list->query_list, key);
	g_mutex_unlock(query_inbytes_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->inbytes_statistic_lock);
		result = tmp_statistic->is_banned;
		g_mutex_unlock(tmp_statistic->inbytes_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}

