/*
 * network-dml-statistic.c
 *
 *  Created on: 2014-5-14
 *      Author: jinxuanhou
 */


#include "network-dml-statistic.h"

query_dml_statistic * query_dml_statistic_new() {
	query_dml_statistic *dml_s = g_new0(query_dml_statistic, 1);

	dml_s->dml_statistic_lock = &dml_s->_dml_statistic_lock;
	dml_s->is_banned = FALSE;
	g_mutex_init(dml_s->dml_statistic_lock);

	g_get_current_time(&dml_s->update_time);

	return dml_s;
}

void query_dml_statistic_free(query_dml_statistic *query_dml) {
	if (NULL == query_dml) {
		return;
	}

	if (query_dml->dml_statistic_lock) {
		g_mutex_clear(query_dml->dml_statistic_lock);
		query_dml->dml_statistic_lock = NULL;
	}

	g_free(query_dml);
}


void g_hash_table_query_dml_statistic_free(gpointer data) {
	if (NULL != data) {
		query_dml_statistic_free((query_dml_statistic *)data);
	}
}

query_dml_list *query_dml_list_new() {
	query_dml_list *dml_list = g_new0(query_dml_list, 1);

	dml_list->list_lock = &dml_list->_list_lock;

	g_mutex_init(dml_list->list_lock);
	dml_list->query_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_query_dml_statistic_free);

	return dml_list;
}

NETWORK_API void query_dml_list_free(query_dml_list *query_dml) {
	if (NULL == query_dml) {
		return;
	}

	g_mutex_lock(query_dml->list_lock);
	g_hash_table_destroy(query_dml->query_list);
	g_mutex_unlock(query_dml->list_lock);

	g_mutex_clear(query_dml->list_lock);

	g_free(query_dml);
}

/** 修改某个用户的状态*/
gboolean modify_query_dml_switch(
		query_dml_list *query_dml_list, const char *username,
		gboolean is_banned) {
	if (NULL == query_dml_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	query_dml_statistic *tmp_statistic = NULL;
	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_dml_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_dml_list->query_list, key);
	if (NULL == tmp_statistic) {
		tmp_statistic = query_dml_statistic_new();
		GString *key_used = g_string_new(username);
		g_hash_table_insert(query_dml_list->query_list, key_used, tmp_statistic);
	}
	g_mutex_unlock(query_dml_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->dml_statistic_lock);
		tmp_statistic->is_banned = is_banned;
		g_get_current_time(&tmp_statistic->update_time);
		g_mutex_unlock(tmp_statistic->dml_statistic_lock);
		result = TRUE;
	}

	g_string_free(key, TRUE);
	return result;
}

/** 查询某个用户的是否被禁用  */
gboolean get_query_dml_switch(
		query_dml_list *query_dml_list, const char *username
) {
	if (NULL == query_dml_list) {
		return FALSE;
	}

	if (NULL == username) {
		return FALSE;
	}

	query_dml_statistic *tmp_statistic = NULL;
	gboolean result = FALSE;
	GString *key = g_string_new(username);

	g_mutex_lock(query_dml_list->list_lock);
	tmp_statistic = g_hash_table_lookup(query_dml_list->query_list, key);
	g_mutex_unlock(query_dml_list->list_lock);

	if (tmp_statistic) {
		g_mutex_lock(tmp_statistic->dml_statistic_lock);
		result = tmp_statistic->is_banned;
		g_mutex_unlock(tmp_statistic->dml_statistic_lock);
	}

	g_string_free(key, TRUE);
	return result;
}

