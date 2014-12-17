/*
 * network-dura-exec-limit.c
 *
 *  Created on: 2013-10-9
 *      Author: jinxuanhou
 */

#include "network-dura-exec-limit.h"

dura_exec_limit * dura_exec_limit_new() {
	dura_exec_limit * dura_limit = g_new0(dura_exec_limit, 1);
	dura_limit->limit_dura = 0;
	dura_limit->limit_switch = TRUE;

	return dura_limit;
}

void dura_exec_limit_free(dura_exec_limit *limit_para) {
	if (limit_para) {
		g_free(limit_para);
	}
}

void g_hash_table_sql_dura_limit_free(gpointer data) {
	dura_exec_limit_free((dura_exec_limit *)data);
}

sql_dura_list *sql_dura_list_new() {
	sql_dura_list * limit_list = g_new0(sql_dura_list, 1);

	g_rw_lock_init(&limit_list->list_lock);
	limit_list->sql_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_sql_dura_limit_free);

	return limit_list;
}

void sql_dura_list_free(sql_dura_list *sql_list) {
	if (NULL == sql_list) {
		return;
	}

	g_rw_lock_writer_lock(&sql_list->list_lock);
	g_hash_table_destroy(sql_list->sql_list);
	sql_list->sql_list = NULL;
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_rw_lock_clear(&sql_list->list_lock);

	g_free(sql_list);
}

void g_hash_table_sql_dura_list_free(gpointer data) {
	sql_dura_list_free((sql_dura_list *)data);
}

/** 增加执行时间限制 */
dura_exec_limit* insert_sql_dura_rule(sql_dura_list *sql_list,
		const char *normalized_sql, guint64 limit, gboolean limit_switch) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return NULL ;
	}

	dura_exec_limit *sql_limit = dura_exec_limit_new();
	sql_limit->limit_dura = limit;
	sql_limit->limit_switch = limit_switch;

	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&sql_list->list_lock);
	g_hash_table_insert(sql_list->sql_list, sql_key, sql_limit);
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	return sql_limit;
}

/** 修改执行超时限制值 */
gboolean modify_sql_dura_para(sql_dura_list *sql_list,
		const char *normalized_sql, guint64 limit) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	dura_exec_limit* dura_limit = NULL;

	g_rw_lock_writer_lock(&sql_list->list_lock);
	dura_limit = g_hash_table_lookup(sql_list->sql_list, sql_key);
	if (dura_limit) {
		dura_limit->limit_dura = limit;
		ret = TRUE;
	}
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/** 修改执行时间限制规则开关 */
gboolean modify_sql_dura_switch(sql_dura_list *sql_list,
		const char *normalized_sql, gboolean limit_switch) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	dura_exec_limit* dura_limit = NULL;

	g_rw_lock_writer_lock(&sql_list->list_lock);
	dura_limit = g_hash_table_lookup(sql_list->sql_list, sql_key);
	if (dura_limit) {
		dura_limit->limit_switch = limit_switch;
		ret = TRUE;
	}
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/** 删除超时时间限制规则 */
gboolean delete_sql_dura_rule(sql_dura_list *sql_list,
		const char *normalized_sql) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);

	g_rw_lock_writer_lock(&sql_list->list_lock);
	ret = g_hash_table_remove(sql_list->sql_list, sql_key);
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/** 查询对应的语句的超时限制规则 */
gboolean get_sql_dura_exec_limit(sql_dura_list *sql_list,
		const char *normalized_sql, dura_exec_limit *dura_limit) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	g_assert(dura_limit);

	gboolean ret = FALSE;
	dura_exec_limit* dura_limit_tmp = NULL;
	GString *sql_key = g_string_new(normalized_sql);

	g_rw_lock_reader_lock(&sql_list->list_lock);
	dura_limit_tmp = g_hash_table_lookup(sql_list->sql_list, sql_key);
	if (dura_limit_tmp) {
		dura_limit->limit_dura = dura_limit_tmp->limit_dura;
		dura_limit->limit_switch = dura_limit_tmp->limit_switch;
		ret = TRUE;
		dura_limit_tmp = NULL;
	}
	g_rw_lock_reader_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

db_sql_dura_list *db_sql_dura_list_new() {
	db_sql_dura_list * limit_list = g_new0(db_sql_dura_list, 1);

	g_rw_lock_init(&limit_list->list_lock);
	limit_list->db_sql_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_sql_dura_list_free);

	return limit_list;
}

void db_sql_dura_list_free(db_sql_dura_list *sql_list) {
	if (NULL == sql_list) {
		return;
	}

	g_rw_lock_writer_lock(&sql_list->list_lock);
	g_hash_table_destroy(sql_list->db_sql_list);
	sql_list->db_sql_list = NULL;
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_rw_lock_clear(&sql_list->list_lock);

	g_free(sql_list);
}


void g_hash_table_db_sql_dura_list_free(gpointer data) {
	db_sql_dura_list_free((db_sql_dura_list *)data);
}

/** 增加超时时间限制 */
dura_exec_limit* insert_db_sql_dura_rule(db_sql_dura_list *db_sql_list,
		const char *db_name, const char *normalized_sql, guint64 limit,
		gboolean limit_switch) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return NULL ;
	}

	dura_exec_limit *ret = NULL;
	sql_dura_list *sql_list_tmp = NULL;

	GString *db_key = NULL;
	if (NULL == db_name) {
		db_key = g_string_new("NULL");
	} else {
		db_key = g_string_new(db_name);
	}

	g_rw_lock_writer_lock(&db_sql_list->list_lock);
	sql_list_tmp = g_hash_table_lookup(db_sql_list->db_sql_list, db_key);
	if (NULL == sql_list_tmp) {
		GString *db_key_used = g_string_new(db_key->str);
		sql_list_tmp = sql_dura_list_new();
		g_hash_table_insert(db_sql_list->db_sql_list, db_key_used,
				sql_list_tmp);
	}
	g_rw_lock_writer_unlock(&db_sql_list->list_lock);

	g_string_free(db_key, TRUE);

	ret = insert_sql_dura_rule(sql_list_tmp, normalized_sql, limit,
			limit_switch);

	return ret;
}

/** 修改超时限制值 */
gboolean modify_db_sql_dura_para(db_sql_dura_list *db_sql_list,
		const char *db_name, const char *normalized_sql, guint64 limit) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	sql_dura_list *sql_list_tmp = NULL;

	GString *db_key = NULL;
	if (NULL == db_name) {
		db_key = g_string_new("NULL");
	} else {
		db_key = g_string_new(db_name);
	}

	g_rw_lock_reader_lock(&db_sql_list->list_lock);
	sql_list_tmp = g_hash_table_lookup(db_sql_list->db_sql_list, db_key);
	g_rw_lock_reader_unlock(&db_sql_list->list_lock);

	g_string_free(db_key, TRUE);

	if (sql_list_tmp) {
		ret = modify_sql_dura_para(sql_list_tmp, normalized_sql, limit);
	}
	return ret;
}

/** 修改超时限制规则开关 */
gboolean modify_db_sql_dura_switch(db_sql_dura_list *db_sql_list,
		const char *db_name, const char *normalized_sql, gboolean limit_switch) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	sql_dura_list *sql_list_tmp = NULL;

	GString *db_key = NULL;
	if (NULL == db_name) {
		db_key = g_string_new("NULL");
	} else {
		db_key = g_string_new(db_name);
	}

	g_rw_lock_reader_lock(&db_sql_list->list_lock);
	sql_list_tmp = g_hash_table_lookup(db_sql_list->db_sql_list, db_key);
	g_rw_lock_reader_unlock(&db_sql_list->list_lock);

	g_string_free(db_key, TRUE);

	if (sql_list_tmp) {
		ret = modify_sql_dura_switch(sql_list_tmp, normalized_sql,
				limit_switch);
	}
	return ret;
}

/** 删除超时限制规则 */
gboolean delete_db_sql_dura_rule(
		db_sql_dura_list *db_sql_list, const char *db_name, const char *normalized_sql) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	sql_dura_list *sql_list_tmp = NULL;

	GString *db_key = NULL;
	if (NULL == db_name) {
		db_key = g_string_new("NULL");
	} else {
		db_key = g_string_new(db_name);
	}

	g_rw_lock_reader_lock(&db_sql_list->list_lock);
	sql_list_tmp = g_hash_table_lookup(db_sql_list->db_sql_list, db_key);
	g_rw_lock_reader_unlock(&db_sql_list->list_lock);

	g_string_free(db_key, TRUE);

	if (sql_list_tmp) {
		ret = delete_sql_dura_rule(sql_list_tmp, normalized_sql);
	}
	return ret;
}

/** 查询对应的语句的超时限制规则 */
gboolean get_db_sql_dura_exec_limit(db_sql_dura_list *db_sql_list,
		const char *db_name, const char *normalized_sql,
		dura_exec_limit*dura_limit) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	g_assert(dura_limit);

	gboolean ret = FALSE;
	sql_dura_list *sql_list_tmp = NULL;

	GString *db_key = NULL;
	if (NULL == db_name) {
		db_key = g_string_new("NULL");
	} else {
		db_key = g_string_new(db_name);
	}

	g_rw_lock_reader_lock(&db_sql_list->list_lock);
	sql_list_tmp = g_hash_table_lookup(db_sql_list->db_sql_list, db_key);
	g_rw_lock_reader_unlock(&db_sql_list->list_lock);

	g_string_free(db_key, TRUE);

	if (sql_list_tmp) {
		ret = get_sql_dura_exec_limit(sql_list_tmp, normalized_sql, dura_limit);
	}
	return ret;
}

user_db_sql_dura_list *user_db_sql_dura_list_new() {
	user_db_sql_dura_list * limit_list = g_new0(user_db_sql_dura_list, 1);

	g_rw_lock_init(&limit_list->list_lock);
	limit_list->user_db_sql_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_sql_dura_list_free);

	return limit_list;
}

void user_db_sql_dura_list_free(user_db_sql_dura_list *sql_list) {
	if (NULL == sql_list) {
		return;
	}

	g_rw_lock_writer_lock(&sql_list->list_lock);
	g_hash_table_destroy(sql_list->user_db_sql_list);
	sql_list->user_db_sql_list = NULL;
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_rw_lock_clear(&sql_list->list_lock);

	g_free(sql_list);
}

void g_hash_table_user_db_sql_dura_list_free(gpointer data) {
	user_db_sql_dura_list_free((user_db_sql_dura_list *)data);
}

/** 增加超时时间限制 */
dura_exec_limit* insert_user_db_sql_dura_rule(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name,
		const char *db_name, const char *normalized_sql, guint64 limit,
		gboolean limit_switch) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return NULL ;
	}

	dura_exec_limit *ret = NULL;
	db_sql_dura_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	if (NULL == db_sql_list_tmp) {
		GString *user_key_used = g_string_new(user_key->str);
		db_sql_list_tmp = db_sql_dura_list_new();
		g_hash_table_insert(user_db_sql_list->user_db_sql_list, user_key_used,
				db_sql_list_tmp);
	}
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	ret = insert_db_sql_dura_rule(db_sql_list_tmp, db_name, normalized_sql,
			limit, limit_switch);

	return ret;
}

/** 修改超时限制值 */
gboolean modify_user_db_sql_dura_para(user_db_sql_dura_list *user_db_sql_list,
		const char * user_name, const char *db_name, const char *normalized_sql,
		guint64 limit) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	db_sql_dura_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = modify_db_sql_dura_para(db_sql_list_tmp, db_name, normalized_sql,
				limit);
	}
	return ret;
}

/** 修改超时限制规则开关 */
gboolean modify_user_db_sql_dura_switch(user_db_sql_dura_list *user_db_sql_list,
		const char * user_name, const char *db_name, const char *normalized_sql,
		gboolean limit_switch) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	db_sql_dura_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = modify_db_sql_dura_switch(db_sql_list_tmp, db_name,
				normalized_sql, limit_switch);
	}
	return ret;
}

/** 删除超时限制规则 */
gboolean delete_user_db_sql_dura_rule(user_db_sql_dura_list *user_db_sql_list,
		const char * user_name, const char *db_name, const char *normalized_sql) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	db_sql_dura_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = delete_db_sql_dura_rule(db_sql_list_tmp, db_name, normalized_sql);
	}
	return ret;
}

/** 查询对应的语句的超时限制规则 */
gboolean get_user_db_sql_dura_exec_limit(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name, const char *db_name, const char *normalized_sql,
		dura_exec_limit *dura_limit) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	g_assert(dura_limit);
	gboolean ret = FALSE;
	db_sql_dura_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = get_db_sql_dura_exec_limit(db_sql_list_tmp, db_name,
				normalized_sql, dura_limit);
	}
	return ret;
}



