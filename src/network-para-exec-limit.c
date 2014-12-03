/*
 * network-para-exec-limit.c
 *
 *  Created on: 2013-9-23
 *      Author: jinxuanhou
 */

#include <glib.h>
#include "glib-ext.h"
#include "network-para-exec-limit.h"

/**
 * @author sohu-inc.com
 * 构造并发限制的变量,返回的变量需要调用者自己释放内存，
 * @see para_exec_limit_free
 * @return 构造的para_exec_limit变量
 */
para_exec_limit * para_exec_limit_new() {
	para_exec_limit * para_limit = g_new0(para_exec_limit, 1);
	para_limit->limit_para = -1;
	para_limit->limit_switch = TRUE;

	return para_limit;
}

/**
 * @author sohu-inc.com
 * 并发限制变量的释放
 * @param limit_parm 需要释放的指针变量
 */
void para_exec_limit_free(para_exec_limit *limit_parm) {
	if (limit_parm) {
		g_free(limit_parm);
	}
}

/**
 * @author sohu-inc.com
 * hashtable value 内存释放函数
 * @param data 需要释放的内存的指针
 */
void g_hash_table_sql_para_limit_free(gpointer data) {
	para_exec_limit_free((para_exec_limit *)data);
}

/** sql-list */
/**
 * @author sohu-inc.com
 * sql并行限制列表变量的构造
 * @return sql_limit_list*
 */
sql_limit_list *sql_limit_list_new() {
	sql_limit_list * limit_list = g_new0(sql_limit_list, 1);

	g_rw_lock_init(&limit_list->list_lock);
	limit_list->sql_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_sql_para_limit_free);

	return limit_list;
}

/**
 * @author sohu-inc.com
 * sql并行限制列表内存释放
 * @param sql_list 需要释放内存的列表指针
 */
void sql_limit_list_free(sql_limit_list *sql_list) {
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

/**
 * @author sohu-inc.com
 * hashtable value 内存释放函数
 * @param data 需要被释放内存的变量指针
 */
void g_hash_table_sql_list_free(gpointer data) {
	sql_limit_list_free((sql_limit_list *) data);
}

/**
 * @author sohu-inc.com
 * 向sql-list 列表中增加一个并行限制规则
 * @param sql_list 限制列表
 * @param normalized_sql 标准化sql
 * @param limit_para 并行限制数
 * @param limit_switch 规则开关
 * @return 新添加的并发限制变量指针
 */
para_exec_limit* insert_sql_limit_rule(sql_limit_list *sql_list,
		const char *normalized_sql, gint limit_para, gboolean limit_switch) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return NULL;
	}

	para_exec_limit *sql_limit = para_exec_limit_new();
	sql_limit->limit_para = limit_para;
	sql_limit->limit_switch = limit_switch;

	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&sql_list->list_lock);
	g_hash_table_insert(sql_list->sql_list, sql_key, sql_limit);
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	return sql_limit;
}

/** 修改并发限制值 */
/**
 * @author sohu-inc.com
 * 修改规则并行限制值
 * @param sql_list 并行限制规则列表
 * @param normalized_sql 标准化sql
 * @param limit_para 并行限制值
 * @return 若修改成功则返回TRUE,反之返回FALSE(说明对应的规则不存在或其他)
 */
gboolean modify_sql_limit_para(sql_limit_list *sql_list,
		const char *normalized_sql, gint limit_para) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	para_exec_limit* para_limit = NULL;

	g_rw_lock_writer_lock(&sql_list->list_lock);
	para_limit = g_hash_table_lookup(sql_list->sql_list, sql_key);
	if (para_limit) {
		para_limit->limit_para = limit_para;
		ret = TRUE;
	}
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/** 修改并发限制规则开关 */
/**
 * @author sohu-inc.com
 * 更新并发限制规则的启停状态
 * @param sql_list 并发现只列表
 * @param normalized_sql 标准化sql
 * @param limit_switch 并发现只开关
 * @return 更新成功返回TRUE;反之因为对应的规则不存在返回FALSE;
 */
gboolean modify_sql_limit_switch(sql_limit_list *sql_list,
		const char *normalized_sql, gboolean limit_switch) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	para_exec_limit* para_limit = NULL;

	g_rw_lock_writer_lock(&sql_list->list_lock);
	para_limit = g_hash_table_lookup(sql_list->sql_list, sql_key);
	if (para_limit) {
		para_limit->limit_switch = limit_switch;
		ret = TRUE;
	}
	g_rw_lock_writer_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/** 删除并发限制规则 */
/**
 * @author sohu-inc.com
 * 删除对应的并发限制规则
 * @param sql_list 并发限制列表
 * @param normalized_sql 标准化的sql
 * @return
 */
gboolean delete_sql_limit_rule(sql_limit_list *sql_list,
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

/** 查询对应的语句的并发现只规则 */
/**
 * @author sohu-inc.com
 * 获取对应语句的并发限制
 * @param sql_list 并发限制列表
 * @param normalized_sql 标准化sql
 * @param para_limit 需要填充的限制变量
 * @return 找到对应的限制变量返回TRUE,没有找到返回FALSE
 */
gboolean get_sql_para_exec_limit(sql_limit_list *sql_list,
		const char *normalized_sql, para_exec_limit *para_limit) {
	if (NULL == sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	g_assert(para_limit);

	gboolean ret = FALSE;
	para_exec_limit* para_limit_tmp = NULL;
	GString *sql_key = g_string_new(normalized_sql);

	g_rw_lock_reader_lock(&sql_list->list_lock);
	para_limit_tmp = g_hash_table_lookup(sql_list->sql_list, sql_key);
	if (para_limit_tmp) {
		para_limit->limit_para = para_limit_tmp->limit_para;
		para_limit->limit_switch = para_limit_tmp->limit_switch;
		ret = TRUE;
		para_limit_tmp = NULL;
	}
	g_rw_lock_reader_unlock(&sql_list->list_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/** db_sql_list */
/**
 * @author sohu-inc.com
 * 构造db_sql 并发限制列表
 * @return 构造的列表变量指针
 */
db_sql_limit_list *db_sql_limit_list_new() {
	db_sql_limit_list *db_sql_list = g_new0(db_sql_limit_list, 1);

	g_rw_lock_init(&db_sql_list->list_lock);
	db_sql_list->db_sql_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_sql_list_free);

	return db_sql_list;
}

/**
 * @author sohu-inc.com
 * db_sql 限制列表释放
 * @param db_sql_list 需要释放内存的限制列表
 */
void db_sql_limit_list_free(db_sql_limit_list *db_sql_list) {
	if (NULL == db_sql_list) {
		return;
	}

	g_rw_lock_writer_lock(&db_sql_list->list_lock);
	g_hash_table_destroy(db_sql_list->db_sql_list);
	db_sql_list->db_sql_list = NULL;
	g_rw_lock_writer_unlock(&db_sql_list->list_lock);

	g_rw_lock_clear(&db_sql_list->list_lock);

	g_free(db_sql_list);
}

/**
 * hash table 销毁函数
 * @param data 需要释放内存的变量的指针
 */
void g_hash_table_db_sql_list_free(gpointer data) {
	db_sql_limit_list_free((db_sql_limit_list *)data);
}

/** 增加并发限制 */
para_exec_limit* insert_db_sql_limit_rule(db_sql_limit_list *db_sql_list,
		const char *db_name, const char *normalized_sql, gint limit_para,
		gboolean limit_switch) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return NULL ;
	}

	para_exec_limit *ret = NULL;
	sql_limit_list *sql_list_tmp = NULL;

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
		sql_list_tmp = sql_limit_list_new();
		g_hash_table_insert(db_sql_list->db_sql_list, db_key_used,
				sql_list_tmp);
	}
	g_rw_lock_writer_unlock(&db_sql_list->list_lock);

	g_string_free(db_key, TRUE);

	ret = insert_sql_limit_rule(sql_list_tmp, normalized_sql, limit_para,
			limit_switch);

	return ret;
}

/** 修改并发限制值 */
gboolean modify_db_sql_limit_para(db_sql_limit_list *db_sql_list,
		const char * db_name, const char *normalized_sql, gint limit_para) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	sql_limit_list *sql_list_tmp = NULL;

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
		ret = modify_sql_limit_para(sql_list_tmp, normalized_sql, limit_para);
	}
	return ret;
}

/** 修改并发限制规则开关 */
gboolean modify_db_sql_limit_switch(db_sql_limit_list *db_sql_list,
		const char * db_name, const char *normalized_sql, gboolean limit_switch) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	sql_limit_list *sql_list_tmp = NULL;

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
		ret = modify_sql_limit_switch(sql_list_tmp, normalized_sql,
				limit_switch);
	}
	return ret;
}

/** 删除并发限制规则 */
gboolean delete_db_sql_limit_rule(db_sql_limit_list *db_sql_list,
		const char * db_name, const char *normalized_sql) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	sql_limit_list *sql_list_tmp = NULL;

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
		ret = delete_sql_limit_rule(sql_list_tmp, normalized_sql);
	}
	return ret;
}

/** 查询对应的语句的并发现只规则 */
gboolean get_db_sql_para_exec_limit(db_sql_limit_list *db_sql_list,
		const char *db_name, const char *normalized_sql,
		para_exec_limit*para_limit) {
	if (NULL == db_sql_list || NULL == normalized_sql) {
		return FALSE;
	}

	g_assert(para_limit);

	gboolean ret = FALSE;
	sql_limit_list *sql_list_tmp = NULL;

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
		ret = get_sql_para_exec_limit(sql_list_tmp, normalized_sql, para_limit);
	}
	return ret;
}

user_db_sql_limit_list *user_db_sql_limit_list_new() {
	user_db_sql_limit_list *user_db_sql_list = g_new0(user_db_sql_limit_list, 1);

	g_rw_lock_init(&user_db_sql_list->list_lock);
	user_db_sql_list->user_db_sql_list = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal, g_hash_table_string_free,
			g_hash_table_db_sql_list_free);

	return user_db_sql_list;
}

void user_db_sql_limit_list_free(user_db_sql_limit_list *user_db_sql_list) {
	if (NULL == user_db_sql_list) {
		return;
	}

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	g_hash_table_destroy(user_db_sql_list->user_db_sql_list);
	user_db_sql_list->user_db_sql_list = NULL;
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_rw_lock_clear(&user_db_sql_list->list_lock);

	g_free(user_db_sql_list);
}

/** 增加并发限制 */
para_exec_limit* insert_user_db_sql_limit_rule(
		user_db_sql_limit_list *user_db_sql_list, const char * user_name,
		const char *db_name, const char *normalized_sql, gint limit_para,
		gboolean limit_switch) {
	if (NULL == user_db_sql_list || NULL == user_name || NULL == normalized_sql) {
		return NULL ;
	}

	para_exec_limit *ret = NULL;
	db_sql_limit_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list, user_key);
	if (NULL == db_sql_list_tmp) {
		GString *user_key_used = g_string_new(user_key->str);
		db_sql_list_tmp = db_sql_limit_list_new();
		g_hash_table_insert(user_db_sql_list->user_db_sql_list, user_key_used,
				db_sql_list_tmp);
	}
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	ret = insert_db_sql_limit_rule(db_sql_list_tmp, db_name, normalized_sql, limit_para,
			limit_switch);

	return ret;
}

/** 修改并发限制值 */
gboolean modify_user_db_sql_limit_para(user_db_sql_limit_list *user_db_sql_list,
		const char *user_name, const char * db_name, const char *normalized_sql,
		gint limit_para) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	db_sql_limit_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = modify_db_sql_limit_para(db_sql_list_tmp, db_name, normalized_sql,
				limit_para);
	}
	return ret;
}

/** 修改并发限制规则开关 */
gboolean modify_user_db_sql_limit_switch(
		user_db_sql_limit_list *user_db_sql_list, const char *user_name, const char * db_name,
		const char *normalized_sql, gboolean limit_switch) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	db_sql_limit_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = modify_db_sql_limit_switch(db_sql_list_tmp, db_name, normalized_sql,
				limit_switch);
	}
	return ret;
}

/** 删除并发限制规则 */
gboolean delete_user_db_sql_limit_rule(user_db_sql_limit_list *user_db_sql_list,
		const char *user_name, const char * db_name, const char *normalized_sql) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	db_sql_limit_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = delete_db_sql_limit_rule(db_sql_list_tmp, db_name,
				normalized_sql);
	}
	return ret;
}

/** 查询对应的语句的并发现只规则 */
gboolean get_user_db_sql_para_exec_limit(
		user_db_sql_limit_list *user_db_sql_list, const char *user_name, const char *db_name,
		const char *normalized_sql, para_exec_limit*para_limit) {
	if (NULL == user_db_sql_list || NULL == user_name
			|| NULL == normalized_sql) {
		return FALSE;
	}

	g_assert(para_limit);
	gboolean ret = FALSE;
	db_sql_limit_list *db_sql_list_tmp = NULL;

	GString *user_key = g_string_new(user_name);

	g_rw_lock_writer_lock(&user_db_sql_list->list_lock);
	db_sql_list_tmp = g_hash_table_lookup(user_db_sql_list->user_db_sql_list,
			user_key);
	g_rw_lock_writer_unlock(&user_db_sql_list->list_lock);

	g_string_free(user_key, TRUE);

	if (db_sql_list_tmp) {
		ret = get_db_sql_para_exec_limit(db_sql_list_tmp, db_name,
				normalized_sql, para_limit);
	}
	return ret;
}

