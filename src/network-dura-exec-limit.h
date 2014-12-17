/*
 * network-exec-limit.h
 *
 *  Created on: 2013-10-9
 *      Author: jinxuanhou
 */

#ifndef NETWORK_DURA_EXEC_LIMIT_H_
#define NETWORK_DURA_EXEC_LIMIT_H_

#include <glib.h>
#include <glib-ext.h>
#include "network-exports.h"

typedef struct dura_exec_limit {
	gboolean limit_switch; /**< 规则开关与否 */
	guint64 limit_dura; /**< 最长执行时间 */
}dura_exec_limit;

NETWORK_API dura_exec_limit * dura_exec_limit_new();
NETWORK_API void dura_exec_limit_free(dura_exec_limit *limit_para);
NETWORK_API void g_hash_table_sql_dura_limit_free(gpointer data);


typedef struct sql_dura_list {
	GRWLock list_lock; /**< 列表超时锁 */
	GHashTable *sql_list; /**< sql超时限制列表 hash<sql, limit> */
} sql_dura_list;
NETWORK_API sql_dura_list *sql_dura_list_new();
NETWORK_API void sql_dura_list_free(sql_dura_list *sql_list);
NETWORK_API void g_hash_table_sql_dura_list_free(gpointer data);

/** 增加超时限制 */
NETWORK_API dura_exec_limit* insert_sql_dura_rule(
		sql_dura_list *sql_list, const char *normalized_sql, guint64 limit,
		gboolean limit_switch);

/** 修改超时限制值 */
NETWORK_API gboolean modify_sql_dura_para(
		sql_dura_list *sql_list, const char *normalized_sql, guint64 limit);

/** 修改超时限制规则开关 */
NETWORK_API gboolean modify_sql_dura_switch(
		sql_dura_list *sql_list, const char *normalized_sql,
		gboolean limit_switch);

/** 删除超时限制规则 */
NETWORK_API gboolean delete_sql_dura_rule(
		sql_dura_list *sql_list, const char *normalized_sql);

/** 查询对应的语句的超时现只规则 */
NETWORK_API gboolean get_sql_dura_exec_limit(
		sql_dura_list *sql_list, const char *normalized_sql,
		dura_exec_limit*para_limit);

typedef struct db_sql_dura_list {
	GRWLock list_lock; /**< 列表超时锁 */
	GHashTable *db_sql_list; /**< sql超时限制列表 hash<sql, limit> */
} db_sql_dura_list;

NETWORK_API db_sql_dura_list *db_sql_dura_list_new();
NETWORK_API void db_sql_dura_list_free(db_sql_dura_list *sql_list);
NETWORK_API void g_hash_table_db_sql_dura_list_free(gpointer data);

/** 增加超时限制 */
NETWORK_API dura_exec_limit* insert_db_sql_dura_rule(
		db_sql_dura_list *db_sql_list, const char *db_name, const char *normalized_sql, guint64 limit,
		gboolean limit_switch);

/** 修改超时限制值 */
NETWORK_API gboolean modify_db_sql_dura_para(
		db_sql_dura_list *db_sql_list, const char *db_name, const char *normalized_sql, guint64 limit);

/** 修改超时限制规则开关 */
NETWORK_API gboolean modify_db_sql_dura_switch(
		db_sql_dura_list *db_sql_list, const char *db_name, const char *normalized_sql,
		gboolean limit_switch);

/** 删除超时限制规则 */
NETWORK_API gboolean delete_db_sql_dura_rule(
		db_sql_dura_list *db_sql_list, const char *db_name, const char *normalized_sql);

/** 查询对应的语句的超时现只规则 */
NETWORK_API gboolean get_db_sql_dura_exec_limit(
		db_sql_dura_list *db_sql_list, const char *db_name, const char *normalized_sql,
		dura_exec_limit*para_limit);

typedef struct user_db_sql_dura_list {
	GRWLock list_lock; /**< 列表超时锁 */
	GHashTable *user_db_sql_list; /**< sql超时限制列表 hash<sql, limit> */
} user_db_sql_dura_list;

NETWORK_API user_db_sql_dura_list *user_db_sql_dura_list_new();
NETWORK_API void user_db_sql_dura_list_free(user_db_sql_dura_list *sql_list);
NETWORK_API void g_hash_table_user_db_sql_dura_list_free(gpointer data);

/** 增加超时限制 */
NETWORK_API dura_exec_limit* insert_user_db_sql_dura_rule(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name, const char *db_name, const char *normalized_sql, guint64 limit,
		gboolean limit_switch);

/** 修改超时限制值 */
NETWORK_API gboolean modify_user_db_sql_dura_para(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name, const char *db_name, const char *normalized_sql, guint64 limit);

/** 修改超时限制规则开关 */
NETWORK_API gboolean modify_user_db_sql_dura_switch(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name, const char *db_name, const char *normalized_sql,
		gboolean limit_switch);

/** 删除超时限制规则 */
NETWORK_API gboolean delete_user_db_sql_dura_rule(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name, const char *db_name, const char *normalized_sql);

/** 查询对应的语句的超时现只规则 */
NETWORK_API gboolean get_user_db_sql_dura_exec_limit(
		user_db_sql_dura_list *user_db_sql_list, const char * user_name, const char *db_name, const char *normalized_sql,
		dura_exec_limit*para_limit);

#endif /* NETWORK_DURA_EXEC_LIMIT_H_ */
