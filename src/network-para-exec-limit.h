/*
 * network-para-exec-limit.h
 *
 *  Created on: 2013-9-23
 *      Author: jinxuanhou
 *
 *  @DESC
 *  实现对并行执行sql的限制的控制管理
 */

#ifndef NETWORK_PARA_EXEC_LIMIT_H_
#define NETWORK_PARA_EXEC_LIMIT_H_

#include <glib.h>
#include "network-exports.h"

typedef struct para_exec_limit {
	gboolean limit_switch; /**< 规则开关与否 */
	gint limit_para; /**< 并发执行数 */
}para_exec_limit;

NETWORK_API para_exec_limit * para_exec_limit_new();
NETWORK_API void para_exec_limit_free(para_exec_limit *limit_parm);
NETWORK_API void g_hash_table_sql_para_limit_free(gpointer data);

typedef struct sql_limit_list {
	GRWLock list_lock; /**< 列表并发锁 */
	GHashTable *sql_list; /**< sql并发限制列表 hash<sql, limit> */
} sql_limit_list;
NETWORK_API sql_limit_list *sql_limit_list_new();
NETWORK_API void sql_limit_list_free(sql_limit_list *sql_list);
NETWORK_API void g_hash_table_sql_list_free(gpointer data);

/** 增加并发限制 */
NETWORK_API para_exec_limit* insert_sql_limit_rule(
		sql_limit_list *sql_list, const char *normalized_sql, gint limit_para,
		gboolean limit_switch);

/** 修改并发限制值 */
NETWORK_API gboolean modify_sql_limit_para(
		sql_limit_list *sql_list, const char *normalized_sql, gint limit_para);

/** 修改并发限制规则开关 */
NETWORK_API gboolean modify_sql_limit_switch(
		sql_limit_list *sql_list, const char *normalized_sql,
		gboolean limit_switch);

/** 删除并发限制规则 */
NETWORK_API gboolean delete_sql_limit_rule(
		sql_limit_list *sql_list, const char *normalized_sql);

/** 查询对应的语句的并发现只规则 */
NETWORK_API gboolean get_sql_para_exec_limit(
		sql_limit_list *sql_list, const char *normalized_sql,
		para_exec_limit*para_limit);

typedef struct db_sql_limit_list {
	GRWLock list_lock; /**< 列表并发锁 */
	GHashTable *db_sql_list; /**< sql并发限制列表 hash<db, sql_limit_list> */
} db_sql_limit_list;

NETWORK_API db_sql_limit_list *db_sql_limit_list_new();
NETWORK_API void db_sql_limit_list_free(db_sql_limit_list *db_sql_list);
NETWORK_API void g_hash_table_db_sql_list_free(gpointer data);

/** 增加并发限制 */
NETWORK_API para_exec_limit* insert_db_sql_limit_rule(
		db_sql_limit_list *db_sql_list, const char *db_name,
		const char *normalized_sql, gint limit_para, gboolean limit_switch);

/** 修改并发限制值 */
NETWORK_API gboolean modify_db_sql_limit_para(
		db_sql_limit_list *db_sql_list, const char * db_name,
		const char *normalized_sql, gint limit_para);

/** 修改并发限制规则开关 */
NETWORK_API gboolean modify_db_sql_limit_switch(
		db_sql_limit_list *db_sql_list, const char * db_name,
		const char *normalized_sql, gboolean limit_switch);

/** 删除并发限制规则 */
NETWORK_API gboolean delete_db_sql_limit_rule(
		db_sql_limit_list *db_sql_list, const char * db_name,
		const char *normalized_sql);

/** 查询对应的语句的并发现只规则 */
NETWORK_API gboolean get_db_sql_para_exec_limit(
		db_sql_limit_list *db_sql_list, const char *db_name,
		const char *normalized_sql, para_exec_limit*para_limit);

typedef struct user_db_sql_limit_list {
	GRWLock list_lock; /**< 列表并发锁 */
	GHashTable *user_db_sql_list; /**< sql并发限制列表 hash<db, sql_limit_list> */
} user_db_sql_limit_list;

NETWORK_API user_db_sql_limit_list *user_db_sql_limit_list_new();
NETWORK_API void user_db_sql_limit_list_free(
		user_db_sql_limit_list *user_db_sql_list);
/** 增加并发限制 */
NETWORK_API para_exec_limit* insert_user_db_sql_limit_rule(
		user_db_sql_limit_list *user_db_sql_list, const char * user_name,
		const char *db_name, const char *normalized_sql, gint limit_para,
		gboolean limit_switch);

/** 修改并发限制值 */
NETWORK_API gboolean modify_user_db_sql_limit_para(
		user_db_sql_limit_list *user_db_sql_list, const char *user_name,
		const char * db_name, const char *normalized_sql, gint limit_para);

/** 修改并发限制规则开关 */
NETWORK_API gboolean modify_user_db_sql_limit_switch(
		user_db_sql_limit_list *user_db_sql_list, const char *user_name,
		const char * db_name, const char *normalized_sql,
		gboolean limit_switch);

/** 删除并发限制规则 */
NETWORK_API gboolean delete_user_db_sql_limit_rule(
		user_db_sql_limit_list *user_db_sql_list, const char *user_name,
		const char * db_name, const char *normalized_sql);

/** 查询对应的语句的并发现只规则 */
NETWORK_API gboolean get_user_db_sql_para_exec_limit(
		user_db_sql_limit_list *user_db_sql_list, const char *user_name,
		const char *db_name, const char *normalized_sql,
		para_exec_limit*para_limit);

#endif /* NETWORK_PARA_EXEC_LIMIT_H_ */
