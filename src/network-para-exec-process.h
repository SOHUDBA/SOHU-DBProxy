/*
 * network-para-exec-process.h
 *
 *  Created on: 2013-9-24
 *      Author: jinxuanhou
 */

#ifndef NETWORK_PARA_EXEC_PROCESS_H_
#define NETWORK_PARA_EXEC_PROCESS_H_

#include <glib.h>
#include "glib-ext.h"
#include "chassis-mainloop.h"
#include "network-sql-normalization.h"
#include "network-para-exec-limit.h"

#define PARA_LIMIT_TYPE_NUM 2
#define PARA_SQL_TYPE_NUM 2

typedef enum {
	PARA_EXEC_INDIVIDUAL, PARA_EXEC_GLOBAL
} para_exec_limit_type;

typedef enum {
	PARA_SQL_SINGLE = 0, PARA_SQL_TEMPLATE
} para_exec_sql_type;

struct para_exec_limit_rules{
	user_db_sql_limit_list *para_exec_individ_rules[PARA_SQL_TYPE_NUM];
	sql_limit_list *para_exec_global_rules[PARA_SQL_TYPE_NUM];
};

NETWORK_API para_exec_limit_rules* para_exec_limit_rules_new();
NETWORK_API void para_exec_limit_rules_free(para_exec_limit_rules *rules);

/** 增加并发限制 */
NETWORK_API para_exec_limit* add_sql_para_rule(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, gint limit_para, gboolean limit_switch);

/** 修改并发限制值 */
NETWORK_API gboolean modify_sql_para_rule_limit_para(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, gint limit_para);

/** 修改并发限制规则开关 */
NETWORK_API gboolean modify_sql_para_rule_limit_switch(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, gboolean limit_switch);

/** 删除并发限制规则 */
NETWORK_API gboolean delete_sql_para_rule_limit_rule(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type);

/** 查询对应的并发限制数 */
NETWORK_API gboolean get_sql_para_rule(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, const GPtrArray *tokens,
		GString *normalized_sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, para_exec_limit*para_limit);

struct statistic_dic{
	GHashTable *statistic_dic[PARA_SQL_TYPE_NUM];
	GMutex dic_lock[PARA_SQL_TYPE_NUM];
};

NETWORK_API statistic_dic *statistic_dic_new();
NETWORK_API void statistic_dic_free(statistic_dic* dic);

NETWORK_API void dec_para_statistic_info (statistic_dic* dic,
		const char *user_db_key, const char *normalized_sql,
		para_exec_sql_type sql_type);

NETWORK_API gint * get_para_statistic_info(statistic_dic* dic,
		const char *user_db_key, const char *normalized_sql,
		para_exec_sql_type sql_type);

#endif /* NETWORK_PARA_EXEC_PROCESS_H_ */
