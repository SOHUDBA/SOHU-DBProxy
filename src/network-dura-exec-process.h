/*
 * network-dura-exec-process.h
 *
 *  Created on: 2013-10-9
 *      Author: jinxuanhou
 */

#ifndef NETWORK_DURA_EXEC_PROCESS_H_
#define NETWORK_DURA_EXEC_PROCESS_H_

#include <glib.h>
#include "glib-ext.h"
#include "chassis-mainloop.h"
#include "network-sql-normalization.h"
#include "network-dura-exec-limit.h"

#define DURA_LIMIT_TYPE_NUM 2
#define DURA_SQL_TYPE_NUM 2

typedef enum {
	DURA_EXEC_INDIVIDUAL, DURA_EXEC_GLOBAL
} dura_exec_limit_type;

typedef enum {
	DURA_SQL_SINGLE = 0, DURA_SQL_TEMPLATE
} dura_exec_sql_type;

struct dura_exec_limit_rules{
	user_db_sql_dura_list *dura_exec_individ_rules[DURA_SQL_TYPE_NUM];
	sql_dura_list *dura_exec_global_rules[DURA_SQL_TYPE_NUM];
};

NETWORK_API dura_exec_limit_rules* dura_exec_limit_rules_new();
NETWORK_API void dura_exec_limit_rules_free(dura_exec_limit_rules *rules);

/** 增加超时限制 */
NETWORK_API dura_exec_limit* add_sql_dura_rule(
		dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type, guint64 limit, gboolean limit_switch);

/** 修改超时限制值 */
NETWORK_API gboolean modify_sql_dura_rule_limit_para(
		dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type, guint64 limit);

/** 修改超时限制规则开关 */
NETWORK_API gboolean modify_sql_dura_rule_limit_switch(
		dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type, gboolean limit_switch);

/** 删除超时限制规则 */
NETWORK_API gboolean delete_sql_dura_rule_limit_rule(
		dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type);

/** 查询对应的超时限制数 */
NETWORK_API gboolean get_sql_dura_rule(
		dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, const GPtrArray *tokens,
		GString *normalized_sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type, dura_exec_limit*dura_limit);

#endif /* NETWORK_DURA_EXEC_PROCESS_H_ */
