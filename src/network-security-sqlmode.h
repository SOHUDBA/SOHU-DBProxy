/*
 * network-security-sqlmode.h
 *
 *  Created on: 2013-7-25
 *      Author: jinxuanhou
 */

#ifndef NETWORK_SECURITY_SQLMODE_H_
#define NETWORK_SECURITY_SQLMODE_H_


#include <glib.h>

#include "chassis-mainloop.h"
#include "network-exports.h"
#include "network-sql-normalization.h"

#define RULE_MODEL_TYPE_NO 2

typedef enum {
	SQL_SINGLE,
	SQL_TEMPLATE
} security_model_type;

typedef enum {
	ACTION_SAFE,
	ACTION_LOG,
	ACTION_WARNING,
	ACTION_BLOCK
} security_action;

NETWORK_API char * get_security_action_name(security_action action);

typedef struct {
	security_action action; /**< 规则实行的动作 */
	GString *sql_content; /**< 对应的sql语句 标准化之后的sql语句 */
	gboolean is_disabled; /**< 是否启用该规则 */
} sql_security_rule;

NETWORK_API sql_security_rule * sql_security_rule_new();
NETWORK_API void sql_security_rule_free(sql_security_rule *sql_rule);
NETWORK_API void g_hash_table_sql_rule_free(gpointer data);

typedef struct {
	GHashTable *sql_rule;
	GRWLock table_lock;
} sql_rule_table;

NETWORK_API sql_rule_table *sql_rule_table_new();
NETWORK_API void sql_rule_table_free(sql_rule_table *table);
NETWORK_API void g_hash_table_sql_rule_table_free(gpointer data);

NETWORK_API sql_security_rule* insert_rule_to_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		security_action action,
		gboolean is_disabled
		); /** < 向最里层的sql-rule 的列表中插入规则*/

NETWORK_API sql_security_rule* get_rule_from_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql
		); /** < 向最里层的sql-rule 的列表中获取相应规则*/

NETWORK_API security_action get_action_from_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		int *exist
		); /** < 从最里层的sql-rule 的列表中获取相应sql语句对应的动作 */

NETWORK_API gboolean delete_rule_from_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql
		); /** < 从最里层的sql-rule 的列表中删除相应的规则*/

NETWORK_API gboolean set_action_in_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		security_action action
		); /** < 设置最里层sql-rule列表中规则的动作*/

NETWORK_API gboolean set_switch_in_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		gboolean is_disabled
		); /** < 设置最里层sql-rule列表中规则的启停开关*/

typedef struct {
	GHashTable *db_sql_rule;
	GRWLock table_lock;
} db_sql_rule_table;

NETWORK_API db_sql_rule_table *db_sql_rule_table_new();
NETWORK_API void db_sql_rule_table_free(db_sql_rule_table *table);
NETWORK_API void g_hash_table_db_rule_table_free(gpointer data);

NETWORK_API sql_security_rule* insert_rule_to_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		security_action action,
		gboolean is_disabled
		); /** < 向db-sql-rule的列表中插入规则*/

NETWORK_API sql_security_rule* get_rule_from_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql
		); /** < 从db-sql-rule 的列表中获取相应规则*/

NETWORK_API security_action get_action_from_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		int *exist
		); /** < 从db-sql-rule 的列表中获取对应语句的动作*/

NETWORK_API gboolean delete_rule_from_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql
		); /** < 从db-sql-rule的列表中删除相应的规则*/

NETWORK_API gboolean set_action_in_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		security_action action
		); /** < 设置db-sql-rule列表中规则的动作*/

NETWORK_API gboolean set_switch_in_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		gboolean is_disabled
		); /** < 设置db-sql-rule列表中规则的启停开关*/

struct user_db_sql_rule_table {
	GHashTable *user_db_sql_rule[RULE_MODEL_TYPE_NO];
	GRWLock table_lock[RULE_MODEL_TYPE_NO];
};

NETWORK_API user_db_sql_rule_table *user_db_sql_rule_table_new();
NETWORK_API void user_db_sql_rule_table_free(user_db_sql_rule_table *table);
NETWORK_API void g_hash_table_user_rule_table_free(gpointer data);

NETWORK_API sql_security_rule* insert_rule_to_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		security_action action,
		gboolean is_disabled
		); /** < 向user-db-sql-rule的列表中插入规则*/

NETWORK_API sql_security_rule* get_rule_from_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type
		); /** < 从user-db-sql-rule的列表中查询相应的规则*/

NETWORK_API security_action get_action_from_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		int *exist
		); /** < 从user-db-sql-rule的列表中查询sql语句对应的动作*/

NETWORK_API gboolean delete_rule_from_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type
		); /** < 从user-db-sql-rule的列表中删除相应的规则*/

NETWORK_API gboolean set_action_in_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		security_action action
		); /** < 设置user-db-sql-rule列表中规则的动作*/

NETWORK_API gboolean set_switch_in_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		gboolean is_disabled
		); /** < 设置user-db-sql-rule列表中规则的启停开关*/

NETWORK_API security_action sql_security_rule_match_process(
		user_db_sql_rule_table *rules,
		const GPtrArray *tokens,
		const char *sql,
		const char *dbname,
		const char *user); /**< 查看用户对应的sql是不是在规则限制列表中 */

NETWORK_API sql_security_rule* add_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type,
		security_action action,
		gboolean is_disabled); /**< 添加语句对应的规则*/

NETWORK_API gboolean del_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type); /**< 删除语句对应的规则*/

NETWORK_API gboolean set_switch_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type,
		gboolean is_disabled); /**< 启用或停用语句对应的规则 */

NETWORK_API gboolean set_action_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type,
		security_action action); /**< 设置语句对应规则的动作 */

#endif /* NETWORK_SECURITY_SQLMODE_H_ */
