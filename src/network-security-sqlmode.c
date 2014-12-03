/*
 * network-security-sqlmode.c
 *
 *  Created on: 2013-7-25
 *      Author: jinxuanhou
 */
#include <glib.h>
#include "glib-ext.h"
#include "network-sql-normalization.h"
#include "network-security-sqlmode.h"

#define IS_CORRECT_TYPE(x) (SQL_SINGLE == x || SQL_TEMPLATE == x)

/**
 * 通过动作获取规则动作的名字
 * @param action 动作
 * @return 动作的名字
 */
char * get_security_action_name(security_action action) {
	switch(action) {
	case ACTION_SAFE:
		return "safe";
	case ACTION_LOG:
		return "log";
	case ACTION_WARNING:
		return "warning";
	case ACTION_BLOCK:
		return "block";
	default:
		return "unknown";
	}
}

/**
 * 构造新的sql规则
 * @return 新的sql规则变量
 */
sql_security_rule * sql_security_rule_new() {
	sql_security_rule * rule = g_new0(sql_security_rule, 1);
	rule->sql_content = g_string_new(NULL); // 这里老忘记释放

	return rule;
}

/**
 * sql 规则销毁
 * @param sql_rule 要被销毁的sql的指针
 */
void sql_security_rule_free(sql_security_rule *sql_rule) {
	if (NULL == sql_rule) {
		return;
	}

	if (NULL != sql_rule->sql_content) {
		g_string_free(sql_rule->sql_content, TRUE);
		sql_rule->sql_content = NULL;
	}

	g_free(sql_rule);
}

/**
 * sql 规则规则内存释放函数
 * @param data 要被回收的sql_rule指针
 */
void g_hash_table_sql_rule_free(gpointer data) {
	sql_security_rule_free((sql_security_rule *)data);
}

/** sql-rule */

/**
 * sql_rule_table 构造函数
 * @return 构造的新的规则表实例
 */
sql_rule_table *sql_rule_table_new() {
	sql_rule_table *table = g_new0(sql_rule_table, 1);
	table->sql_rule = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_sql_rule_free);

	g_rw_lock_init(&table->table_lock);
	return table;
}

/**
 * sql规则表销毁函数
 * @param table 要释放的sql规则表
 */
void sql_rule_table_free(sql_rule_table *table) {
	if (NULL == table) {
		return;
	}

	g_rw_lock_writer_lock(&table->table_lock);
	g_hash_table_destroy(table->sql_rule);
	table->sql_rule = NULL;
	g_rw_lock_writer_unlock(&table->table_lock);

	g_rw_lock_clear(&table->table_lock);

	g_free(table);
}

void g_hash_table_sql_rule_table_free(gpointer data) {
	sql_rule_table_free((sql_rule_table *)data);
}

/**
 * 向最里层的sql-rule 的列表中插入规则
 * @param table 规则列表
 * @param normalized_sql 标准化的sql语句
 * @param action 规则对应的动作
 * @param is_disabled 规则的开关标志
 */
sql_security_rule* insert_rule_to_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		security_action action,
		gboolean is_disabled
		) {
	if (NULL == table || NULL == normalized_sql) {
		return NULL;
	}

	sql_security_rule *rule = sql_security_rule_new();
	rule->action = action;
	rule->is_disabled = is_disabled;
	//rule->sql_content = g_string_new(normalized_sql);
	g_string_assign(rule->sql_content, normalized_sql);

	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&table->table_lock);
	g_hash_table_insert(table->sql_rule, sql_key, rule);
	g_rw_lock_writer_unlock(&table->table_lock);

	return rule;
}

/**
 * 从最里层的sql-rule 的列表中获取规则
 * @param table sql—规则列表
 * @param normalized_sql 标准化的sql
 * @return sql对应的规则
 */
sql_security_rule* get_rule_from_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql
		) {
	if (NULL == table || NULL == normalized_sql) {
		return NULL;
	}

	sql_security_rule *rule = NULL;

	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&table->table_lock);
	rule = g_hash_table_lookup(table->sql_rule, sql_key);
	g_rw_lock_writer_unlock(&table->table_lock);

	g_string_free(sql_key, TRUE);

	return rule;
}

/**
 * 获取对应规则的动作
 * @param table 最里层sql队则列表
 * @param normalized_sql 标准化的sql
 * @param exist[in&&out] 用于标识规则是否存在
 * @return
 */
security_action get_action_from_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		int *exist
		) {
	g_assert(exist);
	*exist = 0;
	security_action ret = ACTION_SAFE;
	if (NULL == table || NULL == normalized_sql) {
			return ret;
	}

	sql_security_rule *rule = NULL;
	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&table->table_lock);
	rule = g_hash_table_lookup(table->sql_rule, sql_key);
	if (rule && !rule->is_disabled) {
		ret = rule->action;
		*exist = 1;
	}
	g_rw_lock_writer_unlock(&table->table_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}
/**
 * 从最里层的sql-rule 的列表中删除相应的规则
 * @param table 规则列表
 * @param normalized_sql 标准化的sql
 * @return 是否删除成功，没有也会返回没有删除成功
 */
gboolean delete_rule_from_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql
		) {
	if (NULL == table || NULL == normalized_sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	g_rw_lock_writer_lock(&table->table_lock);
	ret = g_hash_table_remove(table->sql_rule, sql_key);
	g_rw_lock_writer_unlock(&table->table_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/**
 * 设置最里层sql-rule列表中规则的动作
 * @param table sql规则列表
 * @param normalized_sql 标准化的sql，索引key
 * @param action 要设置为的动作
 * @return TRUE|FALSE 设置动作的执行结果，成功返回TRUE, 失败返回FALSE,没有对应的sql设置失败
 */
gboolean set_action_in_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		security_action action) {
	if (NULL == table || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	sql_security_rule *rule = NULL;
	g_rw_lock_writer_lock(&table->table_lock);
	rule = g_hash_table_lookup(table->sql_rule, sql_key);
	if (rule) {
		rule->action = action;
		ret = TRUE;
	}
	g_rw_lock_writer_unlock(&table->table_lock);

	g_string_free(sql_key, TRUE);

	return ret;
}

/**
 * 设置最里层sql-rule列表中规则的启停开关
 * @param table sql规则列表
 * @param normalized_sql 标准化的sql语句，索引key
 * @param is_disabled 开关标志
 * @return 设置成功返回TRUE,失败返回FALSE,没有找到对应的规则视为失败
 */
gboolean set_switch_in_sql_rule(
		sql_rule_table *table,
		const char *normalized_sql,
		gboolean is_disabled) {
	if (NULL == table || NULL == normalized_sql) {
		return FALSE;
	}

	gboolean ret = FALSE;
	GString *sql_key = g_string_new(normalized_sql);
	sql_security_rule *rule = NULL;
	g_rw_lock_writer_lock(&table->table_lock);
	rule = g_hash_table_lookup(table->sql_rule, sql_key);
	if (rule) {
		rule->is_disabled = is_disabled;
		ret = TRUE;
	}
	g_rw_lock_writer_unlock(&table->table_lock);

	g_string_free(sql_key, TRUE);
	return ret;
}

/** db_sql_rule */
/**
 * db sql规则列表的创建
 * @return db sql规则列表
 */
db_sql_rule_table* db_sql_rule_table_new() {

	db_sql_rule_table *table = g_new0(db_sql_rule_table, 1);
	table->db_sql_rule = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_sql_rule_table_free);

	g_rw_lock_init(&table->table_lock);
	return table;
}

/**
 * db sql规则列表的销毁
 * @param table 要被销毁的db sql规则列表的指针
 */
void db_sql_rule_table_free(db_sql_rule_table *table) {
	if (NULL == table) {
		return;
	}

	g_rw_lock_writer_lock(&table->table_lock);
	g_hash_table_destroy(table->db_sql_rule);
	table->db_sql_rule = NULL;
	g_rw_lock_writer_unlock(&table->table_lock);

	g_rw_lock_clear(&table->table_lock);
	g_free(table);
}

/**
 * db sql规则列表hashtable销毁函数
 * @param data
 */
void g_hash_table_db_rule_table_free(gpointer data) {
	db_sql_rule_table_free((db_sql_rule_table *)data);
}

/**
 * 向db-sql-rule的列表中插入规则
 * @param table db-sql-rule规则列表
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param action 规则对应的动作
 * @param is_disabled 规则对应的开关
 * @return 新建的db-sql-rule变量
 */
sql_security_rule* insert_rule_to_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		security_action action,
		gboolean is_disabled) {
	if (NULL == table) {
		return NULL;
	}
	if (NULL == dbname || NULL == normalized_sql) {
		return NULL;
	}

	GString *db_key = g_string_new(dbname);
	sql_security_rule* rule = NULL;
	sql_rule_table* sql_rule_table_v = NULL;
	g_rw_lock_writer_lock(&table->table_lock);
	sql_rule_table_v = g_hash_table_lookup(table->db_sql_rule, db_key);
	if (NULL == sql_rule_table_v) {
		sql_rule_table_v = sql_rule_table_new();
		GString *db_key_used = g_string_new(dbname);
		g_hash_table_insert(table->db_sql_rule, db_key_used, sql_rule_table_v);
	}
	g_rw_lock_writer_unlock(&table->table_lock);
	rule = insert_rule_to_sql_rule(
			sql_rule_table_v,
			normalized_sql,
			action,
			is_disabled
			);

	g_string_free(db_key, TRUE);
	return rule;
}

/**
 * 从db-sql-rule的列表中获取相应规则
 * @param table db-sql-rule规则列表
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @return 通过dbname和标准化的sql索引的规则
 */
sql_security_rule* get_rule_from_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql) {
	if (NULL == table || NULL == dbname|| NULL == normalized_sql) {
		return FALSE;
	}
	sql_security_rule *rule = NULL;
	GString *db_key = g_string_new(dbname);
	sql_rule_table *sql_rule_table_v = NULL;
	g_rw_lock_reader_lock(&table->table_lock);
	sql_rule_table_v = g_hash_table_lookup(table->db_sql_rule, db_key);
	g_rw_lock_reader_unlock(&table->table_lock);

	if (sql_rule_table_v) {
		rule = get_rule_from_sql_rule(
				sql_rule_table_v,
				normalized_sql
				);
	}
	g_string_free(db_key, TRUE);

	return rule;
}

/**
 * 获取对应对应规则的动作
 * @param table db-sql-rule规则列表
 * @param dbname 规则对应的数据库名
 * @param exist
 * @return 规则对应的动作
 */
security_action get_action_from_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		int *exist
		) {
	g_assert(exist);
	security_action ret = ACTION_SAFE;
	if (NULL == table || NULL == dbname|| NULL == normalized_sql) {
		return ret;
	}

	GString *db_key = g_string_new(dbname);
	sql_rule_table *sql_rule_table_v = NULL;
	g_rw_lock_reader_lock(&table->table_lock);
	sql_rule_table_v = g_hash_table_lookup(table->db_sql_rule, db_key);
	g_rw_lock_reader_unlock(&table->table_lock);

	if (sql_rule_table_v) {
		ret = get_action_from_sql_rule(
				sql_rule_table_v,
				normalized_sql,
				exist
		);
	}
	g_string_free(db_key, TRUE);

	return ret;
}

/**
 * 从db-sql-rule的列表中删除相应的规则
 * @param table db-sql-rule规则列表
 * @param dbname 需要删除规则对应的数据库
 * @param normalized_sql 对应的标准化的sql
 * @return 删除成功返回TRUE,失败返回FALSE
 */
gboolean delete_rule_from_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql) {
	if (NULL == table || NULL == dbname|| NULL == normalized_sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	GString *db_key = g_string_new(dbname);
	sql_rule_table *sql_rule_table_v = NULL;
	g_rw_lock_reader_lock(&table->table_lock);
	sql_rule_table_v = g_hash_table_lookup(table->db_sql_rule, db_key);
	g_rw_lock_reader_unlock(&table->table_lock);

	if (sql_rule_table_v) {
		ret = delete_rule_from_sql_rule(
				sql_rule_table_v,
				normalized_sql);
	}
	g_string_free(db_key, TRUE);

	return ret;
}

/**
 * 设置db-sql-rule列表中规则的动作
 * @param table db-sql-rule规则列表
 * @param dbname 需要更新规则对应的数据库
 * @param normalized_sql 规则对应的标准化的sql
 * @param action 更新后的动作
 * @return 设置成功赶回TRUE,失败返回FALSE,没有找到对应的规则算失败
 */
gboolean set_action_in_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		security_action action) {
	if (NULL == table || NULL == dbname|| NULL == normalized_sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	GString *db_key = g_string_new(dbname);
	sql_rule_table *sql_rule_table_v = NULL;
	g_rw_lock_reader_lock(&table->table_lock);
	sql_rule_table_v = g_hash_table_lookup(table->db_sql_rule, db_key);
	g_rw_lock_reader_unlock(&table->table_lock);

	if (sql_rule_table_v) {
		ret = set_action_in_sql_rule(
				sql_rule_table_v,
				normalized_sql,
				action
				);
	}
	g_string_free(db_key, TRUE);

	return ret;
}

/**
 * 设置db-sql-rule列表中规则的启停开关
 * @param table db-sql-rule规则列表
 * @param dbname 需要更新规则对应的数据库
 * @param normalized_sql 规则对应的标准化的sql
 * @param is_disabled 更新后的开关参数
 * @return 设置成功赶回TRUE,失败返回FALSE,没有找到对应的规则算失败
 */
gboolean set_switch_in_db_sql_rule(
		db_sql_rule_table *table,
		const char *dbname,
		const char *normalized_sql,
		gboolean is_disabled
		) {
	if (NULL == table || NULL == dbname|| NULL == normalized_sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	GString *db_key = g_string_new(dbname);
	sql_rule_table *sql_rule_table_v = NULL;
	g_rw_lock_reader_lock(&table->table_lock);
	sql_rule_table_v = g_hash_table_lookup(table->db_sql_rule, db_key);
	g_rw_lock_reader_unlock(&table->table_lock);

	if (sql_rule_table_v) {
		ret = set_switch_in_sql_rule(
				sql_rule_table_v,
				normalized_sql,
				is_disabled
				);
	}

	g_string_free(db_key, TRUE);
	return ret;
}

/** user_db_sql_rule_table */
/**
 * user_db_sql_rule_table 构造函数
 * @return user_db_sql_rule_table变量指针
 */
user_db_sql_rule_table *user_db_sql_rule_table_new() {
	user_db_sql_rule_table *table = g_new0(user_db_sql_rule_table, 1);
	table->user_db_sql_rule[SQL_SINGLE] = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_db_rule_table_free);

	table->user_db_sql_rule[SQL_TEMPLATE] = g_hash_table_new_full(g_hash_table_string_hash,
				g_hash_table_string_equal,
				g_hash_table_string_free,
				g_hash_table_db_rule_table_free);

	g_rw_lock_init(&table->table_lock[SQL_SINGLE]);
	g_rw_lock_init(&table->table_lock[SQL_TEMPLATE]);

	return table;
}

/**
 * user_db_sql_rule_table内存释放函数
 * @param table user_db_sql_rule_table规则列表
 */
void user_db_sql_rule_table_free(
		user_db_sql_rule_table *table) {
	if (NULL == table) {
		return;
	}

	g_rw_lock_writer_lock(&table->table_lock[SQL_SINGLE]);
	g_hash_table_destroy(table->user_db_sql_rule[SQL_SINGLE]);
	table->user_db_sql_rule[SQL_SINGLE] = NULL;
	g_rw_lock_writer_unlock(&table->table_lock[SQL_SINGLE]);

	g_rw_lock_clear(&table->table_lock[SQL_SINGLE]);

	g_rw_lock_writer_lock(&table->table_lock[SQL_TEMPLATE]);
	g_hash_table_destroy(table->user_db_sql_rule[SQL_TEMPLATE]);
	table->user_db_sql_rule[SQL_TEMPLATE] = NULL;
	g_rw_lock_writer_unlock(&table->table_lock[SQL_TEMPLATE]);

	g_rw_lock_clear(&table->table_lock[SQL_TEMPLATE]);

	g_free(table);
}

/**
 * user_db_sql_rule_table的hashtable销毁函数
 * @param data 需要销毁的user_db_sql_rule_table变量指针
 */
void g_hash_table_user_rule_table_free(gpointer data) {
	user_db_sql_rule_table_free((user_db_sql_rule_table *)data);
}

/**
 * 向user-db-sql-rule的列表中插入规则
 * @param table db-sql-rule规则列表
 * @param user 规则对应的用户名
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param action 规则对应的动作
 * @param is_disabled 规则对应的开关
 * @return 新增的规则的变量指针
 */
sql_security_rule* insert_rule_to_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		security_action action,
		gboolean is_disabled) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == table || NULL == table->user_db_sql_rule[type]) {
		return NULL;
	}
	if (NULL == user || NULL == dbname || NULL == normalized_sql) {
		return NULL;
	}

	GString *user_key = g_string_new(user);
	sql_security_rule* rule = NULL;
	db_sql_rule_table* db_sql_rule_table_v = NULL;

	g_rw_lock_writer_lock(&table->table_lock[type]);
	db_sql_rule_table_v = g_hash_table_lookup(table->user_db_sql_rule[type], user_key);
	if (NULL == db_sql_rule_table_v) {
		db_sql_rule_table_v = db_sql_rule_table_new();
		GString *user_key_used = g_string_new(user);
		g_hash_table_insert(table->user_db_sql_rule[type], user_key_used, db_sql_rule_table_v);
	}
	g_rw_lock_writer_unlock(&table->table_lock[type]);

	rule = insert_rule_to_db_sql_rule(
			db_sql_rule_table_v,
			dbname,
			normalized_sql,
			action,
			is_disabled);

	g_string_free(user_key, TRUE);
	return rule;
}

/** < 从user-db-sql-rule的列表中查询相应的规则*/
/**
 * 从user-db-sql-rule的列表中查询相应的规则
 * @param table db-sql-rule规则列表
 * @param user 规则对应的用户名
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param type 规则的类型
 * @return 规则的变量指针
 */
sql_security_rule* get_rule_from_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == table || NULL == table->user_db_sql_rule[type]) {
		return NULL;
	}
	if (NULL == user || NULL == dbname || NULL == normalized_sql) {
		return NULL;
	}

	GString *user_key = g_string_new(user);
	sql_security_rule* rule = NULL;
	db_sql_rule_table* db_sql_rule_table_v = NULL;

	g_rw_lock_reader_lock(&table->table_lock[type]);
	db_sql_rule_table_v = g_hash_table_lookup(table->user_db_sql_rule[type], user_key);
	g_rw_lock_reader_unlock(&table->table_lock[type]);

	if (db_sql_rule_table_v) {
		rule = get_rule_from_db_sql_rule(
				db_sql_rule_table_v,
				dbname,
				normalized_sql);
	}
	g_string_free(user_key, TRUE);
	return rule;
}

/**
 * 从user-db-sql-rule的列表中查询相应的规则的动作
 * @param table db-sql-rule规则列表
 * @param user 规则对应的用户名
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param type 规则类型
 * @param exist[in] 当exist 为1时，表示规则存在；当exist 被设置为0时表示规则不存在
 * @return 查询规则的动作
 */
security_action get_action_from_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		int *exist
		) {
	security_action ret = ACTION_SAFE;
	g_assert(IS_CORRECT_TYPE(type));
	g_assert(exist);
	if (NULL == table || NULL == table->user_db_sql_rule[type]) {
		return ret;
	}
	if (NULL == user || NULL == dbname || NULL == normalized_sql) {
		return ret;
	}

	GString *user_key = g_string_new(user);

	db_sql_rule_table* db_sql_rule_table_v = NULL;

	g_rw_lock_reader_lock(&table->table_lock[type]);
	db_sql_rule_table_v = g_hash_table_lookup(table->user_db_sql_rule[type], user_key);
	g_rw_lock_reader_unlock(&table->table_lock[type]);

	if (db_sql_rule_table_v) {
		ret = get_action_from_db_sql_rule(
				db_sql_rule_table_v,
				dbname,
				normalized_sql,
				exist);
	}
	g_string_free(user_key, TRUE);

	return ret;
}

/** < 从user-db-sql-rule的列表中删除相应的规则*/
/**
 * 从user-db-sql-rule的列表中删除相应的规则
 * @param table db-sql-rule规则列表
 * @param user 规则对应的用户名
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param type 规则类型
 * @return 删除成功返回TRUE,失败返回FALSE,没有对应规则视为失败
 */
gboolean delete_rule_from_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == table || NULL == table->user_db_sql_rule[type]) {
		return FALSE;
	}
	if (NULL == user || NULL == dbname || NULL == normalized_sql) {
		return FALSE;
	}

	GString *user_key = g_string_new(user);
	gboolean ret = FALSE;
	db_sql_rule_table* db_sql_rule_table_v = NULL;

	g_rw_lock_reader_lock(&table->table_lock[type]);
	db_sql_rule_table_v = g_hash_table_lookup(table->user_db_sql_rule[type], user_key);
	g_rw_lock_reader_unlock(&table->table_lock[type]);

	if (db_sql_rule_table_v) {
		ret = delete_rule_from_db_sql_rule(
				db_sql_rule_table_v,
				dbname,
				normalized_sql);
	}

	g_string_free(user_key, TRUE);
	return ret;
}

/** < 设置user-db-sql-rule列表中规则的动作*/
/**
 * 设置user-db-sql-rule列表中规则的动作
 * @param table db-sql-rule规则列表
 * @param user 规则对应的用户名
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param type 规则类型
 * @param action 更新后规则对应的动作
 * @return 修改成功返回TRUE,失败返回FALSE,没有对应规则视为失败
 */
gboolean set_action_in_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		security_action action) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == table || NULL == table->user_db_sql_rule[type]) {
		return FALSE;
	}
	if (NULL == user || NULL == dbname || NULL == normalized_sql) {
		return FALSE;
	}

	GString *user_key = g_string_new(user);
	gboolean ret = FALSE;
	db_sql_rule_table* db_sql_rule_table_v = NULL;

	g_rw_lock_reader_lock(&table->table_lock[type]);
	db_sql_rule_table_v = g_hash_table_lookup(table->user_db_sql_rule[type], user_key);
	g_rw_lock_reader_unlock(&table->table_lock[type]);

	if (db_sql_rule_table_v) {
		ret = set_action_in_db_sql_rule(
				db_sql_rule_table_v,
				dbname,
				normalized_sql,
				action);
	}

	g_string_free(user_key, TRUE);
	return ret;
}

/** < 设置user-db-sql-rule列表中规则的启停开关 */
/**
 * 设置user-db-sql-rule列表中规则的启停开关
 * @param table db-sql-rule规则列表
 * @param user 规则对应的用户名
 * @param dbname 规则对应的数据库名
 * @param normalized_sql 标准化sql
 * @param type 规则类型
 * @param is_disabled 更新后的开关参数
 * @return 修改成功返回TRUE,失败返回FALSE,没有对应规则视为失败
 */
gboolean set_switch_in_user_db_sql_rule(
		user_db_sql_rule_table *table,
		const char *user,
		const char *dbname,
		const char *normalized_sql,
		security_model_type type,
		gboolean is_disabled) {

	g_assert(IS_CORRECT_TYPE(type));

	if (NULL == table || NULL == table->user_db_sql_rule[type]) {
		return FALSE;
	}
	if (NULL == user || NULL == dbname || NULL == normalized_sql) {
		return FALSE;
	}

	GString *user_key = g_string_new(user);
	gboolean ret = FALSE;
	db_sql_rule_table* db_sql_rule_table_v = NULL;

	g_rw_lock_reader_lock(&table->table_lock[type]);
	db_sql_rule_table_v = g_hash_table_lookup(table->user_db_sql_rule[type], user_key);
	g_rw_lock_reader_unlock(&table->table_lock[type]);

	if (db_sql_rule_table_v) {
		ret = set_switch_in_db_sql_rule(
				db_sql_rule_table_v,
				dbname,
				normalized_sql,
				is_disabled);
	}
	g_string_free(user_key, TRUE);
	return ret;
}

/** 查找匹配规则 */
/**
 * 查找匹配规则
 * @param rules 规则列表
 * @param tokens sql语句对应的tokens列表
 * @param sql sql语句（可以是没有标准化的）
 * @param dbname 对应的database name
 * @param user 对应的用户名
 * @return 返回对应规则的动作，没有找到对应的规则默认是safe
 */
security_action sql_security_rule_match_process(
		user_db_sql_rule_table *rules,
		const GPtrArray *tokens,
		const char *sql,
		const char *dbname,
		const char *user) {
	/**
	 * 我们判定的一个顺序是：
	 * 1. 先在单条sql语句的规则列表中查询
	 * 2. 再在某类sql语句的规则中查找
	 * 3. 若没有找到匹配的规则，返回ACTION_SAFE
	 */
	if (NULL == rules) {
		return ACTION_SAFE;
	}
	g_assert(user);
	g_assert(dbname);
	if (NULL == tokens && NULL == sql) {
		return ACTION_SAFE;
	}
	security_action ret = ACTION_SAFE;
	int exist = 0;
	/**
	 * 接下来，分情况处理：
	 * 1. 若token列表不为空，在直接通过token列表对sql进行标准化，然后进行对比
	 * 2. 若token列表为空，则先对sql语句本身进行分词，然后再做标准化，然后对比
	 */

	char *normalized_sql_for_single = NULL;
	char *normalized_sql_for_template = NULL;
	if (NULL == tokens) {
		normalized_sql_for_single = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql_for_single = sql_normalize_for_single(tokens);
	}

	/**
	 * 单条语句限制规则的对比
	 */
	/**
	sql_security_rule *rule = NULL;
	rule = get_rule_from_user_db_sql_rule(
			rules,
			user,
			dbname,
			normalized_sql_for_single,
			SQL_SINGLE);
	*/
	ret = get_action_from_user_db_sql_rule(
			rules,
			user,
			dbname,
			normalized_sql_for_single,
			SQL_SINGLE,
			&exist);
	if (0 == exist) {
		/**
		 * 没有与单条语句的限制规则匹配则，使用类sql的限制
		 */
		if (NULL == tokens) {
			normalized_sql_for_template = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
		} else {
			normalized_sql_for_template = sql_normalize_for_template(tokens);
		}
		ret = get_action_from_user_db_sql_rule(
				rules,
				user,
				dbname,
				normalized_sql_for_template,
				SQL_TEMPLATE,
				&exist);
	}

	if (1 == exist) {
		g_debug("get Security filter rule for %s", sql);
	}

	if (normalized_sql_for_single != NULL) {
		g_free(normalized_sql_for_single);
		normalized_sql_for_single = NULL;
	}

	if (normalized_sql_for_template != NULL) {
		g_free(normalized_sql_for_template);
		normalized_sql_for_template = NULL;
	}

	return ret;
}

/**< 添加语句对应的规则*/
/**
 * 添加语句对应的规则
 * @param rules 规则列表
 * @param sql sql语句
 * @param dbname 对应的数据库名
 * @param user 对应的用户名
 * @param type 规则类别
 * @param action 规则的动作
 * @param is_disabled 规则的开关
 * @return 新添加的规则的指针
 */
sql_security_rule* add_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type,
		security_action action,
		gboolean is_disabled) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == rules) {
		return NULL;
	}

	if (NULL == sql || NULL == dbname || NULL == user) {
		return NULL;
	}

	sql_security_rule* rule = NULL;
	char * normalized_sql = sql_normalize_with_token(sql, type);

	rule = insert_rule_to_user_db_sql_rule(
			rules,
			user,
			dbname,
			normalized_sql,
			type,
			action,
			is_disabled);

	if (NULL != normalized_sql) {
		g_free(normalized_sql);
	}

	return rule;
}

/**< 删除语句对应的规则*/
/**
 * 删除语句对应的规则
 * @param rules 规则列表
 * @param sql 欲删除规则对应的sql
 * @param dbname 欲删除规则的数据库名
 * @param user 欲删除规则对应的用户名
 * @param type 欲删除规则的类别
 * @return 删除成功返回TRUE,失败返回FALSE,没有找到对应的规则视为失败
 */
gboolean del_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == rules) {
		return FALSE;
	}

	if (NULL == sql || NULL == dbname || NULL == user) {
		return FALSE;
	}

	gboolean ret = FALSE;
	char * normalized_sql = sql_normalize_with_token(sql, type);

	ret = delete_rule_from_user_db_sql_rule(
			rules,
			user,
			dbname,
			normalized_sql,
			type);

	if (NULL != normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/**< 启用或停用语句对应的规则 */
/**
 * 启用或停用语句对应的规则
 * @param rules 规则列表
 * @param sql 规则对应的sql语句
 * @param dbname 规则对应的数据库名
 * @param user 规则对应的用户名
 * @param type 规则类别
 * @param is_disabled 更新后的开关值
 * @return 设置成功赶回TRUE,失败返回FALSE,没有找到对应的规则算失败
 */
gboolean set_switch_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type,
		gboolean is_disabled) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == rules) {
		return FALSE;
	}

	if (NULL == sql || NULL == dbname || NULL == user) {
		return FALSE;
	}

	gboolean ret = FALSE;
	char * normalized_sql = sql_normalize_with_token(sql, type);

	ret = set_switch_in_user_db_sql_rule(
			rules,
			user,
			dbname,
			normalized_sql,
			type,
			is_disabled);

	if (NULL != normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/**< 设置语句对应规则的动作 */
/**
 * 设置语句对应规则的动作
 * @param rules 规则列表
 * @param sql 规则对应的sql
 * @param dbname 规则对应的数据库名
 * @param user 规则对应的用户名
 * @param type 规则的类别
 * @param action 更新后的规则的动作
 * @return 设置成功赶回TRUE,失败返回FALSE,没有找到对应的规则算失败
 */
gboolean set_action_sql_security_rule(
		user_db_sql_rule_table *rules,
		const char *sql,
		const char *dbname,
		const char *user,
		security_model_type type,
		security_action action) {
	g_assert(IS_CORRECT_TYPE(type));
	if (NULL == rules) {
		return FALSE;
	}

	if (NULL == sql || NULL == dbname || NULL == user) {
		return FALSE;
	}

	gboolean ret = FALSE;
	char * normalized_sql = sql_normalize_with_token(sql, type);

	ret = set_action_in_user_db_sql_rule(
			rules,
			user,
			dbname,
			normalized_sql,
			type,
			action);

	if (NULL != normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}
