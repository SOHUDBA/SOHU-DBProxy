/*
 * network-para-exec-process.c
 *
 *  Created on: 2013-9-24
 *      Author: jinxuanhou
 */
#include "network-para-exec-process.h"

para_exec_limit_rules* para_exec_limit_rules_new() {
	para_exec_limit_rules *rules = g_new0(para_exec_limit_rules, 1);

	rules->para_exec_individ_rules[0] = user_db_sql_limit_list_new();
	rules->para_exec_individ_rules[1] = user_db_sql_limit_list_new();

	rules->para_exec_global_rules[0] = sql_limit_list_new();
	rules->para_exec_global_rules[1] = sql_limit_list_new();

	return rules;
}

void para_exec_limit_rules_free(para_exec_limit_rules *rules) {
	if (NULL == rules) {
		return;
	}

	user_db_sql_limit_list_free(rules->para_exec_individ_rules[0]);
	rules->para_exec_individ_rules[0] = NULL;

	user_db_sql_limit_list_free(rules->para_exec_individ_rules[1]);
	rules->para_exec_individ_rules[1] = NULL;

	sql_limit_list_free(rules->para_exec_global_rules[0]);
	rules->para_exec_global_rules[0] = NULL;

	sql_limit_list_free(rules->para_exec_global_rules[1]);
	rules->para_exec_global_rules[1] = NULL;

	g_free(rules);
}

/** 增加并发限制 */
para_exec_limit* add_sql_para_rule(para_exec_limit_rules *rules,
		const char * user_name, const char *db_name, const char *sql,
		para_exec_limit_type limit_type, para_exec_sql_type sql_type,
		gint limit_para, gboolean limit_switch) {

	if (NULL == rules || NULL == sql) {
		return NULL;
	}
	para_exec_limit *ret = NULL;
	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (PARA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (PARA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = insert_user_db_sql_limit_rule(
					rules->para_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql, limit_para, limit_switch);
		}
	} else {
		ret = insert_sql_limit_rule(rules->para_exec_global_rules[sql_type],
				normalized_sql, limit_para, limit_switch);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/** 修改并发限制值 */
gboolean modify_sql_para_rule_limit_para(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, gint limit_para) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (PARA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (PARA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = modify_user_db_sql_limit_para(
					rules->para_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql, limit_para);
		}
	} else {
		ret = modify_sql_limit_para(rules->para_exec_global_rules[sql_type],
				normalized_sql, limit_para);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/** 修改并发限制规则开关 */
gboolean modify_sql_para_rule_limit_switch(
		para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, gboolean limit_switch) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (PARA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (PARA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = modify_user_db_sql_limit_switch(
					rules->para_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql, limit_switch);
		}
	} else {
		ret = modify_sql_limit_switch(rules->para_exec_global_rules[sql_type],
				normalized_sql, limit_switch);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/** 删除并发限制规则 */
gboolean delete_sql_para_rule_limit_rule(para_exec_limit_rules *rules,
		const char * user_name, const char *db_name, const char *sql,
		para_exec_limit_type limit_type, para_exec_sql_type sql_type) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (PARA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (PARA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = delete_user_db_sql_limit_rule(
					rules->para_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql);
		}
	} else {
		ret = delete_sql_limit_rule(rules->para_exec_global_rules[sql_type],
				normalized_sql);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/** 查询对应的并发限制数 */
gboolean get_sql_para_rule(para_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, const GPtrArray *tokens,
		GString *normalized_sql, para_exec_limit_type limit_type,
		para_exec_sql_type sql_type, para_exec_limit*para_limit) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}

	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	gboolean ret = FALSE;
	char *normalized_sql_in_use = NULL;

	// 首先判断是否有已经标准化的结果，若没有这里将sql语句标准化，但为时下次能直接使用会返回给上层。
	if (0 == normalized_sql->len) {
		if (PARA_SQL_SINGLE == sql_type) {
			normalized_sql_in_use = sql_normalize_with_token_dispatch(tokens,
					sql, NORMALIZE_FOR_SINGLE);
		} else {
			normalized_sql_in_use = sql_normalize_with_token_dispatch(tokens,
					sql, NORMALIZE_FOR_TEMPLATE);
		}

		g_assert(normalized_sql_in_use);

		g_string_append(normalized_sql, normalized_sql_in_use);
	}

	if (PARA_EXEC_INDIVIDUAL == limit_type) {
		ret = get_user_db_sql_para_exec_limit(
				rules->para_exec_individ_rules[sql_type], user_name,
				db_name, normalized_sql->str, para_limit);
	} else {
		ret = get_sql_para_exec_limit(
				rules->para_exec_global_rules[sql_type],
				normalized_sql->str, para_limit);
	}

	if (normalized_sql_in_use) {
		g_free(normalized_sql_in_use);
	}

	return ret;
}

statistic_dic *statistic_dic_new() {
	statistic_dic *dic = g_new0(statistic_dic, 1);
	gint line = 0;

	for (line = 0; line < 2; line++) {
		dic->statistic_dic[line] = g_hash_table_new_full(g_hash_table_string_hash,
				g_hash_table_string_equal, g_hash_table_string_free,
				g_hash_table_int_free);
		g_mutex_init(&(dic->dic_lock[line]));
	}

	return dic;
}

void statistic_dic_free(statistic_dic* dic) {
	if (NULL == dic) {
		return;
	}

	gint line = 0;
	for (line = 0; line < 2; line++) {

		g_mutex_lock(&(dic->dic_lock[line]));
		g_hash_table_destroy(dic->statistic_dic[line]);
		g_mutex_unlock(&(dic->dic_lock[line]));

		g_mutex_clear(&(dic->dic_lock[line]));
	}

	g_free(dic);
}

void dec_para_statistic_info (statistic_dic* dic,
		const char *user_db_key, const char *normalized_sql,
		para_exec_sql_type sql_type) {
	if (NULL == dic || NULL == normalized_sql) {
		return;
	}

	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	//g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	GString *key_used = g_string_new(user_db_key);
	g_string_append(key_used, normalized_sql);

	g_mutex_lock(&(dic->dic_lock[sql_type]));
	gint * value = g_hash_table_lookup(dic->statistic_dic[sql_type], key_used);
	if (value) {
		if (*value > 0) {
			*value = *value - 1;
		}
	}
	g_mutex_unlock(&(dic->dic_lock[sql_type]));

	g_string_free(key_used, TRUE);
}

gint * get_para_statistic_info(statistic_dic* dic,
		const char *user_db_key, const char *normalized_sql,
		para_exec_sql_type sql_type) {
	if (NULL == dic || NULL == normalized_sql) {
		return NULL;
	}
	gint *ret = NULL;

	g_assert(PARA_SQL_SINGLE == sql_type || PARA_SQL_TEMPLATE == sql_type);
	//g_assert(PARA_EXEC_INDIVIDUAL == limit_type || PARA_EXEC_GLOBAL == limit_type);

	GString *key_used = g_string_new(user_db_key);
	g_string_append(key_used, normalized_sql);

	g_mutex_lock(&(dic->dic_lock[sql_type]));
	ret = g_hash_table_lookup(dic->statistic_dic[sql_type], key_used);
	g_mutex_unlock(&(dic->dic_lock[sql_type]));

	return ret;
}

