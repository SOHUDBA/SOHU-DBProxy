/*
 * network-dura-exec-process.c
 *
 *  Created on: 2013-10-9
 *      Author: jinxuanhou
 */
#include "network-dura-exec-limit.h"
#include "network-dura-exec-process.h"

dura_exec_limit_rules* dura_exec_limit_rules_new() {
	dura_exec_limit_rules *rules = g_new0(dura_exec_limit_rules, 1);

	rules->dura_exec_individ_rules[0] = user_db_sql_dura_list_new();
	rules->dura_exec_individ_rules[1] = user_db_sql_dura_list_new();

	rules->dura_exec_global_rules[0] = sql_dura_list_new();
	rules->dura_exec_global_rules[1] = sql_dura_list_new();

	return rules;
}

void dura_exec_limit_rules_free(dura_exec_limit_rules *rules) {
	if (NULL == rules) {
		return;
	}

	user_db_sql_dura_list_free(rules->dura_exec_individ_rules[0]);
	rules->dura_exec_individ_rules[0] = NULL;

	user_db_sql_dura_list_free(rules->dura_exec_individ_rules[1]);
	rules->dura_exec_individ_rules[1] = NULL;

	sql_dura_list_free(rules->dura_exec_global_rules[0]);
	rules->dura_exec_global_rules[0] = NULL;

	sql_dura_list_free(rules->dura_exec_global_rules[1]);
	rules->dura_exec_global_rules[1] = NULL;

	g_free(rules);
}

/** 增加超时限制 */
dura_exec_limit* add_sql_dura_rule(dura_exec_limit_rules *rules,
		const char * user_name, const char *db_name, const char *sql,
		dura_exec_limit_type limit_type, dura_exec_sql_type sql_type,
		guint64 limit, gboolean limit_switch) {
	if (NULL == rules || NULL == sql) {
		return NULL ;
	}
	dura_exec_limit *ret = NULL;
	g_assert(DURA_SQL_SINGLE == sql_type || DURA_SQL_TEMPLATE == sql_type);
	g_assert(
			DURA_EXEC_INDIVIDUAL == limit_type
					|| DURA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (DURA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (DURA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = insert_user_db_sql_dura_rule(
					rules->dura_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql, limit, limit_switch);
		}
	} else {
		ret = insert_sql_dura_rule(rules->dura_exec_global_rules[sql_type],
				normalized_sql, limit, limit_switch);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}


/** 修改超时限制值 */
gboolean modify_sql_dura_rule_limit_para(dura_exec_limit_rules *rules,
		const char * user_name, const char *db_name, const char *sql,
		dura_exec_limit_type limit_type, dura_exec_sql_type sql_type,
		guint64 limit) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	g_assert(DURA_SQL_SINGLE == sql_type || DURA_SQL_TEMPLATE == sql_type);
	g_assert(
			DURA_EXEC_INDIVIDUAL == limit_type
					|| DURA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (DURA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (DURA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = modify_user_db_sql_dura_para(
					rules->dura_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql, limit);
		}
	} else {
		ret = modify_sql_dura_para(rules->dura_exec_global_rules[sql_type],
				normalized_sql, limit);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/** 修改超时限制规则开关 */
gboolean modify_sql_dura_rule_limit_switch(
		dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type, gboolean limit_switch) {
	if (NULL == rules || NULL == sql) {
			return FALSE;
		}
		gboolean ret = FALSE;
		g_assert(DURA_SQL_SINGLE == sql_type || DURA_SQL_TEMPLATE == sql_type);
		g_assert(DURA_EXEC_INDIVIDUAL == limit_type || DURA_EXEC_GLOBAL == limit_type);

		char *normalized_sql = NULL;

		if (DURA_SQL_SINGLE == sql_type) {
			normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
		} else {
			normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
		}

		if (DURA_EXEC_INDIVIDUAL == limit_type) {
			if (user_name) {
				ret = modify_user_db_sql_dura_switch(
						rules->dura_exec_individ_rules[sql_type], user_name,
						db_name, normalized_sql, limit_switch);
			}
		} else {
			ret = modify_sql_dura_switch(rules->dura_exec_global_rules[sql_type],
					normalized_sql, limit_switch);
		}

		if (normalized_sql) {
			g_free(normalized_sql);
		}

		return ret;
}

/** 删除超时限制规则 */
gboolean delete_sql_dura_rule_limit_rule(dura_exec_limit_rules *rules,
		const char * user_name, const char *db_name, const char *sql,
		dura_exec_limit_type limit_type, dura_exec_sql_type sql_type) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}
	gboolean ret = FALSE;
	g_assert(DURA_SQL_SINGLE == sql_type || DURA_SQL_TEMPLATE == sql_type);
	g_assert(
			DURA_EXEC_INDIVIDUAL == limit_type
					|| DURA_EXEC_GLOBAL == limit_type);

	char *normalized_sql = NULL;

	if (DURA_SQL_SINGLE == sql_type) {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_SINGLE);
	} else {
		normalized_sql = sql_normalize_with_token(sql, NORMALIZE_FOR_TEMPLATE);
	}

	if (DURA_EXEC_INDIVIDUAL == limit_type) {
		if (user_name) {
			ret = delete_user_db_sql_dura_rule(
					rules->dura_exec_individ_rules[sql_type], user_name,
					db_name, normalized_sql);
		}
	} else {
		ret = delete_sql_dura_rule(rules->dura_exec_global_rules[sql_type],
				normalized_sql);
	}

	if (normalized_sql) {
		g_free(normalized_sql);
	}

	return ret;
}

/** 查询对应的超时限制数 */
gboolean get_sql_dura_rule(dura_exec_limit_rules *rules, const char * user_name,
		const char *db_name, const char *sql, const GPtrArray *tokens,
		GString *normalized_sql, dura_exec_limit_type limit_type,
		dura_exec_sql_type sql_type, dura_exec_limit *dura_limit) {
	if (NULL == rules || NULL == sql) {
		return FALSE;
	}

	g_assert(DURA_SQL_SINGLE == sql_type || DURA_SQL_TEMPLATE == sql_type);
	g_assert(
			DURA_EXEC_INDIVIDUAL == limit_type
					|| DURA_EXEC_GLOBAL == limit_type);

	gboolean ret = FALSE;
	char *normalized_sql_in_use = NULL;

	// 首先判断是否有已经标准化的结果，若没有这里将sql语句标准化，但为时下次能直接使用会返回给上层。
	if (0 == normalized_sql->len) {
		if (DURA_SQL_SINGLE == sql_type) {
			normalized_sql_in_use = sql_normalize_with_token_dispatch(tokens,
					sql, NORMALIZE_FOR_SINGLE);
		} else {
			normalized_sql_in_use = sql_normalize_with_token_dispatch(tokens,
					sql, NORMALIZE_FOR_TEMPLATE);
		}

		g_string_append(normalized_sql, normalized_sql_in_use);
	}

	if (DURA_EXEC_INDIVIDUAL == limit_type) {
		ret = get_user_db_sql_dura_exec_limit(
				rules->dura_exec_individ_rules[sql_type], user_name, db_name,
				normalized_sql->str, dura_limit);
	} else {
		ret = get_sql_dura_exec_limit(rules->dura_exec_global_rules[sql_type],
				normalized_sql->str, dura_limit);
	}

	if (normalized_sql_in_use) {
		g_free(normalized_sql_in_use);
	}

	return ret;
}
