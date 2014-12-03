/*
 * network-check-DMLsql.c
 *
 *  Created on: 2014-5-14
 *      Author: jinxuanhou
 */

#include "network-check-DMLsql.h"

sql_token_id dml_ids[] = TOKEN_IDS;

gboolean is_dml_operation(GPtrArray *tokens, dml_type type) {

	if (NULL == tokens) {
		return FALSE;
	}

	if (type > DML_UPDATE) {
		return FALSE;
	}

	gboolean result = FALSE;

	if (tokens->len >0) {
		if (type != DML_TRUNCATE &&
				((sql_token *)(tokens->pdata[0]))->token_id == dml_ids[type]) {
			result = TRUE;
		} else if (type == DML_TRUNCATE &&
				((sql_token *)(tokens->pdata[0]))->token_id == dml_ids[type]) {
			if (g_ascii_strncasecmp(((sql_token *)(tokens->pdata[0]))->text->str, "truncate", sizeof("truncate"))) {
				result = TRUE;
			}
		}
	}

	return result;
}
