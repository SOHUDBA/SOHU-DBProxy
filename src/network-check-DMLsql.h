/*
 * network-check-DMLsql.h
 *
 *  Created on: 2014-5-14
 *      Author: jinxuanhou
 */

#ifndef NETWORK_CHECK_DMLSQL_H_
#define NETWORK_CHECK_DMLSQL_H_

#include <glib.h>
#include "glib-ext.h"
#include "chassis-mainloop.h"
#include "network-exports.h"
#include "sql-tokenizer.h"

#define TOKEN_IDS {TK_SQL_ALTER, TK_SQL_CREATE, TK_SQL_DELETE, TK_SQL_DROP, TK_SQL_INSERT,  TK_SQL_REPLACE, TK_SQL_RENAME, TK_LITERAL, TK_SQL_UPDATE}

typedef enum {
	DML_ALTER = 0,
	DML_CREATE,
	DML_DELETE,
	DML_DROP,
	DML_INSERT,
	DML_REPLACE,
	DML_RENAME,
	DML_TRUNCATE,
	DML_UPDATE
} dml_type;


NETWORK_API gboolean is_dml_operation(GPtrArray *tokens, dml_type type);

#if 0
NETWORK_API gboolean is_dml_alter(GPtrArray *tokens);
NETWORK_API gboolean is_dml_create(GPtrArray *tokens);
NETWORK_API gboolean is_dml_delete(GPtrArray *tokens);
NETWORK_API gboolean is_dml_drop(GPtrArray *tokens);
NETWORK_API gboolean is_dml_insert(GPtrArray *tokens);
NETWORK_API gboolean is_dml_replace(GPtrArray *tokens);
NETWORK_API gboolean is_dml_rename(GPtrArray *tokens);
NETWORK_API gboolean is_dml_truncate(GPtrArray *tokens);
NETWORK_API gboolean is_dml_update(GPtrArray *tokens);
#endif

#endif /* NETWORK_CHECK_DMLSQL_H_ */
