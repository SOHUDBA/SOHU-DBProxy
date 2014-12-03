/*
 * network-table-engine-normalize.h
 *
 *  Created on: 2014-4-9
 *      Author: jinxuanhou
 */

#ifndef NETWORK_TABLE_ENGINE_NORMALIZE_H_
#define NETWORK_TABLE_ENGINE_NORMALIZE_H_

#include <glib.h>
#include "chassis-mainloop.h"
#include "network-exports.h"
#include <sql-tokenizer.h>

/** 将用户的表的创建及修改的引擎类型全部替换成innodb */
typedef enum {
	REPLACE_NO_NEED = 0,
	REPLACE_SUCCESS,
	REPLACE_ERROR
} table_engine_norm_result;

NETWORK_API table_engine_norm_result normalize_table_engine();


#endif /* NETWORK_TABLE_ENGINE_NORMALIZE_H_ */
