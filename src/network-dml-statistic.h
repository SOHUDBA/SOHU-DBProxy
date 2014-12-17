/*
 * network-dml-statistic.h
 *
 *  Created on: 2014-5-14
 *      Author: jinxuanhou
 */

#ifndef NETWORK_DML_STATISTIC_H_
#define NETWORK_DML_STATISTIC_H_

#include <glib.h>
#include "chassis-mainloop.h"
#include "chassis-gtimeval.h"
#include "network-exports.h"
#include "network-check-DMLsql.h"

typedef struct query_dml_statistic {
	gboolean is_banned;

	GMutex *dml_statistic_lock;
	GMutex _dml_statistic_lock;

	GTimeVal update_time;

} query_dml_statistic;


NETWORK_API query_dml_statistic * query_dml_statistic_new();
NETWORK_API void query_dml_statistic_free(query_dml_statistic *query_dml);
NETWORK_API void g_hash_table_query_dml_statistic_free(gpointer data);


struct query_dml_list {
	GMutex *list_lock; /**< 列表并发锁 */
	GMutex _list_lock;

	GHashTable *query_list; /**< sql流入流量，按字节统计 hash<username, statistic> */
};

NETWORK_API query_dml_list *query_dml_list_new();
NETWORK_API void query_dml_list_free(query_dml_list *query_dml);

/** 修改某个用户的状态*/
NETWORK_API gboolean modify_query_dml_switch(
		query_dml_list *query_dml_list, const char *username,
		gboolean is_banned);

/** 查询某个用户的是否被禁用  */
NETWORK_API gboolean get_query_dml_switch(
		query_dml_list *query_dml_list, const char *username
		);


#endif /* NETWORK_DML_STATISTIC_H_ */
