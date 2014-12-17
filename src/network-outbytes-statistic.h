/*
 * network-outbytes-statistic.h
 *
 *  Created on: 2014-4-4
 *      Author: jinxuanhou
 */

#ifndef NETWORK_OUTBYTES_STATISTIC_H_
#define NETWORK_OUTBYTES_STATISTIC_H_

#include <glib.h>
#include "chassis-mainloop.h"
#include "chassis-gtimeval.h"
#include "network-exports.h"

typedef struct query_outbytes_statistic {
	gint64 query_accumulated_outbytes[PROXY_TYPE_NO];
	gboolean is_banned;

	GMutex *outbytes_statistic_lock;
	GMutex _outbytes_statistic_lock;

	GTimeVal update_time;

} query_outbytes_statistic;


NETWORK_API query_outbytes_statistic * query_outbytes_statistic_new();
NETWORK_API void query_outbytes_statistic_free(query_outbytes_statistic *query_outbytes);
NETWORK_API void g_hash_table_query_outbytes_statistic_free(gpointer data);


struct query_outbytes_list {
	GMutex *list_lock; /**< 列表并发锁 */
	GMutex _list_lock;

	GHashTable *query_list; /**< sql流入流量，按字节统计 hash<username, statistic> */
};

NETWORK_API query_outbytes_list *query_outbytes_list_new();
NETWORK_API void query_outbytes_list_free(query_outbytes_list *query_outbytes);


/** 将用户的sql累计执行数增加incre */
NETWORK_API gint64 query_outbytes_inc(
		query_outbytes_list *query_outbytes_list,
		const char *username,
		gint64 incre,
		proxy_rw type
		);

NETWORK_API gboolean query_outbytes_reset(
		query_outbytes_list *query_outbytes_list, const char *username,
		proxy_rw type
		);

/** 将用户对应的统计量清除 */
NETWORK_API gboolean delete_query_outbytes(
		query_outbytes_list *query_outbytes_list, const char *username);

/** 修改某个用户的状态*/
NETWORK_API gboolean modify_query_outbytes_switch(
		query_outbytes_list *query_outbytes_list, const char *username,
		gboolean is_banned);

/** 查询某个用户的累计执行条数 */
NETWORK_API gint64 get_query_outbytes_num_total(
		query_outbytes_list *query_outbytes_list, const char *username
		);

/** 查询某个用户的是否被禁用  */
NETWORK_API gboolean get_query_outbytes_switch(
		query_outbytes_list *query_outbytes_list, const char *username
		);

#endif /* NETWORK_OUTBYTES_STATISTIC_H_ */
