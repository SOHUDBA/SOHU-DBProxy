/*
 * network-inbytes-statistic.h
 *
 *  Created on: 2014-4-4
 *      Author: jinxuanhou
 */

#ifndef NETWORK_INBYTES_STATISTIC_H_
#define NETWORK_INBYTES_STATISTIC_H_

#include <glib.h>
#include "chassis-mainloop.h"
#include "chassis-gtimeval.h"
#include "network-exports.h"

typedef struct query_inbytes_statistic {
	gint64 query_accumulated_inbytes[PROXY_TYPE_NO];
	gboolean is_banned;

	GMutex *inbytes_statistic_lock;
	GMutex _inbytes_statistic_lock;

	GTimeVal update_time;

} query_inbytes_statistic;


NETWORK_API query_inbytes_statistic * query_inbytes_statistic_new();
NETWORK_API void query_inbytes_statistic_free(query_inbytes_statistic *query_inbytes);
NETWORK_API void g_hash_table_query_inbytes_statistic_free(gpointer data);


struct query_inbytes_list {
	GMutex *list_lock; /**< 列表并发锁 */
	GMutex _list_lock;

	GHashTable *query_list; /**< sql流入流量，按字节统计 hash<username, statistic> */
};

NETWORK_API query_inbytes_list *query_inbytes_list_new();
NETWORK_API void query_inbytes_list_free(query_inbytes_list *query_inbytes);

/** 将用户的sql累计执行数增加incre */
NETWORK_API gint64 query_inbytes_inc(
		query_inbytes_list *query_inbytes_list,
		const char *username,
		gint64 incre,
		proxy_rw type
		);

NETWORK_API gboolean query_inbytes_reset(
		query_inbytes_list *query_inbytes_list, const char *username,
		proxy_rw type
		);

/** 将用户对应的统计量清除 */
NETWORK_API gboolean delete_query_inbytes(
		query_inbytes_list *query_inbytes_list, const char *username);

/** 修改某个用户的状态*/
NETWORK_API gboolean modify_query_inbytes_switch(
		query_inbytes_list *query_inbytes_list, const char *username,
		gboolean is_banned);

/** 查询某个用户的累计执行条数 */
NETWORK_API gint64 get_query_inbytes_num_total(
		query_inbytes_list *query_inbytes_list, const char *username
		);

/** 查询某个用户的是否被禁用  */
NETWORK_API gboolean get_query_inbytes_switch(
		query_inbytes_list *query_inbytes_list, const char *username
		);


#endif /* NETWORK_INBYTES_STATISTIC_H_ */
