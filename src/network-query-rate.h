/*
 * network-query-rate.h
 *
 *  Created on: 2014-4-2
 *      Author: jinxuanhou
 */

#ifndef NETWORK_QUERY_RATE_H_
#define NETWORK_QUERY_RATE_H_

#include <glib.h>
#include "chassis-gtimeval.h"
#include "network-exports.h"
#include "chassis-mainloop.h"

typedef struct query_rate_statistic {
	gint64 query_accumulated_num[PROXY_TYPE_NO];
	gint64 query_accumulated_error_num[PROXY_TYPE_NO];
	gboolean is_banned;

	GMutex *rate_statistic_lock;
	GMutex _rate_statistic_lock;

	GTimeVal update_time;
} query_rate_statistic;


NETWORK_API query_rate_statistic * query_rate_statistic_new();
NETWORK_API void query_rate_statistic_free(query_rate_statistic *query_rate);
NETWORK_API void g_hash_table_query_rate_statistic_free(gpointer data);


struct query_rate_list {
	GMutex *list_lock; /**< 列表并发锁 */
	GMutex _list_lock;

	GHashTable *query_list; /**< sql并发限制列表 hash<username, limit> */
};

NETWORK_API query_rate_list *query_rate_list_new();
NETWORK_API void query_rate_list_free(query_rate_list *query_rate);

/** 添加对某个用户的sql执行累计统计量 */
NETWORK_API query_rate_statistic* insert_query_rate(
		query_rate_list *query_rate_list, const char *username,
		gint64* query_accumulated_num,
		gint64 * query_accumulated_num_error,
		gboolean is_banned);

/** 将用户的sql累计执行数增加1 */
NETWORK_API gint64 query_rate_inc(
		query_rate_list *query_rate_list, const char *username,
		proxy_rw type
		);

/** 将用户的sql累计错误执行数增加1 */
NETWORK_API gint64 query_error_rate_inc(
		query_rate_list *query_rate_list, const char *username,
		proxy_rw type
		);

/** 修改某个用户的sql累计执行统计值 */
NETWORK_API gint64 modify_query_rate_num(
		query_rate_list *query_rate_list, const char *username, gint64 query_accumulated_num,
		proxy_rw type);

/** 修改某个用户的sql累计执行统计值 */
NETWORK_API gint64 modify_query_error_rate_num(
		query_rate_list *query_rate_list, const char *username,
		gint64 query_accumulated_error_num,
		proxy_rw type);

/** 将用户对应的统计量清除 */
NETWORK_API gboolean delete_query_rate(
		query_rate_list *query_rate_list, const char *username);

/** 修改某个用户的状态*/
NETWORK_API gboolean modify_query_rate_switch(
		query_rate_list *query_rate_list, const char *username,
		gboolean is_banned);

/** 查询某个用户的累计执行条数 */
NETWORK_API gint64 get_query_rate_num(
		query_rate_list *query_rate_list, const char *username
		);

/** 查询某个用户的累计错误执行条数 */
NETWORK_API gint64 get_query_error_rate_num(
		query_rate_list *query_rate_list, const char *username
		);

/** 查询某个用户的是否被禁用  */
NETWORK_API gboolean get_query_rate_switch(
		query_rate_list *query_rate_list, const char *username
		);

#endif /* NETWORK_QUERY_RATE_H_ */
