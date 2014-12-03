/* $%BEGINLICENSE%$
 Copyright (c) 2014, Sohu and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */

#ifndef _SLOW_QUERY_LOG_H_
#define _SLOW_QUERY_LOG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

//struct ip_address {
//  gboolean wildcard
//  gchar *address
//};

typedef struct slow_query_log_filter_t {
    //GArray *service_addresses
    //GArray *frontend_addresses
	/** 大于等于此时长的语句算慢查询。单位：秒 */
	gdouble time_threshold_s;
	/** 大于等于此时长的语句算慢查询。单位：微秒 */
	guint64 time_threshold_us;
} slow_query_log_filter_t;

typedef struct slow_query_log_entry_t {
    gchar *service_type;
    gchar *service_address;
    gchar *frontend_address;
    gchar *backend_address;
    guint64 start_time;
    guint64 finish_time;
    GString *start_time_str;
    GString *finish_time_str;
    guint64 execute_time;
    guint thread_id;
    gchar *database_account;
    gchar *database_schema;
    guint command_type;
    gchar *command_text;
    gchar *command_full_text;
    guint64 result_set_rows;
    guint64 result_set_bytes;
} slow_query_log_entry_t;

typedef struct slow_query_log_file_t {
	/** 慢查询日志文件名称 */
	gchar *log_filename;
	/** 互斥锁 */
	GMutex mlock;
	/** 文件句柄 */
	gint log_file_fd;
	/**日志条目*/
	slow_query_log_entry_t *log_entry;
	/**日志字符串*/
	GString *log_ts_str;
} slow_query_log_file_t;

typedef struct slow_query_log_config_t {
	/** 读写锁 */
	GRWLock rwlock;
	/** 是否开启慢查询 */
	gboolean is_enabled;
	/** 日志文件 */
	slow_query_log_file_t *log_file;
	/** 慢查询过滤条件 */
	slow_query_log_filter_t *filter;
} slow_query_log_config_t;

NETWORK_API int slow_query_log_file_write(slow_query_log_file_t *log_file, GString *str);
NETWORK_API void slow_query_log_config_t_free(slow_query_log_config_t *config);
NETWORK_API slow_query_log_config_t *slow_query_log_config_t_new(void);
NETWORK_API gboolean slow_query_log_enable(slow_query_log_config_t *config);
NETWORK_API gboolean slow_query_log_disable(slow_query_log_config_t *config);
NETWORK_API int slow_query_log_update_timestamp(slow_query_log_file_t *log);



#endif /*_SLOW_QUERY_LOG_H_*/



/*eof*/
