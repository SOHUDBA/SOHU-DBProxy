/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.

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
 

#ifndef _NETWORK_CONN_POOL_H_
#define _NETWORK_CONN_POOL_H_

#include <glib.h>

#include "chassis-mainloop.h"
#include "network-socket.h"
#include "network-exports.h"

typedef struct connection_scaler_pool_statistics {
	guint conn_nopool;
	guint conn_zerosize;
	guint conn_toomany;
	guint conn_length;
	guint conn_checked;
	guint conn_nouser;
	guint conn_timeout;
	guint conn_again;
	guint conn_disconnected;
	guint conn_good;
} connection_scaler_pool_statistics;

NETWORK_API void network_connection_scaler_pool_statictics_init(connection_scaler_pool_statistics *pool_stats);
NETWORK_API void network_connection_scaler_pool_statictics_print(
		const connection_scaler_pool_statistics *pool_stats,
		const gchar *username);

/**
 * 表示从连接池取连接的执行结果
 */
typedef enum {
	POOL_CONNECTION_ERRNO_SUCCESS = 0, /**<成功取出一个连接*/
	POOL_CONNECTION_ERRNO_NOPOOL = 1, /**<该用户没有连接池，或连接池大小是零*/
	POOL_CONNECTION_ERRNO_TOOMANY = 3, /**<已达连接池最大连接数*/
	POOL_CONNECTION_ERRNO_UNKNOWN = 9, /**<其它错误*/
} pool_connection_errno;

// 用于维护用户对应的连接池的统计信息，包括空闲的连接数、在创建的连接数及在用的连接数
typedef struct pool_status {
	gint conn_num_in_use;
	gint conn_num_in_pending;
	gint conn_num_in_idle;
	GMutex status_mutex;
} pool_status;

/**
 * 表示(在连接池中的)连接的几种状态
 */
typedef enum {
	POOL_STATUS_STATE_INITIALIZED = 0, /**<开始新建连接*/
	POOL_STATUS_STATE_NOT_CONNECTED = 1, /**<新建连接失败*/
	POOL_STATUS_STATE_PUT_INTO_POOL = 2, /**<新建连接成功后，将其放入连接池*/
	POOL_STATUS_STATE_GET_FROM_POOL = 3, /**<从连接池取出连接*/
	POOL_STATUS_STATE_RETURN_TO_POOL = 4, /**<将连接归还连接池*/
	POOL_STATUS_STATE_DISCONNECTED = 5, /**<断开(在用)连接*/
	POOL_STATUS_STATE_REMOVE_FROM_POOL = 6, /**<从连接池移除连接*/
} pool_status_state;

NETWORK_API pool_status * pool_status_new();
NETWORK_API void pool_status_free(pool_status * pool_st);
NETWORK_API void g_hash_pool_status_free(gpointer data);

typedef struct network_garbage_connection_pool {
	GQueue *entries; //存放pool_entry队列
	GMutex mutex;
} network_garbage_connection_pool;

typedef struct {
	GHashTable *users; /** GHashTable<GString, GQueue<network_connection_pool_entry>> */
	GMutex connection_pool_mutex;

	// added by jinxuan hou, 2013/04/11
	gint num_conns_being_used; /** 记录对应的backend上面的连接数，用于负载均衡时使用*/
	gint num_conns_total; //backend 上面连接的总数

	GHashTable *conn_pool_status; // 数据结构如GHashTable<GString *username, struct pool_status *status>
	GRWLock pool_status_lock; // 该读写锁实现对上面保存连接池统计信息的hashtable的同步访问
//	GHashTable *conn_num_in_use; //与连接池对应，记录该backed上面不同用户对应的连接池的使用情况
//	GHashTable *conn_pending; // 与连接池对应，记录该backend上面不同用户对应的处于pending状态的连接：pending一般对应正在创建的连接
	guint max_idle_connections; //< 默认的最大连接数 ?
	guint min_idle_connections; //< 默认的最小连接数 ?
	gint max_idle_interval; //< 默认的连接最大空闲时间(指在连接池中没有被使用)

	network_garbage_connection_pool *garbage_connection_pool;
} network_connection_pool;

typedef struct {
	network_socket *sock;          /** the idling socket */
	
	network_connection_pool *pool; /** a pointer back to the pool */

	GTimeVal added_ts;             /** added at ... we want to make sure we don't hit wait_timeout */
	GTimeVal last_connect; /**最后一次检查连接成功的时间*/

	network_garbage_connection_pool *garbage_pool;
} network_connection_pool_entry;

///** 加入连接池的位置 */
//typedef enum {
//	NC_POOL_ADD_PREPEND = 0, /**从头追加*/
//	NC_POOL_ADD_APPPEND = 1, /**从尾追加*/
//} nc_pool_add_position_t;

NETWORK_API network_connection_pool_entry *network_connection_pool_entry_new(void);
NETWORK_API void network_connection_pool_entry_free(network_connection_pool_entry *e, gboolean free_sock);


NETWORK_API network_connection_pool *network_connection_pool_init(void) G_GNUC_DEPRECATED;
NETWORK_API network_connection_pool *network_connection_pool_new(void);
NETWORK_API void network_connection_pool_free(network_connection_pool *pool);

NETWORK_API GQueue *network_connection_pool_get_conns(network_connection_pool *pool, const GString *username, GString *);
NETWORK_API network_socket *network_connection_pool_get(network_connection_pool *pool,
		GString *username,
		GString *default_db);

#include "network-backend.h"

NETWORK_API network_socket *network_connection_pool_get_new(chassis *chas,
		network_backend_t *backend, proxy_rw type,
		network_connection_pool *pool, const GString *username,
		user_pool_config *user_pool_conf,
		connection_scaler_pool_statistics *pool_stats);

NETWORK_API network_connection_pool_entry *network_connection_pool_add(network_connection_pool *pool, network_socket *sock);
NETWORK_API gboolean network_connection_pool_add_entry (network_connection_pool *pool, network_connection_pool_entry * entry, gboolean update_add_ts);
NETWORK_API void network_connection_pool_remove(network_connection_pool *pool, network_connection_pool_entry *entry);

NETWORK_API GQueue *pool_users_name_queue_new(network_connection_pool *pool);
NETWORK_API void pool_users_name_queue_free(GQueue *q);

NETWORK_API gboolean check_pool_entry_timeout(
		network_connection_pool_entry *entry, GTimeVal *now_tv,
		gint max_idle_interval);
NETWORK_API gboolean check_pool_entry_connectivity_timeout(
		network_connection_pool_entry *entry, GTimeVal *now_tv);
NETWORK_API gboolean check_pool_entry_connectivity(network_connection_pool_entry *entry);

NETWORK_API network_garbage_connection_pool *garbage_connection_pool_new();
NETWORK_API void garbage_connection_pool_free(network_garbage_connection_pool *gc_pool);
NETWORK_API void garbage_connection_pool_add_entry(network_garbage_connection_pool *gc_pool, network_connection_pool_entry *entry);
NETWORK_API guint garbage_connection_pool_clean_old_entries(network_garbage_connection_pool *gc_pool, gint grace_secs);


// added by jinxuan hou, 添加了一些指定用户的连接统计数的操作函数
NETWORK_API pool_status * get_conn_pool_status(network_connection_pool *pool, const gchar *username);
NETWORK_API void insert_conn_pool_status(network_connection_pool *pool, gchar *username, pool_status *value);
NETWORK_API void update_conn_pool_status_in_state(network_connection_pool *pool,
		const gchar *username, pool_status_state state);
NETWORK_API gint get_conn_sum_count(network_connection_pool *pool, const gchar *username);
NETWORK_API gint get_conn_using_pending_count(network_connection_pool *pool,
		const gchar *username);
NETWORK_API gint get_conn_pending_count(network_connection_pool *pool, const gchar *username);
NETWORK_API gint get_conn_using_count(network_connection_pool *pool, const gchar *username);
NETWORK_API gint get_conn_idle_count(network_connection_pool *pool, const gchar *username);
//NETWORK_API void network_connection_pool_del_by_con(network_socket *con);
//NETWORK_API void network_connection_pool_del_byconn(network_connection_pool *pool, network_socket *con); //将指定的socket连接中连接池中删除

#endif
