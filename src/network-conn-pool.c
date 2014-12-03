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
 

#include <glib.h>

#include "network-conn-pool.h"
#include "network-mysqld-packet.h"
#include "glib-ext.h"
#include "sys-pedantic.h"

/** @file
 * connection pools
 *
 * in the pool we manage idle connections
 * - keep them up as long as possible
 * - make sure we don't run out of seconds
 * - if the client is authed, we have to pick connection with the same user
 * - ...  
 */

/**
 * create a empty connection pool entry
 *
 * @return a connection pool entry
 */
network_connection_pool_entry *network_connection_pool_entry_new(void) {
	network_connection_pool_entry *e;

	e = g_new0(network_connection_pool_entry, 1);

	return e;
}

/**
 * free a conn pool entry
 *
 * @param e the pool entry to free
 * @param free_sock if true, the attached server-socket will be freed too
 */
void network_connection_pool_entry_free(network_connection_pool_entry *e, gboolean free_sock) {
	if (!e) return;

	if (e->sock && free_sock) {
		network_socket *sock = e->sock;
			
		event_del(&(sock->event));
		network_socket_free(sock);
	}

	g_free(e);
}

/**
 * free all pool entries of the queue
 *
 * used as GDestroyFunc in the user-hash of the pool
 *
 * @param q a GQueue to free
 *
 * @see network_connection_pool_new
 * @see GDestroyFunc
 */
static void g_queue_free_all(gpointer q) {
	GQueue *queue = q;
	network_connection_pool_entry *entry;

	while ((entry = g_queue_pop_tail(queue))) network_connection_pool_entry_free(entry, TRUE);

	g_queue_free(queue);
}

/**
 * @author sohu-inc.com
 * pool status init
 */
pool_status *pool_status_new() {
	pool_status *pool_st = g_new0(pool_status, 1);
	g_mutex_init(&pool_st->status_mutex);
	pool_st->conn_num_in_use = 0;
	pool_st->conn_num_in_pending = 0;
	pool_st->conn_num_in_idle = 0;
	return pool_st;
}

void pool_status_free(pool_status *pool_st) {
	if(pool_st == NULL)
		return;
	g_mutex_clear(&pool_st->status_mutex);
	g_free(pool_st);
	return;
}

void g_hash_pool_status_free(gpointer data) {
	pool_status_free((pool_status *)data);
}

#if 0
pool_status *user_pool_status_add_new(GHashTable *user_pool_status, GString *username) {
	gchar *user = NULL;
	pool_status *pool_st = NULL;

	g_assert(user_pool_status);
	g_assert(username);

	user = g_strdup(username->str);
	pool_st = pool_status_new();
	if (pool_st == NULL) {
		g_free(user);
		return NULL;
	}
	g_hash_table_insert(user_pool_status, user, pool_st);

	return pool_st;
}
#endif


network_garbage_connection_pool *garbage_connection_pool_new() {
	network_garbage_connection_pool *gc_pool = NULL;
	gc_pool = g_new0(network_garbage_connection_pool, 1);
	gc_pool->entries = g_queue_new();
	g_mutex_init(&(gc_pool->mutex));
	return gc_pool;
}

void garbage_connection_pool_free(network_garbage_connection_pool *gc_pool) {
	if (gc_pool != NULL) {
		if (gc_pool->entries != NULL) {
			network_connection_pool_entry *entry = NULL;
			while ( (entry = g_queue_pop_head(gc_pool->entries)) != NULL ) {
				network_connection_pool_entry_free(entry, FALSE);
			}
			g_queue_free(gc_pool->entries);
		}
		g_mutex_clear(&(gc_pool->mutex));
		g_free(gc_pool);
	}
	return;
}

void garbage_connection_pool_add_entry(network_garbage_connection_pool *gc_pool, network_connection_pool_entry *entry) {
	g_assert(gc_pool);
	g_assert(entry);

	g_mutex_lock(&(gc_pool->mutex));

	g_get_current_time((&entry->added_ts));
	entry->garbage_pool = gc_pool;
	g_queue_push_tail(gc_pool->entries, entry);

	g_mutex_unlock(&(gc_pool->mutex));

	return;
}

guint garbage_connection_pool_clean_old_entries(network_garbage_connection_pool *gc_pool, gint grace_secs) {
	guint count = 0;
	guint i = 0;
	network_connection_pool_entry *entry = NULL;
	GTimeVal now_tv;
	guint q_len_before = 0;
	guint q_len_after = 0;

	g_assert(gc_pool);

	g_get_current_time(&now_tv);

	g_mutex_lock(&(gc_pool->mutex));
	q_len_before = g_queue_get_length(gc_pool->entries);

	for (i = 0; i < g_queue_get_length(gc_pool->entries); ) {
		entry = g_queue_peek_nth(gc_pool->entries, i);
		if (entry == NULL) {
			i++;
			continue;
		}
		if (now_tv.tv_sec > (entry->added_ts).tv_sec + grace_secs) {
			//remove this entry
			entry = g_queue_pop_nth(gc_pool->entries, i);
			network_connection_pool_entry_free(entry, TRUE);
			entry = NULL;
			count++;
		} else {
			i++;
		}
	}

	q_len_after = g_queue_get_length(gc_pool->entries);

	g_mutex_unlock(&(gc_pool->mutex));

#ifdef DEBUG_CONN_POOL
	if (q_len_before > 0) {
		g_debug("[%s]: gc_pool length before: %d, after: %d, removed: %d",
				G_STRLOC, q_len_before, q_len_after, count);
	}
#endif

	return count;
}


/**
 * @deprecated: will be removed in 1.0
 * @see network_connection_pool_new()
 */
network_connection_pool *network_connection_pool_init(void) {
	return network_connection_pool_new();
}

/**
 * init a connection pool
 */
network_connection_pool *network_connection_pool_new(void) {
	network_connection_pool *pool;

	pool = g_new0(network_connection_pool, 1);

	g_mutex_init(&(pool->connection_pool_mutex));
	g_mutex_lock(&(pool->connection_pool_mutex));
	pool->users = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_queue_free_all);
	g_mutex_unlock(&(pool->connection_pool_mutex));

	/**
	 * added by jinxuan hou, 2013/04/11
	 * initialize statistical information of the conn pool
	 *
	 * @@jinxuanhou
	 */
	
	pool->conn_pool_status = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_hash_pool_status_free);
	//初始化读写锁
	g_rw_lock_init (&pool->pool_status_lock);
	//	pool->conn_num_in_use = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_hash_table_int_free);
	//	pool->conn_pending = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_hash_table_int_free);

	pool->garbage_connection_pool = garbage_connection_pool_new();

	return pool;
}

/**
 * free all entries of the pool
 *
 */
void network_connection_pool_free(network_connection_pool *pool) {
	if (!pool) return;

	g_hash_table_foreach_remove(pool->users, g_hash_table_true, NULL);

	g_mutex_lock(&(pool->connection_pool_mutex));
	g_hash_table_destroy(pool->users);
	g_mutex_unlock(&(pool->connection_pool_mutex));
	g_mutex_clear(&(pool->connection_pool_mutex));

	// added by sohu-inc.com
	g_rw_lock_writer_lock(&pool->pool_status_lock);
	g_hash_table_destroy(pool->conn_pool_status);
	g_rw_lock_writer_unlock(&pool->pool_status_lock);
	g_rw_lock_clear(&pool->pool_status_lock);
//	g_hash_table_destroy(pool->conn_num_in_use);
//	g_hash_table_destroy(pool->conn_pending);

	if (pool->garbage_connection_pool != NULL) {
		garbage_connection_pool_free(pool->garbage_connection_pool);
		pool->garbage_connection_pool = NULL;
	}

	g_free(pool);
}

/**
 * find the entry which has more than max_idle connections idling
 * 
 * @return TRUE for the first entry having more than _user_data idling connections
 * @see network_connection_pool_get_conns 
 */
static gboolean find_idle_conns(gpointer UNUSED_PARAM(_key), gpointer _val, gpointer _user_data)  __attribute__((unused));
static gboolean find_idle_conns(gpointer UNUSED_PARAM(_key), gpointer _val, gpointer _user_data) {
	guint min_idle_conns = *(gint *)_user_data;
	GQueue *conns = _val;

	return (conns->length > min_idle_conns);
}

GQueue *network_connection_pool_get_conns(network_connection_pool *pool, const GString *username, GString *UNUSED_PARAM(default_db)) {
	GQueue *conns = NULL;


	if (username && username->len > 0) {
		conns = g_hash_table_lookup(pool->users, username);
		/**
		 * if we know this use, return a authed connection 
		 */
#ifdef DEBUG_CONN_POOL
		g_debug("%s: (get_conns) get user-specific idling connection for '%s' -> %p", G_STRLOC, username->str, conns);
#endif
		if (conns) return conns;
	}

	/**
	 * we don't have a entry yet, check the others if we have more than 
	 * min_idle waiting
	 */

	//conns = g_hash_table_find(pool->users, find_idle_conns, &(pool->min_idle_connections));
#ifdef DEBUG_CONN_POOL
	g_debug("%s: (get_conns) try to find max-idling conns for user '%s' -> %p", G_STRLOC, username ? username->str : "", conns);
#endif

	return conns;
}


static void pool_users_name_queue_add_foreach(gpointer key, gpointer UNUSED_PARAM(val), gpointer userdata) {
	GString *username = NULL;
	GQueue *users = (GQueue *)userdata;
	g_assert(key);
	if (users != NULL) {
		username = g_string_dup(key);
		g_queue_push_tail(users, username);
	}
	return;
}

GQueue *pool_users_name_queue_new(network_connection_pool *pool) {
	GQueue *users = NULL;
	g_assert(pool);
	users = g_queue_new();
	if (users != NULL) {
		g_mutex_lock(&(pool->connection_pool_mutex));
		g_hash_table_foreach(pool->users, pool_users_name_queue_add_foreach, users);
		g_mutex_unlock(&(pool->connection_pool_mutex));
	}
	return users;
}

void pool_users_name_queue_free(GQueue *q) {
	GString *username = NULL;
	if (q != NULL) {
		while ((username = g_queue_pop_head(q)) != NULL) {
			g_string_free(username, TRUE);
		}
		g_queue_free(q);
	}
}


/**
 * 检查连接池连接是否超时
 * @param[IN] GTimeVal *now_tv 当前时间。如果为NULL则函数里重新计算当前时间
 * @param[IN] gint max_idle_interval 超时时间（秒）
 * @return TRUE 超时
 * @return FALSE 没超时
 */
gboolean check_pool_entry_timeout(network_connection_pool_entry *entry,
		GTimeVal *now_tv, gint max_idle_interval) {
	GTimeVal now_tv_storage;
	gint time_diff;
//#define	POOL_ENTRY_MAX_TIMEOUT (20 * G_USEC_PER_SEC)

	if (max_idle_interval < 0) {
		return FALSE;
	}

	if (now_tv == NULL) {
		g_get_current_time(&now_tv_storage);
		now_tv = &now_tv_storage;
	}
	time_diff = now_tv->tv_sec - (entry->added_ts).tv_sec;
	if (time_diff > max_idle_interval) {
#ifdef DEBUG_CONN_POOL
		char * add_time_str = g_time_val_to_iso8601(&(entry->added_ts));
		char * now_time_str = g_time_val_to_iso8601(now_tv);
		g_debug("[%s]: entry is timed out: %p, added: %s, now: %s, diff: %d(s), timeout: %d(s)"
				, G_STRLOC, entry
				, add_time_str
				, now_time_str
				, time_diff
				, max_idle_interval
				);
		g_free(add_time_str);
		g_free(now_time_str);
#endif
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * 上次连接检查时间是否已过时
 * @param[IN] GTimeVal *now_tv 当前时间。如果为NULL则函数里重新计算当前时间
 * @param[IN] gint max_idle_interval 超时时间（秒）。<0 不超时
 * @return TRUE 已超时
 * @return FALSE 未超时
 */
gboolean check_pool_entry_connectivity_timeout(
		network_connection_pool_entry *entry, GTimeVal *now_tv) {
	GTimeVal now_tv_storage;
#define POOL_ENTRY_CONNECTIVITY_MAX_CHECK_INTERVAL (3) /*最多3秒检查一次连接*/

	if (now_tv == NULL) {
		g_get_current_time(&now_tv_storage);
		now_tv = &now_tv_storage;
	}
	if (now_tv->tv_sec > (entry->last_connect).tv_sec + POOL_ENTRY_CONNECTIVITY_MAX_CHECK_INTERVAL ) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * 检查连接池连接是否可连接，更新检查时间
 * @return TRUE 已连接
 * @return FALSE 已断开
 */
gboolean check_pool_entry_connectivity(network_connection_pool_entry *entry) {
	if (detect_server_socket_disconnect(entry->sock) == TRUE) {
		return FALSE;
	} else {
		g_get_current_time(&(entry->last_connect));
		return TRUE;
	}
}

/**
 * 检查(连接池里的)一个连接的状态
 * 从连接池取出连接前，检查一个连接是否超时、断开
 * @return TRUE 状态正常/不需要删除此连接
 * @return FALSE 不可用（超时或已断开）/接下来后续需要删除此连接
 */
static gboolean check_pool_entry_status(network_connection_pool_entry *entry) {
	GTimeVal now_tv;

	g_get_current_time(&now_tv);

#ifdef DEBUG_CONN_POOL
	g_debug("[%s]: checking pool entry status, %p", G_STRLOC, entry);
#endif

	/**取连接时不需要检查是否超时，只需检查是否断开即可*/
#if 0
	/**检查连接是否超时，若是则需要删除之*/
	if (check_pool_entry_timeout(entry, &now_tv) == TRUE) {
#ifdef DEBUG_CONN_POOL
		g_debug("[%s]: remove timed-out pool entry: %p, %d", G_STRLOC, entry, entry->sock->fd);
#endif
	} else
#endif

	/**检查后端是否断开了，若是则需要删除之*/
	if (check_pool_entry_connectivity(entry) == FALSE) {
#ifdef DEBUG_CONN_POOL
		g_debug("[%s]: remove disconnected pool entry: %p, %d", G_STRLOC, entry, entry->sock->fd);
#endif
	} else {
		return TRUE;
	}

	/**@todo: 搞成异步的？由连接池维护线程释放*/
	//network_connection_pool_entry_free(entry, TRUE);
	//garbage_connection_pool_add_entry(pool->garbage_connection_pool, entry);
	return FALSE;
}

/**
 * get a connection from the pool
 * 从连接池头部取出一个连接
 *
 * make sure we have at lease <min-conns> for each user
 * if we have more, reuse a connect to reauth it to another user
 *
 * @param pool connection pool to get the connection from
 * @param username (optional) name of the auth connection
 * @param default_db (unused) unused name of the default-db
 */
network_socket *network_connection_pool_get(network_connection_pool *pool,
		GString *username,
		GString *UNUSED_PARAM(default_db)) {

	GQueue *conns = NULL;
	network_connection_pool_entry *entry = NULL;
	network_socket *sock = NULL;

	g_mutex_lock(&(pool->connection_pool_mutex));

	conns = network_connection_pool_get_conns(pool, username, NULL);

	/**
	 * if we know this use, return a authed connection 
	 */
#ifndef CONNECTION_POOL_REGISTER_EVENTS_ENABLED
	if (conns) {

		entry = g_queue_pop_head(conns);

		/**
		 * 取出一个状态正常的连接，将状态异常的连接放入垃圾回收池
		 * @todo 这里可以不用检查了？因为已有单独scaler线程定期(若干秒)检查连接状态
		 */
		while (entry != NULL ) {
			if (check_pool_entry_status(entry) == TRUE) {
				break;
			} else {
				garbage_connection_pool_add_entry(pool->garbage_connection_pool, entry);
			}
			entry = g_queue_pop_head(conns);
		}
		if (conns->length == 0) {
			/**
			 * all connections are gone, remove it from the hash
			 */
			g_hash_table_remove(pool->users, username);
		}
	}

#else
	if (conns) {
		entry = g_queue_pop_head(conns);

		if (conns->length == 0) {
			/**
			 * all connections are gone, remove it from the hash
			 */
			g_hash_table_remove(pool->users, username);
		}
	}

#endif

	if (!entry) {
#ifdef DEBUG_CONN_POOL
		g_debug("%s: (get) no entry for user '%s' -> %p", G_STRLOC, username ? username->str : "", conns);
#endif
		g_mutex_unlock(&(pool->connection_pool_mutex));
		return NULL;
	}

	sock = entry->sock;

	network_connection_pool_entry_free(entry, FALSE);

	/**连接加入连接池时没有注册事件，所以取出时也不需要删除事件*/
//	struct event *ev = &(sock->event);
//	/* remove the idle handler from the socket */
//	if(sock->event.ev_base) {
//		g_debug("[%s]: fd: %d, events: %x, callback: %p network_mysqld_pool_con_idle_handle: %p, network_mysqld_cache_con_idle_handle: %p",
//				G_STRLOC, event_get_fd(ev), event_get_events(ev),
//				event_get_callback(ev),
//				network_mysqld_pool_con_idle_handle,
//				network_mysqld_cache_con_idle_handle);
//		event_del(&(sock->event));
//	}
//	g_debug("[%s]: fd: %d, events: %x, callback: %p network_mysqld_pool_con_idle_handle: %p, network_mysqld_cache_con_idle_handle: %p",
//			G_STRLOC, event_get_fd(ev), event_get_events(ev),
//			event_get_callback(ev),
//			network_mysqld_pool_con_idle_handle,
//			network_mysqld_cache_con_idle_handle);

#ifdef DEBUG_CONN_POOL
	g_debug("%s: (get) got socket for user '%s' -> %p", G_STRLOC, username ? username->str : "", sock);
#endif

	g_mutex_unlock(&(pool->connection_pool_mutex));
	return sock;
}


void network_connection_scaler_pool_statictics_init(connection_scaler_pool_statistics *pool_stats) {
	pool_stats->conn_nopool = 0;
	pool_stats->conn_zerosize = 0;
	pool_stats->conn_toomany = 0;
	pool_stats->conn_length = 0;
	pool_stats->conn_checked = 0;
	pool_stats->conn_nouser = 0;
	pool_stats->conn_timeout = 0;
	pool_stats->conn_again = 0;
	pool_stats->conn_disconnected = 0;
	pool_stats->conn_good = 0;
}

void network_connection_scaler_pool_statictics_print(
		const connection_scaler_pool_statistics *pool_stats,
		const gchar *username) {
	g_debug(
			"[%s]: check users pool status: username: %s, nopool: %d, zerosize: %d, "
					"toomany: %d, length: %d, "
					"checked: %d, nouser: %d, "
					"timeout: %d, again: %d, "
					"disconnected: %d, good: %d", G_STRLOC, username,
			pool_stats->conn_nopool, pool_stats->conn_zerosize,
			pool_stats->conn_toomany, pool_stats->conn_length,
			pool_stats->conn_checked, pool_stats->conn_nouser,
			pool_stats->conn_timeout, pool_stats->conn_again,
			pool_stats->conn_disconnected, pool_stats->conn_good);
	return;
}

network_socket *network_connection_pool_get_new(chassis *chas,
		network_backend_t *backend, proxy_rw type,
		network_connection_pool *pool, const GString *username,
		user_pool_config *user_pool_conf,
		connection_scaler_pool_statistics *pool_stats) {
	guint pool_conn_current_using_sum = 0;
	GQueue *conns = NULL;
	network_connection_pool_entry *entry = NULL;
	GTimeVal now_tv;
	guint removed = 0;
	network_socket *sock = NULL;

	g_assert(chas);
	g_assert(backend);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);
	g_assert(pool);
	g_assert(username);
	g_assert(user_pool_conf);
	g_assert(pool_stats);
	g_assert(backend->pool[type] == pool);

	/**
	 * 取用户连接池
	 */
	g_mutex_lock(&(pool->connection_pool_mutex));
	conns = network_connection_pool_get_conns(pool, username, NULL );
	if (conns == NULL ) {
		pool_stats->conn_nopool++;
		goto NETWORK_CONNECTION_POOL_GET_NEW_EXIT;
	}
	pool_stats->conn_length = g_queue_get_length(conns);

	/**
	 * 删除空的用户连接池
	 * 比如最小连接数等于零
	 */
	if (pool_stats->conn_length == 0) {
		pool_stats->conn_zerosize++;
		g_hash_table_remove(pool->users, username);
		goto NETWORK_CONNECTION_POOL_GET_NEW_EXIT;
	}

	/**
	 * 取用户连接池当前连接数，包括未决的和已用的，不包括空闲的(空闲数量应该约等于连接池长度)
	 */
	pool_conn_current_using_sum = get_conn_using_pending_count(pool, username->str);

	/**
	 * 是否[连接池当前连接]大于[最大连接数]
	 */
	if (pool_conn_current_using_sum > user_pool_conf->max_connections) {
		pool_stats->conn_toomany++;
		goto NETWORK_CONNECTION_POOL_GET_NEW_EXIT;
	}

	g_get_current_time(&now_tv);

	/**取出一个连接*/
	for (entry = g_queue_pop_head(conns); conns != NULL && entry != NULL ;
			entry = g_queue_pop_head(conns)) {
		pool_stats->conn_checked++;
		/**proxy_get_server_connection_list()这里idle--*/
		//update_conn_pool_status_in_state(pool, username->str, POOL_STATUS_STATE_REMOVE_FROM_POOL);

		/**
		 * 检查时间间隔未到，不需要检查，退出(此用户连接池)循环
		 */
		if (check_pool_entry_connectivity_timeout(entry, &now_tv) == FALSE) {
			pool_stats->conn_again++;
			break;
		}

		/**
		 * 是否断开
		 */
		if (check_pool_entry_connectivity(entry) == FALSE) {
			update_conn_pool_status_in_state(pool, username->str, POOL_STATUS_STATE_REMOVE_FROM_POOL);
			garbage_connection_pool_add_entry(pool->garbage_connection_pool,
					entry);
			pool_stats->conn_disconnected++;
			entry = NULL;
			pool_conn_current_using_sum = get_conn_using_pending_count(pool, username->str);
			continue;
		}

		/**
		 * 正常的连接
		 */
		if (entry != NULL) {
			pool_stats->conn_good++;
			break;
		}

	}

	NETWORK_CONNECTION_POOL_GET_NEW_EXIT:
	g_mutex_unlock(
			&(pool->connection_pool_mutex));

	removed += pool_stats->conn_disconnected;

	if (entry == NULL ) {
#ifdef DEBUG_CONN_POOL
		g_debug("%s: (get) no entry for user '%s' -> %p", G_STRLOC, username ? username->str : "", conns);
#endif
		return NULL ;
	} else {
		sock = entry->sock;
		network_connection_pool_entry_free(entry, FALSE);
#ifdef DEBUG_CONN_POOL
		g_debug("%s: (get) got socket for user '%s' -> %p", G_STRLOC, username ? username->str : "", sock);
#endif
	}

	return sock;
}


/**
 * add a connection to the connection pool
 * 向连接池队列头部添加一个连接套接字结构
 *
 */
//network_connection_pool_entry *network_connection_pool_add(network_connection_pool *pool, network_socket *sock, nc_pool_add_position_t pos) {
network_connection_pool_entry *network_connection_pool_add(network_connection_pool *pool, network_socket *sock) {
	network_connection_pool_entry *entry;
	GTimeVal now_tv;
	GQueue *conns = NULL;

	entry = network_connection_pool_entry_new();
	entry->sock = sock;
	entry->pool = pool;
	g_get_current_time(&now_tv);
	entry->added_ts = now_tv;
	entry->last_connect = now_tv;
	
#ifdef DEBUG_CONN_POOL
	g_debug("%s: (add) adding socket to pool for user '%s' -> %p fd=%d", G_STRLOC, sock->response->username->str, sock, sock->fd);
#endif

	g_mutex_lock(&(pool->connection_pool_mutex));
	if (NULL == (conns = g_hash_table_lookup(pool->users, sock->response->username))) {
		conns = g_queue_new();

		g_hash_table_insert(pool->users, g_string_dup(sock->response->username), conns);
	}

//	if (pos != NC_POOL_ADD_PREPEND) {
//		g_queue_push_tail(conns, entry);
//	} else {
		g_queue_push_head(conns, entry);
//	}
	g_mutex_unlock(&(pool->connection_pool_mutex));

	return entry;
}

/**
 * @author sohu-inc.com
 * 向连接池队列头部添加一个连接实体，更新（或不更新）添加时间
 */
gboolean network_connection_pool_add_entry (network_connection_pool *pool, network_connection_pool_entry * entry, gboolean update_add_ts) {
	GQueue *conns = NULL;
	network_socket *sock = NULL;

	g_assert(entry);
	g_assert(entry->pool);
	g_assert(entry->sock);
	g_assert(entry->pool == pool);
	
	sock = entry->sock;

	if (update_add_ts == TRUE) {
		g_get_current_time(&(entry->added_ts));
	}
	
#ifdef DEBUG_CONN_POOL
	g_debug("%s: (add) adding socket to pool for user '%s' -> %p fd=%d", G_STRLOC, sock->response->username->str, sock, sock->fd);
#endif
	if(NULL == (conns = g_hash_table_lookup(pool->users, sock->response->username))) {
		conns = g_queue_new();
		g_hash_table_insert(pool->users, g_string_dup(sock->response->username), conns);
	}
	
	g_queue_push_tail(conns, entry);

	return TRUE;
}



/**
 * remove the connection referenced by entry from the pool 
 */
void network_connection_pool_remove(network_connection_pool *pool, network_connection_pool_entry *entry) {
	network_socket *sock = entry->sock;
	GQueue *conns;

	g_mutex_lock(&(pool->connection_pool_mutex));
	if (NULL == (conns = g_hash_table_lookup(pool->users, sock->response->username))) {
		g_mutex_unlock(&(pool->connection_pool_mutex));
		return;
	}

	network_connection_pool_entry_free(entry, TRUE);

	g_queue_remove(conns, entry);
	g_mutex_unlock(&(pool->connection_pool_mutex));
	return;
}



/**
 * 下面实现了一些简单的连接池统计的操作函数,主要是在连接池建立时作为需要建立连接数的修改，以及连接释放时更新的对象
 *
 */
pool_status * get_conn_pool_status(network_connection_pool *pool,
		const gchar *username) {
	pool_status *ps = NULL;
	g_assert(pool);
	g_assert(username);
	g_rw_lock_reader_lock(&pool->pool_status_lock);
	if (pool->conn_pool_status) {
		ps = g_hash_table_lookup(pool->conn_pool_status, username);
	}
	g_rw_lock_reader_unlock(&pool->pool_status_lock);
	return ps;
}

/**
 * @author sohu-inc.com
 * 向连接池统计hashtable中插入一个新的记录
 *
 */
void insert_conn_pool_status(network_connection_pool *pool, gchar *username, pool_status *value) {
	g_assert(pool);
	g_assert(username);
	g_assert(value);
	
	gchar *key = g_strdup(username);
	g_rw_lock_writer_lock (&pool->pool_status_lock);
	g_hash_table_insert(pool->conn_pool_status, key, value);
	g_rw_lock_writer_unlock (&pool->pool_status_lock);
}

/**
 * 更新连接池统计信息
 */
void update_conn_pool_status_in_state(network_connection_pool *pool,
		const gchar *username, pool_status_state state) {
	pool_status *pool_st = NULL;

	g_assert(pool);
	g_assert(username);

	g_rw_lock_reader_lock(&(pool->pool_status_lock));
	pool_st = g_hash_table_lookup(pool->conn_pool_status, username);
	if (pool_st == NULL ) {
		g_rw_lock_reader_unlock(&(pool->pool_status_lock));

		/** @note 后端连接初始化后的特殊处理，可能需要新建一个统计信息 */
		if (state == POOL_STATUS_STATE_INITIALIZED) {
			g_rw_lock_writer_lock(&(pool->pool_status_lock));
			pool_st = g_hash_table_lookup(pool->conn_pool_status, username);
			if (pool_st == NULL ) {
				gchar *user = NULL;
				pool_st = pool_status_new();
				if (pool_st == NULL ) {
					g_error("[%s]: create pool status for user failed, %s",
							G_STRLOC, username);
					g_rw_lock_writer_unlock(&(pool->pool_status_lock));
					return;
				}
				user = g_strdup(username);
				g_hash_table_insert(pool->conn_pool_status, user, pool_st);
			}
			g_mutex_lock(&pool_st->status_mutex);

			pool_st->conn_num_in_pending++;

			g_mutex_unlock(&pool_st->status_mutex);
			g_rw_lock_writer_unlock(&(pool->pool_status_lock));
		}

		return;
	}
	g_mutex_lock(&pool_st->status_mutex);

	switch (state) {
	/** 后端连接初始化 */
	case POOL_STATUS_STATE_INITIALIZED:
		pool_st->conn_num_in_pending++;
		break;
		/** 连接放入连接池(后端连接初始化成功) */
	case POOL_STATUS_STATE_PUT_INTO_POOL:
		pool_st->conn_num_in_idle++;
		/**@note Fall through*/
		/** 连接没建立(后端连接初始化失败) */
	case POOL_STATUS_STATE_NOT_CONNECTED:
		if (pool_st->conn_num_in_pending > 0) {
			pool_st->conn_num_in_pending--;
		}
		break;
		/** 从连接池取出连接 */
	case POOL_STATUS_STATE_GET_FROM_POOL:
		if (pool_st->conn_num_in_idle > 0) {
			pool_st->conn_num_in_idle--;
		}
		pool_st->conn_num_in_use++;
		break;
		/** 连接归还连接池(正常) */
	case POOL_STATUS_STATE_RETURN_TO_POOL:
		pool_st->conn_num_in_idle++;
		/**@note Fall through*/
		/** 连接断开(异常) */
	case POOL_STATUS_STATE_DISCONNECTED:
		if (pool_st->conn_num_in_use > 0) {
			pool_st->conn_num_in_use--;
		}
		break;
	case POOL_STATUS_STATE_REMOVE_FROM_POOL:
		pool_st->conn_num_in_idle--;
		break;
	default:
		g_assert_not_reached()
		;
		break;
	}

	g_mutex_unlock(&pool_st->status_mutex);
	g_rw_lock_reader_unlock(&(pool->pool_status_lock));
	return;
}


gint get_conn_sum_count(network_connection_pool *pool, const gchar *username) {
	pool_status *pool_st = NULL;
	gint ret = 0;

	g_assert(pool);
	g_assert(username);

	g_rw_lock_reader_lock(&(pool->pool_status_lock));
	if (pool->conn_pool_status != NULL ) {
		pool_st = g_hash_table_lookup(pool->conn_pool_status, username);
		if (pool_st == NULL ) {
			ret = 0;
		} else {
			/**@fixme 需要算上未决的(pending)吗？*/
			ret = pool_st->conn_num_in_pending + pool_st->conn_num_in_idle
					+ pool_st->conn_num_in_use;
		}
	}
	g_rw_lock_reader_unlock(&(pool->pool_status_lock));

	return ret;
}

gint get_conn_using_pending_count(network_connection_pool *pool,
		const gchar *username) {
	pool_status *pool_st = NULL;
	gint ret = 0;

	g_assert(pool);
	g_assert(username);

	g_rw_lock_reader_lock(&(pool->pool_status_lock));
	if (pool->conn_pool_status != NULL ) {
		pool_st = g_hash_table_lookup(pool->conn_pool_status, username);
		if (pool_st == NULL ) {
			ret = 0;
		} else {
			ret = pool_st->conn_num_in_pending + pool_st->conn_num_in_use;
		}
	}
	g_rw_lock_reader_unlock(&(pool->pool_status_lock));

	return ret;
}

gint get_conn_pending_count(network_connection_pool *pool, const gchar *username) {
	pool_status *pool_st = NULL;
	gint ret = 0;

	g_assert(pool);
	g_assert(username);

	g_rw_lock_reader_lock(&pool->pool_status_lock);
	if(pool->conn_pool_status) {
		pool_st = g_hash_table_lookup(pool->conn_pool_status, username);
		if (pool_st) {
			g_mutex_lock(&pool_st->status_mutex);
			ret = pool_st->conn_num_in_pending;
			g_mutex_unlock(&pool_st->status_mutex);
		}
	}
	g_rw_lock_reader_unlock(&pool->pool_status_lock);

	return ret;
}

gint get_conn_using_count(network_connection_pool *pool, const gchar *username) {
	pool_status *pool_st = NULL;
	gint ret = 0;

	g_assert(pool);
	g_assert(username);

	g_rw_lock_reader_lock(&pool->pool_status_lock);
	if (pool->conn_pool_status) {
		pool_st = g_hash_table_lookup(pool->conn_pool_status, username);
		if (pool_st) {
			g_mutex_lock(&pool_st->status_mutex);
			ret = pool_st->conn_num_in_use;
			g_mutex_unlock(&pool_st->status_mutex);
		}
	}
	g_rw_lock_reader_unlock(&pool->pool_status_lock);

	return ret;
}

// 获取到对应用户的空闲的连接数，比较准确的是直接获取连接池的长度，但是我们主要还是要一个比较一致的
// 在用的连接数、pending的连接数及空闲的连接数。从这一方面来讲从pool_status中获取比较好,
// 但是单独获取空闲连接书还是从空闲列表比较好。
gint get_conn_idle_count(network_connection_pool *pool, const gchar *username) {
	g_assert(pool);
	g_assert(username);

	GString *key = g_string_new(username);
	gint ret = 0;

	g_mutex_lock(&(pool->connection_pool_mutex)); /**@todo 改成读写锁?*/
	if (pool->users) {
		GQueue *user_pool = g_hash_table_lookup(pool->users, key);
		if (user_pool) {
			ret = user_pool->length;
		}
	}
	g_mutex_unlock(&(pool->connection_pool_mutex));

	if (key) {
		g_string_free(key, TRUE);
	}
	return ret;
}

