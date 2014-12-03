/* $%BEGINLICENSE%$
 Copyright (c) 2013, Sohu and/or its affiliates. All rights reserved.

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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>

#include "network-mysqld-async-con.h"
#include "network-connection-scaler.h"
#include "chassis-mainloop.h"
#include "chassis-event-thread.h"

/**
 * 创建连接管理器线程数据结构(不起线程)
 */
connection_scaler_thread_t *connection_scaler_thread_new(void) {
	connection_scaler_thread_t *connection_scaler_thread;
	connection_scaler_thread = g_new0(connection_scaler_thread_t, 1);
	return connection_scaler_thread;
}


/**
 * 销毁连接管理器线程
 */
void connection_scaler_thread_free(
		connection_scaler_thread_t *connection_scaler_thread) {
	gboolean is_thread = FALSE;

	if (!connection_scaler_thread)
		return;

	is_thread = (connection_scaler_thread->thr != NULL);

	g_debug("join connection scaler thread");
	if (connection_scaler_thread->thr)
		g_thread_join(connection_scaler_thread->thr);

	g_debug("free connection scaler event base");
	if (is_thread && connection_scaler_thread->event_base)
		event_base_free(connection_scaler_thread->event_base);

	/* free the events that are still in the queue */
	//while ((op = g_async_queue_try_pop(threads->event_queue))) {
	//	chassis_event_op_free(op);
	//}
	g_async_queue_unref(connection_scaler_thread->event_queue);

	g_free(connection_scaler_thread);

	return;
}


/**
 * 初始化连接管理器线程
 * 初始化事件base，队列等
 */
void connection_scaler_thread_init_thread(
		connection_scaler_thread_t *connection_scaler_thread, chassis *chas) {
	connection_scaler_thread->event_base = event_base_new();
	connection_scaler_thread->event_queue = g_async_queue_new();
	connection_scaler_thread->chas = chas;
	return;
}


/**
 * 启动连接管理器线程
 */
void connection_scaler_thread_start(
		connection_scaler_thread_t *connection_scaler_thread) {
	GError *gerr = NULL;
	g_message("%s: starting a connection scaler thread", G_STRLOC);
	connection_scaler_thread->thr = g_thread_try_new("connection scaler",
			(GThreadFunc) connection_scaler_thread_loop,
			connection_scaler_thread, &gerr);
	if (gerr) {
		g_critical("%s: %s", G_STRLOC, gerr->message);
		g_error_free(gerr);
		gerr = NULL;
	}
	return;
}




typedef enum {
	NC_CHK_USER_POOL_ENTRY_VERY_GOOD = 0,
	NC_CHK_USER_POOL_ENTRY_TO_GC = 1,
	NC_CHK_USER_POOL_ENTRY_MAX_CHECKED = 2,
	NC_CHK_USER_POOL_ENTRY_BREAK_LOOP = 3,
	NC_CHK_USER_POOL_ENTRY_NO_SUCH_USER = 4,
} nc_chk_user_pool_next_do_t;


static guint network_connection_scaler_check_user_pool_status(chassis *chas,
		network_backend_t *backend, proxy_rw type,
		network_connection_pool *pool, const GString *username,
		user_pool_config *user_pool_conf,
		connection_scaler_pool_statistics *pool_stats) {
	guint pool_conn_current_sum = 0;
	GQueue *conns = NULL;
	network_connection_pool_entry *entry = NULL;
	GTimeVal now_tv;
	guint removed = 0;
	guint queue_length = 0;
	guint nth = 0;
	nc_chk_user_pool_next_do_t nextdo = NC_CHK_USER_POOL_ENTRY_BREAK_LOOP;

	g_assert(chas);
	g_assert(backend);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);
	g_assert(pool);
	g_assert(username);
	g_assert(user_pool_conf);
	g_assert(pool_stats);
	g_assert(backend->pool[type] == pool);

	g_get_current_time(&now_tv);

	for (;;) {

		do {
			/**取用户连接池*/
			g_mutex_lock(&(pool->connection_pool_mutex));
			conns = network_connection_pool_get_conns(pool, username, NULL );
			if (conns == NULL ) {
				pool_stats->conn_nopool++;
				nextdo = NC_CHK_USER_POOL_ENTRY_BREAK_LOOP;
				break;
			}
			queue_length = g_queue_get_length(conns);
			pool_stats->conn_length = queue_length;

			/**删除空的用户连接池*/
			if (queue_length == 0) {
				pool_stats->conn_zerosize++;
				g_hash_table_remove(pool->users, username);
				nextdo = NC_CHK_USER_POOL_ENTRY_BREAK_LOOP;
				break;
			}

			if (queue_length <= pool_stats->conn_good) {
				nextdo = NC_CHK_USER_POOL_ENTRY_BREAK_LOOP;
				break;
			}

			/**取用户连接池当前连接数，包括未决、空闲和已用的(其中空闲数量应该约等于连接池长度)*/
			pool_conn_current_sum = get_conn_sum_count(pool, username->str);

			/**从队列尾部（需要跳过检查正常的放回的连接）取出一个连接*/
			nth = queue_length - 1 - pool_stats->conn_good;
			entry = g_queue_pop_nth(conns, nth);
			if (entry == NULL) {
				nextdo = NC_CHK_USER_POOL_ENTRY_BREAK_LOOP;
				break;
			}

			pool_stats->conn_checked++;
			update_conn_pool_status_in_state(pool, username->str,
					POOL_STATUS_STATE_REMOVE_FROM_POOL);
			g_mutex_unlock(&(pool->connection_pool_mutex));

			/** 每次最多检查N个连接，防止长时间消耗CPU */
	#define MAX_POOL_ENTRIES_COUNT_FOR_CHECK 100
			if (pool_stats->conn_checked > MAX_POOL_ENTRIES_COUNT_FOR_CHECK) {
				nextdo = NC_CHK_USER_POOL_ENTRY_MAX_CHECKED;
				break;
			}

			/**检查用户是否存在，若不存在，则要删除其连接(池)(一次删一个连接，直到删完)*/
			if (check_user_existence(chas, username) == FALSE) {
				pool_stats->conn_nouser++;
				nextdo = NC_CHK_USER_POOL_ENTRY_NO_SUCH_USER;
				break;
			}

			/* == 检查是否超过最大连接数 == */
			/**
			 * 是否[连接池当前连接]大于[最大连接数]
			 * pool_conn_current_sum不准？
			 */
			else if (pool_conn_current_sum > user_pool_conf->max_connections) {
				pool_stats->conn_toomany++;
				nextdo = NC_CHK_USER_POOL_ENTRY_TO_GC;
				break;
			}

			/* == 检查是否超时 == */
			/**是否超时*/
			else if (check_pool_entry_timeout(entry, &now_tv,
					user_pool_conf->max_idle_interval) == TRUE) {
				pool_stats->conn_timeout++;
				nextdo = NC_CHK_USER_POOL_ENTRY_TO_GC;
				break;
			}

			/* == 检查连通性是否正常 == */
			/**是否断开*/
			else if (check_pool_entry_connectivity(entry) == FALSE) {
				pool_stats->conn_disconnected++;
				nextdo = NC_CHK_USER_POOL_ENTRY_TO_GC;
				break;
			}

			/* == 检查结束 == */
			else {
				pool_stats->conn_good++;
				nextdo = NC_CHK_USER_POOL_ENTRY_VERY_GOOD;
				break;
			}
		} while (0);

		if (nextdo == NC_CHK_USER_POOL_ENTRY_BREAK_LOOP) {
			g_mutex_unlock(&(pool->connection_pool_mutex));
			break;
		} else if (nextdo == NC_CHK_USER_POOL_ENTRY_TO_GC) {
			garbage_connection_pool_add_entry(pool->garbage_connection_pool,
					entry);
		} else if (nextdo == NC_CHK_USER_POOL_ENTRY_MAX_CHECKED
				|| nextdo == NC_CHK_USER_POOL_ENTRY_VERY_GOOD) {
			g_mutex_lock(&(pool->connection_pool_mutex));
			/**放回连接池队列尾部，不更新添加时间戳*/
			network_connection_pool_add_entry(pool, entry, FALSE);
			update_conn_pool_status_in_state(pool, username->str,
					POOL_STATUS_STATE_PUT_INTO_POOL);
			g_mutex_unlock(&(pool->connection_pool_mutex));
			if (nextdo == NC_CHK_USER_POOL_ENTRY_MAX_CHECKED) {
				break;
			}
		} else if (nextdo == NC_CHK_USER_POOL_ENTRY_NO_SUCH_USER) {
			garbage_connection_pool_add_entry(pool->garbage_connection_pool,
					entry);
		}

	} /*end of for(;;)*/

	removed += pool_stats->conn_timeout + pool_stats->conn_disconnected + pool_stats->conn_toomany;

	return removed;
}

/**
 * 检查一个连接池连接的状态
 * 调用network_connection_scaler_check_user_pool_status
 * @return guint 移动到垃圾回收池的连接数
 */
static guint network_connection_scaler_check_users_pool_status(chassis *chas,
		network_backend_t *backend, proxy_rw type,
		network_connection_pool *pool) {
	GQueue *users = NULL;
	GString *username = NULL;
	user_pool_config user_pool_conf = {0, 0, 0};
	connection_scaler_pool_statistics pool_stats = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	guint removed = 0;

	g_assert(chas);
	g_assert(backend);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);
	g_assert(pool);
	g_assert(backend->pool[type] == pool);

	/** @note
	 * 连接池用户名缓存到一个队列里，为了避免长时间持有连接池锁?
	 */
	users = pool_users_name_queue_new(pool);
	if (users == NULL) {
		return 0;
	}

	while ((username = g_queue_pop_head(users)) != NULL ) {
		/**取用户连接池配置*/
		get_pool_config_for_user_copy(chas, username, type, &user_pool_conf);

		/**初始化统计信息*/
		network_connection_scaler_pool_statictics_init(&pool_stats);

		removed += network_connection_scaler_check_user_pool_status(chas, backend, type, pool,
				username, &user_pool_conf, &pool_stats);

		if (pool_stats.conn_length > 0) {
			if (!(pool_stats.conn_checked == 1 && pool_stats.conn_again == 1)) {
				network_connection_scaler_pool_statictics_print(&pool_stats, username->str);
			}
		}

		g_string_free(username, TRUE);
	}

	pool_users_name_queue_free(users);

	return removed;
}

/**
 * 检查所有连接池连接的状态
 * 遍历所有后端，调用network_connection_scaler_check_users_pool_status
 */
static void network_connection_scaler_check_backends_pool_status(
		connection_scaler_thread_t *thread) {
	chassis *chas = NULL;
	network_backends_t *backends = NULL;
	guint index = 0;
	network_backend_t *backend = NULL;
	proxy_rw type;
	network_connection_pool *pool = NULL;
	guint removed = 0;

	g_assert(thread);
	g_assert(thread->chas);
	g_assert(thread->chas->priv);
	g_assert(thread->chas->priv->backends);

	chas = thread->chas;
	backends = chas->priv->backends;

	for (index = 0; index < network_backends_count(backends); index++) {
		backend = network_backends_get(backends, index);
		if (backend == NULL ) {
			g_debug("[%s]: we have get all the backends ", G_STRLOC);
			break;
		}

		for (type = PROXY_TYPE_WRITE; type <= PROXY_TYPE_READ; type =
				(proxy_rw) (type + 1)) {
			pool = backend->pool[type];

			removed = network_connection_scaler_check_users_pool_status(chas, backend, type, pool);

			if (removed > 0) {
				g_debug(
						"[%s]: end of checking pool status for backend %s[%s], removed: %d",
						G_STRLOC, backend->addr->name->str,
						(type == PROXY_TYPE_WRITE) ? "RW" : "RO", removed);
			}
		}
	}

	return;
}





/**
 * 清理所有垃圾回收连接池
 */
static void network_connection_scaler_clean_up_backends_gc_pool(
		connection_scaler_thread_t *thread) {
	chassis *chas = NULL;
	network_backends_t *backends = NULL;
	guint index = 0;
	network_backend_t *backend = NULL;
	proxy_rw type;
	network_connection_pool *pool = NULL;
	network_garbage_connection_pool *gc_pool = NULL;
	guint removed = 0;
#define GC_POOL_GRACE_SECONDS (0) /**< 垃圾回收池里的连接的保留时间。0表示不保留 */

	g_assert(thread);
	g_assert(thread->chas);
	g_assert(thread->chas->priv);
	g_assert(thread->chas->priv->backends);

	chas = thread->chas;
	backends = chas->priv->backends;

	for (index = 0; index < network_backends_count(backends); index++) {
		backend = network_backends_get(backends, index);
		if (backend == NULL ) {
			g_debug("[%s]: we have get all the backends ", G_STRLOC);
			break;
		}

		for (type = PROXY_TYPE_WRITE; type <= PROXY_TYPE_READ; type =
				(proxy_rw) (type + 1)) {

			pool = backend->pool[type];
			gc_pool = pool->garbage_connection_pool;

			/*清空队列*/
			removed = garbage_connection_pool_clean_old_entries(gc_pool,
					GC_POOL_GRACE_SECONDS);

			if (removed > 0) {
				g_debug(
						"[%s]: end of cleaning up gc pool for backend %s[%s], removed: %d",
						G_STRLOC, backend->addr->name->str,
						(type == PROXY_TYPE_WRITE) ? "RW" : "RO", removed);
			}
		}
	}

	return;
}





/**
 * 为指定用户在指定后端的指定类型的连接池里建最小连接
 * @return guint 新建连接数（新发起的创建连接的数量，但不一定都能建成功）
 */
static guint create_min_connections_on_backend_for_user(chassis *chas,
		network_backend_t *backend, const GString *username, proxy_rw type) {
	network_connection_pool *pool = NULL;
	gint pool_conn_current_sum = 0;
	guint min_connections = 0;
	gint to_create = 0;
	gint i = 0;

	g_assert(chas);
	g_assert(backend);
	g_assert(username);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);

	pool = backend->pool[type];
	g_assert(pool);

	/**取用户连接池统计信息，计算当前连接数总数，包括空闲和已用的，还有未决的？*/
	pool_conn_current_sum = get_conn_sum_count(pool, username->str);

	/**取用户连接池配置*/
	min_connections = get_pool_config_min_connections_for_user(chas, username, type);

	g_debug("[%s]: creating connections on %s[%s] for %s, cur=%d, min=%d, ",
			G_STRLOC, backend->addr->name->str,
			(type == PROXY_TYPE_WRITE) ? "RW" : "RO", username->str,
			pool_conn_current_sum, min_connections);
	/**
	 * 新建(最小连接数-当前连接数)个连接
	 * min_connections不仅指空闲的连接，还包括已用的，另外现在还算上了未决的
	 * 这里没用后端连接池里保存的配置信息pool->min_idle_connections
	 */
	to_create =
			((min_connections - pool_conn_current_sum) > 0) ?
					(min_connections - pool_conn_current_sum) : 0;
	if (to_create > 0) {
		g_debug(
				"[%s]: %d new connections will be created on backend %s [%s] for user %s",
				G_STRLOC, to_create, backend->addr->name->str,
				(type == PROXY_TYPE_WRITE) ? "RW" : "RO", username->str);
		for (i = 0; i < to_create; i++) {
			/*更新连接池统计信息*/
			update_conn_pool_status_in_state(pool, username->str,
					POOL_STATUS_STATE_INITIALIZED);
			/*新建连接*/
			create_connection_on_backend_for_user(chas, backend, username->str,
					type);
		}
	}

	return i;
}

/**
 * 为指定用户在所有后端的所有类型的连接池里建最小连接
 * 添加一个用户时可使用此函数
 */
static guint create_min_connections_on_all_backends_for_user(chassis *chas, const GString *username) {
	network_backends_t *backends = NULL;
	guint i = 0;
	network_backend_t *backend = NULL;
	proxy_rw type;
	guint created = 0;
	guint created_sum = 0;

	g_assert(chas);
	g_assert(username);
	g_assert(chas->priv);
	g_assert(chas->priv->backends);

	backends = chas->priv->backends;
	for (i = 0; i < network_backends_count(backends); i++) {
		backend = network_backends_get(backends, i);
		if (backend == NULL ) {
			g_warning("[%s]: backend not found, %d", G_STRLOC, i);
			break;
		}
		g_debug("[%s]: initialize connection pool for backend, %s", G_STRLOC,
				backend->addr->name->str);

		if (backend->state != BACKEND_STATE_UP) {
			g_warning("[%s]: backend state is not up, %s, %d", G_STRLOC,
					backend->addr->name->str, backend->state);
			continue;
		}

		for (type = PROXY_TYPE_WRITE; type <= PROXY_TYPE_READ; type = (proxy_rw)(type+1)) {
			created = create_min_connections_on_backend_for_user(chas, backend, username, type);
			if (created > 0) {
				g_message(
						"[%s]: created %d connections on backend %s [%s] for user %s",
						G_STRLOC, created, backend->addr->name->str,
						(type == PROXY_TYPE_WRITE) ? "RW" : "RO",
						username->str);
			}
			created_sum += created;
		}
	}

	return created_sum;
}

/**
 * 按用户最小连接数初始化连接池
 * 前提条件：只有后端状态是UP的才会建连接池
 */
void connection_pool_init(chassis *chas) {
	GQueue *users = NULL;
	GString *username = NULL;
	guint created = 0;
	guint created_sum = 0;

	g_assert(chas);
	g_assert(chas->priv);

//	g_message("initializing connection pool.");

	users = user_infos_name_queue_new(chas);
	if (users == NULL) {
		return;
	}

	while ((username = g_queue_pop_head(users)) != NULL ) {
		g_debug("[%s]: initialize connection pool for user, %s", G_STRLOC,
				username->str);
		created = create_min_connections_on_all_backends_for_user(chas,
				username);
		if (created > 0) {
			g_debug("[%s]: created %d connections for user, %s", G_STRLOC,
					created, username->str);
		}
		created_sum += created;

		g_string_free(username, TRUE);
	}
	//g_debug("[%s]: created %d connections total", G_STRLOC, created_sum);

	g_queue_free(users);
	return;
}



static void update_global_connection_state(chassis *chas) {
	guint i = 0;
	chassis_event_threads_t *threads = NULL;
	g_assert(chas);
	if (chas->threads == NULL) {
		return;
	}
	if (chas->threads->event_threads == NULL) {
		return;
	}
	threads = chas->threads;
	for (i = 0; i < threads->event_threads->len && !chassis_is_shutdown(); i++) {
		chassis_event_thread_t *event_thread = threads->event_threads->pdata[i];
		global_connection_state_set_update(chas->connection_state, event_thread->connection_state);
	}
	return;
}



/**
 * 连接池管理线程主循环
 *
 */
void *connection_scaler_thread_loop(
		connection_scaler_thread_t *connection_scaler_thread) {
	/*connection_scaler_thread_set_event_base(event_thread, event_thread->event_base);*/

	while (!chassis_is_shutdown()) {
		GTimeVal begin_time;
		GTimeVal end_time;
#define CONNECTION_SCALER_THREAD_SLEEP_SECONDS 10
		guint sleep_seconds = CONNECTION_SCALER_THREAD_SLEEP_SECONDS;

		g_get_current_time(&begin_time);

		/* Do something */
		/* @todo 以后可以改成多线程处理? */
		/*检查连接池连接是否超时，是否可连，保留可用连接，将不可用连接放入垃圾回收池*/
		network_connection_scaler_check_backends_pool_status(connection_scaler_thread);

		/*建立最小连接数*/
		if (!chassis_is_shutdown()) {
			connection_pool_init(connection_scaler_thread->chas);
		}

		/*清理垃圾回收连接池*/
		network_connection_scaler_clean_up_backends_gc_pool(connection_scaler_thread);

		/**/
		update_global_connection_state(connection_scaler_thread->chas);

		g_get_current_time(&end_time);

		/* Sleep */
		//g_message("going to sleep for %d seconds", sleep_seconds);
		while ((begin_time.tv_sec + sleep_seconds > end_time.tv_sec)
				&& !chassis_is_shutdown()) {
			struct timeval timeout;
			int rr;
			timeout.tv_sec = 1;
			timeout.tv_usec = 0;
			g_assert(
					event_base_loopexit(connection_scaler_thread->event_base,
							&timeout) == 0);
			rr = event_base_dispatch(connection_scaler_thread->event_base);
			if (rr == -1) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if (errno == EINTR)
					continue;
				g_critical(
						"%s: leaving connection_scaler_thread_loop sleep early, errno != EINTR was: %s (%d)",
						G_STRLOC, g_strerror(errno), errno);
				break;
			}
			g_get_current_time(&end_time);
			/*g_debug("begin_time: %d, end_time: %d", begin_time.tv_sec, end_time.tv_sec);*/
		}
	} /* end of while() */

	g_message("connection scaler thread is shutdown");
	return NULL;
} /* end of connection_scaler_thread_loop() */





/*eof*/
