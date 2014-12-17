/*
 * network-backend-status-updater.c
 *
 *  Created on: 2013-6-30
 *      Author: jinxuanhou
 */

#include "network-backend-status-updater.h"
#include "network-mysqld.h"

/**
 * @author sohu-inc.com
 * 从现在已有的处于up状态的backend中选取一个主库，
 * 采用ip:port 最小的策略
 * 如果已经有一个主库了，选主结束，返回NULL
 * @param backends
 * @return
 */
network_backend_t * master_elect_with_minimum_ip(network_backends_t *backends) {

	if (!backends && backends->backends->len <= 0)
		return NULL;
	network_backend_t *tmp = NULL;
	network_backend_t *tmp_master = NULL;
	guint index = 0;
	g_mutex_lock(backends->backends_mutex);
	for (index = 0; index < backends->backends->len; index++) {
		tmp = backends->backends->pdata[index];
		if (tmp && (BACKEND_STATE_UP == tmp->state) && (BACKEND_TYPE_RO == tmp->type)) {
			if (!tmp_master) {
				tmp_master = tmp;
			} else {
				if (0 < g_strcmp0(tmp_master->addr->name->str, tmp->addr->name->str)) {
					tmp_master = tmp;
				}
			}
		} else if (tmp && (BACKEND_STATE_UP == tmp->state) && (BACKEND_TYPE_RW == tmp->type)) {
			// 如果已经有主库，则停止选主动作。直接退出返回NULL
			tmp_master = NULL;
			break;
		}
	}
	g_mutex_unlock(backends->backends_mutex);
	return tmp_master;
}

/**
 * 按优先级选举主库
 */
network_backend_t *master_elect_with_priority(network_backends_t *backends) {
	guint index = 0;
	network_backend_t *backend = NULL;
	network_backend_t *master = NULL;

	if (!backends && backends->backends->len <= 0) {
		return NULL;
	}

	g_mutex_lock(backends->backends_mutex);
	for (index = 0; index < backends->backends->len; index++) {
		backend = backends->backends->pdata[index];
		if (backend && (BACKEND_STATE_UP == backend->state) && (BACKEND_TYPE_RO == backend->type) && backend->connect_w[PROXY_TYPE_WRITE] > 0) {
			if (!master) {
				master = backend;
			} else {
				if (master->connect_w[PROXY_TYPE_WRITE] < backend->connect_w[PROXY_TYPE_WRITE]) {
					master = backend;
				}
			}
		}
	}
	g_mutex_unlock(backends->backends_mutex);
	return master;
}

/**
 * @author sohu-inc.com
 * 将对应的backend的状态由from 设置为to
 * @note 实现时需要注意：
 * 		1.backend在backend列表中；
 * 		2.且当前的状态时from
 * @param backend
 * @param from
 * @param to
 */
void update_backend_status(
		network_backend_t *backend,
		backend_state_t from,
		backend_state_t to) {
	// backend指针同一性检查放在外层函数进行
	if (!backend)
		return;

	if (from == to)
		return;

	g_assert(backend->state == from);

	backend->state = to;

	if (backend->state == BACKEND_STATE_UNKNOWN) {
		// 如果转换成UNKNOWN，则将状态标志设置为rise
		backend->health_check.health = backend->health_check.rise;
	}

	// 如果是主库将backend的type设置为只读
	/*if (BACKEND_TYPE_RW == backend->type) {
		backend->type = BACKEND_TYPE_RO;
	}*/
}

/**
 * @author sohu-inc.com
 * 将backend上面的空闲连接释放
 * @param backend 状态失效的backend指针
 */
void close_connection_in_pool_for_backend(
		network_backend_t *backend) {
	if (!backend)
		return;

	if (backend->pool[PROXY_TYPE_WRITE]) {
		// 只是将里面的连接全部释放
		g_hash_table_foreach_remove(
				backend->pool[PROXY_TYPE_WRITE]->users,
				g_hash_table_true,
				NULL);
	}

	if (backend->pool[PROXY_TYPE_READ]) {
		// 只是将里面的连接全部释放
		g_hash_table_foreach_remove(
				backend->pool[PROXY_TYPE_READ]->users,
				g_hash_table_true,
				NULL);
	}
}

/**
 * @author sohu-inc.com
 * 将backend上面在用的连接释放
 * @param chas
 * @param backend
 */
void close_connection_in_use_for_backend(
		chassis *chas,
		network_backend_t *backend) {
	g_assert(chas);
	g_assert(chas->priv);
	if (!chas->priv->cons)
		return;

	if (!backend)
		return;

	g_assert(backend->addr->name);
	GString *name_tmp = g_string_new(backend->addr->name->str);

	guint index = 0;
	network_mysqld_con *tmp = NULL;
	GString *bk_tmp = g_string_new(NULL);
	g_mutex_lock(&chas->priv->cons_mutex);
	for (index = 0; index < chas->priv->cons->len; index++) {
		g_string_truncate(bk_tmp, 0);
		tmp = chas->priv->cons->pdata[index];
		if (tmp && tmp->client) {
			g_mutex_lock(&tmp->server_mutex);
			if (tmp->server && tmp->server->dst) {
				g_string_append(bk_tmp, tmp->server->dst->name->str);
				g_mutex_unlock(&tmp->server_mutex);
			} else {
				g_mutex_unlock(&tmp->server_mutex);
				g_mutex_lock(&tmp->cache_server_mutex  );
				if (tmp->cache_server && tmp->cache_server->dst) {
					g_string_append(bk_tmp, tmp->cache_server->dst->name->str);
					g_mutex_unlock(&tmp->cache_server_mutex);
				} else {
					g_mutex_unlock(&tmp->cache_server_mutex);
				}
			}

			// 连接是在状态机中,将对应的连接的状态设置为关闭
			if (bk_tmp->len > 0) {
				if (0 == g_ascii_strcasecmp(name_tmp->str, bk_tmp->str)) {
					mysqld_con_set_shutdown_location(tmp, G_STRLOC);
				}
			}
		}
		tmp = NULL;
	}
	g_mutex_unlock(&chas->priv->cons_mutex);

	g_string_free(name_tmp, TRUE);
	g_string_free(bk_tmp, TRUE);
}

/**
 * @author sohu-inc.com
 * 将backend上面的连接释放，包括空闲连接和在用的连接
 * @param chas
 * @param backend
 */
void close_connection_for_backend(
		chassis *chas,
		network_backend_t *backend) {
	g_assert(chas);
	if (!backend)
		return;
	close_connection_in_use_for_backend(chas, backend);
	//close_connection_in_pool_for_backend(chas, backend); //将连接池中的连接释放，可以不做
}

/**
 * @author sohu-inc.com
 * 创建一个worker线程
 * @return
 */
backend_status_update_worker *backend_status_update_worker_new() {
	backend_status_update_worker *worker;
	worker = g_new0(backend_status_update_worker, 1);
	return worker;
}

/**
 * @author sohu-inc.com
 * 释放worker变量,注意不需要释放backend,chas
 * @param worker
 */
void backend_status_update_worker_free(
		backend_status_update_worker *worker) {
	if (!worker)
		return;

	if (worker->thr) {
		g_debug("[%s]: will join status update worker.", G_STRLOC);
		g_thread_join(worker->thr);
		worker->thr = NULL;
	}

	if (worker->chas) {
		// chas 是上层以指针的形式传递下来，
		// 不是worker 自己创建的不需要释放期内存，只需要复制为NULL
		worker->chas = NULL;
	}
	if (worker->backend) {
		// backend 是上层以指针的形式传递下来，不是worker 自己创建的不需要释放期内存，
		// 只需要复制为NULL
		worker->backend = NULL;
	}

	g_free(worker);
}

/**
 * @author sohu-inc.com
 * 启动一个worker 线程
 * @param worker
 */
void backend_status_update_worker_start(
		backend_status_update_worker *worker) {
	if (!worker)
		return;

	GError *gerr = NULL;
	g_message("%s: starting a status update thread", G_STRLOC);
	worker->thr = g_thread_try_new("backend status updater",
			(GThreadFunc) backend_status_update,
			worker, &gerr);
	if (gerr) {
		g_critical("%s: %s", G_STRLOC, gerr->message);
		g_error_free(gerr);
		gerr = NULL;
	}
	return;
}

/**
 * @author sohu-inc.com
 * 完成对work代表的backend的状态的更新
 * @param worker
 */
void backend_status_update(
		backend_status_update_worker *worker) {
	network_backend_t *master = NULL;

	if (!worker)
		return;

	g_assert(worker->chas);
	g_assert(worker->chas->priv);

	if (!worker->backend)
		return;

	if (worker->from == worker->to) {
		g_warning("[%s]: the status is already in status: %s.",
				G_STRLOC,
				(BACKEND_STATE_UP == worker->to)?"UP":"DOWN");
		return;
	}

	g_message("[%s]: going to set status of backend->%s[%s] from %s to %s",
			G_STRLOC,
			worker->backend->addr->name->str,
			(worker->backend->type==BACKEND_TYPE_RW)?"RW":"RO",
			get_backend_state_name(worker->from),
			get_backend_state_name(worker->to));
	switch (worker->to) {
	case BACKEND_STATE_UP:
		//update_backend_status(worker->backend, worker->from, worker->to);
		if (worker->backend->type == BACKEND_TYPE_RW) {
			update_backend_status(worker->backend, worker->from, worker->to);
		} else if (worker->backend->type == BACKEND_TYPE_RO) {
			//接下来检测backend list中是否有主库没有主库，需要将自己设置为主库
			/**
			 * @author sohu-inc.com
			 * 2013-09-05
			 * 同样这里修改比较重要：将up的ro节点提升为主库，设置需要是原子操作。
			 */
			g_mutex_lock(&worker->chas->priv->backends->master_mutex);
			update_backend_status(worker->backend, worker->from, worker->to); // 先做标记再更新状态
			if (worker->chas->priv->backends->has_master != TRUE) {
				master = master_elect_with_priority(worker->chas->priv->backends);
				if (master == NULL) {
					g_critical("[%s]: master elect failed. No master!", G_STRLOC);
				} else {
					g_message("[%s]: master elect done. new master is %s", G_STRLOC, master->addr->name->str);
					worker->chas->priv->backends->has_master = TRUE;
					master->type = BACKEND_TYPE_RW;
				}
			}
			g_mutex_unlock(&worker->chas->priv->backends->master_mutex);
		}
		/*重新计算负载均衡队列(其实没有写负载均衡，其实可以不用计算)*/
		if (BACKEND_TYPE_RW == worker->backend->type || master != NULL) {
			loadbalance_wrr_calc(worker->chas->priv->backends, PROXY_TYPE_WRITE);
		}
		loadbalance_wrr_calc(worker->chas->priv->backends, PROXY_TYPE_READ);
		break;
	case BACKEND_STATE_DOWN:
	case BACKEND_STATE_PENDING:
		/** 数据库状态变为down和变为pending的逻辑是一样的同事处理，避免代码冗余*/
		//update_backend_status(worker->backend, worker->from, worker->to);
		if (worker->backend->type == BACKEND_TYPE_RW) {
			//如果主库down掉，将主库存在标志设置为FALSE

			/**
			 * @author sohu-inc.com
			 * 2013-09-05
			 * 这里更新比较重要，主库状态改为down和设置主库不存在的标志应该是原子操作
			 * 这里做了修正
			 */
			g_mutex_lock(&worker->chas->priv->backends->master_mutex);
			update_backend_status(worker->backend, worker->from, worker->to);
			if (worker->chas->priv->backends->has_master == TRUE) {
				worker->chas->priv->backends->has_master = FALSE; //之前自己是主库，将主库标记设置为FALSE
			}
			worker->backend->type = BACKEND_TYPE_RO; // 自己成为RO节点
			// 若down的是主库，则重新选主
			//master = master_elect_with_minimum_ip(worker->chas->priv->backends);
			master = master_elect_with_priority(worker->chas->priv->backends);
			if (master == NULL) {
				g_critical("[%s]: master elect failed. Maybe there is already a master!", G_STRLOC);
			} else {
				g_message("[%s]: master elect done. new master is %s", G_STRLOC, master->addr->name->str);
				worker->chas->priv->backends->has_master = TRUE;
				master->type = BACKEND_TYPE_RW;
			}
			g_mutex_unlock(&worker->chas->priv->backends->master_mutex);
			loadbalance_wrr_calc(worker->chas->priv->backends, PROXY_TYPE_WRITE);
		} else if (worker->backend->type == BACKEND_TYPE_RO) {
			update_backend_status(worker->backend, worker->from, worker->to);
		}
		/*重新计算负载均衡队列(其实没有写负载均衡，其实可以不用计算)*/
		loadbalance_wrr_calc(worker->chas->priv->backends, PROXY_TYPE_READ);
		close_connection_for_backend(worker->chas, worker->backend);
		break;
	case BACKEND_STATE_UNKNOWN:
		update_backend_status(worker->backend, worker->from, worker->to);
		break;
	default:
		g_critical("[%s]: backend status unknown.", G_STRLOC);
		return;
	}
}

/**
 * 设置指定backend的状态为to
 * @param backends
 * @param ip_port
 * @param to
 * @return
 */
int set_backend_status(chassis *chas, network_backends_t *bs, const gchar *ip_port, backend_state_t to) {
	if (!bs || !ip_port)
		return -1;

	g_assert(chas);
	g_assert(to == BACKEND_STATE_UNKNOWN ||
			to == BACKEND_STATE_PENDING ||
			to == BACKEND_STATE_DOWN ||
			to == BACKEND_STATE_UP);

	network_backend_t *tmp;
	gint index = 0;
	// so big a lock
	g_mutex_lock(bs->backends_mutex);
	gint len = bs->backends->len;
	for (index = 0; index < len; index++) {
		tmp = bs->backends->pdata[index];
		if (0 == g_strcmp0(tmp->addr->name->str, ip_port)) {
			break;
		} else {
			tmp = NULL;
		}
	}
	g_mutex_unlock(bs->backends_mutex);
	if (tmp && tmp->state != to) {
		backend_status_update_worker *worker = backend_status_update_worker_new();
		worker->chas = chas;
		worker->backend = tmp;
		worker->from = tmp->state;
		worker->to = to;
		backend_status_update(worker);
		backend_status_update_worker_free(worker); // 释放内存
	}
	return 0;
}
