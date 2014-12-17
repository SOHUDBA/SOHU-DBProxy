/*
 * network-backend-status-updater.h
 *
 *  Created on: 2013-6-30
 *      Author: jinxuanhou
 */

#ifndef NETWORK_BACKEND_STATUS_UPDATER_H_
#define NETWORK_BACKEND_STATUS_UPDATER_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "chassis-mainloop.h"

#include "network-exports.h"
#include "network-backend.h"
#include "network-mysqld.h"
/**
 * @author sohu-inc.com
 * 这里的函数实现在backend钻台有变化时，对backend的状态进行更新
 * 同时，将该backend对应的在用连接close,然后更新负载均衡的权重矩阵。
 * @note 是否需要另启动一个线程做这件事情？
 */
typedef struct {
	GThread *thr; /**< 更新的线程 */
	chassis * chas; /**< 基础变量 */
	network_backend_t *backend; /**< 要更新状态的backend指针 */
	backend_state_t from; /**< 原来的状态 */
	backend_state_t to; /**< 更新后的状态 */
} backend_status_update_worker;

NETWORK_API backend_status_update_worker *backend_status_update_worker_new(); /**< 创建一个worker线程　*/
NETWORK_API void backend_status_update_worker_free(
		backend_status_update_worker *worker); /**< 释放worker变量 */
NETWORK_API void backend_status_update_worker_start(
		backend_status_update_worker *worker); /**< 启动worker线程 */

NETWORK_API network_backend_t * master_elect_with_minimum_ip(network_backends_t *backends);
NETWORK_API network_backend_t *master_elect_with_priority(network_backends_t *backends);

NETWORK_API void update_backend_status(
		network_backend_t *backend,
		backend_state_t from,
		backend_state_t to); /**< 将backend的状态设置为：to.
							  * 实现时需要注意：1.backend在backend列表中；
							  * 			2.且当前的状态时from
							  */

NETWORK_API void close_connection_in_pool_for_backend(
		network_backend_t *backend); /**< 将backend上面的空闲连接释放 */
NETWORK_API void close_connection_in_use_for_backend(
		chassis *chas,
		network_backend_t *backend); /**< 将backend上面在用的连接释放 */
NETWORK_API void close_connection_for_backend(
		chassis *chas,
		network_backend_t *backend); /**< 将backend上面的连接释放，包括空闲连接和在用的连接 */

NETWORK_API void backend_status_update(
		backend_status_update_worker *worker); /**< 完成对work代表的backend的状态的更新 */

NETWORK_API int set_backend_status(chassis *chas, network_backends_t *bs,
		const gchar *ip_port,
		backend_state_t to); /**< 设置backend的状态为to */
#endif /* NETWORK_BACKEND_STATUS_UPDATER_H_ */
