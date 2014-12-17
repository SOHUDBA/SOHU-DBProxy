/*
 * network-detection-event-thread.h
 *
 *  Created on: 2013-6-23
 *      Author: jinxuanhou
 */

#ifndef NETWORK_DETECTION_EVENT_THREAD_H_
#define NETWORK_DETECTION_EVENT_THREAD_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <event.h>     /* struct event_base */

#include "chassis-mainloop.h"

#include "network-exports.h"
#include "network-backend.h"
#include "network-mysqld.h"
#include "network-zabbix-socket.h"
#include "network-zabbix-agentd.h"

typedef struct backend_detect_thread_t backend_detect_thread_t;

typedef struct detection_task {
	backend_detect_thread_t *detect_thread;

	zabbix_socket *sock;

	backend_state_t backend_check_state;
	backend_result *backend_check_result;

	/* 监测配置相关信息 */
	gboolean on; /**< 是否是一直检测。没用 */

} detection_task;

struct backend_detect_thread_t {
	GThread *thr;
	struct event_base *event_base;

	network_backend_t *backend; /**< 指向该线程负责检查的backend */
	chassis *chas; /**< 基础变量 */

	guint index;
	GString *name;

	detection_task *task;
};

NETWORK_API detection_task *detection_task_new(backend_detect_thread_t *detect_thread);
NETWORK_API void detection_task_free(detection_task *task);
NETWORK_API void detection_task_config(detection_task *task);

NETWORK_API backend_detect_thread_t *backend_detect_thread_new(); /**< 创建一个后端检测线程 */
NETWORK_API void backend_detect_thread_free(backend_detect_thread_t *detect_thread); /**< 销毁后端检测线程 */
NETWORK_API void backend_detect_thread_init(backend_detect_thread_t *detect_thread, chassis *chas, network_backend_t *backend); /**< 初始化后端检测线程 */
NETWORK_API void backend_detect_thread_start(backend_detect_thread_t *detect_thread); /**< 开始运行后端检测线程 */
NETWORK_API void *backend_detect_thread_loop(backend_detect_thread_t *detect_thread); /**< 检查是否关闭及循环事件处理  */

NETWORK_API GPtrArray *backend_detect_threads_new(void);
NETWORK_API void backend_detect_threads_free(GPtrArray *detect_threads);

NETWORK_API backend_state_t network_zabbix_status_check(detection_task *task, const network_backend_t *backend);
NETWORK_API backend_state_t adjust_backend(backend_state_t state, chassis *chas, network_backend_t *backend);

#endif /* CHASSIS_DETECTION_EVENT_THREAD_H_ */
