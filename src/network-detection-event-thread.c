/*
 * network-detection-event-thread.c
 *
 *  Created on: 2013-6-23
 *      Author: jinxuanhou
 */
#include <errno.h>

#include "network-detection-event-thread.h"
#include "network-backend-status-updater.h"
#include "network-zabbix-agentd.h"


/**
 * 构造检查任务
 */
detection_task *detection_task_new(backend_detect_thread_t *detect_thread) {
	detection_task *task = NULL;

	g_assert(detect_thread);

	task = g_new0(detection_task, 1);
	if (task != NULL) {
		task->detect_thread = detect_thread;

		task->sock = zabbix_socket_new();
		zabbix_socket_set_thread_event_base(task->sock, detect_thread->event_base);

		task->backend_check_result = backend_result_new();

		if (task->sock == NULL || task->backend_check_result == NULL) {
			detection_task_free(task);
			task = NULL;
			return NULL;
		}
	}
	return task;
}

/**
 * 销毁检查任务
 */
void detection_task_free(detection_task *task) {
	if (task != NULL) {
		if (task->detect_thread != NULL) {
			task->detect_thread = NULL;
		}

		if (task->sock != NULL) {
			zabbix_socket_free(task->sock);
			task->sock = NULL;
		}

		if (task->backend_check_result != NULL) {
			backend_result_free(task->backend_check_result);
			task->backend_check_result = NULL;
		}

		g_free(task);
	}
}

/**
 * 修改配置
 * @todo 现在是写死的，以后可从backend配置中读取用户名、密码，（从chassis配置中读取zabbix地址）
 * 当配置发生更改后，调用此函数
 */
void detection_task_config(detection_task *task) {
	network_backend_t *backend = NULL;
	zabbix_socket *sock = NULL;

	g_assert(task);
	g_assert(task->detect_thread);
	g_assert(task->detect_thread->backend);
	g_assert(task->sock);

	backend = task->detect_thread->backend;
	sock = task->sock;

	gchar *user = "test";
	gchar *password = "test";

	extern char *zabbixuser;
	extern char *zabbixuserpassword;


	if(zabbixuser != NULL && zabbixuserpassword != NULL)
	{
		user = (gchar *)zabbixuser;
		password = (gchar *)zabbixuserpassword;
	}
	

	// 生成后端检测的命令
	zabbix_socket_set_agentd_cmd(sock, "pxc.checkStatus", backend->ip->str,
			backend->port, user, password);
	// 设置socket 的地址
	zabbix_socket_set_agentd_address(sock, "127.0.0.1", 10050);

	return;
}


/**
 * @author suhu-inc.com
 * 后端检测线程的创建函数
 * @return
 */
backend_detect_thread_t *backend_detect_thread_new(guint index) {
	backend_detect_thread_t *thread = NULL;
	thread = g_new0(backend_detect_thread_t, 1);
	thread->index = index;
	thread->name = g_string_new(NULL);
	g_string_printf(thread->name, "detect_%d", index);
	return thread;
}

/**
 * @author sohu-inc.com
 * 后端检测线程释放销毁
 * @param detect_thread
 */
void backend_detect_thread_free(backend_detect_thread_t *detect_thread) {
	gboolean is_thread = FALSE;

	if (!detect_thread)
		return;

	is_thread = (detect_thread->thr != NULL);

	g_debug("[%s]: will join detect thread if needed.", G_STRLOC);
	if (detect_thread->thr != NULL) {
		g_thread_join(detect_thread->thr);
		detect_thread->thr = NULL;
	}

	g_debug("[%s]: deleting the event_base of detect thread", G_STRLOC);
	if (is_thread && detect_thread->event_base) {
		event_base_free(detect_thread->event_base);
		detect_thread->event_base = NULL;
	}

	if (detect_thread->backend != NULL) {
		// 这里应用的是上层传来的指针，不用释放backend指向的内存，
		// 只是将backend置为NULL即可
		detect_thread->backend = NULL;
	}

	if (detect_thread->chas) {
		// 这里应用的是上层传来的指针，不用释放chas指向的内存，
		// 只是将chas置为NULL即可
		detect_thread->chas = NULL;
	}

	if (detect_thread->name != NULL) {
		g_string_free(detect_thread->name, TRUE);
		detect_thread->name = NULL;
	}

	if (detect_thread->task != NULL) {
		detection_task_free(detect_thread->task);
		detect_thread->task = NULL;
	}

	g_free(detect_thread);
}

static void backend_detect_thread_free_wrapper (gpointer data) {
	backend_detect_thread_t *detect_thread = (backend_detect_thread_t *)data;
	backend_detect_thread_free(detect_thread);
	return;
}

/**
 * @author sohu-inc.com
 * 对后端检测线程初始化，建task结构，给backend,chas赋值
 * @param detect_thread
 */
void backend_detect_thread_init(backend_detect_thread_t *detect_thread, chassis *chas, network_backend_t *backend) {
	detection_task *task = NULL;

	detect_thread->event_base = event_base_new();
	detect_thread->chas = chas;
	detect_thread->backend = backend;

	task = detection_task_new(detect_thread);
	g_assert(task);
	detection_task_config(task);
	detect_thread->task = task;

	return;
}

/**
 * @author sohu-inc.com
 * 启动后端检测的线程
 * @param detect_thread
 */
void backend_detect_thread_start(backend_detect_thread_t *detect_thread) {
	GError *gerr = NULL;
	g_message("%s: starting a backend detect thread", G_STRLOC);
	detect_thread->thr = g_thread_try_new(detect_thread->name->str,
			(GThreadFunc) backend_detect_thread_loop,
			detect_thread, &gerr);
	if (gerr) {
		g_critical("%s: %s", G_STRLOC, gerr->message);
		g_error_free(gerr);
		gerr = NULL;
	}
	return;
}


GPtrArray *backend_detect_threads_new(void) {
	GPtrArray *detect_threads = NULL;
	/**
	 * 为了在添加backend时，方便的增加后端检测线程，现将detect_threads放在了chas里面
	 */
	detect_threads = g_ptr_array_new();
	if (detect_threads != NULL) {
		g_ptr_array_set_free_func(detect_threads, backend_detect_thread_free_wrapper);
	}
	return detect_threads;
}

void backend_detect_threads_free(GPtrArray *detect_threads) {
	if (detect_threads != NULL) {
		g_ptr_array_free(detect_threads, TRUE);
	}
}

#if 0
static void append_int_to_string(GString *str, int port) {
	if (!str)
		return;

	if (port <= 0)
		return;

	char buffer[32];
	sprintf(buffer, "%d", port);

	g_string_append(str, buffer);
}
#endif



/**
 * @author sohu-inc.com
 * 通过backend的检测脚本返回的结果判定backend的状态
 * @param[OUT] detection_task *task
 * @param[IN] network_backend_t *backend
 * @return backend_state_t 函数的执行状态
 */
backend_state_t network_zabbix_status_check(detection_task *task, const network_backend_t *backend) {
	zabbix_socket *sock = NULL;
	backend_state_t backend_check_state;

	g_assert(task);
	g_assert(task->sock);

	sock = task->sock;

	if (sock->is_over == TRUE) {
		g_debug("detection is over");
		// 根据状态机退出的状态判定backend的状态
		switch (sock->exit_status) {
		case ZABBIX_STATUS_MACHINE_SUCCESS: {
			backend_result_check_status_t ret;
			/**
			 * 该状态标示dbproxy 与 zabbix 通信正常，dbproxy已经从zabbix获取了返回结果
			 * 包括NOT_SUPPORTED
			 */
			// 1. 判定接收到的返回结果是不是NOT_SUPPORTED
			// 2. 判定接收到信息是不是预先设定的格式
			ret = network_zabbix_result_process(sock->result, task->backend_check_result);
			switch (ret) {
			case BACKEND_CHECK_UP:
				g_debug("[%s]: backend->%s status is up!",
						G_STRLOC,
						backend->addr->name->str);
				backend_check_state = BACKEND_STATE_UP;
				break;
			case BACKEND_CHECK_DOWN:
				g_critical("[%s]: backend->%s status is down!",
						G_STRLOC,
						backend->addr->name->str);
				backend_check_state = BACKEND_STATE_DOWN;
				break;
			case BACKEND_CHECK_NOTSUPPORT:
				g_warning("[%s]: check backend->%s returns not_supported.",
						G_STRLOC,
						backend->addr->name->str);
				backend_check_state = BACKEND_STATE_UNKNOWN;
				break;
			case BACKEND_CHECK_RESULT_ERROR:
				g_warning("[%s]: result retured can not be recognised when checking backend->%s.",
						G_STRLOC,
						backend->addr->name->str);
				backend_check_state = BACKEND_STATE_UNKNOWN;
				break;
			}
			break;
		}
		case ZABBIX_STATUS_MACHINE_TIMEOUT:
			g_warning("[%s]: check timeout when checking backend->%s.",
					G_STRLOC,
					backend->addr->name->str);
			backend_check_state = BACKEND_STATE_UNKNOWN;
			break;
		case ZABBIX_STATUS_MACHINE_NETWORK_ERROR:
			g_warning("[%s]: encounter network error when checking backend->%s. may be connectting to zabbix or connecting backend",
					G_STRLOC,
					backend->addr->name->str);
			backend_check_state = BACKEND_STATE_UNKNOWN;
			break;
		case ZABBIX_STATUS_MACHINE_SERVER_CLOSE_CON:
			g_warning("[%s]: encounter network error when checking backend->%s.",
					G_STRLOC,
					backend->addr->name->str);
			backend_check_state = BACKEND_STATE_UNKNOWN;
			break;
		case ZABBIX_STATUS_MACHINE_NO_RESULT:
			g_warning("[%s]: got none result when checking backend->%s.",
					G_STRLOC,
					backend->addr->name->str);
			backend_check_state = BACKEND_STATE_UNKNOWN;
			break;
		}

	} else {
		g_debug("detection is timeout");
		backend_check_state = BACKEND_STATE_UNKNOWN;
	}

	return backend_check_state;
}

/**
 * 根据检查结果修改后端状态
 * @param[IN] backend_state_t state 状态
 * @param[IN] const chassis *chas
 * @param[OUT] network_backend_t *backend
 * @return int
 */
backend_state_t adjust_backend(backend_state_t state, chassis *chas, network_backend_t *backend) {
	health_check_t *health_check = NULL;

	g_assert(chas);
	g_assert(backend);

	health_check = &(backend->health_check);

	switch (state) {
	case BACKEND_STATE_UP:
		if (health_check->health
				< health_check->rise + health_check->fall - 1) {
			health_check->health++;
			if (health_check->health == health_check->rise
					|| backend->state == BACKEND_STATE_UNKNOWN) {
				/*down->up*/
				/**
				 * @todo update the state and load balance, should fork a new thread
				 */
				/* DOWN or UNKNOWN */
				if (BACKEND_STATE_UP != backend->state) {
					g_message(
							"[%s]: will update backend status from down to up",
							G_STRLOC);
					backend_status_update_worker *worker =
							backend_status_update_worker_new();
					worker->backend = backend;
					worker->chas = chas;
					worker->from = backend->state;
					worker->to = BACKEND_STATE_UP;
					backend_status_update_worker_start(worker);
					backend_status_update_worker_free(worker);
				}
			}
			if (health_check->health >= health_check->rise) {
				health_check->health = health_check->rise + health_check->fall
						- 1;
			}
		}
		break;
	case BACKEND_STATE_DOWN:
	case BACKEND_STATE_UNKNOWN:
		if (health_check->health > health_check->rise) {
			health_check->health--;
		} else {
			if (health_check->health == health_check->rise
					|| backend->state == BACKEND_STATE_UNKNOWN) {
				/*up->down*/
				/**
				 * @todo update the state and load balance, should fork a new thread
				 * 需要将backend上面的连接释放掉！
				 */
				/*UP or UNKNOWN*/
				if (BACKEND_STATE_DOWN != backend->state) {
					g_warning(
							"[%s]: will update backend status from up to down",
							G_STRLOC);
					backend_status_update_worker *worker =
							backend_status_update_worker_new();
					worker->backend = backend;
					worker->chas = chas;
					worker->from = backend->state;
					worker->to = BACKEND_STATE_DOWN;
					backend_status_update_worker_start(worker);
					backend_status_update_worker_free(worker);
				}
			}
			health_check->health = 0;
		}
		break;
	case BACKEND_STATE_PENDING:
		health_check->health = health_check->rise;
		break;
	}

	return state;
}


/**
 * @author sohu-inc.com
 * event-handler thread,主要是完成后端检测
 * @param detect_thread
 */
void *backend_detect_thread_loop(backend_detect_thread_t *detect_thread) {
	/**
	 * @note 需要完成如下事情：
	 * 1. 创建socket,建立连接
	 * 2. 设置socket的状态为：ZABBIX_CON_STATE_WRITE_HEAD,意味着接下来向zabbix_agent端写数据
	 * 3. 调用network_zabbix_con_handle，开始与zabbix的交互.(由于network_zabbix_con_handle为异步处理，因而可能会中途返回)
	 * 4. 根据socket中状态机是否结束的标志及退出状态机的状态确定，确定接下来的动作。（若状态机没有退出，则不作特殊处理；若状态机退出，分情况处理）
	 * 5. 在认定后端down的情况下，需要另起一个线程对backend状态更新及已有连接处理。（因而最好保存一个检测的backend的指针！！！）
	 */

	g_assert(detect_thread);

	// 设置初始的状态，设置检测的状态机检测成功
	// 需要增加一个状态判定检测是不是成功

	/* 死循环 */
	while (!chassis_is_shutdown()) {
		GTimeVal begin_time;
		GTimeVal end_time;
		guint interval_seconds = 0;

		detection_task *task = NULL;
		network_backend_t *backend = NULL;
		chassis *chas = NULL;
		zabbix_socket *detect_socket = NULL;

		g_assert(detect_thread->task);
		g_assert(detect_thread->backend);
		g_assert(detect_thread->chas);
		g_assert(detect_thread->task->sock);

		task = detect_thread->task;
		backend = detect_thread->backend;
		chas = detect_thread->chas;
		detect_socket = task->sock;

		g_get_current_time(&begin_time);

		/* 状态pending的不需要检查 */
		if (backend->state == BACKEND_STATE_PENDING) {
			adjust_backend(BACKEND_STATE_PENDING, chas, backend);
			goto SLEEP;
		}

		/* 根据当前状态，取不同的间隔时间 */
		if (backend->state == BACKEND_STATE_DOWN) {
			interval_seconds = backend->health_check.fastdowninter;
		} else {
			interval_seconds = backend->health_check.inter;
		}
		//g_debug("timeout is set to %d seconds", interval_seconds);

		/**
		 * 初始化：
		 * 1. 设置需要检测的backend的ip，port
		 * 2. 创建与zabbix agent 的socket连接
		 * 3. 设置event_base, backend指针
		 */
		zabbix_socket_reset(detect_socket); // 初始化连接的标志信息
		/*设置套接字读写超时时间*/
		zabbix_socket_set_timeout(detect_socket, interval_seconds);
		network_zabbix_con_handle(-1, 0, detect_socket); // 开始与zabbix的通信过程

		/* 等待与zabbix通信完成，直到超时 */
		g_get_current_time(&end_time);
//		g_debug("begin_time: %ld.%06ld, end_time: %ld.%06ld", begin_time.tv_sec,
//				begin_time.tv_usec, end_time.tv_sec, end_time.tv_usec);
		while ((begin_time.tv_sec + interval_seconds > end_time.tv_sec)
				&& !chassis_is_shutdown()) {
			struct timeval timeout;
			int rr;
			/*0.1秒*/
			timeout.tv_sec = 0;
			timeout.tv_usec = 100000;
			g_assert(
					event_base_loopexit(detect_thread->event_base,
							&timeout) == 0);
			rr = event_base_dispatch(detect_thread->event_base);
			if (rr == -1) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if (errno == EINTR)
					continue;
				g_critical(
						"%s: leaving network_detection_thread_loop sleep early, errno != EINTR was: %s (%d)",
						G_STRLOC, g_strerror(errno), errno);
				break;
			}
			g_get_current_time(&end_time);
//			g_debug("begin_time: %ld.%06ld, end_time: %ld.%06ld", begin_time.tv_sec,
//					begin_time.tv_usec, end_time.tv_sec, end_time.tv_usec);

			if (detect_socket->is_over == TRUE) {
				break;
			}
		}
		/* （超时情况下）network_zabbix_con_handle可能注册了READ/WRITE事件，删除之 */
		event_del(&detect_socket->event);

		//接下来我们会判断返回的结果确定backend的状态
		task->backend_check_state = network_zabbix_status_check(task, task->detect_thread->backend);

		/**调整后端状态*/
		adjust_backend(task->backend_check_state, chas, task->detect_thread->backend);

SLEEP:
		/* 等待超过检查时间间隔后，再继续循环，否则一直等待 */
		if (backend->state == BACKEND_STATE_DOWN) {
			interval_seconds = backend->health_check.fastdowninter;
		} else if (backend->state == BACKEND_STATE_PENDING) {
			interval_seconds = backend->health_check.fastdowninter;
		} else {
			interval_seconds = backend->health_check.inter;
		}
		//g_debug("sleeptime is set to %d seconds", interval_seconds);
		g_get_current_time(&end_time);
		while ((begin_time.tv_sec + interval_seconds > end_time.tv_sec)
				&& !chassis_is_shutdown()) {
			struct timeval timeout;
			int rr;
			/*0.2秒*/
			timeout.tv_sec = 0;
			timeout.tv_usec = 200000;
			g_assert(
					event_base_loopexit(detect_thread->event_base,
							&timeout) == 0);
			rr = event_base_dispatch(detect_thread->event_base);
			if (rr == -1) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if (errno == EINTR)
					continue;
				g_critical(
						"%s: leaving network_detection_thread_loop sleep early, errno != EINTR was: %s (%d)",
						G_STRLOC, g_strerror(errno), errno);
				break;
			}
			g_get_current_time(&end_time);
//			g_debug("begin_time: %ld.%06ld, end_time: %ld.%06ld", begin_time.tv_sec,
//					begin_time.tv_usec, end_time.tv_sec, end_time.tv_usec);
		}

	} /* end of while() */

	g_message("detection thread is shutdown");
	return NULL;
}



/*eof*/
