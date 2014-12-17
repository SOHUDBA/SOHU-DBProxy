/* $%BEGINLICENSE%$
 Copyright (c) 2009, 2012, Oracle and/or its affiliates. All rights reserved.

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
 

#ifndef _CHASSIS_EVENT_THREAD_H_
#define _CHASSIS_EVENT_THREAD_H_

#include <glib.h>    /* GPtrArray */

#include "chassis-exports.h"
#include "chassis-mainloop.h"
#include "network-backend.h"
#include "network-mysqld.h"

/**
 * event operations
 *
 * event-ops are sent through the async-queues
 */

typedef struct {
	enum {
		CHASSIS_EVENT_OP_UNSET,
		CHASSIS_EVENT_OP_ADD
	} type;

	struct event *ev;

	struct timeval _tv_storage;
	struct timeval *tv; /* points to ._tv_storage or to NULL */
} chassis_event_op_t;

CHASSIS_API chassis_event_op_t *chassis_event_op_new();
CHASSIS_API void chassis_event_op_free(chassis_event_op_t *e);
CHASSIS_API void chassis_event_op_set_timeout(chassis_event_op_t *op, struct timeval *tv); 
CHASSIS_API void chassis_event_add(chassis *chas, struct event *ev);
CHASSIS_API void chassis_event_add_with_timeout(chassis *chas, struct event *ev, struct timeval *tv);
CHASSIS_API void chassis_event_add_local(chassis *chas, struct event *ev);
CHASSIS_API void chassis_event_add_local_with_timeout(chassis *chas, struct event *ev, struct timeval *tv);


CHASSIS_API void chassis_local_event_add(network_mysqld_con* client_con);
CHASSIS_API struct event_base *chassis_thread_get_local_event_base(chassis *chas);
CHASSIS_API chassis_event_thread_t *chassis_thread_get_local_thread(chassis *chas);
#ifdef TEST_ADMIN_USE_INDEPENDENDT_THREAD
CHASSIS_API GString *chassis_thread_get_local_name(chassis *chas);
#endif


/**
 * a event-thread
 */
struct chassis_event_thread_t {
	chassis *chas;

	int global_notify_fd;
	struct event global_notify_fd_event;

	int local_notify_fds[2];
    int local_notify_receive_fd;
    int local_notify_send_fd;
	struct event local_notify_fd_event;

	GThread *thr;
	GString *name; /** 线程名 */

	struct event_base *event_base;

	guint index;

	/** 线程级的连接统计信息 */
	thread_connection_state_set *connection_state;
};

CHASSIS_API void chassis_global_event_handle(int event_fd, short events, void *user_data);
CHASSIS_API void chassis_local_event_handle(int event_fd, short events, void *user_data);

CHASSIS_API chassis_event_thread_t *chassis_event_thread_new(const GString *thr_name, guint index);
CHASSIS_API void chassis_event_thread_free(chassis_event_thread_t *event_thread);
#if 0
CHASSIS_API void chassis_event_thread_set_event_base(chassis_event_thread_t *e, struct event_base *event_base);
#endif
CHASSIS_API void *chassis_event_thread_loop(chassis_event_thread_t *);

struct chassis_event_threads_t {
 	GPtrArray *event_threads;

	GAsyncQueue *global_event_queue;
	GAsyncQueue *local_event_queue;

	int global_event_notify_fds[2];
};

CHASSIS_API chassis_event_threads_t *chassis_event_threads_new();
CHASSIS_API void chassis_event_threads_free(chassis_event_threads_t *threads);
CHASSIS_API void chassis_event_threads_add(chassis_event_threads_t *threads, chassis_event_thread_t *thread);
CHASSIS_API int chassis_event_threads_init_thread(chassis_event_threads_t *threads, chassis_event_thread_t *event_thread, chassis *chas);
CHASSIS_API void chassis_event_threads_start(chassis_event_threads_t *threads);
CHASSIS_API void chassis_admin_thread_start(chassis_event_thread_t *admin_thread);

#endif
