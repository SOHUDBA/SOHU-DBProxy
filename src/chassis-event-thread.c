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

#include <glib.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for write() */
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>	/* for SOCK_STREAM and AF_UNIX/AF_INET */
#endif

#ifdef WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>	/* for write, read, _pipe etc */
#include <fcntl.h>
#undef WIN32_LEAN_AND_MEAN
#endif

#include <event.h>

#include "network-connection-state.h"
#include "chassis-event-thread.h"

#define C(x) x, sizeof(x) - 1
#ifndef WIN32
#define closesocket(x) close(x)
#endif

#ifdef _WIN32
#define E_NET_CONNRESET WSAECONNRESET
#define E_NET_CONNABORTED WSAECONNABORTED
#define E_NET_WOULDBLOCK WSAEWOULDBLOCK
#define E_NET_INPROGRESS WSAEINPROGRESS
#else
#define E_NET_CONNRESET ECONNRESET
#define E_NET_CONNABORTED ECONNABORTED
#define E_NET_INPROGRESS EINPROGRESS
#if EWOULDBLOCK == EAGAIN
/**
 * some system make EAGAIN == EWOULDBLOCK which would lead to a 
 * error in the case handling
 *
 * set it to -1 as this error should never happen
 */
#define E_NET_WOULDBLOCK -1
#else
#define E_NET_WOULDBLOCK EWOULDBLOCK
#endif
#endif

/**
 * create a new event-op
 *
 * event-ops are async requests around event_add()
 */
chassis_event_op_t *chassis_event_op_new() {
	chassis_event_op_t *e;

	e = g_slice_new0(chassis_event_op_t);

	return e;
}

/**
 * free a event-op
 */
void chassis_event_op_free(chassis_event_op_t *e) {
	if (!e) return;

	g_slice_free(chassis_event_op_t, e);
}

/**
 * execute a event-op on a event-base
 *
 * @see: chassis_event_add_local(), chassis_threaded_event_op()
 */
void chassis_event_op_apply(chassis_event_op_t *op, struct event_base *event_base) {
	switch (op->type) {
	case CHASSIS_EVENT_OP_ADD:
		event_base_set(event_base, op->ev);
		event_add(op->ev, op->tv);
		break;
	case CHASSIS_EVENT_OP_UNSET:
		g_assert_not_reached();
		break;
	}
}

/**
 * set the timeout 
 *
 * takes a deep-copy of the timeout as we have our own lifecycle independent of the caller 
 */
void
chassis_event_op_set_timeout(chassis_event_op_t *op, struct timeval *tv) {
	if (NULL != tv) {
		op->_tv_storage = *tv;
		op->tv = &(op->_tv_storage);
	} else {
		op->tv = NULL;
	}
}

void chassis_event_add_with_timeout(chassis *chas, struct event *ev, struct timeval *tv) {
	chassis_event_op_t *op = chassis_event_op_new();
	gssize ret;

	op->type = CHASSIS_EVENT_OP_ADD;
	op->ev   = ev;
	chassis_event_op_set_timeout(op, tv);

	g_async_queue_lock(chas->threads->global_event_queue);
	g_async_queue_push_unlocked(chas->threads->global_event_queue, op);

	/* ping the event handler */
	if (1 != (ret = send(chas->threads->global_event_notify_fds[1], C("."), 0))) {
		int last_errno; 

#ifdef WIN32
		last_errno = WSAGetLastError();
#else
		last_errno = errno;
#endif

		switch (last_errno) {
		case EAGAIN:
		case E_NET_WOULDBLOCK:
			/* that's fine ... */
			g_debug("%s: send() to event-notify-pipe failed: %s (len = %d)",
					G_STRLOC,
					g_strerror(errno),
					g_async_queue_length_unlocked(chas->threads->global_event_queue));
			break;
		default:
			g_critical("%s: send() to event-notify-pipe failed: %s (len = %d)",
					G_STRLOC,
					g_strerror(errno),
					g_async_queue_length_unlocked(chas->threads->global_event_queue));
			break;
		}
	}
	g_async_queue_unlock(chas->threads->global_event_queue);
}

/**
 * add a event asynchronously
 *
 * the event is added to the global event-queue and a fd-notification is sent allowing any
 * of the event-threads to handle it
 *
 * @see network_mysqld_con_handle()
 */
void chassis_event_add(chassis *chas, struct event *ev) {
	chassis_event_add_with_timeout(chas, ev, NULL);
}

#if 0
//GPrivate *tls_event_base_key = NULL;
static GPrivate tls_event_base_key_storage;
static GPrivate *tls_event_base_key = &tls_event_base_key_storage;
#endif

/**
 * add a event to the current thread 
 *
 * needs event-base stored in the thread local storage
 *
 * @see network_connection_pool_lua_add_connection()
 */
void chassis_event_add_local_with_timeout(chassis G_GNUC_UNUSED *chas, struct event *ev, struct timeval *tv) {
	struct event_base *event_base = ev->ev_base;
	chassis_event_op_t *op;

	//if (!event_base) event_base = g_private_get(tls_event_base_key);
	event_base = chassis_thread_get_local_event_base(chas);

	g_assert(event_base); /* the thread-local event-base has to be initialized */

	op = chassis_event_op_new();

	op->type = CHASSIS_EVENT_OP_ADD;
	op->ev   = ev;
	chassis_event_op_set_timeout(op, tv);

	chassis_event_op_apply(op, event_base);
	
	chassis_event_op_free(op);
}

void chassis_event_add_local(chassis *chas, struct event *ev) {
	chassis_event_add_local_with_timeout(chas, ev, NULL);
}

/**
 * handled events sent through the global event-queue 
 *
 * each event-thread has its own listener on the event-queue and 
 * calls chassis_event_handle() with its own event-base
 *
 * @see chassis_event_add()
 */
void chassis_global_event_handle(int G_GNUC_UNUSED event_fd, short G_GNUC_UNUSED events, void *user_data) {
	chassis_event_thread_t *event_thread = user_data;
	struct event_base *event_base = event_thread->event_base;
	chassis *chas = event_thread->chas;
	chassis_event_op_t *op;

	do {
		char ping[1];

		g_async_queue_lock(chas->threads->global_event_queue);
		if ((op = g_async_queue_try_pop_unlocked(chas->threads->global_event_queue))) {
			gsize ret;
			chassis_event_op_apply(op, event_base);

			chassis_event_op_free(op);
	       
			if (1 != (ret = recv(event_thread->global_notify_fd, ping, 1, 0))) {
				/* we failed to pull .'s from the notify-queue */
				int last_errno; 

#ifdef WIN32
				last_errno = WSAGetLastError();
#else
				last_errno = errno;
#endif

				switch (last_errno) {
				case EAGAIN:
				case E_NET_WOULDBLOCK:
					/* that's fine ... */
					g_debug("%s: recv() from event-notify-fd failed: %s",
							G_STRLOC,
							g_strerror(last_errno));
					break;
				default:
					g_critical("%s: recv() from event-notify-fd failed: %s",
							G_STRLOC,
							g_strerror(last_errno));
					break;
				}
			}
		}
		g_async_queue_unlock(chas->threads->global_event_queue);
	} while (op); /* even if op is 'free()d' it still is != NULL */
}


/**
 * add a event asynchronously
 *
 * the event is added to the global event-queue and a fd-notification is sent allowing any
 * of the event-threads to handle it
 *
 * @see network_mysqld_con_handle()
 */
//主线程负责接收和分配。接收到一个连接后，放入全局队列，轮询选择一个线程，通知此线程从队列取出一个连接进行后续处理（线程取出的连接不一定是刚才放入的那个）
void chassis_local_event_add(network_mysqld_con* client_con) {
	chassis* chas = client_con->srv;
	gsize ret;

	g_async_queue_push(chas->threads->local_event_queue, client_con);

	// choose a event thread
	static guint last_event_thread = 0;
	if (last_event_thread == (guint)(chas->event_thread_count)) { /**@fixme warning: comparison between signed and unsigned*/
		last_event_thread = 0;
	}
	chassis_event_thread_t *event_thread = chas->threads->event_threads->pdata[last_event_thread];
	++last_event_thread;

	//if (write(event_thread->notify_send_fd, "", 1) != 1) g_error("pipes - write error: %s", g_strerror(errno));

	//g_async_queue_lock(chas->threads->event_queue);
	//g_async_queue_push_unlocked(chas->threads->event_queue, op);

	/* ping the event handler */
	if (1 != (ret = send(event_thread->local_notify_send_fd, C("."), 0))) {
		int last_errno;

#ifdef WIN32
		last_errno = WSAGetLastError();
#else
		last_errno = errno;
#endif

		switch (last_errno) {
		case EAGAIN:
		case E_NET_WOULDBLOCK:
			/* that's fine ... */
//			g_debug("%s: send() to event-notify-pipe failed: %s (len = %d)",
//					G_STRLOC,
//					g_strerror(errno),
//					g_async_queue_length_unlocked(chas->threads->event_queue));
			g_debug("%s: send() to event-notify-pipe failed: %s",
					G_STRLOC,
					g_strerror(errno));
			break;
		default:
//			g_critical("%s: send() to event-notify-pipe failed: %s (len = %d)",
//					G_STRLOC,
//					g_strerror(errno),
//					g_async_queue_length_unlocked(chas->threads->event_queue));
			g_critical("%s: send() to event-notify-pipe failed: %s",
					G_STRLOC,
					g_strerror(errno));
			break;
		}
	}
	//g_async_queue_unlock(chas->threads->event_queue);

	return;
}

static GPrivate tls_index;

struct event_base *chassis_thread_get_local_event_base(chassis *chas) {
	guint index = GPOINTER_TO_UINT(g_private_get(&tls_index));
	chassis_event_thread_t* thread = g_ptr_array_index(chas->threads->event_threads, index);
	return thread->event_base;
}

/**
 * 获取当前线程的结构指针
 */
chassis_event_thread_t *chassis_thread_get_local_thread(chassis *chas) {
	guint index = GPOINTER_TO_UINT(g_private_get(&tls_index));
	chassis_event_thread_t *thread = g_ptr_array_index(chas->threads->event_threads, index);
	return thread;
}

#ifdef TEST_ADMIN_USE_INDEPENDENDT_THREAD
GString *chassis_thread_get_local_name(chassis *chas) {
	guint index = GPOINTER_TO_UINT(g_private_get(&tls_index));
	chassis_event_thread_t* thread = g_ptr_array_index(chas->threads->event_threads, index);
	return thread->name;
}
#endif


void chassis_local_event_handle(int G_GNUC_UNUSED event_fd, short G_GNUC_UNUSED events, void *user_data) {
	chassis_event_thread_t *event_thread = user_data;
	chassis *chas = event_thread->chas;

	char ping[1];
	//if (read(event_thread->notify_receive_fd, ping, 1) != 1) g_error("pipes - read error");
	gsize ret;
	if (1 != (ret = recv(event_thread->local_notify_receive_fd, ping, 1, 0))) {
		/* we failed to pull .'s from the notify-queue */
		int last_errno;

#ifdef WIN32
		last_errno = WSAGetLastError();
#else
		last_errno = errno;
#endif

		switch (last_errno) {
		case EAGAIN:
		case E_NET_WOULDBLOCK:
			/* that's fine ... */
			g_debug("%s: recv() from event-notify-fd failed: %s",
					G_STRLOC,
					g_strerror(last_errno));
			break;
		default:
			g_critical("%s: recv() from event-notify-fd failed: %s",
					G_STRLOC,
					g_strerror(last_errno));
			break;
		}
	}

	network_mysqld_con* client_con = g_async_queue_try_pop(chas->threads->local_event_queue);
	if (client_con != NULL) network_mysqld_con_handle(-1, 0, client_con);
}






/**
 * create the data structure for a new event-thread
 */
chassis_event_thread_t *chassis_event_thread_new(const GString *thr_name, guint index) {
	chassis_event_thread_t *event_thread;

	event_thread = g_new0(chassis_event_thread_t, 1);

	if (event_thread != NULL) {
		if ( thr_name != NULL && thr_name->str != NULL) {
			event_thread->name = g_string_new(thr_name->str);
			event_thread->index = index;
		}
		event_thread->connection_state = thread_connection_state_set_new();
	}

	return event_thread;
}

/**
 * free the data-structures for a event-thread
 *
 * joins the event-thread, closes notification-pipe and free's the event-base
 */
void chassis_event_thread_free(chassis_event_thread_t *event_thread) {
	gboolean is_thread = (event_thread->thr != NULL);

	if (!event_thread) return;

	if (event_thread->thr) {
		g_thread_join(event_thread->thr);
		event_thread->thr = NULL;
	}

	if (event_thread->global_notify_fd != -1) {
		event_del(&(event_thread->global_notify_fd_event));
		closesocket(event_thread->global_notify_fd);
	}
	if (event_thread->local_notify_fds[0] != -1) {
		event_del(&(event_thread->local_notify_fd_event));
		closesocket(event_thread->local_notify_fds[0]);
		event_thread->local_notify_fds[0] = -1;
	}
	if (event_thread->local_notify_fds[1] != -1) {
		closesocket(event_thread->local_notify_fds[1]);
		event_thread->local_notify_fds[1] = -1;
	}

	/* we don't want to free the global event-base */
	if (is_thread && event_thread->event_base) {
		event_base_free(event_thread->event_base);
		event_thread->event_base = NULL;
	}

	if (event_thread->connection_state != NULL) {
		g_debug("thread connection state: %s", (event_thread->name != NULL) ? event_thread->name->str : "NULL");
		thread_connection_state_set_dump(event_thread->connection_state);
		global_connection_state_set_update(event_thread->chas->connection_state, event_thread->connection_state);
		thread_connection_state_set_free(event_thread->connection_state);
		event_thread->connection_state = NULL;
	}

	if (event_thread->name != NULL) {
		g_string_free(event_thread->name, TRUE);
		event_thread->name = NULL;
	}


	g_free(event_thread);
}

#if 0
/**
 * set the event-based for the current event-thread
 *
 * @see chassis_event_add_local()
 */
void chassis_event_thread_set_event_base(chassis_event_thread_t G_GNUC_UNUSED *e, struct event_base *event_base) {
	g_private_set(tls_event_base_key, event_base);
}
#endif

/**
 * create the event-threads handler
 *
 * provides the event-queue that is contains the event_ops from the event-threads
 * and notifies all the idling event-threads for the new event-ops to process
 */
chassis_event_threads_t *chassis_event_threads_new() {
	chassis_event_threads_t *threads;

	//tls_event_base_key = g_private_new(NULL);

	threads = g_new0(chassis_event_threads_t, 1);

	/* create the ping-fds
	 *
	 * the event-thread write a byte to the ping-pipe to trigger a fd-event when
	 * something is available in the event-async-queues
	 */
	if (0 != evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, threads->global_event_notify_fds)) {
		int err;
#ifdef WIN32
		err = WSAGetLastError();
#else
		err = errno;
#endif
		g_error("%s: evutil_socketpair() failed: %s (%d)",
				G_STRLOC,
				g_strerror(err),
				err);
	}
	threads->event_threads = g_ptr_array_new();
	threads->global_event_queue = g_async_queue_new();

	/* make both ends non-blocking */
	evutil_make_socket_nonblocking(threads->global_event_notify_fds[0]);
	evutil_make_socket_nonblocking(threads->global_event_notify_fds[1]);

	threads->local_event_queue = g_async_queue_new();

	return threads;
}

/**
 * free all event-threads
 *
 * frees all the registered event-threads and event-queue
 */
void chassis_event_threads_free(chassis_event_threads_t *threads) {
	guint i;
	chassis_event_op_t *op;
	network_mysqld_con *con;

	if (!threads) return;

	/* all threads are running, now wait until they are down again */
	for (i = 0; i < threads->event_threads->len; i++) {
		chassis_event_thread_t *event_thread = threads->event_threads->pdata[i];

		chassis_event_thread_free(event_thread);
	}

	g_ptr_array_free(threads->event_threads, TRUE);

	/* free the events that are still in the queue */
	while ((op = g_async_queue_try_pop(threads->global_event_queue))) {
		chassis_event_op_free(op);
	}
	g_async_queue_unref(threads->global_event_queue);

	while ((con = g_async_queue_try_pop(threads->local_event_queue))) {
		network_mysqld_con_free(con);
	}
	g_async_queue_unref(threads->local_event_queue);

	/* close the notification pipe */
	if (threads->global_event_notify_fds[0] != -1) {
		closesocket(threads->global_event_notify_fds[0]);
	}
	if (threads->global_event_notify_fds[1] != -1) {
		closesocket(threads->global_event_notify_fds[1]);
	}

	g_free(threads);
}

/**
 * add a event-thread to the event-threads handler
 */
void chassis_event_threads_add(chassis_event_threads_t *threads, chassis_event_thread_t *thread) {
	g_ptr_array_add(threads->event_threads, thread);
}


/**
 * setup the notification-fd of a event-thread
 *
 * all event-threads listen on the same notification pipe
 *
 * @see chassis_event_handle()
 */ 
int chassis_event_threads_init_thread(chassis_event_threads_t *threads, chassis_event_thread_t *event_thread, chassis *chas) {
#ifdef WIN32
	LPWSAPROTOCOL_INFO lpProtocolInfo;
#endif
	event_thread->event_base = event_base_new();
	event_thread->chas = chas;

#ifdef WIN32
	lpProtocolInfo = g_malloc(sizeof(WSAPROTOCOL_INFO));
	if (SOCKET_ERROR == WSADuplicateSocket(threads->global_event_notify_fds[0], GetCurrentProcessId(), lpProtocolInfo)) {
		g_error("%s: Could not duplicate socket: %s (%d)", G_STRLOC, g_strerror(WSAGetLastError()), WSAGetLastError());
	}
	event_thread->global_notify_fd = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, lpProtocolInfo, 0, 0);
	if (INVALID_SOCKET == event_thread->global_notify_fd) {
		g_error("%s: Could not create duplicated socket: %s (%d)", G_STRLOC, g_strerror(WSAGetLastError()), WSAGetLastError());
	}
	g_free(lpProtocolInfo);
#else
	event_thread->global_notify_fd = dup(threads->global_event_notify_fds[0]);
#endif

//	event_set(&(event_thread->notify_fd_event), event_thread->notify_fd, EV_READ | EV_PERSIST, chassis_event_handle, event_thread);
//	event_base_set(event_thread->event_base, &(event_thread->notify_fd_event));
	event_assign(&(event_thread->global_notify_fd_event), event_thread->event_base, event_thread->global_notify_fd, EV_READ | EV_PERSIST, chassis_global_event_handle, event_thread);
	event_add(&(event_thread->global_notify_fd_event), NULL);


//	int fds[2];
//	if (pipe(fds)) {
//		int err;
//		err = errno;
//		g_error("%s: evutil_socketpair() failed: %s (%d)",
//				G_STRLOC,
//				g_strerror(err),
//				err);
//	}
//	event_thread->notify_receive_fd = fds[0];
//	event_thread->notify_send_fd = fds[1];

	/* create the ping-fds
	 *
	 * the event-thread write a byte to the ping-pipe to trigger a fd-event when
	 * something is available in the event-async-queues
	 */
	if (0
			!= evutil_socketpair(AF_UNIX, SOCK_STREAM, 0,
					event_thread->local_notify_fds)) {
		int err;
#ifdef WIN32
		err = WSAGetLastError();
#else
		err = errno;
#endif
		g_error("%s: evutil_socketpair() failed: %s (%d)", G_STRLOC,
				g_strerror(err), err);
	}
	/* make both ends non-blocking */
	evutil_make_socket_nonblocking(event_thread->local_notify_fds[0]);
	evutil_make_socket_nonblocking(event_thread->local_notify_fds[1]);

	event_thread->local_notify_receive_fd = event_thread->local_notify_fds[0];
	event_thread->local_notify_send_fd = event_thread->local_notify_fds[1];

	event_assign(&(event_thread->local_notify_fd_event), event_thread->event_base, event_thread->local_notify_receive_fd, EV_READ | EV_PERSIST, chassis_local_event_handle, event_thread);
	event_add(&(event_thread->local_notify_fd_event), NULL);

	return 0;
}

/**
 * event-handler thread
 *
 */
void *chassis_event_thread_loop(chassis_event_thread_t *event_thread) {
#if 0
	chassis_event_thread_set_event_base(event_thread, event_thread->event_base);
#endif
	g_private_set(&tls_index, GUINT_TO_POINTER(event_thread->index));

	/**
	 * check once a second if we shall shutdown the proxy
	 */
	while (!chassis_is_shutdown()) {
		struct timeval timeout;
		int r;

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		g_assert(event_base_loopexit(event_thread->event_base, &timeout) == 0);

		r = event_base_dispatch(event_thread->event_base);

		if (r == -1) {
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if (errno == EINTR) continue;
			g_critical("%s: leaving chassis_event_thread_loop early, errno != EINTR was: %s (%d)", G_STRLOC, g_strerror(errno), errno);
			break;
		}
	}
	g_debug("thread is terminated. %s", event_thread->name->str);

	return NULL;
}

/**
 * start all the event-threads 
 *
 * starts all the event-threads that got added by chassis_event_threads_add()
 *
 * @see chassis_event_threads_add
 */
void chassis_event_threads_start(chassis_event_threads_t *threads) {
	guint i;

	g_message("%s: starting %d threads", G_STRLOC, threads->event_threads->len - 1);

	for (i = 1; i < threads->event_threads->len; i++) { /* the 1st is the main-thread and already set up */
		chassis_event_thread_t *event_thread = threads->event_threads->pdata[i];
		GError *gerr = NULL;

		//event_thread->thr = g_thread_create((GThreadFunc)chassis_event_thread_loop, event_thread, TRUE, &gerr);
		event_thread->thr = g_thread_new(event_thread->name->str, (GThreadFunc)chassis_event_thread_loop, event_thread);

		if (gerr) {
			g_critical("%s: %s", G_STRLOC, gerr->message);
			g_error_free(gerr);
			gerr = NULL;
		}
	}
}

void chassis_admin_thread_start(chassis_event_thread_t *admin_thread) {
	GError *gerr = NULL;
	g_message("%s: starting a admin event thread", G_STRLOC);
	admin_thread->thr = g_thread_try_new(admin_thread->name->str,
			(GThreadFunc) chassis_event_thread_loop,
			admin_thread, &gerr);
	if (gerr) {
		g_critical("%s: %s", G_STRLOC, gerr->message);
		g_error_free(gerr);
		gerr = NULL;
	}
}


