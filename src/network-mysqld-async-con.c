/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2012, Oracle and/or its affiliates. All rights reserved.

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

#include <sys/types.h>

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h> /* required for FIONREAD on solaris */
#endif

#ifndef _WIN32
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h> /** inet_ntoa */
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netdb.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <io.h>
#define ioctl ioctlsocket
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <glib.h>

#include <mysql.h>
#include <mysqld_error.h>
// added by jinxuan hou , for scramble
#include <mysql_com.h>

#include "network-debug.h"
#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "network-conn-pool.h"
#include "chassis-mainloop.h"
#include "chassis-event-thread.h"
//#include "lua-scope.h"
#include "glib-ext.h"
#include "network-asn1.h"
#include "network-spnego.h"

#include "chassis-regex.h"
#include "network-mysqld-async-con.h"


#if defined(HAVE_SYS_SDT_H) && defined(ENABLE_DTRACE)
#include <sys/sdt.h>
#include "proxy-dtrace-provider.h"
#else
#include "disable-dtrace.h"
#endif

#ifdef HAVE_WRITEV
#define USE_BUFFERED_NETIO
#else
#undef USE_BUFFERED_NETIO
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
 * a handy marco for constant strings
 */
#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

// added by jinxuan hou
// define client default capability and charset
#define DEFAULT_FLAGS  CLIENT_FOUND_ROWS | CLIENT_LONG_PASSWORD | CLIENT_CONNECT_WITH_DB | CLIENT_LONG_FLAG | CLIENT_LOCAL_FILES | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_STATEMENTS |CLIENT_MULTI_RESULTS
#define DEFAULT_CHARSET   '\x21'     //default charset is utf

static const char *get_event_name(int events);


/**
 * added by jinxuan hou
 * 连接异步创建过程中对应的状态名
 */
static char *sz_async_state[] = {
		"CON_STATE_ASYNC_INIT",                 // 0
		"CON_STATE_ASYNC_READ_HANDSHAKE",
		"CON_STATE_ASYNC_CREATE_AUTH",
		"CON_STATE_ASYNC_SEND_AUTH",
		"CON_STATE_ASYNC_READ_AUTH_RESULT",
		"CON_STATE_ASYNC_SELECT_DB",
		"CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD",
		"CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORD",
		"CON_STATE_ASYNC_ERROR",
		"CON_STATE_ASYNC_NONE"
};

/*
static char *sz_rw_state[] = {
		"NET_RW_STATE_NONE",            // 0
		"NET_RW_STATE_WRITE",
		"NET_RW_STATE_READ",
		"NET_STATE_READ",               // normal inline read
		"NET_RW_STATE_ERROR"
};
*/


/**
 * added by jinxuan hou, 2013/04/11
 * as follow, we will add several functions related to
 * asynchronous connections establish
 *
 * 1. 异步连接建立的标志变量
 * 2. 异步连接建立过程状态机的hook 函数对应的plugin
 * 3. 连接创建的中间结构体的穿件删除函数
 * 4. 连接创建成功后需要将连接放入对应的连接池中（注册空闲超时处理函数）
 *
 * @@jinxuanhou
 */

// 初始化一个后端连接对应的变量
server_connection_state* network_mysqld_async_con_init(
		const gchar *username, const gchar *backend_str, chassis *srv) {
	server_connection_state *con = NULL;
	//plugin_con_state *st;

	// added on 2013/05/03
	g_assert(username);
	g_assert(backend_str);

	con = g_new0(server_connection_state, 1);

	con->srv = srv;
	con->server = network_socket_new();
	con->state = CON_STATE_ASYNC_INIT;

	// added by jinxuan hou, i do not know what the meaning of adding an element
	// of plugin_con_state here.
	//con->plugin_con_state = st = plugin_con_state_init();

	//if (NULL == (st->global_state = plugin_srv_state_get(srv))) {
	//	return NULL;
	//}

	con->plugins.con_init = proxy_async_init;
	con->plugins.con_read_handshake = proxy_async_read_handshake;
	con->plugins.con_create_auth = proxy_async_create_auth;
	con->plugins.con_send_auth = NULL;
	con->plugins.con_read_auth_result = proxy_async_read_auth_result;

	// we should set the address of serve we will connect to
	network_address_set_address(con->server->dst, backend_str);
	con->username = g_string_new(username);
	con->backend_addr = g_string_new(backend_str);

	return con;
}

/**
 * added by jinxuan hou,
 * here we will delete an unestablished connection from the pending queue
 * note:
 */
void network_mysqld_async_con_free(server_connection_state *server_con_st) {
	if (!server_con_st)
		return;

	if (server_con_st->username)
		g_string_free(server_con_st->username, TRUE);
	if (server_con_st->backend_addr)
		g_string_free(server_con_st->backend_addr, TRUE);
	if (server_con_st->server)
		network_socket_free(server_con_st->server);

	g_free(server_con_st);
	return;
}



/**
 * @author sohu-inc.com
 * 与后端的backend建立socket连接
 * @param srv 全局结构基座保存了所需的全局变量
 * @param con 连接的中间结构体
 *
 */
int network_mysqld_async_con_connect(chassis *UNUSED_PARAM(srv), server_connection_state *con) {
	int val = 1;
	network_socket *server = NULL;

	//log_debug("%s.%d: con_connect\n", __FILE__, __LINE__ );

	g_assert(con);
	g_assert(con->server);
	//g_assert(con->dst->addr);

	server = con->server;

	/**
	 * con->dst->addr.ipv4.sin_family is always mapped to the same field
	 * even if it is not a IPv4 address as we use a union
	 */
	if (-1 == (server->fd = socket(server->dst->addr.ipv4.sin_family, SOCK_STREAM, 0))) {
		g_critical("[%s]: socket(%s) failed: %s", G_STRLOC, server->dst->name->str, g_strerror(errno));
		return -1;
	}

	setsockopt(server->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val) );

	// define a starting point for the connection
	if (-1 == connect(server->fd, (struct sockaddr *) &(server->dst->addr), server->dst->len)) {
		g_critical("[%s]: connect(%s) failed: %s", G_STRLOC, server->dst->name->str, g_strerror(errno));
		return -1;
	}

	return 0;
}


/**
 * newly added by sohu-inc
 * handle the different states of the MySQL asynchronous connection protocol
 * from the Proxy to the Databases
 * @param event_fd 事件对应的文件描述符
 * @param events 描述符接收到的事件
 * @param user_data 异步连接建立的中间结构
 */
void network_mysqld_async_con_handle(int event_fd, short events,
		void *user_data) {
	async_con_state ostate;
	server_connection_state * con = (server_connection_state *) user_data;
	chassis * srv = con->srv;
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(func) = NULL;
	int ret;

/*
#define ASYNC_WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
		g_debug("%s.%d SOCKET=%d: ASYNC_WAIT_FOR_EVENT %s.\n", __FILE__, __LINE__, ev_struct->fd, get_event_name(ev_type));\
		event_set(&(ev_struct->event), ev_struct->fd, ev_type, network_mysqld_async_con_handle, user_data); \
		chassis_event_add_with_timeout(srv, &(ev_struct->event), timeout);
*/
	/* 异步建立后端连接的事件放到了原来全局的队列中，由所有线程竞争
	 * 这里event_assign（srv->event_base）是因为libevent2推荐用assign，又必须指定一个base
	 * +可以指定NULL，默认是global_current_base
	 */
#define ASYNC_WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
		g_debug("%s.%d SOCKET=%d: ASYNC_WAIT_FOR_EVENT %s.\n", __FILE__, __LINE__, ev_struct->fd, get_event_name(ev_type));\
		event_assign(&(ev_struct->event), NULL /*srv->event_base*/, ev_struct->fd, ev_type, network_mysqld_async_con_handle, user_data); \
		chassis_event_add_with_timeout(srv, &(ev_struct->event), timeout);

	// processing special state
	if (events == EV_READ) {
		int b = -1;

		if (ioctl(con->server->fd, FIONREAD, &b)) {
			g_error("ioctl(%d, FIONREAD, ...) failed: %s", event_fd,
					strerror(errno));
			con->state = CON_STATE_ASYNC_ERROR;
		} else if (b != 0) {
			con->server->to_read = b;
		} else {
			g_debug(
					"%s.%d: CON_STATE_ASYNC_ERROR EV_READ addr=%s errno=%d error:%s",
					__FILE__, __LINE__, con->server->dst->name->str, errno,
					strerror(errno));
			errno = 0;
			if (errno == 0 || errno == EWOULDBLOCK) {
				g_critical("why can this happen");
				return;  //simply do nothing
			} else {
				con->state = CON_STATE_ASYNC_ERROR;
				//g_error("%s.%d: CON_STATE_ASYNC_ERROR EV_READ addr=%s errno=%d error:%s", __FILE__, __LINE__, con->server->dst->name->str, errno, strerror(errno));
			}
			return;
		}
	}

	do {
		ostate = con->state;
		if (con->state != CON_STATE_ASYNC_INIT)
			g_debug("%s.%d SOCKET=%d: async_state=%s, events=%s.", __FILE__,
					__LINE__, con->server->fd, sz_async_state[con->state],
					get_event_name(events));

		switch (con->state) {

		/*防止 enumeration value 'CON_STATE_ASYNC_READ_SELECT_DB' not handled in switch*/
		case CON_STATE_ASYNC_READ_SELECT_DB:
			//g_assert_not_reached();
			g_critical(
					"[%s]: should not reached to CON_STATE_ASYNC_READ_SELECT_DB",
					G_STRLOC);
			break;

		case CON_STATE_ASYNC_NONE:
		{
			g_debug("CON_STATE_ASYNC_NONE");
			// this state indicates that connection was established
			// we should make sure that the recv_queue of server if cleared
			if (con->server->recv_queue->chunks != NULL ) {
				GList *tmp = con->server->recv_queue->chunks->head;
				if (tmp != NULL ) {
					GString *packet = (GString *) (tmp->data);
					g_queue_delete_link(con->server->recv_queue->chunks, tmp);
					g_string_free(packet, TRUE);
				}
			}
			network_mysqld_async_con_free(con);
			return;
		} // end of CON_STATE_ASYNC_NONE

		case CON_STATE_ASYNC_ERROR:
		{
			g_critical("[%s] :CON_STATE_ASYNC_ERROR %s failed: %s", G_STRLOC,
				((con->server != NULL ) && (con->server->dst != NULL) && (con->server->dst->name)) ? con->server->dst->name->str : "srv", g_strerror(errno));
			// 这里我们需要将该连接对应的pending连接数减1
			// 接下来需要将pending的连接数减1
			network_backend_t * bk_l = network_backends_get_by_name(srv->priv->backends, con->backend_addr->str);
			if (!bk_l) {
				g_warning("[%s]: get backend: %s error when want to free server_connection_state", G_STRLOC, con->backend_addr->str);
				network_mysqld_async_con_free(con);
				return;
			}
			update_conn_pool_status_in_state(bk_l->pool[con->type], con->username->str, POOL_STATUS_STATE_NOT_CONNECTED);

			network_mysqld_async_con_free(con);
			return;
		} // end of CON_STATE_ASYNC_ERROR

		case CON_STATE_ASYNC_INIT://proxy_async_init
		{
			g_debug("[%s]: this sentence should not be reached",G_STRLOC);
			func = con->plugins.con_init;
			if ((ret = (*func)(srv, con)) != 0 )
				g_critical("[%s]: CON_STATE_ASYNC_INIT returned an error = %d", G_STRLOC, ret);
			con->state = CON_STATE_ASYNC_READ_HANDSHAKE;
			break;
		} // end of CON_STATE_ASYNC_INIT

		case CON_STATE_ASYNC_READ_HANDSHAKE://proxy_async_read_handshake
		{
			g_assert(events == 0 || event_fd == con->server->fd);

			switch (network_mysqld_read(con->srv, con->server))
			{
			case NETWORK_SOCKET_SUCCESS:
				g_debug("[%s]: have read handshake packet to recv_queue of socket=%d successfully", G_STRLOC, con->server->fd);
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				/* call us again when you have a event */
				ASYNC_WAIT_FOR_EVENT(con->server, EV_READ, NULL);
				return;
			case NETWORK_SOCKET_ERROR:
			case NETWORK_SOCKET_ERROR_RETRY:
				g_critical("%s.%d: plugin_call(CON_STATE_ASYNC_READ_HANDSHAKE) returned an error", __FILE__, __LINE__);
				con->state = CON_STATE_ASYNC_ERROR;
				break;
			}

			if ( con->state == CON_STATE_ASYNC_ERROR )
				break;

			func = con->plugins.con_read_handshake;
			switch( (*func)(srv, con) )
			{
			case RET_SUCCESS:
				con->state = CON_STATE_ASYNC_CREATE_AUTH;
				break;
			case RET_ERROR:
				/**
				 * we couldn't understand the pack from the server we have
						 something in the queue and will send it to the client
						 and close the connection afterwards
				 */
				con->state = CON_STATE_ASYNC_ERROR;
				g_critical("%s.%d: CON_STATE_ASYNC_READ_HANDSHAKE con_read_handshake failed returned an error", __FILE__, __LINE__);
				break;
			default:
				con->state = CON_STATE_ASYNC_ERROR;
				g_critical("%s.%d: ...", __FILE__, __LINE__);
				break;
			}

			break;
		} // end of CON_STATE_ASYNC_READ_HANDSHAKE

		case CON_STATE_ASYNC_CREATE_AUTH:
		{
			g_debug("[%s]: proxy creating auth packet for connection from proxy to client", G_STRLOC);
			/* no need to send a handshake to the client, SpockProxy
					 logs into the database itself. */

			func = con->plugins.con_create_auth;
			switch ( (*func)(srv, con) )
			{
			case RET_SUCCESS:
				break;
			case RET_ERROR:
			{
				GList *chunk = con->server->send_queue->chunks->head;
				if ( chunk != NULL )
				{
					//con->server->packet_len = PACKET_LEN_UNSET;
					g_string_free((GString *)(chunk->data), TRUE );
					g_queue_delete_link(con->server->send_queue->chunks, chunk);
				}

				con->state = CON_STATE_ASYNC_ERROR;
				g_critical("%s.%d: plugin_call(CON_STATE_ASYNC_SEND_AUTH) returned an error", __FILE__, __LINE__);
				break;
			}
			default:
				g_error("%s.%d: unexpected return from plugins.con_create_auth.", __FILE__, __LINE__);
				break;
			} // end of switch

			// make sure that server recv_queue is empty
			if ( con->server->recv_queue->chunks != NULL )
			{
				GList *chunk = con->server->recv_queue->chunks->head;
				if ( chunk != NULL )
				{
					GString *packet = (GString *)(chunk->data);
					g_queue_delete_link(con->server->recv_queue->chunks,
							chunk);
					g_string_free( packet, TRUE );
				}
			}
			con->state = CON_STATE_ASYNC_SEND_AUTH;
			break;
		} // end of CON_STATE_CREATE_AUTH

		case CON_STATE_ASYNC_SEND_AUTH:
		{
			/* send auth packet from PROXY ---- to ---> SERVER */

			/* send the auth-response to the server */
			switch (network_mysqld_write(srv, con->server))
			{
			case NETWORK_SOCKET_SUCCESS:
				con->state = CON_STATE_ASYNC_READ_AUTH_RESULT;
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				con->state = CON_STATE_ASYNC_READ_AUTH_RESULT;
				ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
				return;
			case NETWORK_SOCKET_ERROR:
			case NETWORK_SOCKET_ERROR_RETRY:
				con->state = CON_STATE_ASYNC_ERROR;
				/* might be a connection close, we should just close
						 the connection and be happy */
				g_critical("[%s]: network_mysqld_write(CON_STATE_ASYNC_SEND_AUTH) returned an error", G_STRLOC);
				return;
			}

			break;
		} // end of CON_STATE_ASYNC_SEND_AUTH

		case CON_STATE_ASYNC_READ_AUTH_RESULT:
		{
			/* SERVER -------> PROXY read the auth result from the server */
			GList *chunk;
			GString *packet;

			g_assert(events == 0 || event_fd == con->server->fd);

			switch (network_mysqld_read(con->srv, con->server))
			{
			case NETWORK_SOCKET_SUCCESS:
				g_debug("[%s]: read auth result packet from server successfully", G_STRLOC);
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				ASYNC_WAIT_FOR_EVENT(con->server, EV_READ, NULL);
				return;
			case NETWORK_SOCKET_ERROR:
			case NETWORK_SOCKET_ERROR_RETRY:
				con->state = CON_STATE_ASYNC_ERROR;
				//g_error("%s.%d: network_mysqld_read(CON_STATE_ASYNC_READ_AUTH_RESULT) returned an error", __FILE__, __LINE__);
				break;
			}

			if ( con->state == CON_STATE_ASYNC_ERROR )
				break;

			/**
			 * depending on the result-set we have different exit-points
			 * - OK  -> READ_QUERY
			 * - EOF -> (read old password hash)
			 * - ERR -> ERROR
			 */
			chunk = con->server->recv_queue->chunks->head;
			packet = (GString *)(chunk->data);
			g_assert(packet);
			g_assert(packet->len > NET_HEADER_SIZE);
			//con->parse.state.auth_result.state = packet->str[NET_HEADER_SIZE];

			func = con->plugins.con_read_auth_result;
			switch( (*func)(srv, con) )
			{
			case RET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_ASYNC_READ_AUTH_RESULT) != RET_SUCCESS", __FILE__, __LINE__);
				con->state = CON_STATE_ASYNC_ERROR;
				break;
			}

			if ( con->state == CON_STATE_ASYNC_ERROR )
				break;

			switch ( (guchar)(packet->str[NET_HEADER_SIZE]) )
			{
			case MYSQLD_PACKET_OK:
			{
				// now add to the backend pool associated to
				// this configuration
				con->state = CON_STATE_ASYNC_NONE;
				break;
			}
			case MYSQLD_PACKET_ERR:
				g_critical("%s.%d: error in response for SEND_ASYNC_AUTH_RESULT: %02x", __FILE__, __LINE__, packet->str[NET_HEADER_SIZE]);
				con->state = CON_STATE_ASYNC_ERROR;
				break;
			case MYSQLD_PACKET_EOF:
				/* the MySQL 4.0 hash in a MySQL 4.1+ connection */
				con->state = CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD;
				break;
			default:
				g_critical("%s.%d:unexpected state in ASYNC_READ_AUTH_RESULT:%02x",__FILE__, __LINE__, packet->str[NET_HEADER_SIZE]);
				con->state = CON_STATE_ASYNC_ERROR;
				break;
			}

			//con->server->packet_len = PACKET_LEN_UNSET;
			//delete the auth result packet from server recv_queue
			//g_string_free(con->server->recv_queue->chunks, chunk);
			g_string_free(g_queue_pop_tail(con->server->recv_queue->chunks), TRUE);
			//g_string_free( packet, TRUE );

			if ( con->state == CON_STATE_ASYNC_ERROR )
			{
				break;
			}

			// if there is a default db send the request to select it
			// we will not set db for connection create recently. but when shall we add and to where?
			// added by jinxuan hou
			/*
			if ( NULL != con->server->default_db )
			{
				 network_mysqld_con_send_select_db(con->server,
				 con->server->default_db->str);

				 START_PERF( con->server, con->server->addr.str, PF_SEND );
				 switch (network_mysqld_write(srv, con->server))
				 {
				 case RET_SUCCESS:
					 END_PERF( con->server, PF_SEND );
					 con->state = CON_STATE_ASYNC_READ_SELECT_DB;
					 break;
				 case RET_WAIT_FOR_EVENT:
					 con->state = CON_STATE_ASYNC_READ_SELECT_DB;
					 ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
					 return;
				 case RET_ERROR:
				 	 {
					 con->state = CON_STATE_ASYNC_ERROR;
					 log_warning("%s.%d: network_mysqld_write(CON_STATE_ASYNC_READ_AUTH_RESULT) returned an error", __FILE__, __LINE__);
					 break;
				 	 }
			 	 }
			}
			else
			*/
			if ( con->state == CON_STATE_ASYNC_NONE )
			{
				// define an ending point for the connection
				g_debug("[%s]: adding connection to the pool of server=%s, fd=%d", G_STRLOC, con->server?con->server->dst->name->str:"NONE", con->server->fd);
				network_backend_t * bk_l = network_backends_get_by_name(srv->priv->backends, con->backend_addr->str);
				//if (!bk_l) {
				//	g_warning("[%s]: get backend: %s error when want to free server_connection_state", G_STRLOC, backend);
				//}
				g_assert(bk_l);
				struct pool_status * pool_s = get_count_of_conn_status(bk_l, con->username->str, con->type);
				g_assert(pool_s);
				/*
						 if (!pool_s) {
						 g_warning("[%s]: get pool status for user: %s at backend: %s", G_STRLOC, username, backend);
						 pool_s = g_new(struct pool_status, 1);
						 // 没有加锁
						 pool_s->idle = 1;
						 pool_s->pending = 0;
						 pool_s->using = 0;
						 }*/
				//g_mutex_lock(&(pool_s->status_mutex));
				//if (pool_s->conn_num_in_pending >0) {
				//	pool_s->conn_num_in_pending--;
				//	pool_s->conn_num_in_idle++;
				//}
				//g_mutex_unlock(&(pool_s->status_mutex));
				network_mysqld_pool_async_con_add_soket(con, con->server);
				con->server = NULL;

				/*这里直接释放了con，所以不会到达CON_STATE_ASYNC_NONE状态*/
				network_mysqld_async_con_free(con);
				return;
			}
			break;
		} // end of CON_STATE_ASYNC_READ_AUTH_RESULT

		case CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD:
		{
			// 不会做后续的工作,我们应该在这里实现旧式密码的认证方式
			// 这个可以在后续实现
			/**
			 * @todo 这个可以在后续实现旧式密码的认证方式
			 */
			break;
		} // end of CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD

		case CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORDS:
		{
			// 只是直接向server发送auth-response数据包吗？
			// 其实现在server->send_queue 里面数据时空的，调用network_mysqld_write会直接返回正确
			/* send the auth-response to the server */
			switch (network_mysqld_write(srv, con->server)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
				return;
			case NETWORK_SOCKET_ERROR:
				con->state = CON_STATE_ASYNC_ERROR;
				/* might be a connection close, we should just close the connection and be happy */
				g_critical("%s.%d: network_mysqld_write(CON_STATE_SEND_AUTH_OLD_PASSWORD) returned an error", __FILE__, __LINE__);
				return;
				/*防止 enumeration value 'NETWORK_SOCKET_ERROR_RETRY' not handled in switch*/
			case NETWORK_SOCKET_ERROR_RETRY:
				g_critical("[%s]: should not reached to NETWORK_SOCKET_ERROR_RETRY", G_STRLOC);
				//g_assert_not_reached();
				return;
			}

			func = con->plugins.con_send_auth_old_password;
			switch( (*func)(srv, con) ) {
			case RET_SUCCESS:
				break;
			default:
				g_error("%s.%d: plugin_call(CON_STATE_SEND_AUTH_OLD_PASSWORD) != RET_SUCCESS", __FILE__, __LINE__);
				break;
			}

			break;
		} // end of CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORDS

		} // end of switch
		event_fd = -1;
		events = 0;
	} while (ostate != con->state);

	return;
}


/**
 * added by jinxuan hou, for asynchronous connection established
 * 1. init                      :do nothing
 * 2. read_handshake            :process handshake packet from mysql server
 * 3. create auth packet        :create auth packet
 * 4. read auth result          :read auth result from mysql server
 *
 * @@ jinxuanhou
 */

// proxy init do nothing
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_init)
{
	(void)(srv);
	(void)(con);
	return RET_SUCCESS;
}

/**
 * parse the hand-shake packet from the server
 *
 * modified by jinxuan hou, 2013/04/11
 * @note the SSL and COMPRESS flags are disabled as we can't
 *       intercept or parse them.
 */
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_read_handshake) {
	network_packet hd_packet; // 数据包变量
	network_socket *recv_sock;

	(void)(srv);
	recv_sock = con->server;

	hd_packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks); //获取第一个数据包数据
	hd_packet.offset = 0;

	int err = 0;

	guint length = network_mysqld_proto_get_packet_len(hd_packet.data);

	// 考虑的情况包括：包过短，server端直接拒绝连接，接着判断协议版本，
	// 然后根据server端发送过来的随机包对密码加密（密码的需要从注册的用户中查询）
	if (hd_packet.data->len != length + NET_HEADER_SIZE) {
		g_critical("[%s]: handshake packet too small", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}

	if (hd_packet.data->str[NET_HEADER_SIZE + 0] == '\xff') {
		/** mysql server do not like us and sends a ERR packet */
		g_critical("[%s]: handshake packet error", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	} else if (hd_packet.data->str[NET_HEADER_SIZE + 0] != '\x0a') {
		/** the server is not 4.1+ server, send client a ERR packe*/
		g_critical("[%s]: handshake packet error , < version 4.1 server",
				G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}

	/** scanf for a \0 */
	gsize off = 0;
	for (off = NET_HEADER_SIZE + 1;
			off < hd_packet.data->len + NET_HEADER_SIZE
					&& hd_packet.data->str[off]; off++)
		;
	if (hd_packet.data->str[off] != '\0') {
		/** the server has sent us garbage*/
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}

	gint maj, min, patch;
	if (3
			!= sscanf(hd_packet.data->str + NET_HEADER_SIZE + 1, "%d.%d.%d%*s",
					&maj, &min, &patch)) {
		/* can't parse the protocol */
		//recv_sock->packet_len = PACKET_LEN_UNSET;
		//g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		//g_string_free(packet, TRUE);
		g_critical("[%s]: handshake packet has invalid version", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}
	/** check the server version */
	if (min < 0 || min > 100 || patch < 0 || patch > 100 || maj < 0
			|| maj > 10) {
		g_critical("[%s]: version is out of range", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}

	err = err || network_mysqld_proto_skip_network_header(&hd_packet);
	if (err) {
		g_critical("[%s]: mysql packet skip network header error", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}

	guint8 status = 0;
	err = err || network_mysqld_proto_peek_int8(&hd_packet, &status);
	if (err) {
		g_critical("[%s]: mysql packet get server status error", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		return RET_ERROR;
	}

	network_mysqld_auth_challenge * challenge =
			network_mysqld_auth_challenge_new();

	// 解析server端发送的handshake包，并构造对应的结构变量
	/**
	 * struct network_mysqld_auth_challenge {
	 * guint8    protocol_version;
	 * gchar    *server_version_str;
	 * guint32   server_version;
	 * guint32   thread_id;
	 * GString  *auth_plugin_data;
	 * guint32   capabilities;
	 * guint8    charset;
	 * guint16   server_status;
	 * GString  *auth_plugin_name;
	 * };
	 * 与handshake 包的结构一一对应（当然是非0xff开头的包）
	 */
	if (network_mysqld_proto_get_auth_challenge(&hd_packet, challenge)) {
		g_critical("[%s]: get server handshake packet error", G_STRLOC);
		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
		network_mysqld_auth_challenge_free(challenge);
		return RET_ERROR;
	}

	con->server->challenge = challenge;

	/* we can't sniff compressed packets nor do we support SSL */
	challenge->capabilities &= ~(CLIENT_COMPRESS);
	challenge->capabilities &= ~(CLIENT_SSL);

	/** bug fix !! */
    const gchar *charset = charset_dic[challenge->charset];
    const gchar *collation = collation_dic[challenge->charset];

	if (0 != g_ascii_strcasecmp(con->server->character_set_connection->str, charset)) {
		g_string_truncate(con->server->character_set_connection, 0);
		g_string_append(con->server->character_set_connection, charset);
	}

	if (0 != g_ascii_strcasecmp(con->server->collection_connect->str, collation)) {
		g_string_truncate(con->server->collection_connect, 0);
		g_string_append(con->server->collection_connect, collation);
	}

	if (0 != g_ascii_strcasecmp(con->server->character_set_results->str, charset)) {
		g_string_truncate(con->server->character_set_results, 0);
		g_string_append(con->server->character_set_results, charset);
	}

#if 0
	switch (proxy_lua_read_handshake(con)) {
		case PROXY_NO_DECISION:
		break;
		case PROXY_SEND_QUERY:
		/* the client overwrote and wants to send its own packet
		 * it is already in the queue */

		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		return RET_ERROR;
		default:
		log_error("%s.%d: ...", __FILE__, __LINE__);
		break;
	}
#endif

	/*
	 * move the packets from the server queue
	 */
	//g_string_free(hd_packet.data, TRUE);
	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

	g_debug("[%s]: get server handshake packet successfullly", G_STRLOC);
	return RET_SUCCESS;
}

/**
 * added by jinxuan hou
 * process the auth packet send from proxy to mysql server
 * something as follow will be considered.
 * 1. Client capability
 * 2. username
 * 3. scrambled password
 *      Result Format:
 *              4 byte Mysql-Packet Header
 *              4 byte CLIENT_FLAGS
 *              4 byte PACKET LENGTH
 *              1 byte CHARSET
 *              23 byte UNKNOWN
 *              N bytes USERNAME
 *              N bytes SCRAMBLED PASSOWRD
 *(opt) N bytes DEFAULT_DB
 *
 *
 *  Example:
 *      38 00 00 01 85 a6 03 00  8 . . . . . . .
 *      00 00 00 01 08 00 00 00  . . . . . . . .
 *      00 00 00 00 00 00 00 00  . . . . . . . .
 *      00 00 00 00 00 00 00 00  . . . . . . . .
 *      00 00 00 00 73 61 00 14  . . . . s a . .
 *      4b 0c 15 84 3e b0 b0 d6  K . . . > . . .
 *      66 eb 04 47 0d 68 a1 df  f . . G . h . .
 *      84 5f 09 98  . _ . .
 *
 */
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_create_auth) {
	/* create auth for proxy as a client */
	network_socket *send_sock;
	char scrambled[256];
	GString *new_packet;
	GString *packet;

	g_assert(con);
	g_assert(con->srv);
	g_assert(con->server);
	g_assert(con->username);

	(void)(srv);
	send_sock = con->server;

	/**
	 * @\0\0\1
	 *  \215\246\3\0 - client-flags
	 *  \0\0\0\1     - max-packet-len
	 *  \10          - charset-num
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0       - fillers
	 *  root\0       - username
	 *  \24          - len of the scrambled buf
	 *    ~    \272 \361 \346
	 *    \211 \353 D    \351
	 *    \24  \243 \223 \257
	 *    \0   ^    \n   \254
	 *    t    \347 \365 \244
	 *
	 *  world\0
	 */

	// 4 byte packet header
	// 4 byte CLIENT_FLAGS
	// 4 byte PACKET LENGTH
	// 1 byte CHARSET
	// 23 byte UNKNOWN
	// N bytes USERNAME
	// N bytes SCRAMBLED PASSOWRD
	// N bytes DEFAULT_DB
	guint32 client_flags;
	network_mysqld_auth_response *auth;

	if (con->server->challenge) {
		auth = network_mysqld_auth_response_new(
				con->server->challenge->capabilities);
		client_flags = con->server->challenge->capabilities;
	} else {
		g_debug(
				"[%s]: capability of server in handshake packet is null, will be setted to be default client flags",
				G_STRLOC);
		auth = network_mysqld_auth_response_new((guint32) DEFAULT_FLAGS);
		client_flags = (guint32) DEFAULT_FLAGS;
	}
	con->server->response = auth;
	//note: in the pool connection without db is prefered
	client_flags &= ~CLIENT_CONNECT_WITH_DB;
	client_flags &= ~CLIENT_NO_SCHEMA;
	client_flags &= ~CLIENT_MULTI_STATEMENTS;
	client_flags = client_flags | CLIENT_FOUND_ROWS;

	//auth = network_mysqld_auth_response_new(client_flags);
	if (!auth) {
		g_critical("[%s]: create auth packet error", G_STRLOC);
		return RET_ERROR;
	}

	auth->client_capabilities = client_flags;
	//set charset for this connection, default charset is utf
	auth->charset = con->srv->collation_index;

	const gchar *charset = charset_dic[auth->charset];
	/** 同样的问题，auth数据包只是影响到con->server->character_set_client */
	if (0
			!= g_ascii_strcasecmp(con->server->character_set_client->str,
					charset)) {
		g_string_truncate(con->server->character_set_client, 0);
		g_string_append(con->server->character_set_client, charset);
	}
	// server端连接的字符集也需要根据auth 包的字符集做相应的修改
	if (0
			!= g_ascii_strcasecmp(con->server->character_set_connection->str,
					charset)) {
		g_string_truncate(con->server->character_set_connection, 0);
		g_string_append(con->server->character_set_connection, charset);
	}
	if (0
			!= g_ascii_strcasecmp(con->server->character_set_results->str,
					charset)) {
		g_string_truncate(con->server->character_set_results, 0);
		g_string_append(con->server->character_set_results, charset);
	}

	// we should get the username and password from the user_infos hashtable
	if (!con->username) {
		g_critical("[%s]: we should not create connection without username",
				G_STRLOC);
		return RET_ERROR;
	}
	// 为后端连接对应的username赋值，主要是连接建立完成之后会放到连接池是用到
	g_string_append_len(auth->username, con->username->str, con->username->len);

	GString *passwd = get_passwd_for_user(con->username, con->srv);
	if (!passwd) {
		g_warning("[%s]: get NULL for password of user: %s", G_STRLOC,
				con->username->str);
	}

	new_packet = g_string_new(NULL );

	// skip puting the header
	//network_mysqld_proto_append_int32( new_packet, (guint32)0 );

	// 4 byte CLIENT_FLAGS
	//network_mysqld_proto_append_int32( new_packet, (guint32)client_flags);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0x0003a685);

	// 4 byte max packet length
	network_mysqld_proto_append_int32(new_packet, (guint32) 0x01000000);
	// 1 byte CHARSET
	network_mysqld_proto_append_int8(new_packet, (guint8) auth->charset);

	// 23 byte zero buffer
	network_mysqld_proto_append_int8(new_packet, (guint8) 0);
	network_mysqld_proto_append_int16(new_packet, (guint16) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);

	// N bytes USERNAME
	g_string_append_len(new_packet, con->username->str, con->username->len);
	g_string_append_c(new_packet, '\0');

	// N bytes scrambled password
	memset((void*) scrambled, 0, sizeof(scrambled));

	//g_string_truncate(send_sock->scramble_buf, SCRAMBLE_LENGTH);
	//g_string_append_c(send_sock->scramble_buf, '\0');
	g_string_truncate(con->server->challenge->auth_plugin_data,
			SCRAMBLE_LENGTH);
	g_string_append_c(con->server->challenge->auth_plugin_data, '\0');

	if (passwd) {
		g_string_append_c(passwd, '\0');
		mysql_scramble(scrambled, con->server->challenge->auth_plugin_data->str,
				passwd->str);
		/**
		 * @author sohu-inc.com
		 * 这里对passwd做了操作，现在改成各自复制一份，记得释放内存
		 */
		g_string_free(passwd, TRUE);
		passwd = NULL;
	} else {
		mysql_scramble(scrambled, con->server->challenge->auth_plugin_data->str,
				"");
	}

	g_string_truncate(auth->auth_plugin_data, 0);
	g_string_append_len(auth->auth_plugin_data, scrambled, SCRAMBLE_LENGTH);

	g_string_append_c(new_packet, SCRAMBLE_LENGTH);
	g_string_append_len(new_packet, scrambled, SCRAMBLE_LENGTH);

	// 1 byte filler, we do not need this ?
	// g_string_append_c(new_packet, '\0');

	// N bytes default_db (optional) - zero terminated??
	// with pool and user can access several db, we will not set the default
	if (NULL != NULL ) {
		//g_string_append_len(new_packet, con->config->default_db->str, con->config->default_db->len);

		// null terminated?
		g_string_append_len(new_packet, "test", 4);
		g_string_append_c(new_packet, '\0');
	}

	packet = g_string_new(NULL );
	network_mysqld_proto_append_int16(packet, (guint16) new_packet->len);
	network_mysqld_proto_append_int8(packet, 0);
	network_mysqld_proto_append_int8(packet, 0x1);
	g_string_append_len(packet, new_packet->str, new_packet->len);

	network_queue_append_chunk(send_sock->send_queue, packet);

	g_string_free(new_packet, TRUE);
	con->server->last_packet_id += (guint) 1;

	return RET_SUCCESS;
}

/**
 * added by jinxuan hou
 * read the authentication result from the database server
 * can do nothing
 */
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_read_auth_result) {
	(void)(srv);
	(void)(con);
	return RET_SUCCESS;
}




/**
 * added by jinxuan hou
 * for asynchronous connection establish
 * the states are
 * @@jinxuanhou
 */

/**
 * added by jinxuan hou
 * to get the event name for events
 * @param events 事件
 */
static const char *get_event_name(int events)
{
    static char name[64];
    name[0] = 0;

    if (events & EV_TIMEOUT)
        strcat(name, "|EV_TIMEOUT");
    if (events & EV_READ)
        strcat(name, "|EV_READ");
    if (events & EV_WRITE)
        strcat(name, "|EV_WRITE");
    if (events & EV_SIGNAL)
        strcat(name, "|EV_SIGNAL");
    if (events & EV_PERSIST)
        strcat(name, "|EV_PERSIST");

    if (name[0] == '\0')
        return "NONE";
    else
        return name + 1;
}


/**
 * add by jinxuan hou
 * Add the connection established asynchronously to the pool related
 * @param pscs  :the server_connection_state parameter with a authed mysql connection
 *
 * @return      int SUCCESS 0, FAILED -1
 */
gboolean network_mysqld_pool_async_con_add_soket(server_connection_state *con, network_socket *sock) {
	proxy_rw type;
	chassis *srv = NULL;
	network_backend_t *bk_end = NULL;
	network_connection_pool_entry *entry = NULL;

	g_assert(con);
	g_assert(sock);
	g_assert(con->srv);
	g_assert(con->srv->priv);
	g_assert(con->srv->priv->backends);

	type = con->type;
	srv = con->srv;

	bk_end = network_backends_get_by_name(srv->priv->backends, sock->dst->name->str);
	if (!bk_end) {
		g_critical("[%s] : get backend for connection error", G_STRLOC);
		network_socket_free(sock);
		return FALSE;
	}

	entry = network_connection_pool_add(bk_end->pool[type], sock);
	if (entry == NULL) {
		g_critical("[%s]: add connect to pool for server = %s error", G_STRLOC,
				sock->dst->name->str);
		// 连接加入到连接池失败。pending--,同时释放连接
		update_conn_pool_status_in_state(bk_end->pool[type],
				sock->response->username->str, POOL_STATUS_STATE_NOT_CONNECTED);

		network_socket_free(sock);
		return FALSE;
	}

	// 4. 修正连接池统计信息，连接释放到连接池中,pending--,idle++
	update_conn_pool_status_in_state(bk_end->pool[type],
			sock->response->username->str, POOL_STATUS_STATE_PUT_INTO_POOL);

	// 5. backend 对应的活动链接处--
	//client_desc(bk_end, type);

	return TRUE;
}














/**
 * 在指定的一个backend上面为指定的用户创建单个连接
 *
 * 只负责创连接的创建，pending++ 在调用该函数的函数中进行，
 * +另外pending-- 操作需要在连接创建过程中进行，包括idle的++操作
 *
 * @param[IN] username 连接池对应的用户名
 * @param[IN] backend 连接池对应的backend包括ip+port
 * @param[IN] srv 对应dbproxy的全局环境变量
 */
void create_connection_on_backend_for_user(chassis *srv,
		network_backend_t *backend, const gchar *username, proxy_rw type) {
//	network_backend_t *backend = NULL;
	server_connection_state *pscs = NULL;

	g_assert(srv);
	g_assert(backend);
	g_assert(username);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);

//	bk_t = network_backends_get_by_name(srv->priv->backends, backend);
//	if (!bk_t)
//		return;

	pscs = network_mysqld_async_con_init(username, backend->addr->name->str, srv);
	pscs->type = type;
	//next we should connect to the backend,
	// 如果连接失败需要将pending的连接数减1

	/**
	 * @todo 需要考虑连接的重试，因为有时候因为设置socket为非阻塞返回
	 * 失败的情况，通过测试errno来判定，但是如果返回那个该如何重试呢？
	 * 如果调用mysql-proxy的socket的接口应该考虑这个情况。
	 * 为了避免过多的考虑这种情况暂时采用spock的做法，
	 * 先不管set_noblocking引起的connect错误。
	 */
	if (0 != network_mysqld_async_con_connect(srv, pscs)) {
		//backend->state = BACKEND_STATE_DOWN;
		//g_get_current_time(&(backend->state_since));

		// 接下来需要将pending的连接数减1
		update_conn_pool_status_in_state(backend->pool[type], username, POOL_STATUS_STATE_NOT_CONNECTED);

		network_mysqld_async_con_free(pscs);
		return;
	}

	g_debug("[%s]: SOCKET=%d: new backend connection, remote=%s.\n", G_STRLOC,
			pscs->server->fd, pscs->server->dst->name->str);

//	if (backend->state != BACKEND_STATE_UP) {
//		//backend->state = BACKEND_STATE_UP;
//		//g_get_current_time(&(backend->state_since));
//	}

#if 1
	// 将socket 设置为非阻塞的
#ifdef _WIN32
	ioctlvar = 1;
	ioctl(pscs->server->fd, FIONBIO, &ioctlvar);
#else
	fcntl(pscs->server->fd, F_SETFL, O_NONBLOCK | O_RDWR);
#endif
#endif

	pscs->state = CON_STATE_ASYNC_READ_HANDSHAKE;
	g_get_current_time(&(pscs->lastused));

	// add a EV_READ event, because we just connected to the serve
	g_debug("[%s]: SOCKET=%d: wait for event EV_READ.", G_STRLOC,
			pscs->server->fd);

	// we we expect to read data from the server
	struct timeval tv;
	tv.tv_sec = 45;  //<@fixme for test 7200  max_backend_connect_timeout
	tv.tv_usec = 0;

//	event_set(&(pscs->server->event), pscs->server->fd, EV_READ,
//			network_mysqld_async_con_handle, pscs);
	event_assign(&(pscs->server->event), NULL /*srv->event_base*/, pscs->server->fd, EV_READ,
			network_mysqld_async_con_handle, pscs);
	chassis_event_add_with_timeout(srv, &(pscs->server->event), &tv);

	// add the pending connection to the array(in case
	// of failure or network connection we can clean this up
	//g_ptr_array_add( backend->pending_dbconn, pscs);

	/*
	// we already performed the connecte_server, look for
	// handshake
	pscs->state = CON_STATE_ASYNC_READ_HANDSHAKE;

	// update the time we last used this object
	g_get_current_time(&(pscs->lastused));
	*/

	return;
}

/**
 * 在指定的一个backend上面为指定的用户创多个建连接
 */
void create_many_connections_on_backend_for_user(chassis *srv,
		network_backend_t *backend, const gchar *username, proxy_rw type,
		guint count) {
	guint index = 1;

	g_assert(srv);
	g_assert(backend);
	g_assert(username);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);

	for (index = 1; index <= count; index++) {
		create_connection_on_backend_for_user(srv, backend, username, type);
	}
	return;
}

/**
 * 在指定的多个backend上面分别建立一个连接
 */
void create_connections_on_many_backends_for_user(chassis *chas,
		GPtrArray *backends_array, const gchar *username, proxy_rw type) {
	guint index = 0;
	GString *backend_name = NULL;
	network_backend_t *backend = NULL;

	g_assert(chas);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);
	g_assert(chas->priv);

	if (!backends_array) {
		g_critical("[%s]: backend null", G_STRLOC);
		return;
	}
	if (!username) {
		g_critical("[%s]: username null", G_STRLOC);
		return;
	}

	g_debug("[%s]: backends_array's length: %d", G_STRLOC, backends_array->len);
	for (index = 0; index < backends_array->len; index++) {
		/**
		 * 这里判断是否能够创建新的连接，先直接创建
		 * @todo 检查
		 */
		backend_name = (GString *) (backends_array->pdata[index]);

		backend = network_backends_get_by_name(chas->priv->backends,
				backend_name->str);
		if (!backend) {
			g_debug("[%s]: backend not found %s", G_STRLOC, backend_name->str);
			break; /*@fixme 不继续了？*/
		}

		//更新pending数目
		update_conn_pool_status_in_state(backend->pool[type], username,
				POOL_STATUS_STATE_INITIALIZED);

		// 创建连接
		create_connection_on_backend_for_user(chas, backend, username, type);
	}

	return;
}


#if 0
/**
 * 实现连接池的初始化工作
 * @author sohu-inc.com
 * @param chas 全局结构变量
 * @return void
 */
void init_connection_pool(chassis *chas) {
	guint index = 0;
	//gint count = 0;
	network_backend_t *bk;

	g_assert(chas);
	g_assert(chas->priv);
	g_assert(chas->priv->backends);

	for (index = 0; index < network_backends_count(chas->priv->backends); index++) {
		bk = network_backends_get(chas->priv->backends, index);
		if (!bk) {
			g_debug("[%s]: we have get all the backends ", G_STRLOC);
			break;
		}

		// 接下来遍历所有的用户列表，创建对应的连接池
		GHashTableIter iter;
		gpointer key, value;
		struct pool_status *status_tmp1, *status_tmp2;

		g_hash_table_iter_init(&iter, chas->user_infos);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			GString *user = (GString *) key;
			/* do something with key and value */
			// 我们接下来初始化创建pending数目的连接
			status_tmp1 = user_pool_status_add_new(
					bk->pool[PROXY_TYPE_WRITE]->conn_pool_status, user);
			network_connection_pool_create_conns(user->str, bk->addr->name->str,
					chas, 10, PROXY_TYPE_WRITE);

			status_tmp2 = user_pool_status_add_new(
					bk->pool[PROXY_TYPE_READ]->conn_pool_status, user);
			network_connection_pool_create_conns(user->str, bk->addr->name->str,
					chas, 10, PROXY_TYPE_READ);
		}
	}
}
#endif



/*eof*/
