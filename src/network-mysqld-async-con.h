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


#ifndef NETWORK_MYSQLD_ASYNC_CON_H_
#define NETWORK_MYSQLD_ASYNC_CON_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
/**
 * event.h needs struct timeval and doesn't include sys/time.h itself
 */
#include <sys/time.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#include <winsock2.h>
#endif

#include <mysql.h>
// added by jinxuan hou
#include <mysql_com.h>
#include <errmsg.h>

#include <glib.h>

#include "network-exports.h"

#include "network-socket.h"
#include "network-conn-pool.h"
#include "network-mysqld-packet.h"
#include "chassis-plugin.h"
#include "chassis-mainloop.h"
#include "chassis-timings.h"
#include "sys-pedantic.h"
//#include "lua-scope.h"
#include "network-backend.h"
//#include "lua-registry-keys.h"




/**
 * added by jinxuan hou, 2013/04/11
 * here are elements needed by server connection async init
 * 1. server connection state
 * 2. state machine processing functions
 * 3. 注意错误信息要准确。是不是异步的连接建立必须使用连接池了？不是（取连接的地方可以控制）
 * 4. 在创建的连接要放到backend的pengding列表中吗？（应该不是必须的?）
 *
 * @@jinxuanhou
 */


// 异步连接创建的状态
typedef enum async_con_state {
	CON_STATE_ASYNC_INIT, 			// 0
	CON_STATE_ASYNC_READ_HANDSHAKE,
	CON_STATE_ASYNC_CREATE_AUTH,
	CON_STATE_ASYNC_SEND_AUTH,
	CON_STATE_ASYNC_READ_AUTH_RESULT,
	CON_STATE_ASYNC_READ_SELECT_DB,
	CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD,
	CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORDS,
	CON_STATE_ASYNC_ERROR,
	CON_STATE_ASYNC_NONE
} async_con_state;


typedef enum {
        RET_SUCCESS,
        RET_WAIT_FOR_EVENT,
        RET_ERROR
} retval_t;

typedef struct server_connection_state server_connection_state;

#define NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(x) retval_t (*x)(chassis *srv, server_connection_state *con)
#define NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(x) retval_t x(chassis *srv, server_connection_state *con)

//  连接异步创建过程中的处理函数
typedef struct network_mysqld_async_plugins {
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_init);
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_read_handshake);
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_create_auth);
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_send_auth);
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_read_auth_result);
	NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_send_auth_old_password);
} network_mysqld_async_plugins;

// 用于标示与mysql server连接建立过程的中间状态
// 至少应该标示所属的backend由ip:port标示，所属的用户名：username
// 包含到后端的socket连接， 及连接异步创建过程的处理函数
struct server_connection_state {

	/* asynchornous connection states
	 */
	async_con_state	state;

	network_mysqld_async_plugins plugins;
	network_socket		*server;	/* database connection */
	chassis 		*srv; 		/* our srv object */
	GTimeVal 		lastused;   /** last time this object was talked to*/
	GString *backend_addr; //added by jinxuan hou, 用于标示该链接属于哪个backend 或者是增加一个backend的回指指针？
	GString *username; // added by jinxuan hou, 标示该链接对应的用户信息

	//added by sohu-inc.com, 2013/05/15
	proxy_rw type;
};
//typedef struct server_connection_state server_connection_state;


server_connection_state* network_mysqld_async_con_init(
		const gchar *username, const gchar *backend_str, chassis *srv);
void network_mysqld_async_con_free(server_connection_state *server_con_st);

int network_mysqld_async_con_connect(chassis *srv, server_connection_state *con);
void network_mysqld_async_con_handle(int event_fd, short events,
		void *user_data);
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_init);
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_read_handshake);
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_create_auth);
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_read_auth_result);



gboolean network_mysqld_pool_async_con_add_soket(server_connection_state *con, network_socket *sock);


void create_connection_on_backend_for_user(chassis *srv,
		network_backend_t *backend, const gchar *username, proxy_rw type);
void create_many_connections_on_backend_for_user(chassis *srv,
		network_backend_t *backend, const gchar *username, proxy_rw type,
		guint count);
void create_connections_on_many_backends_for_user(chassis *chas,
		GPtrArray *backends_array, const gchar *username, proxy_rw type);
// 连接池的初始化函数,这个函数放在哪里是个问题！
//void init_connection_pool(chassis *chas);



#endif /* NETWORK_MYSQLD_ASYNC_CON_H_ */
