/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.

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
#ifndef __NETWORK_MYSQLD_T__
#define __NETWORK_MYSQLD_T__

//#include <lua.h>

#include "network-backend.h" /* query-status */
#include "network-injection.h" /* query-status */

#include "network-exports.h"

typedef enum {
	PROXY_NO_DECISION,
	PROXY_SEND_QUERY,
	PROXY_SEND_RESULT,
	PROXY_SEND_INJECTION,
	PROXY_IGNORE_RESULT       /** for read_query_result */
} network_mysqld_stmt_ret;

typedef enum {
	REGISTER_CALLBACK_SUCCESS,
	REGISTER_CALLBACK_LOAD_FAILED,
	REGISTER_CALLBACK_EXECUTE_FAILED
} network_mysqld_register_callback_ret;

#if 0
NETWORK_API int network_mysqld_con_getmetatable(lua_State *L);
NETWORK_API void network_mysqld_lua_init_global_fenv(lua_State *L);
#endif

//NETWORK_API void network_mysqld_lua_setup_global(lua_State *L, chassis_private *g);

/**
 * Encapsulates injected queries information passed back from the a Lua callback function.
 * 
 * @todo Simplify this structure, it should be folded into network_mysqld_con_t.
 */
struct network_mysqld_con_injection {
	network_injection_queue *queries;	/**< An ordered list of queries we want to have executed. */
	int sent_resultset;					/**< Flag to make sure we send only one result back to the client. */
};
/**
 * Contains extra connection state used for Lua-based plugins.
 */
typedef struct {
	struct network_mysqld_con_injection injected;	/**< A list of queries to send to the backend.*/

	/**
	 * @author sohu-inc.com
	 * 下面两个变量用于存储上下文恢复或纠正sql语句执行的状态返回的bug
	 * 这里的两个变量的复制阶段？
	 * post_injected应该是在分析语句判定语句是set autocommit = 1且执行成功之后加进去
	 * pre_injected应该只是针对新分配的连接，在分配完连接之后对比字符集及database是否一样，不同需要加入相应的请求数据包。
	 */
	struct network_mysqld_con_injection pre_injected; //存放位于client执行语句之前，连接上下文恢复的语句
	struct network_mysqld_con_injection post_injected;//存放位于client执行语句之后，用于修正mysql-server状态，主要是对set autocommit=1 等隐式提交。

	//lua_State *L;                  /**< The Lua interpreter state of the current connection. */
	int L_ref;                     /**< The reference into the lua_scope's registry (a global structure in the Lua interpreter) */

	network_backend_t *backend;
	int backend_ndx;               /**< [lua] index into the backend-array */

	gboolean connection_close;     /**< [lua] set by the lua code to close a connection */

	struct timeval interval;       /**< The interval to be used for evt_timer, currently unused. */
	struct event evt_timer;        /**< The event structure used to implement the timer callback, currently unused. */

	gboolean is_reconnecting;      /**< if true, critical messages concerning failed connect() calls are suppressed, as they are expected errors */
} network_mysqld_con_t;

NETWORK_API network_mysqld_con_t *network_mysqld_con_t_new();
NETWORK_API void network_mysqld_con_t_free(network_mysqld_con_t *st);

/** be sure to include network-mysqld.h */
//NETWORK_API network_mysqld_register_callback_ret network_mysqld_con_lua_register_callback(network_mysqld_con *con, const char *lua_script);
//NETWORK_API int network_mysqld_con_lua_handle_proxy_response(network_mysqld_con *con, const char *lua_script);

#endif
