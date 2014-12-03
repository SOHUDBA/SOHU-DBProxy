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
 

#ifndef _NETWORK_MYSQLD_H_
#define _NETWORK_MYSQLD_H_

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

#include <glib.h>

#include "network-exports.h"

#include "network-socket.h"
#include "network-conn-pool.h"
#include "chassis-plugin.h"
#include "chassis-mainloop.h"
#include "chassis-timings.h"
#include "sys-pedantic.h"
//#include "lua-scope.h"
#include "network-backend.h"
//#include "lua-registry-keys.h"
#include "network-para-exec-process.h"
#include "network-dura-exec-process.h"
#include "network-mysql-error.h"
#include "network-sql-normalization.h"
#include "network-connection-state.h"

// 已经被转移到了chassis-mainloop.h中
//typedef struct network_mysqld_con network_mysqld_con; /* forward declaration */

#undef NETWORK_MYSQLD_WANT_CON_TRACK_TIME
#ifdef NETWORK_MYSQLD_WANT_CON_TRACK_TIME
#define NETWORK_MYSQLD_CON_TRACK_TIME(con, name) chassis_timestamps_add(con->timestamps, name, __FILE__, __LINE__)
#else
#define NETWORK_MYSQLD_CON_TRACK_TIME(con, name) 
#endif

/**
 * A macro that produces a plugin callback function pointer declaration.
 */
#define NETWORK_MYSQLD_PLUGIN_FUNC(x) network_socket_retval_t (*x)(chassis *, network_mysqld_con *)
/**
 * The prototype for plugin callback functions.
 * 
 * Some plugins don't use the global "chas" pointer, thus it is marked "unused" for GCC.
 */
#define NETWORK_MYSQLD_PLUGIN_PROTO(x) static network_socket_retval_t x(chassis G_GNUC_UNUSED *chas, network_mysqld_con *con)

/**
 * The function pointers to plugin callbacks for each customizable state in the MySQL Protocol.
 * 
 * Any of these callbacks can be NULL, in which case the default pass-through behavior will be used.
 * 
 * The function prototype is defined by #NETWORK_MYSQLD_PLUGIN_PROTO, which is used in each plugin to define the callback.
 * #NETWORK_MYSQLD_PLUGIN_FUNC can be used to create a function pointer declaration.
 */
typedef struct {
	/**
	 * Called when a new client connection to MySQL Proxy was created.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_init);
	/**
	 * Called when MySQL Proxy needs to establish a connection to a backend server
	 *
	 * Returning a handshake response packet from this callback will cause the con_read_handshake step to be skipped.
	 * The next state then is con_send_handshake.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_connect_server);
	/**
	 * Called when MySQL Proxy has read the handshake packet from the server.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_handshake);
	/**
	 * Called when MySQL Proxy wants to send the handshake packet to the client.
	 * 
	 * @note No known plugins actually implement this step right now, but rather return a handshake challenge from con_init instead.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_handshake);
	/**
	 * Called when MySQL Proxy has read the authentication packet from the client.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_auth);
	/**
	 * Called when MySQL Proxy wants to send the authentication packet to the server.
	 * 
	 * @note No known plugins actually implement this step.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_auth);
	/**
	 * Called when MySQL Proxy has read the authentication result from the backend server, in response to con_send_auth.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_auth_result);
	/**
	 * Called when MySQL Proxy wants to send the authentication response packet to the client.
	 * 
	 * @note No known plugins implement this callback, but the default implementation deals with the important case that
	 * the authentication response used the pre-4.1 password hash method, but the client didn't.
	 * @see network_mysqld_con::auth_result_state
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_auth_result);
	/**
	 * Called when MySQL Proxy receives a COM_QUERY packet from a client.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_query);
	/**
	 * Called when MySQL Proxy receives a result set from the server.
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_query_result);
	/**
	 * Called when MySQL Proxy sends a result set to the client.
	 * 
	 * The proxy plugin, for example, uses this state to inject more queries into the connection, possibly in response to a
	 * result set received from a server.
	 * 
	 * This callback should not cause multiple result sets to be sent to the client.
	 * @see network_mysqld_con_injection::sent_resultset
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_query_result);
    /**
     * Called when an internal timer has elapsed.
     * 
     * This state is meant to give a plugin the opportunity to react to timers.
     * @note This state is currently unused, as there is no support for setting up timers.
     * @deprecated Unsupported, there is no way to set timers right now. Might be removed in 1.0.
     */
    NETWORK_MYSQLD_PLUGIN_FUNC(con_timer_elapsed);
    /**
     * Called when either side of a connection was either closed or some network error occurred.
     * 
     * Usually this is called because a client has disconnected. Plugins might want to preserve the server connection in this case
     * and reuse it later. In this case the connection state will be ::CON_STATE_CLOSE_CLIENT.
     * 
     * When an error on the server connection occurred, this callback is usually used to close the client connection as well.
     * In this case the connection state will be ::CON_STATE_CLOSE_SERVER.
     * 
     * @note There are no two separate callback functions for the two possibilities, which probably is a deficiency.
     */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_cleanup);

	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_local_infile_data);
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_local_infile_data);
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_local_infile_result);
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_local_infile_result);
	NETWORK_MYSQLD_PLUGIN_FUNC(con_read_auth_old_password);
	NETWORK_MYSQLD_PLUGIN_FUNC(con_send_auth_old_password);

	NETWORK_MYSQLD_PLUGIN_FUNC(con_timeout);
	/**
         * @author sohu-inc.com
         *　实现对client端sql语句的词法分析
         */
        NETWORK_MYSQLD_PLUGIN_FUNC(con_process_read_query);

	/**
	 * @author sohu-inc.com
	 *　用于处理proxy对请求的负载均衡最后结果是选取一个合适的backend
	 */
	NETWORK_MYSQLD_PLUGIN_FUNC(con_get_server_list);
	/**
         * @author sohu-inc.com
         *　为client端请求，从指定的backend中取出一个可用的连接
         */
        NETWORK_MYSQLD_PLUGIN_FUNC(con_get_server_connection_list);
	/**
         * @author sohu-inc.com
         * 处理连接上下文的恢复，负责将上下文恢复的数据包及client的端的请求数据包
	 * 发送到con->server端的send_queue中。
         */
        NETWORK_MYSQLD_PLUGIN_FUNC(con_send_query);
} network_mysqld_hooks;

/**
 * A structure containing the parsed packet for a command packet as well as the common parts necessary to find the correct
 * packet parsing function.
 * 
 * The correct parsing function is chose by looking at both the current state as well as the command in this structure.
 * 
 * @todo Currently the plugins are responsible for setting the first two fields of this structure. We have to investigate
 * how we can refactor this into a more generic way.
 */
struct network_mysqld_con_parse {
	enum enum_server_command command;	/**< The command indicator from the MySQL Protocol */

	gpointer data;						/**< An opaque pointer to a parsed command structure */
	void (*data_free)(gpointer);		/**< A function pointer to the appropriate "free" function of data */
};

/**
 * The possible states in the MySQL Protocol.
 * 
 * Not all of the states map directly to plugin callbacks. Those states that have no corresponding plugin callbacks are marked as
 * <em>internal state</em>.
 */
typedef enum { 
	CON_STATE_INIT = 0,                  /**< A new client connection was established */
	CON_STATE_CONNECT_SERVER = 1,        /**< A connection to a backend is about to be made */
	CON_STATE_READ_HANDSHAKE = 2,        /**< A handshake packet is to be read from a server */
	CON_STATE_SEND_HANDSHAKE = 3,        /**< A handshake packet is to be sent to a client */
	CON_STATE_READ_AUTH = 4,             /**< An authentication packet is to be read from a client */
	CON_STATE_SEND_AUTH = 5,             /**< An authentication packet is to be sent to a server */
	CON_STATE_READ_AUTH_RESULT = 6,      /**< The result of an authentication attempt is to be read from a server */
	CON_STATE_SEND_AUTH_RESULT = 7,      /**< The result of an authentication attempt is to be sent to a client */
	CON_STATE_READ_AUTH_OLD_PASSWORD = 8,/**< The authentication method used is for pre-4.1 MySQL servers, internal state */
	CON_STATE_SEND_AUTH_OLD_PASSWORD = 9,/**< The authentication method used is for pre-4.1 MySQL servers, internal state */
	CON_STATE_READ_QUERY = 10,           /**< COM_QUERY packets are to be read from a client */
	CON_STATE_SEND_QUERY = 11,           /**< COM_QUERY packets are to be sent to a server */
	CON_STATE_READ_QUERY_RESULT = 12,    /**< Result set packets are to be read from a server */
	CON_STATE_SEND_QUERY_RESULT = 13,    /**< Result set packets are to be sent to a client */
	
	CON_STATE_CLOSE_CLIENT = 14,         /**< The client connection should be closed */
	CON_STATE_SEND_ERROR = 15,           /**< An unrecoverable error occurred, leads to sending a MySQL ERR packet to the client and closing the client connection */
	CON_STATE_ERROR = 16,                /**< An error occurred (malformed/unexpected packet, unrecoverable network error), internal state */

	CON_STATE_CLOSE_SERVER = 17,         /**< The server connection should be closed */

	/* handling the LOAD DATA LOCAL INFILE protocol extensions */
	CON_STATE_READ_LOCAL_INFILE_DATA = 18,
	CON_STATE_SEND_LOCAL_INFILE_DATA = 19,
	CON_STATE_READ_LOCAL_INFILE_RESULT = 20,
	CON_STATE_SEND_LOCAL_INFILE_RESULT = 21,

	/** 新增加的中间处理状态 */
	CON_STATE_PROCESS_READ_QUERY = 22, /**< COM_QUERY packets are to be processed to get token list */
	CON_STATE_GET_SERVER_LIST = 23, /**< 将要根据sql语句的类型及预设规则选取可用的合适的backend */
	CON_STATE_GET_SERVER_CONNECTION_LIST = 24  /**< 从已经选取的backend中去的可用的连接赋予con->server */

	, CON_STATE_SEND_ERROR_TO_CLIENT = 25  /**< 同CON_STATE_SEND_ERROR，但不会关闭连接 */
} network_mysqld_con_state_t;

/**
 * get the name of a connection state
 */
NETWORK_API const char *network_mysqld_con_state_get_name(network_mysqld_con_state_t state);

typedef enum {
	EX_TRANSACTION_KILLED, /**< 标识长时间未commit连接被kill*/
	EX_PREPARE_KILLED, /**< 标示长时间未close连接被kill */
	EX_BACKEND_DOWN, /**< 标示对应的后端不能正常服务，连接将被kill */
	EX_KILLED, /**< 主动kill */
	EX_STATE_WELL /**< 标识连接正常 */
} exception_type; /**< 用于标识con连接的状态 */

/**
 * Encapsulates the state and callback functions for a MySQL protocol-based connection to and from MySQL Proxy.
 * 
 * New connection structures are created by the function responsible for handling the accept on a listen socket, which
 * also is a network_mysqld_con structure, but only has a server set - there is no "client" for connections that we listen on.
 * 
 * The chassis itself does not listen on any sockets, this is left to each plugin. Plugins are free to create any number of
 * connections to listen on, but most of them will only create one and reuse the network_mysqld_con_accept function to set up an
 * incoming connection.
 * 
 * Each plugin can register callbacks for the various states in the MySQL Protocol, these are set in the member plugins.
 * A plugin is not required to implement any callbacks at all, but only those that it wants to customize. Callbacks that
 * are not set, will cause the MySQL Proxy core to simply forward the received data.
 */
struct network_mysqld_con {
	/**
	 * The current/next state of this connection.
	 * 
	 * When the protocol state machine performs a transition, this variable will contain the next state,
	 * otherwise, while performing the action at state, it will be set to the connection's current state
	 * in the MySQL protocol.
	 * 
	 * Plugins may update it in a callback to cause an arbitrary state transition, however, this may result
	 * reaching an invalid state leading to connection errors.
	 * 
	 * @see network_mysqld_con_handle
	 */
	network_mysqld_con_state_t state;
	gboolean goto_next_state;
	network_mysqld_con_state_t next_state;

	/**
	 * The server side of the connection as it pertains to the low-level network implementation.
	 */
	network_socket *server;
	GMutex server_mutex; /* 实现对con->server 的同步访问控制*/
	/**
	 * The client side of the connection as it pertains to the low-level network implementation.
	 */
	network_socket *client;
	GMutex client_mutex; /* 实现对con->client的同步访问控制*/
	/**
	 * Function pointers to the plugin's callbacks.
	 * 
	 * Plugins don't need set any of these, but if unset, the plugin will not have the opportunity to
	 * alter the behavior of the corresponding protocol state.
	 * 
	 * @note In theory you could use functions from different plugins to handle the various states, but there is no guarantee that
	 * this will work. Generally the plugins will assume that config is their own chassis_plugin_config (a plugin-private struct)
	 * and violating this constraint may lead to a crash.
	 * @see chassis_plugin_config
	 */
	network_mysqld_hooks plugins;

	/**
	 * A pointer to a plugin-private struct describing configuration parameters.
	 * 
	 * @note The actual struct definition used is private to each plugin.
	 */
	chassis_plugin_config *config;

	/**
	 * A pointer back to the global, singleton chassis structure.
	 */
	chassis *srv; /* our srv object */

	/**
	 * A boolean flag indicating that this connection should only be used to accept incoming connections.
	 * 
	 * It does not follow the MySQL protocol by itself and its client network_socket will always be NULL.
	 */
	int is_listen_socket;

	/**
	 * An integer indicating the result received from a server after sending an authentication request.
	 * 
	 * This is used to differentiate between the old, pre-4.1 authentication and the new, 4.1+ one based on the response.
	 */
	guint8 auth_result_state;

	/* track the auth-method-switch state */
	GString *auth_switch_to_method;
	GString *auth_switch_to_data;
	guint32  auth_switch_to_round;
	gboolean auth_next_packet_is_from_server;

	/** Flag indicating if we the plugin doesn't need the resultset itself.
	 * 
	 * If set to TRUE, the plugin needs to see the entire resultset and we will buffer it.
	 * If set to FALSE, the plugin is not interested in the content of the resultset and we'll
	 * try to forward the packets to the client directly, even before the full resultset is parsed.
	 */
	gboolean resultset_is_needed;
	/**
	 * Flag indicating whether we have seen all parts belonging to one resultset.
	 */
	gboolean resultset_is_finished;

	/**
	 * Flag indicating that we have received a COM_QUIT command.
	 * 
	 * This is mainly used to differentiate between the case where the server closed the connection because of some error
	 * or if the client asked it to close its side of the connection.
	 * MySQL Proxy would report spurious errors for the latter case, if we failed to track this command.
	 */
	gboolean com_quit_seen;

	/**
	 * Flag indicating whether we have received all data from load data infile.
	 */
	gboolean local_file_data_is_finished;

	/**
	 * @author sohu-inc.com
	 * 用于标示是否连接client端是否已经通过验证
	 */
	gboolean client_is_authed;

	/**
	 * Contains the parsed packet.
	 */
	struct network_mysqld_con_parse parse;

	/**
	 * An opaque pointer to a structure describing extra connection state needed by the plugin.
	 * 
	 * The content and meaning is completely up to each plugin and the chassis will not access this in any way.
	 * 
	 * @note In practice, all current plugins and the chassis assume this to be network_mysqld_con_t.
	 */
	void *plugin_con_state;

	/**
	 * track the timestamps of the processing of the connection
	 *
	 * 
	 */
	chassis_timestamps_t *timestamps;

	/* connection specific timeouts */
	struct timeval connect_timeout;
	struct timeval read_timeout;
	struct timeval write_timeout;

	/** added by jinxuan hou, 2013/04/13 */
	GHashTable *stmtids; // ids of prapare statement
	guint32 last_id; // 记录上一次close的prepare statement的id
	GHashTable *stmtnames; //names of prepare statement
	GString *last_stmt; // 记录上一次执行的prepare statement的名称

	int tx_flag; // flag of whether in transaction
	GString *sql_sentence;
	GPtrArray *tokens; // 客户端发送的sql的token list
	GPtrArray *related_bk; // 需要处理请求的backend的列表，存储的是Gstring *

	network_socket *cache_server; //用于存储上次连接缓存的后端连接，
	GMutex cache_server_mutex; /* 用于实现对cache_server的同步访问（主要是在回收及缓存阶段）*/

	int is_injection; // 用于标识查询语句是否是上下文恢复语句
	gboolean inj_execute_correctly; // 用于标示上下文恢复语句是否执行成功

	// added by sohu-inc.com, 2013/05/15
	proxy_rw type; //

	// added by sohu-inc.com, 2103/05/23
	GString *sql_running;
	GString *first_key;
	GString *last_key;
	GString *second_key;

	// added by sohu-inc.com
	gboolean multiplex;

	//added by sohu-inc.com
	volatile exception_type is_well; //flag of connection state, 在监听的连接中用EX_KILLED标示监听端口被关闭了

	guint connection_id;

	/**
	 * 因为cache超时事件和正常连接处理可能由两个线程执行，同时访问event和con结构，存在线程同步问题
	 * 为了保证两个线程操作不能同时发生，增加了此互斥锁和标识符
	 * @todo 其它有些地方貌似可移除一些之前加的cache_server_mutex，server_mutex?
	 *
	 * 主要逻辑如下：
	 * 1. 对cache超时事件（network_mysqld_cache_con_idle_handle）整个过程加锁，并首先判断标识符的值，
	 *    +决定是否执行后续的超时操作
	 * 2. 对正常连接，当读取查询请求(proxy_read_query)时，首先加锁，删除cache超时事件，并修改标识符的值，
	 *    +然后解锁
	 */
	GMutex cache_idle_timeout_mutex;
	/**
	 * 标识符作用是，假如在删掉事件之前，就进入了回调函数，这样还有机会再次检查一下是否需要执行超时操作
	 * 初始化值是FALSE，表示可以执行超时操作。反之，表示不能执行超时操作
	 *
	 * 有如下3处使用和修改了此标识符：
	 * 1. network_mysqld_cache_con_idle_handle()判断若此值是TRUE就直接跳过后续超时处理
	 * 2. proxy_read_query()里将此值设置为TRUE
	 * 3. cache_server_connection()设置cache超时处理事件之前，将此值设置/恢复为FALSE
	 */
	gboolean cache_idle_timeout_flag;

	/*
	对上面的一些说明


	a. 如下操作增加了cache server超时事件

	1. CON_STATE_SEND_QUERY时
	如果命令是COM_STMT_CLOSE，就会执行cache_server_connection()，缓存当前后端连接，然后设置下一个状态为CON_STATE_READ_QUERY

	2. CON_STATE_READ_QUERY_RESULT
	若不需要返回结果至客户端，则执行cache_server_connection()，缓存当前后端连接，然后设置下一个状态为CON_STATE_READ_QUERY

	3. CON_STATE_SEND_QUERY_RESULT
	发送完查询结果后，执行cache_server_connection()，缓存当前后端连接，然后设置下一个状态为CON_STATE_READ_QUERY


	b. 如下操作修改了cache server

	1. proxy_get_server_list()
	检查cache server是否存在，并删除其事件(就是超时事件)。然后进入状态CON_STATE_GET_SERVER_CONNECTION_LIST

	(修改后，改到proxy_read_query了!)

	2. proxy_get_server_connection_list()
	检查cache server是否存在，并放回server

	(修改后，cache server没有同步问题了)

	3. proxy_disconnect_client()
	若是COM_STMT_SEND_LONG_DATA或CON_STATE_CLOSE_CLIENT，删除cache server及其事件

	（需要么？）

	4. network_mysqld_con_handle()
	一开始，如为EV_READ事件，判断是否是cache_server触发的，打印信息(只有这里用到了)

	（没影响）

	5. cache_server_connection()
	注册事件(network_mysqld_cache_con_idle_handle)，保存cache server

	6. network_mysqld_cache_con_idle_handle()
	超时处理，不解释


	c.
	增加超时事件后，进入CON_STATE_READ_QUERY状态，接下来可能进入：
	1. CON_STATE_PROCESS_READ_QUERY, CON_STATE_CLOSE_CLIENT, CON_STATE_SEND_ERROR_TO_CLIENT
	2. CON_STATE_GET_SERVER_LIST, CON_STATE_SEND_ERROR_TO_CLIENT
	3. ...

	在进入CON_STATE_READ_QUERY状态后，proxy_read_query()中删除掉cache超时事件，之后就不会有线程同步问题了

	*/

	gint get_conn_try_times; /**< 获取连接重试的次数，默认情况下连接获取超过三次会返回错误 */

	/** 获取连接的错误码。表示从连接池成功获取、无可用连接，或连接已满等状态 */
	pool_connection_errno get_server_connection_errno;
	
	/** 为show proxy processlist增加的字段 */
	guint64 start_timestamp;
	guint64 end_timestamp;
	gboolean is_sql_running;

	/**SQL执行结束后计算的执行时长*/
	guint64 execute_time_us;


	/** 为减少sql标准化的次数,将执行sql的标准化后的语句记录下来 */
	GString * normalized_sql[SQL_NORMALIZE_TYPE_NUM];
	gboolean para_limit_used[SQL_NORMALIZE_TYPE_NUM]; /** 记录是否适用了相应的限制规则，便于后续更新执行条数时使用 */
	GString * para_limit_user_db_key_used; /** 记录更新并行执行条数时的user_db */

	/** 执行超时时间会使用多次，避免多次查询，这里记录下语句对应的超时时间 */
	guint64 max_dura_time; /** 记录语句的最长执行时间，单位us;若为-1,表明使用默认的超时时间 */

	/** 连接的当前和前次状态，和连接级的统计信息 */
	connection_state_set *connection_state;

	/** 用于标识是否需要将语句记录到sql执行的直方图中 */
	gboolean need_record;
};

NETWORK_API void mysqld_con_set_shutdown_location(
		network_mysqld_con * con,
		const gchar* location); /**< 将con的连接标志设置为关闭，便于连接自己关闭 */

NETWORK_API void mysqld_con_set_transaction_killed_location(
		network_mysqld_con * con,
		const gchar* location); /**< 设置连接因事务长期未关闭而被kill的标识，便于前端client感知 */

NETWORK_API void mysqld_con_set_prepare_killed_location(
		network_mysqld_con * con,
		const gchar* location); /**< 设置连接因prepare长期未关闭而被kill的标识，便于前端client感知 */

NETWORK_API void mysqld_con_set_killed_location(
		network_mysqld_con * con,
		const gchar* location); /**< 将连接设置为被killed, 这个可以在管理命令主动kill连接中用到 */

NETWORK_API void mysqld_con_set_well_location(
		network_mysqld_con * con,
		const gchar* location); /**< 将连接的异常标识设置为正常 */

NETWORK_API exception_type get_mysqld_con_exception_state(
		network_mysqld_con *con);/**< 查询对应的连接异常状态 */

NETWORK_API gboolean mysqld_con_shutdown(
		network_mysqld_con *con);/**< 查询对应的连接是否需要关闭 */

NETWORK_API void g_list_string_free(gpointer data, gpointer UNUSED_PARAM(user_data));
NETWORK_API gboolean g_hash_table_true(gpointer UNUSED_PARAM(key), gpointer UNUSED_PARAM(value), gpointer UNUSED_PARAM(u));

NETWORK_API network_mysqld_con *network_mysqld_con_init(void) G_GNUC_DEPRECATED;
NETWORK_API network_mysqld_con *network_mysqld_con_new(void);
NETWORK_API void network_mysqld_con_free(network_mysqld_con *con);

/** 
 * should be socket 
 */
NETWORK_API void network_mysqld_con_accept(int event_fd, short events, void *user_data); /** event handler for accept() */
NETWORK_API void network_mysqld_admin_con_accept(int G_GNUC_UNUSED event_fd, short events, void *user_data); /** event handler for admin accept() */

NETWORK_API int network_mysqld_con_send_ok(network_socket *con);
NETWORK_API int network_mysqld_con_send_ok_full(network_socket *con, guint64 affected_rows, guint64 insert_id, guint16 server_status, guint16 warnings);
NETWORK_API int network_mysqld_con_send_error(network_socket *con, const gchar *errmsg, gsize errmsg_len);
NETWORK_API int network_mysqld_con_send_error_full(network_socket *con, const char *errmsg, gsize errmsg_len, guint errorcode, const gchar *sqlstate);
NETWORK_API int network_mysqld_con_send_error_pre41(network_socket *con, const gchar *errmsg, gsize errmsg_len);
NETWORK_API int network_mysqld_con_send_error_full_pre41(network_socket *con, const char *errmsg, gsize errmsg_len, guint errorcode);
NETWORK_API int network_mysqld_con_send_resultset(network_socket *con, GPtrArray *fields, GPtrArray *rows);
NETWORK_API void network_mysqld_con_reset_command_response_state(network_mysqld_con *con);

/**
 * should be socket 
 */
NETWORK_API network_socket_retval_t network_mysqld_read(chassis *srv, network_socket *con);
NETWORK_API network_socket_retval_t network_mysqld_write(chassis *srv, network_socket *con);
NETWORK_API network_socket_retval_t network_mysqld_write_len(chassis *srv, network_socket *con, int send_chunks);
NETWORK_API network_socket_retval_t network_mysqld_con_get_packet(chassis G_GNUC_UNUSED*chas, network_socket *con);

/**
 * @author sohu-inc.com
 * 为实现对cons的同步访问
 */
struct chassis_private {
	GMutex cons_mutex;
	GPtrArray *cons;                          /**< array(network_mysqld_con) */

	#if 0
	lua_scope *sc;
	#endif

	network_backends_t *backends;

	gint connection_id_sequence;
};

NETWORK_API int network_mysqld_init(chassis *srv);
NETWORK_API void network_mysqld_add_connection(chassis *srv, network_mysqld_con *con);
NETWORK_API void network_mysqld_con_handle(int event_fd, short events, void *user_data);
NETWORK_API int network_mysqld_queue_append(network_socket *sock, network_queue *queue, const char *data, size_t len);
NETWORK_API int network_mysqld_queue_append_raw(network_socket *sock, network_queue *queue, GString *data);
NETWORK_API int network_mysqld_queue_reset(network_socket *sock);
NETWORK_API int network_mysqld_queue_sync(network_socket *dst, network_socket *src);


// 判断连接是否在prepare中
NETWORK_API gboolean is_in_prepare(network_mysqld_con *con);
NETWORK_API void clean_prepare_context(network_mysqld_con *con);
// 根据事务状态、prepare的状态来实现连接的归还策略
NETWORK_API void cache_server_connection(chassis *chas, network_mysqld_con *con);
NETWORK_API void network_mysqld_cache_con_idle_handle(int event_fd, short events, void *user_data);
#if 0
void network_mysqld_pool_con_idle_handle(int event_fd, short events, void *user_data);
#endif
NETWORK_API gboolean network_mysqld_pool_con_add_soket(network_mysqld_con *con, network_socket *sock);

// 实现连接的主动释放,主要是用在连接不够需要kill个别用户的一些连接再新建其他用户的一些连接
// 或者是在连接执行过程中时间过长，需要主动kill掉连接的情况
NETWORK_API void kill_network_con(network_socket *s);

NETWORK_API void free_gstring_ptr_array(GPtrArray *array);

/**
 * 更新对应规则对应的语句的执行条数减1
 * 规则查询的原则是：先查找invidual,再查找普适的规则
 * 若找到individual规则就以individual规则为准；没有再去找普适规则；
 * 对于每类规则：又分为单条和某类的规则，需要满足这两种规则。
 * 即若有规则a=1和a=？时，两个规则都要满足。语句a=1运行会同时更新a=1和a=?的统计值
 */
NETWORK_API network_socket_retval_t process_sql_para_rule(network_mysqld_con *con);

/**
 * 处理超时时间对应规则
 * 规则查询的原则是：以最细匹配原则为准；
 * 先找individual的限制规则，先去匹配单条语句的限制规则，再去匹配某类语句的限制规则
 * 再找global的限制规则，同样是先去匹配单条语句的限制规则，再去匹配某类语句的限制规则
 * 避免多次查询需要在con 中记录该条语句的最长限制时间
 * 涉及到的状态机是：send_query 及 read_query_result
 */
NETWORK_API gboolean process_sql_dura_rule(network_mysqld_con *con);

#endif
