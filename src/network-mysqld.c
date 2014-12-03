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

#include "sql-tokenizer.h"
#include "network-mysqld-async-con.h"
#include "network-sql-statistics.h"

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
static void clean_read_query_timeout(network_mysqld_con *con);

/**
 * call the cleanup callback for the current connection
 *
 * @param srv	global context
 * @param con	connection context
 *
 * @return	   NETWORK_SOCKET_SUCCESS on success
 */
network_socket_retval_t plugin_call_cleanup(chassis *srv, network_mysqld_con *con) {
	NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;
	network_socket_retval_t retval = NETWORK_SOCKET_SUCCESS;

	func = con->plugins.con_cleanup;
	
	if (!func) return retval;

	//LOCK_LUA(srv->priv->sc);
	retval = (*func)(srv, con);
	//UNLOCK_LUA(srv->priv->sc);

	return retval;
}

/**
 * call the timeout callback for the current connection
 *
 * @param srv	global context
 * @param con	connection context
 *
 * @return	   NETWORK_SOCKET_SUCCESS on success
 */
static network_socket_retval_t
plugin_call_timeout(chassis *srv, network_mysqld_con *con)  __attribute__((unused));
static network_socket_retval_t
plugin_call_timeout(chassis *srv, network_mysqld_con *con) {
	NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;
	network_socket_retval_t retval = NETWORK_SOCKET_ERROR;

	func = con->plugins.con_timeout;
	
	if (!func) {
		/* default implementation */
		g_debug("%s: connection between %s and %s timed out. closing it",
				G_STRLOC,
				con->client ? con->client->src->name->str : "(client)",
				con->server ? con->server->dst->name->str : "(server)");
		con->state = CON_STATE_ERROR;
		return NETWORK_SOCKET_SUCCESS;
	}

	//LOCK_LUA(srv->priv->sc);
	retval = (*func)(srv, con);
	//UNLOCK_LUA(srv->priv->sc);

	return retval;
}


chassis_private *network_mysqld_priv_init(void) {
	chassis_private *priv;

	priv = g_new0(chassis_private, 1);

	g_mutex_init(&priv->cons_mutex);
	priv->cons = g_ptr_array_new();
	//priv->sc = lua_scope_new();
	priv->backends  = network_backends_new();

	priv->connection_id_sequence = 0;

	return priv;
}

void network_mysqld_priv_shutdown(chassis *chas, chassis_private *priv) {
	if (!priv) return;

	/* network_mysqld_con_free() changes the priv->cons directly
	 *
	 * always free the first element until all are gone 
	 */
	//g_mutex_lock(&priv->cons_mutex);
	while (0 != priv->cons->len) {
		network_mysqld_con *con = priv->cons->pdata[0];

		plugin_call_cleanup(chas, con);
		network_mysqld_con_free(con);
	}
	//g_mutex_unlock(&priv->cons_mutex);
}

void network_mysqld_priv_free(chassis G_GNUC_UNUSED *chas, chassis_private *priv) {
	if (!priv) return;

	g_mutex_lock(&priv->cons_mutex);
	g_ptr_array_free(priv->cons, TRUE);
	g_mutex_unlock(&priv->cons_mutex);

	g_mutex_clear(&priv->cons_mutex);

	network_backends_free(priv->backends);

	//lua_scope_free(priv->sc);

	g_free(priv);
}

int network_mysqld_init(chassis *srv) {
	//lua_State *L;
	srv->priv_free = network_mysqld_priv_free;
	srv->priv_shutdown = network_mysqld_priv_shutdown;
	srv->priv	  = network_mysqld_priv_init();

	/* store the pointer to the chassis in the Lua registry */
	#if 0
	L = srv->priv->sc->L;
	lua_pushlightuserdata(L, (void*)srv);
	lua_setfield(L, LUA_REGISTRYINDEX, CHASSIS_LUA_REGISTRY_KEY);
	#endif
	
	return 0;
}


network_mysqld_con *network_mysqld_con_init() {
	return network_mysqld_con_new();
}
/**
 * create a connection 
 *
 * @return	   a connection context
 */
network_mysqld_con *network_mysqld_con_new() {
	network_mysqld_con *con;

	con = g_new0(network_mysqld_con, 1);
	con->config = NULL;
	con->client = NULL;
	g_mutex_init(&(con->client_mutex));

	con->server = NULL;
	g_mutex_init(&(con->server_mutex));

	g_mutex_init(&(con->cache_server_mutex));
	con->cache_server = NULL;

	con->timestamps = chassis_timestamps_new();
	con->parse.command = -1;
	con->auth_switch_to_method = g_string_new(NULL);
	con->auth_switch_to_round  = 0;
	con->auth_switch_to_data   = g_string_new(NULL);;

	/* some tiny helper macros */
#define SECONDS ( 1 )
#define MINUTES ( 60 * SECONDS )
#define HOURS ( 60 * MINUTES )
	con->connect_timeout.tv_sec = 2 * SECONDS;
	con->connect_timeout.tv_usec = 0;

	con->read_timeout.tv_sec = 8 * HOURS;
	con->read_timeout.tv_usec = 0;
	
	con->write_timeout.tv_sec = 8 * HOURS;
	con->write_timeout.tv_usec = 0;
#undef SECONDS
#undef MINUTES
#undef HOURS
	con->stmtids = g_hash_table_new_full(g_int_hash, g_int_equal, g_hash_table_int_free, g_hash_table_int_free);
	//con->stmtnames = g_hash_table_new_full(g_str_hash, g_str_equal, g_hash_table_string_free, NULL);
	con->stmtnames = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_int_free);
	con->sql_sentence = g_string_new("");
		
	con->tx_flag = 0;
	con->related_bk = g_ptr_array_new();
	con->tokens = NULL;

	// added by sohu-inc.com, 2013/05/15
	con->type = PROXY_TYPE_WRITE;//默认是建立写的连接池

	// added by sohu-inc.com, 2013/05/23
	con->sql_running = g_string_new(NULL);
	con->first_key = g_string_new(NULL);
	con->last_key = g_string_new(NULL);
	con->second_key = g_string_new(NULL);

	con->client_is_authed = FALSE;

	g_mutex_init(&(con->cache_idle_timeout_mutex));
	con->cache_idle_timeout_flag = FALSE;

	con->get_conn_try_times = 0;
	
	/**
	 * added by zhenfan, 2013/08/14
	 */
	con->is_sql_running = FALSE;
	con->start_timestamp = chassis_get_rel_microseconds();
	con->end_timestamp = chassis_get_rel_microseconds();
	
	con->is_well = EX_STATE_WELL;
	con->inj_execute_correctly = TRUE;

	/** sql 语句标准化变量初始化 */
	con->normalized_sql[0] = g_string_new(NULL);
	con->normalized_sql[1] = g_string_new(NULL);

	con->para_limit_used[0] = FALSE;
	con->para_limit_used[1] = FALSE;


	/** 记录对应的user_db */
	con->para_limit_user_db_key_used = g_string_new(NULL);

	con->connection_state = connection_state_set_new();

	con->need_record = TRUE;

	return con;
}

/**
 * @author sohu-inc.com
 * 将con的连接标志设置为关闭，便于连接自己关闭
 * @param con
 * @param location
 */
void mysqld_con_set_shutdown_location(
		network_mysqld_con * con,
		const gchar* location) {
	/*if (!con)
		return;
	if (con->is_shutdown == 0) {
		g_message("Initiating shutdown, requested from %s",
				(location != NULL ? location : "Connection kill handler"));
	}
	con->is_shutdown = 1;*/

	if (!con)
		return;
	if (con->is_well != EX_BACKEND_DOWN) {
		g_message("Initiating shutdown, requested from %s",
				(location != NULL ? location : "Connection kill handler"));
	}
	con->is_well = EX_BACKEND_DOWN;
}

/**
 * @author sohu-inc.com
 * 设置连接的异常状态为事务长期未关闭而被kill
 * @param con 要被设置的连接变量
 * @param location 调用该函数的代码位置
 */
void mysqld_con_set_transaction_killed_location(
		network_mysqld_con * con,
		const gchar* location) {

	if (!con)
		return;
	if (con->is_well != EX_TRANSACTION_KILLED) {
		g_message("Initiating transaction killed, requested from %s",
				(location != NULL ? location : "Connection transaction kill handler"));
	}
	con->is_well = EX_TRANSACTION_KILLED;
}

/**
 * @author sohu-inc.com
 * 设置连接因prepare长期未关闭而被kill的标识，便于前端client感知
 * @param con 要被设置的连接变量
 * @param location 调用该函数的代码位置
 */
void mysqld_con_set_prepare_killed_location(
		network_mysqld_con * con,
		const gchar* location) {
	if (!con)
		return;
	if (con->is_well != EX_PREPARE_KILLED) {
		g_message("Initiating prepare killed, requested from %s",
				(location != NULL ? location : "Connection prepare kill handler"));
	}
	con->is_well = EX_PREPARE_KILLED;
}

/**
 * @author sohu-inc.com
 * 将连接设置为被killed, 这个可以在主动kill连接中用到
 * @param con 要被设置的连接变量
 * @param location 调用该函数的代码位置
 */
void mysqld_con_set_killed_location(
		network_mysqld_con * con,
		const gchar* location){
	if (!con)
		return;
	if (con->is_well != EX_KILLED) {
		g_message("Initiating exec killed, requested from %s",
				(location != NULL ? location : "Connection kill handler"));
	}
	con->is_well = EX_KILLED;
}

/**
 * @author sohu-inc.com
 * 将连接的异常标识设置为正常
 * @param con 要被设置的连接变量
 * @param location 调用该函数的代码位置
 */
void mysqld_con_set_well_location(
		network_mysqld_con * con,
		const gchar* location) {
	if (!con)
		return;
	if (con->is_well != EX_STATE_WELL) {
		g_message("Initiating con->is_well to be well, requested from %s",
				(location != NULL ? location : "Connection handler"));
	}
	con->is_well = EX_STATE_WELL;
}

/**
 * @author sohu-inc.com
 * 查询对应的连接异常状态
 * @param con 被查询的连接变量
 * @return 连接的异常状态信息
 */
exception_type get_mysqld_con_exception_state(
		network_mysqld_con *con) {
	if (!con)
		return EX_STATE_WELL;
	return con->is_well;
}

/**
 * @author sohu-inc.com
 * 查询对应的连接是否需要关闭
 * @param con
 * @return
 */
gboolean mysqld_con_shutdown(
		network_mysqld_con *con) {
	if (!con)
		return FALSE;
	return con->is_well == EX_BACKEND_DOWN || con->is_well == EX_KILLED;
}

void network_mysqld_add_connection(chassis *srv, network_mysqld_con *con) {
	con->srv = srv;
	/**
	 * 向srv->priv->cons里面添加连接时需要对cons加锁
	 */
	g_mutex_lock(&srv->priv->cons_mutex);
	/*connection_id递增，其实好像不需要原子操作*/
	//con->connection_id = (guint) g_atomic_int_add(&(srv->priv->connection_id_sequence), 1);
	con->connection_id = (guint)(srv->priv->connection_id_sequence)++;

	g_ptr_array_add(srv->priv->cons, con);
	g_mutex_unlock(&srv->priv->cons_mutex);
}

//void network_mysqld_remove_connection(chassis *srv, network_mysqld_con *con) {}

/**
 * 用于清除负载均衡阶段选取的服务的backend PtrArray
 */
void free_gstring_ptr_array(GPtrArray *array) {
	if (array == NULL)
		return;

	guint idx = 0;
	for(idx = 0; idx < array->len; idx++ ) {
		g_string_free((GString *)(array->pdata[idx]), TRUE );
	}
	g_ptr_array_free(array, TRUE);
}

/**
 * free a connection 
 *
 * closes the client and server sockets 
 *
 * @param con	connection context
 */
void network_mysqld_con_free(network_mysqld_con *con) {
	if (!con)
		return;

	g_mutex_lock(&con->srv->priv->cons_mutex);
	if (con->parse.data && con->parse.data_free) {
		con->parse.data_free(con->parse.data);
	}

	g_mutex_lock(&con->client_mutex);
	if (con->client) {
		network_socket_free(con->client);
		con->client = NULL;
	}
	g_mutex_unlock(&con->client_mutex);
	g_mutex_clear(&con->client_mutex);

	g_mutex_lock(&con->server_mutex);
	if (con->server) {
		network_socket_free(con->server);
		con->server = NULL;
	}
	g_mutex_unlock(&con->server_mutex);
	g_mutex_clear(&con->server_mutex);

	g_mutex_lock(&con->cache_server_mutex);
	if (con->cache_server) {
		network_socket_free(con->cache_server);
		con->cache_server = NULL;
	}
	con->cache_idle_timeout_flag = FALSE;
	g_mutex_unlock(&con->cache_server_mutex);
	g_mutex_clear(&con->cache_server_mutex);

	g_string_free(con->auth_switch_to_method, TRUE);
	g_string_free(con->auth_switch_to_data, TRUE);

	/* we are still in the conns-array */

	g_ptr_array_remove_fast(con->srv->priv->cons, con);

	chassis_timestamps_free(con->timestamps);

	g_hash_table_destroy(con->stmtids);
	g_hash_table_destroy(con->stmtnames);
	if (con->last_stmt != NULL) {
		g_string_free(con->last_stmt, TRUE);
	}
	if (con->sql_sentence != NULL) {
		g_string_free(con->sql_sentence, TRUE);
	}

	if (con->related_bk != NULL) {
		free_gstring_ptr_array(con->related_bk);
		con->related_bk = NULL;
	}

	if (con->tokens != NULL) {
		if (con->tokens->len > 0) {
			g_warning("there are some SQL tokens not being freed.");
			//sql_tokens_free(con->tokens);
		}
		g_ptr_array_free(con->tokens, TRUE);
		con->tokens = NULL;
	}

	if (con->sql_running != NULL) {
		g_string_free(con->sql_running, TRUE);
		con->sql_running = NULL;
	}
	if (con->first_key != NULL) {
		g_string_free(con->first_key, TRUE);
		con->first_key = NULL;
	}
	if (con->last_key != NULL) {
		g_string_free(con->last_key, TRUE);
		con->last_key = NULL;
	}
	if (con->second_key != NULL) {
		g_string_free(con->second_key, TRUE);
		con->second_key = NULL;
	}
		
	if (con->normalized_sql[0] != NULL) {
		g_string_free(con->normalized_sql[0], TRUE);
		con->normalized_sql[0] = NULL;
	}

	if (con->normalized_sql[1] != NULL ) {
		g_string_free(con->normalized_sql[1], TRUE);
		con->normalized_sql[1] = NULL;
	}

	if (con->para_limit_user_db_key_used != NULL) {
		g_string_free(con->para_limit_user_db_key_used, TRUE);
		con->para_limit_user_db_key_used = NULL;
	}

	g_mutex_unlock(&con->srv->priv->cons_mutex);
	g_mutex_clear(&(con->cache_idle_timeout_mutex));

	if (con->connection_state != NULL) {
		connection_state_set_free(con->connection_state);
		con->connection_state = NULL;
	}

	g_free(con);
}

#if 0 
static void dump_str(const char *msg, const unsigned char *s, size_t len) {
	GString *hex;
	size_t i;
		
       	hex = g_string_new(NULL);

	for (i = 0; i < len; i++) {
		g_string_append_printf(hex, "%02x", s[i]);

		if ((i + 1) % 16 == 0) {
			g_string_append(hex, "\n");
		} else {
			g_string_append_c(hex, ' ');
		}

	}

	g_message("(%s): %s", msg, hex->str);

	g_string_free(hex, TRUE);
}
#endif

int network_mysqld_queue_reset(network_socket *sock) {
	sock->packet_id_is_reset = TRUE;

	return 0;
}

/**
 * synchronize the packet-ids of two network-sockets 
 */
int network_mysqld_queue_sync(network_socket *dst, network_socket *src) {
	g_assert_cmpint(src->packet_id_is_reset, ==, FALSE);

	if (dst->packet_id_is_reset == FALSE) {
		/* this shouldn't really happen */
	}

	dst->last_packet_id = src->last_packet_id - 1;

	return 0;
}

/**
 * appends a raw MySQL packet to the queue 
 *
 * the packet is append the queue directly and shouldn't be used by the caller afterwards anymore
 * and has to by in the MySQL Packet format
 *
 */
int network_mysqld_queue_append_raw(network_socket *sock, network_queue *queue, GString *data) {
	guint32 packet_len;
	guint8  packet_id;

	/* check that the length header is valid */
	if (queue != sock->send_queue &&
	    queue != sock->recv_queue) {
		g_critical("%s: queue = %p doesn't belong to sock %p",
				G_STRLOC,
				(void *)queue,
				(void *)sock);
		return -1;
	}

	g_assert_cmpint(data->len, >=, 4);

	packet_len = network_mysqld_proto_get_packet_len(data);
	packet_id  = network_mysqld_proto_get_packet_id(data);

	g_assert_cmpint(packet_len, ==, data->len - 4);

	if (sock->packet_id_is_reset) {
		/* the ->last_packet_id is undefined, accept what we get */
		sock->last_packet_id = packet_id;
		sock->packet_id_is_reset = FALSE;
	} else if (packet_id != (guint8)(sock->last_packet_id + 1)) {
		sock->last_packet_id++;
#if 0
		g_critical("%s: packet-id %d doesn't match for socket's last packet %d, patching it",
				G_STRLOC,
				packet_id,
				sock->last_packet_id);
#endif
		network_mysqld_proto_set_packet_id(data, sock->last_packet_id);
	} else {
		sock->last_packet_id++;
	}

	network_queue_append(queue, data);

	return 0;
}

/**
 * appends a payload to the queue
 *
 * the packet is copied and prepened with the mysql packet header before it is appended to the queue
 * if neccesary the payload is spread over multiple mysql packets
 */
int network_mysqld_queue_append(network_socket *sock, network_queue *queue, const char *data, size_t packet_len) {
	gsize packet_offset = 0;

	do {
		GString *s;
		gsize cur_packet_len = MIN(packet_len, PACKET_LEN_MAX);

		s = g_string_sized_new(packet_len + 4);

		if (sock->packet_id_is_reset) {
			sock->packet_id_is_reset = FALSE;
			sock->last_packet_id = 0xff; /** the ++last_packet_id will make sure we send a 0 */
		}

		network_mysqld_proto_append_packet_len(s, cur_packet_len);
		network_mysqld_proto_append_packet_id(s, ++sock->last_packet_id);
		g_string_append_len(s, data + packet_offset, cur_packet_len);

		network_queue_append(queue, s);

		if (packet_len == PACKET_LEN_MAX) {
			s = g_string_sized_new(4);

			network_mysqld_proto_append_packet_len(s, 0);
			network_mysqld_proto_append_packet_id(s, ++sock->last_packet_id);

			network_queue_append(queue, s);
		}

		packet_len -= cur_packet_len;
		packet_offset += cur_packet_len;
	} while (packet_len > 0);

	return 0;
}


/**
 * create a OK packet and append it to the send-queue
 *
 * @param con             a client socket 
 * @param affected_rows   affected rows 
 * @param insert_id       insert_id 
 * @param server_status   server_status (bitfield of SERVER_STATUS_*) 
 * @param warnings        number of warnings to fetch with SHOW WARNINGS 
 * @return 0
 *
 * @todo move to network_mysqld_proto
 */
int network_mysqld_con_send_ok_full(network_socket *con, guint64 affected_rows, guint64 insert_id, guint16 server_status, guint16 warnings ) {
	GString *packet = g_string_new(NULL);
	network_mysqld_ok_packet_t *ok_packet;

	ok_packet = network_mysqld_ok_packet_new();
	ok_packet->affected_rows = affected_rows;
	ok_packet->insert_id     = insert_id;
	ok_packet->server_status = server_status;
	ok_packet->warnings      = warnings;

	network_mysqld_proto_append_ok_packet(packet, ok_packet);
	
	network_mysqld_queue_append(con, con->send_queue, S(packet));
	network_mysqld_queue_reset(con);

	g_string_free(packet, TRUE);
	network_mysqld_ok_packet_free(ok_packet);

	return 0;
}

/**
 * send a simple OK packet
 *
 * - no affected rows
 * - no insert-id
 * - AUTOCOMMIT
 * - no warnings
 *
 * @param con             a client socket 
 */
int network_mysqld_con_send_ok(network_socket *con) {
	return network_mysqld_con_send_ok_full(con, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
}

static int network_mysqld_con_send_error_full_all(network_socket *con,
		const char *errmsg, gsize errmsg_len,
		guint errorcode,
		const gchar *sqlstate,
		gboolean is_41_protocol) {
	GString *packet;
	network_mysqld_err_packet_t *err_packet;

	packet = g_string_sized_new(10 + errmsg_len);
	
	err_packet = is_41_protocol ? network_mysqld_err_packet_new() : network_mysqld_err_packet_new_pre41();
	err_packet->errcode = errorcode;
	if (errmsg) g_string_assign_len(err_packet->errmsg, errmsg, errmsg_len);
	if (sqlstate) g_string_assign_len(err_packet->sqlstate, sqlstate, strlen(sqlstate));

	network_mysqld_proto_append_err_packet(packet, err_packet);

	network_mysqld_queue_append(con, con->send_queue, S(packet));
	network_mysqld_queue_reset(con);

	network_mysqld_err_packet_free(err_packet);
	g_string_free(packet, TRUE);

	return 0;
}

/**
 * send a error packet to the client connection
 *
 * @note the sqlstate has to match the SQL standard. If no matching SQL state is known, leave it at NULL
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 * @param errorcode   mysql error-code we want to send
 * @param sqlstate    if none-NULL, 5-char SQL state to send, if NULL, default SQL state is used
 *
 * @return 0 on success
 */
int network_mysqld_con_send_error_full(network_socket *con, const char *errmsg, gsize errmsg_len, guint errorcode, const gchar *sqlstate) {
	return network_mysqld_con_send_error_full_all(con, errmsg, errmsg_len, errorcode, sqlstate, TRUE);
}


/**
 * send a error-packet to the client connection
 *
 * errorcode is 1000, sqlstate is NULL
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 *
 * @see network_mysqld_con_send_error_full
 */
int network_mysqld_con_send_error(network_socket *con, const char *errmsg, gsize errmsg_len) {
	return network_mysqld_con_send_error_full(con, errmsg, errmsg_len, ER_UNKNOWN_ERROR, NULL);
}

/**
 * send a error packet to the client connection (pre-4.1 protocol)
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 * @param errorcode   mysql error-code we want to send
 *
 * @return 0 on success
 */
int network_mysqld_con_send_error_pre41_full(network_socket *con, const char *errmsg, gsize errmsg_len, guint errorcode) {
	return network_mysqld_con_send_error_full_all(con, errmsg, errmsg_len, errorcode, NULL, FALSE);
}

/**
 * send a error-packet to the client connection (pre-4.1 protocol)
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 *
 * @see network_mysqld_con_send_error_pre41_full
 */
int network_mysqld_con_send_error_pre41(network_socket *con, const char *errmsg, gsize errmsg_len) {
	return network_mysqld_con_send_error_pre41_full(con, errmsg, errmsg_len, ER_UNKNOWN_ERROR);
}


/**
 * get a full packet from the raw queue and move it to the packet queue 
 */
network_socket_retval_t network_mysqld_con_get_packet(chassis G_GNUC_UNUSED*chas, network_socket *con) {
	GString *packet = NULL;
	GString header;
	char header_str[NET_HEADER_SIZE + 1] = "";
	guint32 packet_len;
	guint8  packet_id;

	/** 
	 * read the packet header (4 bytes)
	 */
	header.str = header_str;
	header.allocated_len = sizeof(header_str);
	header.len = 0;

	/* read the packet len if the leading packet */
	if (!network_queue_peek_string(con->recv_queue_raw, NET_HEADER_SIZE, &header)) {
		/* too small */

		return NETWORK_SOCKET_WAIT_FOR_EVENT;
	}

	packet_len = network_mysqld_proto_get_packet_len(&header);
	packet_id  = network_mysqld_proto_get_packet_id(&header);

	/* move the packet from the raw queue to the recv-queue */
	if ((packet = network_queue_pop_string(con->recv_queue_raw, packet_len + NET_HEADER_SIZE, NULL))) {
#ifdef NETWORK_DEBUG_TRACE_IO
		/* to trace the data we received from the socket, enable this */
		g_debug_hexdump(G_STRLOC, S(packet));
#endif

		if (con->packet_id_is_reset) {
			con->last_packet_id = packet_id;
			con->packet_id_is_reset = FALSE;
		} else if (packet_id != (guint8)(con->last_packet_id + 1)) {
			g_critical("%s: received packet-id %d, but expected %d ... out of sync.",
					G_STRLOC,
					packet_id,
					con->last_packet_id + 1);
			g_string_free(packet, TRUE);
			return NETWORK_SOCKET_ERROR;
		} else {
			con->last_packet_id = packet_id;
		}
	
		network_queue_append(con->recv_queue, packet);
	} else {
		return NETWORK_SOCKET_WAIT_FOR_EVENT;
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * read a MySQL packet from the socket
 *
 * the packet is added to the con->recv_queue and contains a full mysql packet
 * with packet-header and everything 
 */
network_socket_retval_t network_mysqld_read(chassis G_GNUC_UNUSED*chas, network_socket *con) {
	switch (network_socket_read(con)) {
	case NETWORK_SOCKET_WAIT_FOR_EVENT:
		return NETWORK_SOCKET_WAIT_FOR_EVENT;
	case NETWORK_SOCKET_ERROR:
		return NETWORK_SOCKET_ERROR;
	case NETWORK_SOCKET_SUCCESS:
		break;
	case NETWORK_SOCKET_ERROR_RETRY:
		g_error("NETWORK_SOCKET_ERROR_RETRY wasn't expected");
		break;
	}

	return network_mysqld_con_get_packet(chas, con);
}

network_socket_retval_t network_mysqld_write(chassis G_GNUC_UNUSED*chas, network_socket *con) {
	network_socket_retval_t ret;

	ret = network_socket_write(con, -1);

	return ret;
}

/**
 * call the hooks of the plugins for each state
 *
 * if the plugin doesn't implement a hook, we provide a default operation
 *
 * @param srv      the global context
 * @param con      the connection context
 * @param state    state to handle
 * @return         NETWORK_SOCKET_SUCCESS on success
 */
network_socket_retval_t plugin_call(chassis *srv, network_mysqld_con *con, int state) {
	network_socket_retval_t ret;
	NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;

	switch (state) {
	case CON_STATE_INIT:
		func = con->plugins.con_init;

		if (!func) { /* default implementation */
			con->state = CON_STATE_CONNECT_SERVER;
		}
		break;
	case CON_STATE_CONNECT_SERVER:
		func = con->plugins.con_connect_server;

		if (!func) { /* default implementation */
			con->state = CON_STATE_READ_HANDSHAKE;
		}

		break;
	case CON_STATE_SEND_HANDSHAKE:
		func = con->plugins.con_send_handshake;

		if (!func) { /* default implementation */
			con->state = CON_STATE_READ_AUTH;
		}

		break;
	case CON_STATE_READ_HANDSHAKE:
		func = con->plugins.con_read_handshake;

		break;
	case CON_STATE_READ_AUTH:
		func = con->plugins.con_read_auth;

		break;
	case CON_STATE_SEND_AUTH:
		func = con->plugins.con_send_auth;

		if (!func) { /* default implementation */
			con->state = CON_STATE_READ_AUTH_RESULT;
		}
		break;
	case CON_STATE_READ_AUTH_RESULT:
		func = con->plugins.con_read_auth_result;
		break;
	case CON_STATE_SEND_AUTH_RESULT: 
		/* called after the auth data is sent to the client */
		func = con->plugins.con_send_auth_result;

		if (!func) {
			/*
			 * figure out what to do next:
			 * - switch to 'read command from client'
			 * - close connection
			 * - read auth-data from client
			 * - read another auth-result packet from server
			 */
			switch (con->auth_result_state) {
			case MYSQLD_PACKET_OK:
				/* OK, delivered to client, switch to command phase */
				con->state = CON_STATE_READ_QUERY;
				break;
			case MYSQLD_PACKET_ERR:
				/* ERR delivered to client, close the connection now */
				con->state = CON_STATE_ERROR;
				break;
			case 0x01: /* more auth data */
				/**
				 * FIXME: we should track that the server only sends us a 0x01 reply if
				 * we first went through "switch auth packet"
				 */

				/**
				 * if we switched to win-auth and SPNEGO is used, check if the response packet contains:
				 * 
				 *   negState = accept-succeeded.
				 */
				if ((strleq(S(con->auth_switch_to_method), C("authentication_windows_client"))) &&
				    con->auth_next_packet_is_from_server) {
					/* we either have SPNEGO or NTLM */
					con->state = CON_STATE_READ_AUTH_RESULT;
					break;
				}
			case MYSQLD_PACKET_EOF:
				/*
				 * next, read the auth data from the client
				 */
				con->state = CON_STATE_READ_AUTH_OLD_PASSWORD;
				break;
			default:
				g_debug("%s.%d: unexpected state for SEND_AUTH_RESULT: %02x", 
						__FILE__, __LINE__,
						con->auth_result_state);
				con->state = CON_STATE_ERROR;
				break;
			}
		}
		break;
	case CON_STATE_READ_AUTH_OLD_PASSWORD:
		func = con->plugins.con_read_auth_old_password;

		if (!func) {
			network_socket *recv_sock, *send_sock;
			network_packet packet;
			guint32 packet_len;

			/* move the packet to the send queue */

			recv_sock = con->client;
			send_sock = con->server;

			if (NULL == con->server) {
				/**
				 * we have to auth against same backend as we did before
				 * but the user changed it
				 */

				g_message("%s.%d:  read-auth-old-password failed as backend_ndx got reset.", __FILE__, __LINE__);

				network_mysqld_con_send_error(con->client, C(" read-auth-old-password failed as backend_ndx got reset."));
				con->state = CON_STATE_SEND_ERROR;
				break;
			}

			packet.data = g_queue_peek_head(recv_sock->recv_queue->chunks);
			packet.offset = 0;

			packet_len = network_mysqld_proto_get_packet_len(packet.data);

			if ((strleq(S(con->auth_switch_to_method), C("authentication_windows_client"))) &&
			    (con->auth_switch_to_round == 0) &&
			    (packet_len == 255)) {
#if 1
				/**
				 * FIXME: the 2-packet win-auth protocol enhancements aren't properly tested yet.
				 * therefore they are disabled for now.
				 */
				g_string_free(g_queue_pop_head(recv_sock->recv_queue->chunks), TRUE);

				network_mysqld_con_send_error(recv_sock, C("long packets for windows-authentication aren't completely handled yet. Please use another auth-method for now."));

				con->state = CON_STATE_SEND_ERROR;
#else
				con->auth_switch_to_round++;
				/* move the packet to the send-queue
				 */
				network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
						g_queue_pop_head(recv_sock->recv_queue->chunks));

				/* stay in this state and read the next packet too */
#endif
			} else {
				/* move the packet to the send-queue
				 */
				network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
						g_queue_pop_head(recv_sock->recv_queue->chunks));

				con->state = CON_STATE_SEND_AUTH_OLD_PASSWORD;
			}
		}
		break;
	case CON_STATE_SEND_AUTH_OLD_PASSWORD:
		/**
		 * data is at the server, read the response next 
		 */
		con->state = CON_STATE_READ_AUTH_RESULT;
		break;
	case CON_STATE_READ_QUERY:
		func = con->plugins.con_read_query;
		break;
	case CON_STATE_SEND_QUERY:
		func = con->plugins.con_send_query;
		break;
	case CON_STATE_PROCESS_READ_QUERY:
		func = con->plugins.con_process_read_query;
		break;
	case CON_STATE_GET_SERVER_LIST:
		func = con->plugins.con_get_server_list;
		break;
	case CON_STATE_GET_SERVER_CONNECTION_LIST:
		func = con->plugins.con_get_server_connection_list;
		break;
	case CON_STATE_READ_QUERY_RESULT:
		func = con->plugins.con_read_query_result;
		break;
	case CON_STATE_SEND_QUERY_RESULT:
		func = con->plugins.con_send_query_result;

		if (!func) { /* default implementation */
			con->state = CON_STATE_READ_QUERY;
		}
		break;

	case CON_STATE_SEND_LOCAL_INFILE_DATA:
		func = con->plugins.con_send_local_infile_data;

		if (!func) { /* default implementation */
			con->state = CON_STATE_READ_LOCAL_INFILE_RESULT;
		}

		break;
	case CON_STATE_READ_LOCAL_INFILE_DATA:
		func = con->plugins.con_read_local_infile_data;

		if (!func) { /* the plugins have to implement this function to track LOAD DATA LOCAL INFILE handling work */
			con->state = CON_STATE_ERROR;
		}

		break;
	case CON_STATE_SEND_LOCAL_INFILE_RESULT:
		func = con->plugins.con_send_local_infile_result;

		if (!func) { /* default implementation */
			con->state = CON_STATE_READ_QUERY;
		}

		break;
	case CON_STATE_READ_LOCAL_INFILE_RESULT:
		func = con->plugins.con_read_local_infile_result;

		if (!func) { /* the plugins have to implement this function to track LOAD DATA LOCAL INFILE handling work */
			con->state = CON_STATE_ERROR;
		}

		break;
	case CON_STATE_ERROR:
		g_debug("%s.%d: not executing plugin function in state CON_STATE_ERROR", __FILE__, __LINE__);
		return NETWORK_SOCKET_SUCCESS;
	default:
		g_error("%s.%d: unhandled state: %d", 
				__FILE__, __LINE__,
				state);
	}
	if (!func) return NETWORK_SOCKET_SUCCESS;

	//LOCK_LUA(srv->priv->sc);
	ret = (*func)(srv, con);
	//UNLOCK_LUA(srv->priv->sc);

	return ret;
}

/**
 * reset the command-response parsing
 *
 * some commands needs state information and we have to 
 * reset the parsing as soon as we add a new command to the send-queue
 */
void network_mysqld_con_reset_command_response_state(network_mysqld_con *con) {
	con->parse.command = -1;
	if (con->parse.data && con->parse.data_free) {
		con->parse.data_free(con->parse.data);

		con->parse.data = NULL;
		con->parse.data_free = NULL;
	}
}

/**
 * get the name of a connection state
 */
const char *network_mysqld_con_state_get_name(network_mysqld_con_state_t state) {
	switch (state) {
	case CON_STATE_INIT: return "CON_STATE_INIT";
	case CON_STATE_CONNECT_SERVER: return "CON_STATE_CONNECT_SERVER";
	case CON_STATE_READ_HANDSHAKE: return "CON_STATE_READ_HANDSHAKE";
	case CON_STATE_SEND_HANDSHAKE: return "CON_STATE_SEND_HANDSHAKE";
	case CON_STATE_READ_AUTH: return "CON_STATE_READ_AUTH";
	case CON_STATE_SEND_AUTH: return "CON_STATE_SEND_AUTH";
	case CON_STATE_READ_AUTH_OLD_PASSWORD: return "CON_STATE_READ_AUTH_OLD_PASSWORD";
	case CON_STATE_SEND_AUTH_OLD_PASSWORD: return "CON_STATE_SEND_AUTH_OLD_PASSWORD";
	case CON_STATE_READ_AUTH_RESULT: return "CON_STATE_READ_AUTH_RESULT";
	case CON_STATE_SEND_AUTH_RESULT: return "CON_STATE_SEND_AUTH_RESULT";
	case CON_STATE_READ_QUERY: return "CON_STATE_READ_QUERY";
	case CON_STATE_SEND_QUERY: return "CON_STATE_SEND_QUERY";
	case CON_STATE_READ_QUERY_RESULT: return "CON_STATE_READ_QUERY_RESULT";
	case CON_STATE_SEND_QUERY_RESULT: return "CON_STATE_SEND_QUERY_RESULT";
	case CON_STATE_READ_LOCAL_INFILE_DATA: return "CON_STATE_READ_LOCAL_INFILE_DATA";
	case CON_STATE_SEND_LOCAL_INFILE_DATA: return "CON_STATE_SEND_LOCAL_INFILE_DATA";
	case CON_STATE_READ_LOCAL_INFILE_RESULT: return "CON_STATE_READ_LOCAL_INFILE_RESULT";
	case CON_STATE_SEND_LOCAL_INFILE_RESULT: return "CON_STATE_SEND_LOCAL_INFILE_RESULT";
	case CON_STATE_CLOSE_CLIENT: return "CON_STATE_CLOSE_CLIENT";
	case CON_STATE_CLOSE_SERVER: return "CON_STATE_CLOSE_SERVER";
	case CON_STATE_ERROR: return "CON_STATE_ERROR";
	case CON_STATE_SEND_ERROR: return "CON_STATE_SEND_ERROR";
	// 补充了三个中间的状态
	case CON_STATE_PROCESS_READ_QUERY: return "CON_STATE_PROCESS_READ_QUERY";
	case CON_STATE_GET_SERVER_LIST: return "CON_STATE_GET_SERVER_LIST";
	case CON_STATE_GET_SERVER_CONNECTION_LIST: return "CON_STATE_GET_SERVER_CONNECTION_LIST";
	case CON_STATE_SEND_ERROR_TO_CLIENT: return "CON_STATE_SEND_ERROR_TO_CLIENT";
	}

	return "unknown";
}

static int network_mysqld_con_track_auth_result_state(network_mysqld_con *con) {
	network_packet packet;
	guint8 state;
	int err = 0;

	/**
	 * depending on the result-set we have different exit-points
	 * - OK  -> READ_QUERY
	 * - EOF -> (read old password hash) 
	 * - ERR -> ERROR
	 */
	packet.data = g_queue_peek_head(con->server->recv_queue->chunks);
	packet.offset = 0;

	err = err || network_mysqld_proto_skip_network_header(&packet);
	err = err || network_mysqld_proto_peek_int8(&packet, &state);

	if (err) return -1;

	con->auth_result_state = state;

	if (state == 0xfe) {
		/* a long auth-switch packet */
		err = err || network_mysqld_proto_skip(&packet, 1);

		if (packet.data->len - packet.offset > 0) {
			err = err || network_mysqld_proto_get_gstring(&packet, con->auth_switch_to_method);
			err = err || network_mysqld_proto_get_gstring_len(&packet, packet.data->len - packet.offset, con->auth_switch_to_data);
		} else {
			/* just in case we get here switch ... which shouldn't happen ... */
			g_string_truncate(con->auth_switch_to_method, 0);
			g_string_truncate(con->auth_switch_to_data, 0);
		}
		con->auth_switch_to_round = 0;
		con->auth_next_packet_is_from_server = FALSE;
	} else if (state == 0x01) {
		if ((strleq(S(con->auth_switch_to_method), C("authentication_windows_client")))) {
			GError *gerr = NULL;

			/* if the packet comes from the server, has a 0x01, is SPNEGO and has 'accept-completed' set,
			 * the next packet comes from the server too 
			 */
			if (0 != network_mysqld_proto_skip(&packet, 1)) {
				/* hmm ... what to do now ? */
				err = 1;
			} else if (FALSE == network_asn1_is_valid(&packet, &gerr)) {
				g_debug("%s: ASN1 packet is invalid: %s", G_STRLOC, gerr->message);
				g_clear_error(&gerr);
				err = 1;
			} else {
				network_spnego_response_token *token;

				token = network_spnego_response_token_new();

				if (TRUE == network_spnego_proto_get_response_token(&packet, token, &gerr)) {
					if (token->negState != SPNEGO_RESPONSE_STATE_ACCEPT_INCOMPLETE) {
						con->auth_next_packet_is_from_server = TRUE;
					}
				} else {
					g_debug("%s: parsing spnego failed: %s", G_STRLOC, gerr->message);
					/* do we care why it failed ? */
					g_clear_error(&gerr);
				}

				network_spnego_response_token_free(token);
			}
		}
	}
	return err ? -1 : 0;
}

void ev_dump_info(struct event *ev) {
	if (ev != NULL ) {
		g_debug(
				"fd: %d, base: %p, events: %x, callback: %p, args: %p",
				event_get_fd(ev), event_get_base(ev),
				event_get_events(ev), event_get_callback(ev),
				event_get_callback_arg(ev));
	}
}

void all_cb_dump_info(void) {
	g_debug("network_mysqld_con_accept: %p", network_mysqld_con_accept);
	g_debug("chassis_global_event_handle: %p", chassis_global_event_handle);
	g_debug("chassis_local_event_handle: %p", chassis_local_event_handle);
	g_debug("network_mysqld_con_handle: %p", network_mysqld_con_handle);
	g_debug("network_mysqld_async_con_handle: %p", network_mysqld_async_con_handle);
	g_debug("network_mysqld_cache_con_idle_handle: %p", network_mysqld_cache_con_idle_handle);
}

static void desc_clients_for_con(network_mysqld_con *con) {
	if (NULL == con || NULL == con->srv || NULL == con->srv->priv) {
		return;
	}
	network_backend_t * bk_tmp = NULL;
	if (con->srv->priv->backends && con->related_bk) {
		guint index = 0;
		GString *bk_name_tmp = NULL;
		for (index = 0; index < con->related_bk->len; index++) {
			bk_name_tmp = con->related_bk->pdata[index];
			if (NULL != bk_name_tmp) {
				bk_tmp = network_backends_get_by_name(
						con->srv->priv->backends,
						bk_name_tmp->str);
				if (bk_tmp) {
					client_desc(bk_tmp, con->type);
				}
			}
		}
	}
}

/**
 * handle the different states of the MySQL protocol
 *
 * @param event_fd     fd on which the event was fired
 * @param events       the event that was fired
 * @param user_data    the connection handle
 */

void network_mysqld_con_handle(int event_fd, short events, void *user_data) {
	//主要的处理流程的函数修改在这里
	network_mysqld_con_state_t ostate;
	network_mysqld_con *con = user_data;

	g_assert(con);

	chassis *srv = con->srv;
	int retval;
	network_socket_retval_t call_ret;

	g_assert(srv);

//	g_debug("[%s]: event_fd(%d) events(%d) ud(%p) server(%d) cache_server(%d) client(%d)"
//			, G_STRLOC, event_fd, events, user_data
//			, (con->server) ? con->server->fd : 0
//			, (con->cache_server) ? con->cache_server->fd : 0
//			, (con->client) ? con->client->fd : 0);
//	if (con->server && con->server->fd == event_fd) ev_dump_info(&(con->server->event));
//	if (con->cache_server && con->cache_server->fd == event_fd) ev_dump_info(&(con->cache_server->event));
//	if (con->client && con->client->fd == event_fd) ev_dump_info(&(con->client->event));
//	all_cb_dump_info();

	/* @fixme 据说泄漏 */
	if ((-1 != event_fd) && (con->client != NULL)
			&& (event_fd != con->client->fd) && (EV_TIMEOUT == events) && (con->state != CON_STATE_READ_QUERY_RESULT)) {
		all_cb_dump_info();

		g_critical("con->server = %d , con->cache_server = %d , event_fd = %d",
				con->server?con->server->fd:-1,
				con->cache_server?con->cache_server->fd:-1, event_fd);

//		g_error(
//				"[%s]: EV_TIMEOUT event_fd(%d) events(%d) ud(%p) unexpected event for server",
//				G_STRLOC, event_fd, events, user_data);
		g_critical(	"[%s]: EV_TIMEOUT event_fd(%d) events(%d) ud(%p) unexpected event for server",
					G_STRLOC, event_fd, events, user_data);
		return;
	}

	if (events == EV_READ) {
		gboolean from_client = TRUE;
		g_mutex_lock(&con->cache_server_mutex);
		if (con->cache_server != NULL && con->cache_server->fd == event_fd) {
			from_client = FALSE;
		}
		g_mutex_unlock(&con->cache_server_mutex);
		if (con->server && event_fd == con->server->fd) {
			from_client = FALSE;
		}
		int b = -1;
		g_debug("[%s]: %s SOCKET=%d get event EV_READ.", G_STRLOC, from_client?"CLIENT":"SERVER", event_fd);
		/**
		 * check how much data there is to read
		 *
		 * ioctl()
		 * - returns 0 if connection is closed
		 * - or -1 and ECONNRESET on solaris
		 *   or -1 and EPIPE on HP/UX
		 */
		if (ioctl(event_fd, FIONREAD, &b)) {

			g_debug("[%s]：get connection close for SOCKET = %d", G_STRLOC, event_fd);

			switch (errno) {
			case E_NET_CONNRESET: /* solaris */
			case EPIPE: /* hp/ux */
				if (con->client && event_fd == con->client->fd) {
					/* the client closed the connection, let's keep the server side open */
					g_debug("[%s]：the client closed the connection, let's keep the server side open. fd=%d", G_STRLOC, event_fd);
					con->state = CON_STATE_CLOSE_CLIENT;
				} else if (con->server && event_fd == con->server->fd && con->com_quit_seen) {
					g_debug("[%s]：the server closed the connection by COM_QUIT. fd=%d", G_STRLOC, event_fd);
					con->state = CON_STATE_CLOSE_SERVER;
				} else if (con->cache_server && event_fd == con->cache_server->fd && con->com_quit_seen) {
					g_debug("[%s]：the cache server closed the connection by COM_QUIT. fd=%d", G_STRLOC, event_fd);
					con->state = CON_STATE_CLOSE_SERVER;
				} else {
					/* server side closed on use, oops, close both sides */
					g_debug("[%s]：server side closed on use, oops, close both sides. fd=%d", G_STRLOC, event_fd);
					con->state = CON_STATE_ERROR;
				}
				break;
			default:
				g_critical("ioctl(%d, FIONREAD, ...) failed: %s", event_fd, g_strerror(errno));

				con->state = CON_STATE_ERROR;
				break;
			}
		} else if (b != 0) {
			if (con->client && event_fd == con->client->fd) {
				con->client->to_read = b;
			} else if (con->server && event_fd == con->server->fd) {
				con->server->to_read = b;
			} else if (con->cache_server && event_fd == con->cache_server->fd) {
				con->cache_server->to_read = b;
			} else {
				g_error("%s.%d: neither nor", __FILE__, __LINE__);
			}
		} else { /* Linux */
			if (con->client && event_fd == con->client->fd) {
				/* the client closed the connection, let's keep the server side open */
				con->state = CON_STATE_CLOSE_CLIENT;
			} else if (con->server && event_fd == con->server->fd && con->com_quit_seen) {
				con->state = CON_STATE_CLOSE_SERVER;
			} else if (con->cache_server && event_fd == con->cache_server->fd && con->com_quit_seen) {
				con->state = CON_STATE_CLOSE_SERVER;
			} else {
				/* server side closed on use, oops, close both sides */
				g_warning(
						"[%s]: EV_READ event_fd(%d) events(%d) unexpected event, con state=%s clientfd=%d serverfd=%d cacheserverfd=%d errno=%d, %s",
						G_STRLOC, event_fd, events,
						network_mysqld_con_state_get_name(con->state),
						con->client ? con->client->fd : 0,
						con->server ? con->server->fd : 0,
						con->cache_server ? con->cache_server->fd : 0,
						errno,
						g_strerror(errno));
				con->state = CON_STATE_ERROR;
			}
		}
	} else if (events == EV_WRITE) {
		g_debug("[%s]: EV_WRITE event_fd(%d) events(%d)", G_STRLOC, event_fd, events);
	} else if (events == EV_TIMEOUT) {
		g_debug("[%s]: EV_TIMEOUT event_fd(%d) events(%d)", G_STRLOC, event_fd, events);

		if (con->state == CON_STATE_READ_QUERY && (con->client != NULL) && con->client->fd == event_fd) {
			g_warning("client connection socket=%d has been idle for too long, closing ...\n", event_fd);
			con->state = CON_STATE_CLOSE_CLIENT;
		}
		// 因为修改之后server端的连接超时或者send auth的超时不是在本函数中处理，
		// 因而一下代码不在需要，不过可以借鉴一下代码的实现来实现后端proxy与server连接的重试工作
		/* if we got a timeout on CON_STATE_CONNECT_SERVER we should pick another backend */
		//switch ((retval = plugin_call_timeout(srv, con))) {
		//case NETWORK_SOCKET_SUCCESS:
			/* the plugin did set a reasonable next state */
		//	break;
		//default:
		//	con->state = CON_STATE_ERROR;
		//	break;
		//}
	}

	if (mysqld_con_shutdown(con)) {
		// 对应的后端关闭，需要对其特殊处理
		/**
		 * 现在直接设置con的状态为error,让其自己关闭自身连接
		 * @todo 最好实现向client发送错误包
		 */
		con->state = CON_STATE_ERROR;
	}

#ifdef ONE_QUEUE_PER_THREAD_DISABLED
	/*
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	event_set(&(ev_struct->event), ev_struct->fd, ev_type, network_mysqld_con_handle, user_data); \
	chassis_event_add_with_timeout(srv, &(ev_struct->event), timeout);
	*/
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	event_assign(&(ev_struct->event), srv->event_base, ev_struct->fd, ev_type, network_mysqld_con_handle, user_data); \
	chassis_event_add_with_timeout(srv, &(ev_struct->event), timeout);
#else
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	event_assign(&(ev_struct->event), chassis_thread_get_local_event_base(srv), ev_struct->fd, ev_type, network_mysqld_con_handle, user_data); \
	event_add(&(ev_struct->event), timeout);
#endif

	/**
	 * loop on the same connection as long as we don't end up in a stable state
	 */

	if (event_fd != -1) {
		NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::done");
	} else {
		NETWORK_MYSQLD_CON_TRACK_TIME(con, "con_handle_start");
	}

	do {
		if (mysqld_con_shutdown(con)) {
			// 对应的后端关闭，需要对其特殊处理
			/**
			 * 现在直接设置con的状态为error,让其自己关闭自身连接
			 * @todo 最好实现向client发送错误包
			 */
			con->state = CON_STATE_ERROR;
		}
		struct timeval timeout;

		ostate = con->state;
#ifdef NETWORK_DEBUG_TRACE_STATE_CHANGES
		/* if you need the state-change information without dtrace, enable this */
		g_debug("%s: [%d] %s",
				G_STRLOC,
				getpid(),
				network_mysqld_con_state_get_name(con->state));
#endif

		MYSQLPROXY_STATE_CHANGE(event_fd, events, con->state);
		switch (con->state) {
		case CON_STATE_ERROR:
			// 这里我们需要将连接数更新，然后再释放连接
			// 我们认为出错的连接没有复用的价值了，
			// 因而这里会将client及server端的连接都释放掉
			/**
			 * @author sohu-inc.com
			 * 2013/05/22
			 * 这里还需要将前端连接限制的连接数减1
			 */
			//已经将下面的统计数的同步工作放到了，proxy_disconnect_client中来做了
			/*if (con->client && con->client->response && con->client->ip_region ) {
				guint *con_in_use = get_login_users(con->srv, con->type, con->client->response->username->str, con->client->ip_region);
				if(con_in_use) {
					g_atomic_int_dec_and_test(con_in_use);
				}
			}
			if (con->server && con->server->dst->name) {
				// 1. 相应的backend连接数--
				network_backend_t * bk_tmp = network_backends_get_by_name(con->srv->priv->backends, con->server->dst->name->str);
                		g_assert(bk_tmp);
				g_mutex_lock(&bk_tmp->mutex[con->type]);
				bk_tmp->connected_clients[con->type]--;
				g_mutex_unlock(&bk_tmp->mutex[con->type]);
				
				pool_status * pool_st = get_conn_pool_status(bk_tmp->pool[con->type], con->server->response->username->str);
				g_assert(pool_st);
				// 2. 相应的连接池的统计数据更新：using--
				g_mutex_lock(&pool_st->status_mutex);
				pool_st->conn_num_in_use--;
				if(pool_st->conn_num_in_use < 0 )
					pool_st->conn_num_in_use = 0;
				g_mutex_unlock(&pool_st->status_mutex);
			}*/
			/* we can't go on, close the connection */
			{
				gchar *which_connection = "a"; /* some connection, don't know yet */
				if (con->server && event_fd == con->server->fd) {
					which_connection = "server";
				} else if (con->client && event_fd == con->client->fd) {
					which_connection = "client";
				}
				g_debug("[%s]: error on %s connection (fd: %d event: %d). closing client connection.",
						G_STRLOC, which_connection,	event_fd, events);
			}
			plugin_call_cleanup(srv, con);
			network_mysqld_con_free(con);

			con = NULL;

			return;

		case CON_STATE_CLOSE_CLIENT:
		case CON_STATE_CLOSE_SERVER: {
			chassis_event_thread_t *current_thread = chassis_thread_get_local_thread(srv);
			/* FIXME: this comment has nothing to do with reality...
			 * the server connection is still fine, 
			 * let's keep it open for reuse */
			connection_state_update(con, CONNECTION_STATE_CLOSE, CONNECTION_STATE_TYPE_CPU);
			/*刷新线程级的连接统计信息*/
			thread_connection_state_set_update(current_thread->connection_state, con->connection_state->statistics);

			plugin_call_cleanup(srv, con);

			g_debug("connection state: %d", con->connection_id);
			connection_state_set_dump(con->connection_state);
			thread_connection_state_set_dump(current_thread->connection_state);

#ifdef NETWORK_MYSQLD_WANT_CON_TRACK_TIME 
			/* dump the timestamps of this connection */
			if (srv->log->min_lvl == G_LOG_LEVEL_DEBUG) {
				GList *node;
				guint64 abs_usec = 0;
				guint64 wait_event_usec = 0;
				guint64 lua_usec = 0;

				for (node = con->timestamps->timestamps->head; node; node = node->next) {
					chassis_timestamp_t *prev = node->prev ? node->prev->data : NULL;
					chassis_timestamp_t *cur = node->data;
					guint64 rel_usec = prev ? cur->usec - prev->usec: 0;
					guint64 rel_cycles = prev ? cur->cycles - prev->cycles: 0;

					abs_usec += rel_usec;

					g_debug("%-35s usec=%8"G_GUINT64_FORMAT", cycles=%8"G_GUINT64_FORMAT", abs-usec=%8"G_GUINT64_FORMAT" (%s:%d)",
							cur->name,
							rel_usec,
							rel_cycles,
							abs_usec,
							cur->filename, cur->line
					       );

					if (strstr(cur->name, "leave_lua")) {
						lua_usec += rel_usec;
					} else if (strstr(cur->name, "wait_for_event::done")) {
						wait_event_usec += rel_usec;
					}
				}

				g_debug("%-35s usec=%8"G_GUINT64_FORMAT"",
						"abs wait-for-event::done",
						wait_event_usec
				       );
				g_debug("%-35s usec=%8"G_GUINT64_FORMAT"",
						"abs lua-exec::done",
						lua_usec
				       );


			}
#endif

			network_mysqld_con_free(con);

			con = NULL;

			return;
		}
		case CON_STATE_INIT:
			connection_state_update(con, CONNECTION_STATE_INIT, CONNECTION_STATE_TYPE_CPU);

			/* if we are a proxy ask the remote server for the hand-shake packet 
			 * if not, we generate one */
			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				/**
				 * no luck, let's close the connection
				 */
				g_critical("%s.%d: plugin_call(CON_STATE_INIT) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				
				break;
			}

			break;

		case CON_STATE_CONNECT_SERVER:
			// 认证提前之后这个状态不会再经过，可以去掉
			g_assert_not_reached();
			switch ((retval = plugin_call(srv, con, con->state))) {
			case NETWORK_SOCKET_SUCCESS:

				/**
				 * hmm, if this is success and we have something in the clients send-queue
				 * we just send it out ... who needs a server ? */

				if ((con->client != NULL && con->client->send_queue->chunks->length > 0) && 
				     con->server == NULL) {
					/* we want to send something to the client */

					con->state = CON_STATE_SEND_HANDSHAKE;
				} else {
					g_assert(con->server);
				}

				break;
			case NETWORK_SOCKET_ERROR_RETRY:
				if (con->server) {
					timeout = con->connect_timeout;
					/**
					 * we have a server connection waiting to begin writable
					 */
					WAIT_FOR_EVENT(con->server, EV_WRITE, &timeout);
					NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::connect_server");
					return;
				} else {
					/* try to get a connection to another backend,
					 *
					 * setting ostate = CON_STATE_INIT is a hack to make sure
					 * the loop is coming back to this function again */
					ostate = CON_STATE_INIT;
				}

				break;
			case NETWORK_SOCKET_ERROR:
				/**
				 * connecting failed and no option to retry
				 *
				 * close the connection
				 */
				con->state = CON_STATE_SEND_ERROR;
				break;
			default:
				g_critical("%s: hook for CON_STATE_CONNECT_SERVER return invalid return code: %d", 
						G_STRLOC, 
						retval);

				con->state = CON_STATE_ERROR;
				
				break;
			}

			break;

		case CON_STATE_READ_HANDSHAKE:
		{
			/**
			 * read auth data from the remote mysql-server 
			 */
			// 认证提前之后这个状态也不会经过
			g_assert_not_reached();
			network_socket *recv_sock;
			recv_sock = con->server;
			g_assert(events == 0 || event_fd == recv_sock->fd);

			switch (network_mysqld_read(srv, recv_sock)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT: 
				timeout = con->read_timeout;

				/* call us again when you have a event */
				WAIT_FOR_EVENT(con->server, EV_READ, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_handshake");

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical("%s.%d: network_mysqld_read(CON_STATE_READ_HANDSHAKE) returned an error", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}

			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_ERROR:
				/**
				 * we couldn't understand the pack from the server 
				 * 
				 * we have something in the queue and will send it to the client
				 * and close the connection afterwards
				 */
				
				con->state = CON_STATE_SEND_ERROR;

				break;
			default:
				g_critical("%s.%d: ...", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}
	
			break;
		}

		case CON_STATE_SEND_HANDSHAKE:
			/* PROXY --------> CLIENT */
			/* send the hand-shake to the client and wait for a response */
			connection_state_update(con, CONNECTION_STATE_SEND_HANDSHAKE, CONNECTION_STATE_TYPE_CPU);

			switch (network_mysqld_write(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT: 
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_handshake");
				connection_state_update(con, CONNECTION_STATE_SEND_HANDSHAKE, CONNECTION_STATE_TYPE_IOWAIT);

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				/**
				 * writing failed, closing connection
				 */
				con->state = CON_STATE_ERROR;
				break;
			}

			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_SEND_HANDSHAKE) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}

			break;

		case CON_STATE_READ_AUTH:
		{
			/* CLIENT -------> PROXY */
			/* read auth from client */
			network_socket *recv_sock;

			recv_sock = con->client;

			g_assert(events == 0 || event_fd == recv_sock->fd);

			connection_state_update(con, CONNECTION_STATE_READ_AUTH, CONNECTION_STATE_TYPE_CPU);

			switch (network_mysqld_read(srv, recv_sock)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->read_timeout;

				WAIT_FOR_EVENT(con->client, EV_READ, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_auth");
				connection_state_update(con, CONNECTION_STATE_READ_AUTH, CONNECTION_STATE_TYPE_IOWAIT);

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical("%s.%d: network_mysqld_read(CON_STATE_READ_AUTH) returned an error", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}
			
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_ERROR:
				con->state = CON_STATE_SEND_ERROR;
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_READ_AUTH) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}

			break;
		}

		case CON_STATE_SEND_AUTH:
			/** 认证提前之后这个状态不会被经过 */
			g_assert_not_reached();
			/* send the auth-response to the server */
			switch (network_mysqld_write(srv, con->server)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->server, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_auth");

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				/* might be a connection close, we should just close the connection and be happy */
				con->state = CON_STATE_ERROR;

				break;
			}
			
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_SEND_AUTH) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}

			break;

		case CON_STATE_READ_AUTH_RESULT:
		{
			/** 认证提前之后，这个状态不会经过*/
			g_assert_not_reached();
			/* read the auth result from the server */
			network_socket *recv_sock;

			recv_sock = con->server;

			g_assert(events == 0 || event_fd == recv_sock->fd);

			switch (network_mysqld_read(srv, recv_sock)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->read_timeout;

				WAIT_FOR_EVENT(con->server, EV_READ, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_auth_result");
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical("%s.%d: network_mysqld_read(CON_STATE_READ_AUTH_RESULT) returned an error", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			if (0 != network_mysqld_con_track_auth_result_state(con)) {
				con->state = CON_STATE_ERROR;
				break;
			}

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_READ_AUTH_RESULT) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				break;
			}

			break;
		}

		case CON_STATE_SEND_AUTH_RESULT:
		{
			/** PROXY ------> CLIENT */
			/* send the hand-shake to the client and wait for a response */
			connection_state_update(con, CONNECTION_STATE_SEND_AUTH_RESULT, CONNECTION_STATE_TYPE_CPU);

			switch (network_mysqld_write(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_auth_result");
				connection_state_update(con, CONNECTION_STATE_SEND_AUTH_RESULT, CONNECTION_STATE_TYPE_IOWAIT);
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_debug("%s.%d: network_mysqld_write(CON_STATE_SEND_AUTH_RESULT) returned an error", __FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				break;
			}
			
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: ...", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}
				
			break;
		}

		case CON_STATE_READ_AUTH_OLD_PASSWORD: 
			/* read auth from client */
			switch (network_mysqld_read(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->read_timeout;

				WAIT_FOR_EVENT(con->client, EV_READ, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_auth_old_password");

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical("%s.%d: network_mysqld_read(CON_STATE_READ_AUTH_OLD_PASSWORD) returned an error", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				return;
			}
			
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_READ_AUTH_OLD_PASSWORD) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}

			break;

		case CON_STATE_SEND_AUTH_OLD_PASSWORD:
			/* send the auth-response to the server */
			switch (network_mysqld_write(srv, con->server)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->server, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_auth_old_password");

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				/* might be a connection close, we should just close the connection and be happy */
				g_debug("%s.%d: network_mysqld_write(CON_STATE_SEND_AUTH_OLD_PASSWORD) returned an error", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_SEND_AUTH_OLD_PASSWORD) != NETWORK_SOCKET_SUCCESS", __FILE__, __LINE__);
				con->state = CON_STATE_ERROR;
				break;
			}

			break;

		case CON_STATE_READ_QUERY: {
			/** CLIENT ------> PROXY */
			// 将client发送的请求读取到con->client的recv_queue中
			network_socket *recv_sock;
			network_packet last_packet;

			recv_sock = con->client;

			g_assert(events == 0 || event_fd == recv_sock->fd);

			connection_state_update(con, CONNECTION_STATE_READ_QUERY, CONNECTION_STATE_TYPE_CPU);

			/**
			 * 避免一些特殊的情况没有考虑清楚，
			 * 导致client的recv_queue数据包里面会残留上一次的请求语句
			 * 现在我们需要在之前都将dbproxy client接收队列的数据清空
			 */

			if (recv_sock->recv_queue && recv_sock->recv_queue->len >0 ) {
				/**
				 * @fixme 还不清楚为什么会出现这种情况，需要将sql语句清空吗？应该不需要
				 */
				g_debug("%s: What there is still query packet in client recv queue! next we should clean it!!", G_STRLOC);
			}

			do { 
				switch (network_mysqld_read(srv, recv_sock)) {
				case NETWORK_SOCKET_SUCCESS:
					break;
				case NETWORK_SOCKET_WAIT_FOR_EVENT:
					timeout = con->read_timeout;

					WAIT_FOR_EVENT(con->client, EV_READ, &timeout);
					NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_query");
					connection_state_update(con, CONNECTION_STATE_READ_QUERY, CONNECTION_STATE_TYPE_IOWAIT);
					return;
				case NETWORK_SOCKET_ERROR_RETRY:
				case NETWORK_SOCKET_ERROR:
					g_critical("%s.%d: network_mysqld_read(CON_STATE_READ_QUERY) returned an error", __FILE__, __LINE__);
					con->state = CON_STATE_ERROR;
					break;
				}
				if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

				last_packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
			} while (last_packet.data->len == PACKET_LEN_MAX + NET_HEADER_SIZE); /* read all chunks of the overlong data */

			/*删除cache server超时事件*/
			g_mutex_lock(&(con->cache_server_mutex));
			if (con->cache_server != NULL) {
				g_debug("[%s]: delete timeout event on cache server: fd=%d", G_STRLOC, con->cache_server->fd);
				event_del(&(con->cache_server->event));
			} else {
				g_debug("[%s]: no timeout event on cache server", G_STRLOC);
			}
		    con->cache_idle_timeout_flag = TRUE;
		    g_mutex_unlock(&(con->cache_server_mutex));

			if (con->state == CON_STATE_ERROR) {
				return;
			}
			if (con->server &&
			    con->server->challenge &&
			    con->server->challenge->server_version > 50113 && con->server->challenge->server_version < 50118) {
				/**
				 * Bug #25371
				 *
				 * COM_CHANGE_USER returns 2 ERR packets instead of one
				 *
				 * we can auto-correct the issue if needed and remove the second packet
				 * Some clients handle this issue and expect a double ERR packet.
				 */
				network_packet packet;
				guint8 com;

				packet.data = g_queue_peek_head(recv_sock->recv_queue->chunks);
				packet.offset = 0;

				if (0 == network_mysqld_proto_skip_network_header(&packet) &&
				    0 == network_mysqld_proto_get_int8(&packet, &com)  &&
				    com == COM_CHANGE_USER) {
					network_mysqld_con_send_error(con->client, C("COM_CHANGE_USER is broken on 5.1.14-.17, please upgrade the MySQL Server"));
					con->state = CON_STATE_SEND_QUERY_RESULT;
					break;
				}
			}
			/** 
			 * added by zhenfan, 2013/08/14 
			 * @note 在CON_STATE_READ_QUERY状态时需要统计sql开始时间戳
			 */
			if (CON_STATE_READ_QUERY == con->state) {
				con->start_timestamp = chassis_get_rel_microseconds();
				con->is_sql_running = TRUE;
			}
			if (con->normalized_sql[0]->len != 0) {
				g_string_truncate(con->normalized_sql[0], 0);
			}
			if (con->normalized_sql[1]->len != 0) {
				g_string_truncate(con->normalized_sql[1], 0);
			}
			GString *packet = NULL;
			/** 判断连接是否被kill（事务或prepare相关的） */
			exception_type exp = get_mysqld_con_exception_state(con);
			if (EX_TRANSACTION_KILLED == exp || EX_PREPARE_KILLED == exp) {
				g_critical("[%s]:connection FD = %d was killed for none query execution for long time. Will drop query of this time!",
						G_STRLOC,
						con->client->fd);

				/** @todo 后续需要将dbproxy的返回错误规整化 */
//				network_mysqld_con_send_error_full(con->client,
//						C("connection was killed for none query execution for long time in transaction or prepare. "
//								"Will drop query of this time!"),
//								3086,
//								"30080");
				mpe_send_error(con->client, MPE_PRX_RQ_TX_TIMEOUT);

				/** 将对应的连接里面的请求清空  */
				while ((packet = (GString *) g_queue_pop_head(
						recv_sock->recv_queue->chunks))) {
					g_string_free(packet, TRUE);
				}

				con->goto_next_state = TRUE;
				con->next_state = CON_STATE_READ_QUERY;
				con->state = CON_STATE_SEND_ERROR_TO_CLIENT;

				// 将异常标识位复位
				mysqld_con_set_well_location(
						con,
						G_STRLOC);
				break;
			}

			/** 判断连接的查询是否超过最长的语句序列 */
			packet = (GString *)g_queue_peek_head(recv_sock->recv_queue->chunks);
			if (packet && packet->len > con->srv->max_allowed_packet_size) {
				g_critical("[%s]:connection FD = %d send query so bigger than con->max_allowed_query:%d."
						"Drop it!", G_STRLOC, con->client->fd, con->srv->max_allowed_packet_size);
//				network_mysqld_con_send_error_full(con->client,
//						C("sql sentence exceeds max_allowded_packet!"),
//								3087,
//								"30080");
				mpe_send_error(con->client, MPE_PRX_RQ_PACKET_TOO_LARGE);

				/** 将对应的连接里面的请求清空  */
				while ((packet = (GString *) g_queue_pop_head(
						recv_sock->recv_queue->chunks))) {
					g_string_free(packet, TRUE);
				}

				con->goto_next_state = TRUE;
				con->next_state = CON_STATE_READ_QUERY;
				con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
				break;
			}

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_READ_QUERY) failed", __FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				break;
			}

			/**
			 * there should be 3 possible next states from here:
			 *
			 * - CON_STATE_ERROR (if something went wrong and we want to close the connection
			 * - CON_STATE_SEND_QUERY (if we want to send data to the con->server)
			 * - CON_STATE_SEND_QUERY_RESULT (if we want to send data to the con->client)
			 *
			 * @todo verify this with a clean switch ()
			 */

			/* reset the tracked command
			 *
			 * if the plugin decided to send a result, it has to track the commands itself
			 * otherwise LOAD DATA LOCAL INFILE and friends will fail
			 */
/*
			if (con->state == CON_STATE_SEND_QUERY) {
				network_mysqld_con_reset_command_response_state(con);
			}
*/
			break; 
		}

		case CON_STATE_PROCESS_READ_QUERY: {
			/** 
			 * 开始处理客户端发送来的sql语句
			 * 并对COM_QUERY类型的语句token化
			 * @todo 这里会用到安全组同学开发的词法分析的工具？
			 */
			// 这里我们不做词法分析，只是简单的占位，后续需要补充
			network_socket *recv_sock;
			network_socket *send_sock;
			GString *packet;
			GList *chunk;

			recv_sock = con->client;
			send_sock = con->client;

			connection_state_update(con, CONNECTION_STATE_PROCESS_READ_QUERY, CONNECTION_STATE_TYPE_CPU);

			// 若读取的请求为空，我们认为出现了错误，会关闭客户端连接
			if ((NULL == recv_sock->recv_queue->chunks)
					|| (NULL == recv_sock->recv_queue->chunks->head)) {
				g_warning(
						"[%s]: CON_STATE_PROCESS_READ_QUERY() recv_queue empty",
						G_STRLOC);
				con->state = CON_STATE_ERROR;
				break;
			}

			// 接下来我们将sql语句token 化
			/**
			 * 以下只是简单实现
			 * @todo come on
			 */
			chunk = recv_sock->recv_queue->chunks->head;
			if (chunk != NULL ) {

				packet = (GString *) (chunk->data);
				if (COM_QUIT == packet->str[NET_HEADER_SIZE + 0]) {
					// close the client, but don't send this to the server
					con->state = CON_STATE_CLOSE_CLIENT;
					break;
				} else {
					// 我们在这里添加需要对哪些类型的语句做词法分析
					/**
					 * @todo 这里可以用tranc,append.避免重复的内存分配
					 */
					if (con->sql_sentence) {
						g_string_truncate(con->sql_sentence, 0);
						g_string_append_len(con->sql_sentence,
								packet->str + NET_HEADER_SIZE + 1,
								packet->len - NET_HEADER_SIZE - 1);
					}
					//con->sql_sentence = g_string_new_len(
					//		packet->str + NET_HEADER_SIZE + 1,
					//		packet->len - NET_HEADER_SIZE - 1);
				}
			}
			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				con->state = CON_STATE_GET_SERVER_LIST;
				break;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR: {
				// @todo 若sql语句解析失败或者是不安全返回错误给客户端
				GString *packet;
				g_warning("SQL not allowed for this con!");
				while ((packet = (GString *)g_queue_pop_head(recv_sock->recv_queue->chunks)))
				{
					g_string_free(packet, TRUE);
				}
				/* @fixme 修改错误编码 */
//				network_mysqld_con_send_error_full(send_sock,
//						C("SQL not allowed: May be it's not safe to run this sentence"),
//						1045,
//						"28000");
				/**
				 * process_read_query阶段做的工作越来越多，
				 * 直接在上层做客户端错误的返回不太合适，故将错误的处理放在plugin的具体处理函数中
				 **/
//				mpe_send_error(send_sock, MPE_PRX_PRCRQ_SQL_UNSAFE);
//				con->goto_next_state = TRUE;
//				con->next_state = CON_STATE_READ_QUERY;
//				con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
				//END_PERF(con->client, PF_QUERY);
				break;
			}
			default:
				g_critical(
						"[%s]: plugin_call(CON_STATE_GET_SERVER_LIST) failed",
						G_STRLOC);
				con->state = CON_STATE_ERROR;
				break;
			}
			break;
		}

		case CON_STATE_GET_SERVER_LIST: {
			/** 
			 * 为前端的client 请求需找一个合适的backend，提供服务
			 * @note 影响这个的因素有哪些？
			 * 1.是否有缓存的连接，若有，则不需要重新分配连接直接使用缓存的连接
			 * (注意接收到请求几乎同时缓存过期的情况！！因为涉及到两个fd 的事件处理需要对cache server做一个同步)
			 * 2.缓存没有的情况下：需要根据读写情况、影响到主备库的选择？
			 *                     从库的话还需要根据各从库的压力，选择合适的从库提供服务。
			 * 3.？？还有吗
			 */
			connection_state_update(con, CONNECTION_STATE_GET_SERVER_LIST, CONNECTION_STATE_TYPE_CPU);
			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				con->state = CON_STATE_GET_SERVER_CONNECTION_LIST;
				break;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR: {
				network_socket *recv_sock = con->client;
				network_socket *send_sock = con->client;
				// @todo 将client端请求已经接受到的请求查询清除,继续等待客户端请求
				// 一般不会出现get_server_list出错的情况，除非是所有的backend均不可用
				GString *packet;
				g_warning("No backend available");
				while ((packet = (GString *) g_queue_pop_head(
						recv_sock->recv_queue->chunks))) {
					g_string_free(packet, TRUE);
				}
				/* @fixme 修改错误编码 */
//				network_mysqld_con_send_error_full(send_sock,
//						C("No backend available"), 1045, "28000");
				mpe_send_error(send_sock, MPE_PRX_GETSRV_NO_BACKEND);
				con->goto_next_state = TRUE;
				con->next_state = CON_STATE_READ_QUERY;
				con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
				break;
				/*
				 GString *packet;

				 network_mysqld_write(srv, con->client);
				 con->state = CON_STATE_READ_QUERY;
				 //END_PERF(con->client, PF_QUERY);

				 while ((packet = (GString *)g_queue_pop_head(con->client->recv_queue->chunks)))
				 {
				 g_string_free(packet, TRUE);
				 }
				 //con->client->packet_len = PACKET_LEN_UNSET;
				 return;
				 */
			}
			default:
				g_error("[%s]: plugin_call(CON_STATE_GET_SERVER_LIST) failed",
						G_STRLOC);
				con->state = CON_STATE_ERROR;
				break;
			}
			break;
		}

		case CON_STATE_GET_SERVER_CONNECTION_LIST: {
			connection_state_update(con, CONNECTION_STATE_GET_SERVER_CONNECTION_LIST, CONNECTION_STATE_TYPE_CPU);
			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				if (!con->goto_next_state) {
					con->state = CON_STATE_SEND_QUERY;
				}
				con->get_conn_try_times = 0;
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT: {
				network_socket *recv_sock = con->client;
				network_socket *send_sock = con->client;

				if (con->get_server_connection_errno
						== POOL_CONNECTION_ERRNO_TOOMANY) {
					GString *packet;
					g_warning("Too many connections.");
					while ((packet = (GString *) g_queue_pop_head(
							recv_sock->recv_queue->chunks))) {
						g_string_free(packet, TRUE);
					}
					/* @fixme 修改错误编码 */
//					network_mysqld_con_send_error_full(send_sock,
//							C("Too many connections."), 1045, "28000");
					mpe_send_error(send_sock, MPE_PRX_GETCON_TOO_MANY_CONNECTIONS);
					/** 前面负载均衡阶段已经将backend的client的数目增加了，这里需要减1 */
					desc_clients_for_con(con); // 将其相关的backend的连接数减1
					con->goto_next_state = TRUE;
					con->next_state = CON_STATE_READ_QUERY;
					con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
					break;
				}

				// more connection in the pool is needed
				// 这里需要判断是不是能够创建新的连接，若可以创建，才触发创建
				// 反之，不触发创建只是等待100us,再去重新获取新的连接
				g_warning(
						"[%s]: connection not enough, going to reestablish more",
						G_STRLOC);
				create_connections_on_many_backends_for_user(srv,
						con->related_bk, con->client->response->username->str,
						con->type);

				// need to add code to try this operation again after
				// a server connects
				//没有获取连接等待100us再重试
				con->get_conn_try_times++;
				if (con->get_conn_try_times > 4) {
//					network_mysqld_con_send_error_full(send_sock,
//							C("Have tried 4 times, no connection available on backend"),
//							1045, "28000");
					g_warning("[%s]:Have trived %d for user:%s, but no connection avaiable. Client ip is: %s",
							G_STRLOC,
							con->get_conn_try_times - 1,
							con->client->response->username->str,
							con->client->src->name->str);
					mpe_send_error(send_sock, MPE_PRX_GETCON_NO_CONNECTION_IN_POOL, con->get_conn_try_times);
					/** 将对应的连接里面的请求清空  */
					GString *packet = NULL;
					while ((packet = (GString *) g_queue_pop_head(
							recv_sock->recv_queue->chunks))) {
						g_string_free(packet, TRUE);
					}
					/** 前面负载均衡阶段已经将backend的client的数目增加了，这里需要减1 */
					desc_clients_for_con(con); // 将其相关的backend的连接数减1
					con->goto_next_state = TRUE;
					con->next_state = CON_STATE_READ_QUERY;
					con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
					break;
				} else {
					struct timeval tv;
					gint power_param = (1<<con->get_conn_try_times);
					tv.tv_sec = 0;
					tv.tv_usec = power_param * con->srv->base_wait_time;
					WAIT_FOR_EVENT(con->client, EV_TIMEOUT, &tv);
					connection_state_update(con, CONNECTION_STATE_GET_SERVER_CONNECTION_LIST, CONNECTION_STATE_TYPE_IOWAIT);
					return;
				}
			}
			case NETWORK_SOCKET_ERROR: {
				g_critical("[%s]:Over the restrictions of concurrent execution,  will send error to client.", G_STRLOC);

				// 将接收到的查询语句清空
				GString *packet = NULL;
				while ((packet = (GString *) g_queue_pop_head(
						con->client->recv_queue->chunks))) {
					g_string_free(packet, TRUE);
				}
				desc_clients_for_con(con); // 将其相关的backend的连接数减1
				con->goto_next_state = TRUE;
				con->next_state = CON_STATE_READ_QUERY;
				con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
				break;
			}
			default:
				//g_error("[%s]: plugin_call(CON_STATE_GET_SERVER_CONNECTION_LIST) failed", G_STRLOC);
				con->state = CON_STATE_ERROR;
				break;
			}
			break;
		}

		case CON_STATE_SEND_QUERY:
			/*
			 * 这里我们需要通过判断是否要恢复连接的上下文
			 * 同时为了能够在得到结果时，判定是不是恢复上下文的语句
			 * 需要加一个标示。
			 * 为了实现在加入上下文恢复的数据包的情况下，处理流程不发生变化
			 * 需要先将一个数据包写入到server端的send_queue中然后调用network_mysqld_write，
			 * 将接下来的状态设置为CON_STATE_READ_QUERY_RESULT
			 */
			/* send the query to the server
			 *
			 * this state will loop until all the packets from the send-queue are flushed 
			 */
			connection_state_update(con, CONNECTION_STATE_SEND_QUERY, CONNECTION_STATE_TYPE_CPU);
			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s.%d: plugin_call(CON_STATE_SEND_QUERY) failed", __FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				break;
			}

			//if (con->state == CON_STATE_SEND_QUERY) {
			// 重置con 解析数据包的存储结构
			// network_mysqld_con_reset_command_response_state(con);
			//}

			if (con->server->send_queue->offset == 0) {
				// 重置con 解析数据包的存储结构
				network_mysqld_con_reset_command_response_state(con);
				/* only parse the packets once */
				network_packet packet;

				packet.data = g_queue_peek_head(con->server->send_queue->chunks);
				packet.offset = 0;
				
				int ret;
				if (0 != (ret = network_mysqld_con_command_states_init(con, &packet))) {
					if (-2 == ret) {
						mpe_send_error(con->client, MPE_ADM_RAUTH_UNKNOWN_USER);
						g_string_free((GString *)g_queue_pop_head(con->server->send_queue->chunks), TRUE);
						cache_server_connection(con->srv, con);
						con->goto_next_state = TRUE;
						con->next_state = CON_STATE_READ_QUERY;
						con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
					} else {
						con->state = CON_STATE_ERROR;
					}
						
					g_debug("[%s]: tracking mysql protocol states failed", G_STRLOC);
					break;
				}
			}
			
			switch (network_mysqld_write(srv, con->server)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->server, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_query");
				connection_state_update(con, CONNECTION_STATE_SEND_QUERY, CONNECTION_STATE_TYPE_IOWAIT);
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_debug("%s.%d: network_mysqld_write(CON_STATE_SEND_QUERY) returned an error", __FILE__, __LINE__);

				/**
				 * write() failed, close the connections 
				 */
				con->state = CON_STATE_ERROR;
				break;
			}
			
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			/* some statements don't have a server response */
			switch (con->parse.command) {
			case COM_STMT_SEND_LONG_DATA: /* not acked */
				con->state = CON_STATE_READ_QUERY;
				if (con->client) network_mysqld_queue_reset(con->client);
				if (con->server) {
					network_mysqld_queue_reset(con->server);
					if (con->multiplex) {
						g_debug("[%s]:multiplex of connection enabled, will cache the connect",G_STRLOC);
						cache_server_connection(con->srv, con);
					}

				}
				break;
			case COM_STMT_CLOSE:
				con->state = CON_STATE_READ_QUERY;
				/**
				 * @author sohu-inc.com
				 * prepare statement关闭了，需要将其对应的id从hashtable中删除
				 * @note :在连接复用过程中，如果是prepare语句的缓存的连接超时释放时需要注意
				 * 		     如果是将连接kill则不需要处理prepare及事务的清理工作，
				 * 		     若是将连接放回带连接池中，继续使用则需要住相应的清理工作。
				 */
				if (con->multiplex) {
					g_assert(con->stmtids);
					g_message("[%s]:get prepare statement close sql, will going to remove the prepare state id[%d] from con->ids", G_STRLOC, con->last_id);
					guint *key_tmp = g_new0(guint, 1);
					*key_tmp = con->last_id;
					g_hash_table_remove(con->stmtids, key_tmp);
					g_free(key_tmp);
				}
				if (con->client) network_mysqld_queue_reset(con->client);
				if (con->server) {
					network_mysqld_queue_reset(con->server);
					if (con->multiplex) {
						g_debug("[%s]:multiplex of connection enabled, will cache the connect",G_STRLOC);
						cache_server_connection(con->srv, con);
					}
				}
				break;
			default:
				con->state = CON_STATE_READ_QUERY_RESULT;
				break;
			}

			break;

		case CON_STATE_READ_QUERY_RESULT: 
			/* read all packets of the resultset 
			 *
			 * depending on the backend we may forward the data to the client right away
			 */
			/**
			 * @author sohu-inc.com
			 * 从server端读取数据结构，
			 * 这里需要根据是上下文恢复语句的执行结果还是真正的客户端请求语句的执行选择下一个连接的状态
			 * 可能的后续的步骤是：
			 * 1. 上下文恢复数据包执行失败，向客户端返回错误，将连接的上下文清空，计入状态CON_STATE_READ_QUERY
			 * 2. 上下文恢复数据包执行成功，进入CON_STATE_SEND_QUERY 阶段，继续向后端发送上下文恢复数据包或客户请求数据包
			 * 3. 若是真正的客户请求，无论处理成功或失败都向客户端原样返回结果？不过要求考虑执行后server_status字段的含义
			 */
			connection_state_update(con, CONNECTION_STATE_READ_QUERY_RESULT, CONNECTION_STATE_TYPE_CPU);
			do {
				network_socket *recv_sock;

				recv_sock = con->server;

				g_assert(events == 0 || event_fd == recv_sock->fd);

				//if (EV_TIMEOUT == events && ((chassis_get_rel_microseconds() - con->start_timestamp) > con->max_dura_time)) {
				if (EV_TIMEOUT == events) {
					// 如果是等待查询结果超时，直接返回不需要再去做read操作
					clean_read_query_timeout(con); // 里面需要将对应的backend 连接数减1
					g_critical("[%s]: query execute too long, will kill it. The sql is %s",
							G_STRLOC,
							con->sql_sentence->str);
					break;
				}

				switch (network_mysqld_read(srv, recv_sock)) {
				case NETWORK_SOCKET_SUCCESS:
					break;
				case NETWORK_SOCKET_WAIT_FOR_EVENT:
					/**
					 * 注册读取超时时间时，
					 * 若配置了执行超时时间我们将超时时间设置为超时时间减去已经执行的时间
					 */
					if (con->srv->dura_limit_on && con->max_dura_time > 0) {
						guint64 now_in_usec = chassis_get_rel_microseconds();
						if ((now_in_usec - con->start_timestamp) > con->max_dura_time) {
							g_critical("[%s]:exec too long for sql: %s, actual time is %ld us ,limit is %ld us",
									G_STRLOC,
									con->sql_sentence->str,
									now_in_usec - con->start_timestamp,
									con->max_dura_time);
							clean_read_query_timeout(con); // 里面需要将对应的backend 连接数减1
							break;
						} else {
							timeout.tv_sec = (con->max_dura_time + con->start_timestamp - now_in_usec)/1000000L;
							timeout.tv_usec = (con->max_dura_time + con->start_timestamp - now_in_usec)%1000000;
						}
					} else {
						timeout = con->read_timeout;
					}

					struct event *ev = &(con->server->event);
					ev_dump_info(ev);
					WAIT_FOR_EVENT(con->server, EV_READ, &timeout);
					NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_query_result");
					connection_state_update(con, CONNECTION_STATE_READ_QUERY_RESULT, CONNECTION_STATE_TYPE_IOWAIT);
					return;
				case NETWORK_SOCKET_ERROR_RETRY:
				case NETWORK_SOCKET_ERROR:
					g_critical("%s.%d: network_mysqld_read(CON_STATE_READ_QUERY_RESULT) returned an error", __FILE__, __LINE__);
					con->state = CON_STATE_ERROR;
					break;
				}
				if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

				switch (plugin_call(srv, con, con->state)) {
				case NETWORK_SOCKET_SUCCESS:
					if (con->goto_next_state) {
						break;
					}
					/* if we don't need the resultset, forward it to the client */
					if (!con->resultset_is_finished && !con->resultset_is_needed) {
						/* check how much data we have in the queue waiting, no need to try to send 5 bytes */
						if (con->client->send_queue->len > 64 * 1024) {
							con->state = CON_STATE_SEND_QUERY_RESULT;
						}
					}
					break;
				case NETWORK_SOCKET_ERROR:
					/* something nasty happend, let's close the connection */
					con->state = CON_STATE_ERROR;
					break;
				default:
					g_critical("%s.%d: ...", __FILE__, __LINE__);
					con->state = CON_STATE_ERROR;
					break;
				}


			} while (con->state == CON_STATE_READ_QUERY_RESULT);
	
			break; 
		case CON_STATE_SEND_QUERY_RESULT:
			/**
			 * send the query result-set to the client */
			connection_state_update(con, CONNECTION_STATE_SEND_QUERY_RESULT, CONNECTION_STATE_TYPE_CPU);
			switch (network_mysqld_write(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				/** 
				 * added by zhenfan, 2013/08/14
				 * @note 在CON_STATE_SEND_QUERY_RESULT状态时需要统计sql结束的时间
				 */
				con->end_timestamp = chassis_get_rel_microseconds();
				con->is_sql_running = FALSE;
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_query_result");
				connection_state_update(con, CONNECTION_STATE_SEND_QUERY_RESULT, CONNECTION_STATE_TYPE_IOWAIT);
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				/**
				 * client is gone away
				 *
				 * close the connection and clean up
				 */
				con->state = CON_STATE_ERROR;
				break;
			}

			/* if the write failed, don't call the plugin handlers */
			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			/* in case we havn't read the full resultset from the server yet, go back and read more
			 */
			if (!con->resultset_is_finished && con->server) {
				con->state = CON_STATE_READ_QUERY_RESULT;
				break;
			}

			switch (plugin_call(srv, con, con->state)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				con->state = CON_STATE_ERROR;
				break;
			}

			/* special treatment for the LOAD DATA LOCAL INFILE command */
			if (con->state != CON_STATE_ERROR &&
			    con->parse.command == COM_QUERY &&
			    1 == network_mysqld_com_query_result_is_local_infile(con->parse.data)) {
				con->state = CON_STATE_READ_LOCAL_INFILE_DATA;
			}

			break;
		case CON_STATE_READ_LOCAL_INFILE_DATA: {
			/**
			 * read the file content from the client 
			 */
			network_socket *recv_sock;

			recv_sock = con->client;

			/**
			 * LDLI is usually a whole set of packets
			 */
			do {
				switch (network_mysqld_read(srv, recv_sock)) {
				case NETWORK_SOCKET_SUCCESS:
					break;
				case NETWORK_SOCKET_WAIT_FOR_EVENT:
					timeout = con->read_timeout;
					/* call us again when you have a event */
					WAIT_FOR_EVENT(recv_sock, EV_READ, &timeout);
					NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_load_infile_data");

					return;
				case NETWORK_SOCKET_ERROR_RETRY:
				case NETWORK_SOCKET_ERROR:
					g_critical("%s: network_mysqld_read(%s) returned an error",
							G_STRLOC,
							network_mysqld_con_state_get_name(ostate));
					con->state = CON_STATE_ERROR;
					break;
				}

				if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

				/**
				 * do the plugin call to decode the result-set to track if we are finished already
				 * or we need to keep reading the data
				 */
				switch ((call_ret = plugin_call(srv, con, con->state))) {
				case NETWORK_SOCKET_SUCCESS:
					/**
					 * if we still haven't read all data from LDLI, lets forward immediatly
					 * the data to the backends so that we can read the next packets
					 */
					if (!con->local_file_data_is_finished && con->server) {
						con->state = CON_STATE_SEND_LOCAL_INFILE_DATA;
					}

					break;
				default:
					g_critical("%s: plugin_call(%s) unexpected return value: %d",
							G_STRLOC,
							network_mysqld_con_state_get_name(ostate),
							call_ret);

					con->state = CON_STATE_ERROR;
					break;
				}
			/* read packets from the network until the plugin decodes to go to the next state */
			} while (con->state == CON_STATE_READ_LOCAL_INFILE_DATA);
	
			break; }
		case CON_STATE_SEND_LOCAL_INFILE_DATA: 
			/* send the hand-shake to the client and wait for a response */

			switch (network_mysqld_write(srv, con->server)) {
			case NETWORK_SOCKET_SUCCESS:
				/* if we still haven't read all data from LDLI so we need to go back and read more
				 */
				if (!con->local_file_data_is_finished && con->server) {
					con->state = CON_STATE_READ_LOCAL_INFILE_DATA;
				}
				/* we have read all data from LDLI so we need to read the LDLI result from the server
				 */
				else {
					con->state = CON_STATE_READ_LOCAL_INFILE_RESULT;
				}

				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->server, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_load_infile_data");
				
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				/**
				 * writing failed, closing connection
				 */
				con->state = CON_STATE_ERROR;
				break;
			}

			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch ((call_ret = plugin_call(srv, con, con->state))) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s: plugin_call(%s) unexpected return value: %d",
						G_STRLOC,
						network_mysqld_con_state_get_name(ostate),
						call_ret);

				con->state = CON_STATE_ERROR;
				break;
			}

			break;
		case CON_STATE_READ_LOCAL_INFILE_RESULT: {
			/**
			 * read auth data from the remote mysql-server 
			 */
			network_socket *recv_sock;
			recv_sock = con->server;
			g_assert(events == 0 || event_fd == recv_sock->fd);

			switch (network_mysqld_read(srv, recv_sock)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->read_timeout;

				/* call us again when you have a event */
				WAIT_FOR_EVENT(recv_sock, EV_READ, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::read_load_infile_result");

				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical("%s: network_mysqld_read(%s) returned an error",
						G_STRLOC,
						network_mysqld_con_state_get_name(ostate));

				con->state = CON_STATE_ERROR;
				break;
			}

			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch ((call_ret = plugin_call(srv, con, con->state))) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s: plugin_call(%s) unexpected return value: %d",
						G_STRLOC,
						network_mysqld_con_state_get_name(ostate),
						call_ret);

				con->state = CON_STATE_ERROR;
				break;
			}
	
			break; }
		case CON_STATE_SEND_LOCAL_INFILE_RESULT: 
			/* send the hand-shake to the client and wait for a response */

			switch (network_mysqld_write(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_load_infile_result");
				
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				/**
				 * writing failed, closing connection
				 */
				con->state = CON_STATE_ERROR;
				break;
			}

			if (con->state != ostate) break; /* the state has changed (e.g. CON_STATE_ERROR) */

			switch ((call_ret = plugin_call(srv, con, con->state))) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			default:
				g_critical("%s: plugin_call(%s) unexpected return value: %d",
						G_STRLOC,
						network_mysqld_con_state_get_name(ostate),
						call_ret);

				con->state = CON_STATE_ERROR;
				break;
			}

			break;

		case CON_STATE_SEND_ERROR:
			/**
			 * send error to the client
			 * and close the connections afterwards
			 *  */
			connection_state_update(con, CONNECTION_STATE_SEND_ERROR, CONNECTION_STATE_TYPE_CPU);
			switch (network_mysqld_write(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout)
				;
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_error");
				connection_state_update(con, CONNECTION_STATE_SEND_ERROR, CONNECTION_STATE_TYPE_IOWAIT);
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical(
						"%s.%d: network_mysqld_write(CON_STATE_SEND_ERROR) returned an error",
						__FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				break;
			}

			con->state = CON_STATE_CLOSE_CLIENT;

			break;

		case CON_STATE_SEND_ERROR_TO_CLIENT:
			/**
			 * send error to the client
			 * and close the connections afterwards
			 *  */
			connection_state_update(con, CONNECTION_STATE_SEND_ERROR_TO_CLIENT, CONNECTION_STATE_TYPE_CPU);
			switch (network_mysqld_write(srv, con->client)) {
			case NETWORK_SOCKET_SUCCESS:
				break;
			case NETWORK_SOCKET_WAIT_FOR_EVENT:
				timeout = con->write_timeout;

				WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout)
				;
				NETWORK_MYSQLD_CON_TRACK_TIME(con, "wait_for_event::send_error");
				connection_state_update(con, CONNECTION_STATE_SEND_ERROR_TO_CLIENT, CONNECTION_STATE_TYPE_CPU);
				return;
			case NETWORK_SOCKET_ERROR_RETRY:
			case NETWORK_SOCKET_ERROR:
				g_critical(
						"%s.%d: network_mysqld_write(CON_STATE_SEND_ERROR) returned an error",
						__FILE__, __LINE__);

				con->state = CON_STATE_ERROR;
				break;
			}
			if (con->state == CON_STATE_ERROR) {
				con->goto_next_state = FALSE;
			}
			if (con->goto_next_state == TRUE) {
				con->goto_next_state = FALSE;
				con->state = con->next_state;
			} else {
				con->state = CON_STATE_CLOSE_CLIENT;
			}

			break;

		}

		event_fd = -1;
		events   = 0;
	} while (ostate != con->state);
	NETWORK_MYSQLD_CON_TRACK_TIME(con, "con_handle_end");

	/**
	 * there are two ways to leave the state-engine:
	 * - wait for event and return (WAIT_FOR_EVENT(); return;)
	 * - close the socket and return
	 *
	 * if you have to stay in the same state create your own tiny loop
	 *
	 * in other words: this code below should never be triggered.
	 */
	g_critical("%s: left the MySQL protocol's state-machine at state '%s'. You may see the connection hang now.",
			G_STRLOC,
			network_mysqld_con_state_get_name(con->state));


	return;
}

/**
 * accept a connection
 *
 * event handler for listening connections
 *
 * @param event_fd     fd on which the event was fired
 * @param events       the event that was fired
 * @param user_data    the listening connection handle
 * 
 */
void network_mysqld_con_accept(int G_GNUC_UNUSED event_fd, short events, void *user_data) {
	network_mysqld_con *listen_con = user_data;
	network_mysqld_con *client_con;
	network_socket *client;

	g_assert(events == EV_READ);
	g_assert(listen_con->server);

	// 查看监听端口是否被关闭
	if (listen_con->is_well == EX_KILLED) {
		// 若被关闭，需要将该对应的socket的监听事件关闭
		// 同时将连接关闭，并返回即可
		g_message("[%s]:listen con on %s, will not accept client request on it...",
				G_STRLOC,
				listen_con->server->src->name->str);

		event_del(&listen_con->server->event); // 删除监听事件
		network_mysqld_con_free(listen_con); // 将连接释放
		listen_con = NULL;
		return;
	}

	client = network_socket_accept(listen_con->server);
	if (!client) return;
	g_message("[%s]: get %s connect request",G_STRLOC, (listen_con->type == PROXY_TYPE_WRITE)?"PROXY_TYPE_WRITE":"PROXY_TYPE_READ");
	/* looks like we open a client connection */
	client_con = network_mysqld_con_new();
	client_con->client = client;

	NETWORK_MYSQLD_CON_TRACK_TIME(client_con, "accept");
	connection_state_update(client_con, CONNECTION_STATE_ACCEPT, CONNECTION_STATE_TYPE_CPU);

	network_mysqld_add_connection(listen_con->srv, client_con);
	client_con->multiplex = listen_con->srv->multiplex; // 沿用整体的复用配置参数，之后更新对于已有的连接不会再更新
	
	/**
	 * inherit the config to the new connection 
	 */

	client_con->plugins = listen_con->plugins;
	client_con->config  = listen_con->config;
	client_con->type = listen_con->type;

#ifdef ONE_QUEUE_PER_THREAD_DISABLED
	network_mysqld_con_handle(-1, 0, client_con);
#else
	chassis_local_event_add(client_con);
#endif

	return;
}

/**
 * added by zhenfan, 2013/09/10
 * accept a admin connection
 *
 * event handler for listening connections
 *
 * @param event_fd     fd on which the event was fired
 * @param events       the event that was fired
 * @param user_data    the listening connection handle
 * 
 */
void network_mysqld_admin_con_accept(int G_GNUC_UNUSED event_fd, short events, void *user_data) {
	network_mysqld_con *listen_con = user_data;
	network_mysqld_con *client_con;
	network_socket *client;

	g_assert(events == EV_READ);
	g_assert(listen_con->server);

	client = network_socket_accept(listen_con->server);
	if (!client) return;
	g_message("[%s]: get %s connect request",G_STRLOC, "ADMIN");
	
#ifdef TEST_ADMIN_USE_INDEPENDENDT_THREAD
	GString *thread_name = chassis_thread_get_local_name(listen_con->srv);
	g_message("[%s]: accept admin request using thread %s",G_STRLOC, thread_name->str);
#endif
	/* looks like we open a client connection */
	client_con = network_mysqld_con_new();
	client_con->client = client;

	NETWORK_MYSQLD_CON_TRACK_TIME(client_con, "accept");

	network_mysqld_add_connection(listen_con->srv, client_con);
	client_con->multiplex = listen_con->srv->multiplex; // 沿用整体的复用配置参数，之后更新对于已有的连接不会再更新
	
	/**
	 * inherit the config to the new connection 
	 */

	client_con->plugins = listen_con->plugins;
	client_con->config  = listen_con->config;
	client_con->type = listen_con->type;

	network_mysqld_con_handle(-1, 0, client_con);
	return;
}

/**
 * @todo move to network_mysqld_proto
 */
int network_mysqld_con_send_resultset(network_socket *con, GPtrArray *fields, GPtrArray *rows) {
	GString *s;
	gsize i, j;

	g_assert(fields->len > 0);

	s = g_string_new(NULL);

	/* - len = 99
	 *  \1\0\0\1 
	 *    \1 - one field
	 *  \'\0\0\2 
	 *    \3def 
	 *    \0 
	 *    \0 
	 *    \0 
	 *    \21@@version_comment 
	 *    \0            - org-name
	 *    \f            - filler
	 *    \10\0         - charset
	 *    \34\0\0\0     - length
	 *    \375          - type 
	 *    \1\0          - flags
	 *    \37           - decimals
	 *    \0\0          - filler 
	 *  \5\0\0\3 
	 *    \376\0\0\2\0
	 *  \35\0\0\4
	 *    \34MySQL Community Server (GPL)
	 *  \5\0\0\5
	 *    \376\0\0\2\0
	 */

	network_mysqld_proto_append_lenenc_int(s, fields->len); /* the field-count */
	network_mysqld_queue_append(con, con->send_queue, S(s));

	for (i = 0; i < fields->len; i++) {
		MYSQL_FIELD *field = fields->pdata[i];
		
		g_string_truncate(s, 0);

		network_mysqld_proto_append_lenenc_string(s, field->catalog ? field->catalog : "def");   /* catalog */
		network_mysqld_proto_append_lenenc_string(s, field->db ? field->db : "");                /* database */
		network_mysqld_proto_append_lenenc_string(s, field->table ? field->table : "");          /* table */
		network_mysqld_proto_append_lenenc_string(s, field->org_table ? field->org_table : "");  /* org_table */
		network_mysqld_proto_append_lenenc_string(s, field->name ? field->name : "");            /* name */
		network_mysqld_proto_append_lenenc_string(s, field->org_name ? field->org_name : "");    /* org_name */

		g_string_append_c(s, '\x0c');                  /* length of the following block, 12 byte */
		g_string_append_len(s, "\x08\x00", 2);         /* charset */
		g_string_append_c(s, (field->length >> 0) & 0xff); /* len */
		g_string_append_c(s, (field->length >> 8) & 0xff); /* len */
		g_string_append_c(s, (field->length >> 16) & 0xff); /* len */
		g_string_append_c(s, (field->length >> 24) & 0xff); /* len */
		g_string_append_c(s, field->type);             /* type */
		g_string_append_c(s, field->flags & 0xff);     /* flags */
		g_string_append_c(s, (field->flags >> 8) & 0xff); /* flags */
		g_string_append_c(s, 0);                       /* decimals */
		g_string_append_len(s, "\x00\x00", 2);         /* filler */
#if 0
		/* this is in the docs, but not on the network */
		network_mysqld_proto_append_lenenc_string(s, field->def);         /* default-value */
#endif
		network_mysqld_queue_append(con, con->send_queue, S(s));
	}

	g_string_truncate(s, 0);
	
	/* EOF */	
	g_string_append_len(s, "\xfe", 1); /* EOF */
	g_string_append_len(s, "\x00\x00", 2); /* warning count */
	g_string_append_len(s, "\x02\x00", 2); /* flags */
	
	network_mysqld_queue_append(con, con->send_queue, S(s));

	for (i = 0; i < rows->len; i++) {
		GPtrArray *row = rows->pdata[i];

		g_string_truncate(s, 0);

		for (j = 0; j < row->len; j++) {
			network_mysqld_proto_append_lenenc_string(s, row->pdata[j]);
		}

		network_mysqld_queue_append(con, con->send_queue, S(s));
	}

	g_string_truncate(s, 0);

	/* EOF */	
	g_string_append_len(s, "\xfe", 1); /* EOF */
	g_string_append_len(s, "\x00\x00", 2); /* warning count */
	g_string_append_len(s, "\x02\x00", 2); /* flags */

	network_mysqld_queue_append(con, con->send_queue, S(s));
	network_mysqld_queue_reset(con);

	g_string_free(s, TRUE);

	return 0;
}


/**
 * @author sohu-inc.com
 * 判断连接是否是在prepare处理过程中
 */
gboolean is_in_prepare(network_mysqld_con *con) {
	g_assert(con);
	
	//GList *tmp1 = NULL;
	//GList *tmp2 = NULL;
	gint len = 0;
	if(con->stmtids) {
		len = g_hash_table_size(con->stmtids);
	}

	if (con->stmtnames) {
		len += g_hash_table_size(con->stmtnames);
	}

	if (len > 0)
		return TRUE;
	else
		return FALSE;
	//return (len > 0)?TRUE:FALSE;
}

/**
 * @author sohu-inc.com
 * 清理连接prepare的上下文
 */
void clean_prepare_context(network_mysqld_con *con){
	g_assert(con);

	g_hash_table_remove_all(con->stmtids);
	g_hash_table_remove_all(con->stmtnames);
}
/**
 * @author sohu-inc.com
 * 通过判断连接的状态，确定缓存连接的策略
 * 主要包括prepare的状态、事务状态
 * 若不在事务中且不在prepare中，则默认缓存较短时间
 * @param con 将要处理的连接
 * @param chas 全局基础变量
 */
void cache_server_connection(chassis *chas, network_mysqld_con *con) {
	network_socket *server = NULL;
	guint wait_time = 0;
    struct timeval tv;

    g_assert(chas);
	g_assert(con);

	g_mutex_lock(&con->server_mutex);
	if (con->server) {
		server = con->server;
		con->server = NULL;
	}
	g_mutex_unlock(&con->server_mutex);

	if(!server) {
		g_critical("[%s]:there is no server socket should be put to cache_server", G_STRLOC);
		return;
	}

	con->cache_idle_timeout_flag = FALSE;

	// 若即在事务中又在prepare中选择较大的时间
	if(is_in_prepare(con)) {
		g_message("[%s]:connection is in prepare, will set the wait to be 20", G_STRLOC);
		wait_time = 20;
	}
	if(con->tx_flag) {
		g_message("[%s]:connection is in transaction, will set the wait to be 18", G_STRLOC);
		if(wait_time <18)
			wait_time = 18;
	}
    // 这里超时时间需要能够动态配置且支持个性化配置?
	if (wait_time) {
        tv.tv_sec = wait_time;
        tv.tv_usec = 0;
	} else { // 将连接放在cache server中，并注册超时事件,注意超时时间是默认的100us
		tv.tv_sec = 0;
		tv.tv_usec = 10000;// 10 ms
	}

	// 将连接放在cache server中，并注册超时事件
	/*
	if(server && server->event.ev_base) {
		g_message("[%s]: there is already a event register", G_STRLOC);
		event_del(&(server->event));
		if(server->event.ev_base)
			g_critical("[%s]:yet, still has event_base!!", G_STRLOC);
	}
	*/
	if(server) {
		g_debug("[%s]: caching connect and adding timeout event for socket SOCKET=%d", G_STRLOC, server->fd);
		g_mutex_lock(&(con->cache_server_mutex));
		event_del(&(server->event));
	    //con->cache_idle_timeout_flag = FALSE;
#ifdef ONE_QUEUE_PER_THREAD_DISABLED
		//event_set(&(server->event), server->fd, EV_READ | EV_TIMEOUT | EV_FINALIZE, network_mysqld_cache_con_idle_handle, con);
		event_assign(&(server->event), chas->event_base, server->fd, EV_READ | EV_TIMEOUT | EV_FINALIZE, network_mysqld_cache_con_idle_handle, con);
        chassis_event_add_with_timeout(chas, &(server->event), &tv);
#else
		event_assign(&(server->event), chassis_thread_get_local_event_base(chas), server->fd, EV_READ | EV_TIMEOUT, network_mysqld_cache_con_idle_handle, con);
        event_add(&(server->event), &tv);
#endif
        con->cache_server = server;
    	g_mutex_unlock(&(con->cache_server_mutex));
	}

	return;
}


/**
 * @author sohu-inc.com
 * 缓存连接超时的处理函数
 * @param event_fd 缓存超时的连接的文件描述符
 * @param events 接收到的时间
 * @param user_data 超时的连接
 */
void network_mysqld_cache_con_idle_handle(int event_fd, short events, void *user_data) {
	// 在缓存的连接超时之后需要将用户的连接放回到连接池中
	// 并且注册超时处理函数，避免连接池中连接空闲时间过长
	network_mysqld_con * con = (network_mysqld_con *)user_data;
	g_assert(con);
	//g_assert(con->cache_server);
	network_socket * server = NULL;
	proxy_rw type = con->type;
	//chassis *srv = con->srv;

	//g_debug("network_mysqld_cache_con_idle_handle()");
	if (con->cache_server == NULL) {
		g_debug("[%s]: con maybe free, %p", G_STRLOC, con);
		return;
	}
	g_mutex_lock(&con->cache_server_mutex);
	if (con->cache_idle_timeout_flag == TRUE) {
		g_debug("[%s]: ignore timeout handler on cache server", G_STRLOC);
		/** @todo 这里需要将连接统计信息更新？？*/
		goto cache_idle_timeout_clear;
	}

	if (con->cache_server) {
		server = con->cache_server;
		con->cache_server = NULL;
	}

	// 若连接为空，就没有将连接放回连接池的需要了，直接返回。
	if (!con)
		goto cache_idle_timeout_clear;
		//return;
	
	//若缓存的连接为空，也没有将连接放回连接池的需要了，直接返回。
	if (!server)
		goto cache_idle_timeout_clear;
		//return;

	g_assert(server->fd == event_fd);

	if (events == EV_READ) {
		int b = -1;

		/**
		 * FIXME: we have to handle the case that the server really sent use something
		 * up to now we just ignore it
		 */
		if (ioctl(event_fd, FIONREAD, &b)) {
			g_error("[%s]: ioctl(%d, FIONREAD, ...) failed: %s", G_STRLOC, event_fd, strerror(errno));
		} else if (b != 0) {
			g_error("[%s]: ioctl(%d, FIONREAD, ...) said there is something to read, oops: %d, but this should not happen", G_STRLOC, event_fd, b);
		} else {
			/**
			 * 若是在缓存的连接中，后端突然因为某种原因失效，则缓存连接失败
			 * 具体应该怎么做？给应用端返回错误说后端失败还是怎么做？
			 * @todo 根据事务、prepare的情况，做不同处理
			 * 在事务中或在prepare中则返回失败；其他将连接清除即可？
			 * 因为cache server不在连接池中，不需要将连接从连接池中删除,因为其不在连接池中。
			 */
            //network_connection_pool_del_byconn(pool, server);
			network_backend_t * bk_end = NULL;
			if (server && server->dst && server->dst->name) {
				bk_end = network_backends_get_by_name(con->srv->priv->backends, server->dst->name->str);
				if (bk_end) {
					/** @todo 这里需要将连接池对应的在用连接数减1 */
					client_desc(bk_end, con->type);; ///backend 上面的连接数减1
					update_conn_pool_status_in_state(bk_end->pool[type],
											server->response->username->str,
											POOL_STATUS_STATE_DISCONNECTED); /// 对应的连接池在使用的连接数减1
				}
			}
			network_socket_free(server);
		}
	} else if (events == EV_TIMEOUT) {
		//若缓存的时间过长，超过了时间的限制则需要将连接放回至连接池中
		g_debug("[%s]: cache connection over time, will put it SOCKET = %d to pool.", G_STRLOC, event_fd);
		network_backend_t * bk_end = NULL;
		if (server && server->dst && server->dst->name) {
			bk_end = network_backends_get_by_name(con->srv->priv->backends, server->dst->name->str);
		}
		
		if(!bk_end) {
			g_critical("[%s] : get backend for connection error, SOCKET = %d. HOW CAN THIS HAPPEN!", G_STRLOC, event_fd);
			network_socket_free(server);
			goto cache_idle_timeout_clear;
			//return;
		}
		// 将该backend对应的连接数减1
		client_desc(bk_end, con->type);
		/**
		 * 为了能够在处理连接超时将连接从连接池中删除，
		 * 我们需要给连接池的超时处理函数提供更多的信息,而不仅仅是后端的一个socket
		 * 还需要知道连接所在的连接池,因而我们至少需要一个network_connection_pool_entry变量
		 */
		// 如果连接在事务中，需要将连接释放掉先测试一下close连接后事务是提交了还是回滚了
		// 经过确认，直接关闭socket！！！mysql事务是不会提交的
		//判断在事务中或者是在prepare中，kill掉后端的连接是不是应该放在proxy_disconnect_client中实现呢？？？
		if(server && con->tx_flag) {
			if (server->response) {
				g_message("[%s]:connection is in trans, will kill the connection to server. the client is %s", G_STRLOC,con->client->src->name->str);
				update_conn_pool_status_in_state(bk_end->pool[type],
						server->response->username->str,
						POOL_STATUS_STATE_DISCONNECTED);
				kill_network_con(server);
				mysqld_con_set_transaction_killed_location(
						con,
						G_STRLOC);
				//con->cache_server = NULL;
				con->tx_flag = 0;
				if(is_in_prepare(con))
					clean_prepare_context(con);
			} else {
				kill_network_con(server);
			}
			goto cache_idle_timeout_clear;
			//return;
		}

		// 对于prepare超时的连接，同样也需要将其后端关闭释放
		if(server && is_in_prepare(con)) {
			if(server->response) {
				g_message("[%s]:connection is in prepare, will kill the connection to server。the client is %s", G_STRLOC,con->client->src->name->str);
				update_conn_pool_status_in_state(bk_end->pool[type],
						server->response->username->str,
						POOL_STATUS_STATE_DISCONNECTED);
				kill_network_con(server);
				mysqld_con_set_prepare_killed_location(
						con,
						G_STRLOC);
				//con->cache_server = NULL;
				clean_prepare_context(con);
			} else {
				kill_network_con(server);
			}
			goto cache_idle_timeout_clear;
			//return;
		}

		// 反之，我们会将连接放回到连接池中以供复用
		if (server != NULL) {
			int fd = server->fd;
			if ((network_connection_pool_add(bk_end->pool[type], server)) == NULL) {
				// 连接加入到连接池失败。use--,同时释放连接
				update_conn_pool_status_in_state(bk_end->pool[type],
						server->response->username->str,
						POOL_STATUS_STATE_DISCONNECTED);
				network_socket_free(server);
				server = NULL;
				goto cache_idle_timeout_clear;
			}
			g_debug("[%s]: addded SOCKET = %d into pool", G_STRLOC, fd);
		}

		// 4. 修正连接池统计信息，连接释放到连接池中,use--,idle++
		update_conn_pool_status_in_state(bk_end->pool[type],
				server->response->username->str,
				POOL_STATUS_STATE_RETURN_TO_POOL);

		// 5. backend 对应的活动链接处--
		// client_desc(bk_end, type);
	}

cache_idle_timeout_clear:
	g_mutex_unlock(&(con->cache_server_mutex));

	return;
}


#if 0
/**
 * @author sohu-inc.com
 * 连接池中的连接空闲超时处理函数
 * @param event_fd 缓存超时的连接的文件描述符
 * @param events 接收到的时间
 * @param user_data 超时的连接
 */
void network_mysqld_pool_con_idle_handle(int event_fd, short events, void *user_data) {
	// 要做的处理是将连接从连接池中祛除，释放其内存
	network_connection_pool_entry * entry = (network_connection_pool_entry *)user_data;

	g_message("[%s]:SOCKET=%d to server:%s idle timeout or server shutdown connection, going to close it.", G_STRLOC,entry->sock->fd, entry->sock->dst->name->str );
	network_connection_pool_remove(entry->pool, entry);
}
#endif


/**
 * @author sohu-inc.com
 * 将连接sock添加到con对应的连接池中
 * @param con 主要是通过con获取连接池信息
 * @param sock 需要添加到连接池中的后端的连接
 */
gboolean network_mysqld_pool_con_add_soket(network_mysqld_con *con, network_socket *sock) {
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
	if(!bk_end) {
		g_error("[%s] : get backend for connection error", G_STRLOC);
		network_socket_free(sock);
		return FALSE;
	}

	entry = network_connection_pool_add(bk_end->pool[type], sock);
	if (entry == NULL) {
		g_critical("[%s]: add connect to pool for server = %s error", G_STRLOC,
				sock->dst->name->str);
		// 连接加入到连接池失败。use--,同时释放连接
		update_conn_pool_status_in_state(bk_end->pool[type],
				sock->response->username->str, POOL_STATUS_STATE_DISCONNECTED);

		network_socket_free(sock);
		return FALSE;
	}

	// 4. 修正连接池统计信息，连接释放到连接池中,use--,idle++
	update_conn_pool_status_in_state(bk_end->pool[type],
			sock->response->username->str, POOL_STATUS_STATE_RETURN_TO_POOL);

	// 5. backend 对应的活动链接处--
	client_desc(bk_end, type);

	return TRUE;
}



/**
 * @author sohu-inc.com
 * 连接的主动释放，指的是socket连接
 * @param s 将要被取消（kill）的socket连接
 */
void kill_network_con(network_socket *s) {
	
	if (!s) return;
	if (s->event.ev_base) {/** < 如果 .ev_base没有被设置，这个时间久没有被添加过不需要event_del */
		event_del(&(s->event));
	}

	/*
	network_queue_free(s->send_queue);
	network_queue_free(s->recv_queue);
	network_queue_free(s->recv_queue_raw);

	if (s->response) network_mysqld_auth_response_free(s->response);
	if (s->challenge) network_mysqld_auth_challenge_free(s->challenge);

	network_address_free(s->dst);
	network_address_free(s->src);

	if (s->fd != -1) {
		closesocket(s->fd);
	}

	g_string_free(s->default_db, TRUE);

	g_free(s);
	*/
	network_socket_free(s);

}

static void reset_para_limit_used(network_mysqld_con *con) {
	if (NULL == con || NULL == con->para_limit_used) {
		return;
	}

	con->para_limit_used[0] = FALSE;
	con->para_limit_used[1] = FALSE;
}

/**
 * 更新对应规则对应的语句的执行条数减1
 * 规则查询的原则是：先查找invidual,再查找普适的规则
 * 若找到individual规则就以individual规则为准；没有再去找普适规则；
 * 对于每类规则：又分为单条和某类的规则，需要满足这两种规则。
 * 即若有规则a=1和a=？时，两个规则都要满足。语句a=1运行会同时更新a=1和a=?的统计值
 */
network_socket_retval_t process_sql_para_rule(network_mysqld_con *con) {
	network_socket_retval_t ret = NETWORK_SOCKET_SUCCESS;
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->para_limit_rules);
	g_assert(con->client);

	char *user_name = NULL;
	char *db_name = NULL;

	if (NULL == con->client->response->username
			|| NULL == con->client->response->username->str) {
		user_name = "NULL";
	} else {
		user_name = con->client->response->username->str;
	}

	if (NULL == con->client->default_db
			|| NULL == con->client->default_db->str) {
		db_name = "NULL";
	} else {
		db_name = con->client->default_db->str;
	}

	g_string_truncate(con->para_limit_user_db_key_used, 0);
	g_string_append(con->para_limit_user_db_key_used, user_name);
	g_string_append(con->para_limit_user_db_key_used, db_name);

	gboolean tmp_ret = FALSE;
	GString *found_key = g_string_new(con->para_limit_user_db_key_used->str);
	para_exec_limit *para_limit = para_exec_limit_new();
	gint limit_type = 0;
	gint sql_type = 0;
	gint * running_num = NULL;

	reset_para_limit_used(con); /** 将并行限制使用规则标志复位 */
	for (limit_type = PARA_EXEC_INDIVIDUAL; limit_type <= PARA_EXEC_GLOBAL;
			limit_type++) {
		for (sql_type = PARA_SQL_SINGLE; sql_type <= PARA_SQL_TEMPLATE;
				sql_type++) {
			g_string_truncate(found_key, con->para_limit_user_db_key_used->len);
			/**
			 * 查找遍历individual及普适规则，看是否有对应的规则.
			 */
			// 先找单条规则
			//sql_type = PARA_SQL_SINGLE;
			tmp_ret = get_sql_para_rule(con->srv->para_limit_rules, user_name,
					db_name, con->sql_sentence->str, con->tokens,
					con->normalized_sql[sql_type], limit_type, sql_type,
					para_limit);
			if (tmp_ret && para_limit->limit_switch) {
				// 如果查到对应的规则，会对比现有的执行条数和限制数的关系
				g_mutex_lock(
						&(con->srv->para_running_statistic_dic->dic_lock[sql_type]));
				g_string_append(found_key, con->normalized_sql[sql_type]->str);
				running_num = g_hash_table_lookup(
						con->srv->para_running_statistic_dic->statistic_dic[sql_type],
						found_key);
				if (NULL == running_num) {
					GString *key_used = g_string_new(found_key->str);
					running_num = g_new0(gint, 1);
					*running_num = 0;
					g_hash_table_insert(
							con->srv->para_running_statistic_dic->statistic_dic[sql_type],
							key_used, running_num);
				}

				// 检查是否能够执行
				if (0 == para_limit->limit_para) {
					// 没有限制
					g_debug("[%s]: the %s:%s para limit of %s is unlimit.",
							G_STRLOC,
							(PARA_EXEC_INDIVIDUAL == limit_type) ?
									"INDIVIDUAL" : "GLOBAL",
							(PARA_SQL_SINGLE == sql_type) ?
									"SINGLE" : "TEMPLATE", found_key->str);
					con->para_limit_used[sql_type] = TRUE;
					*running_num += 1;
				} else if (0 > para_limit->limit_para) {
					// 需要像前端返回错误，告知明确的错误信息
					g_message("[%s]:the %s:%s para limit of %s is forbid.",
							G_STRLOC,
							(PARA_EXEC_INDIVIDUAL == limit_type) ?
									"INDIVIDUAL" : "GLOBAL",
							(PARA_SQL_SINGLE == sql_type) ?
									"SINGLE" : "TEMPLATE", found_key->str);
					ret = NETWORK_SOCKET_ERROR;

					/**
					 * @todo 向客户端发送明确的错误信息
					 */
					mpe_send_error(con->client, MPE_PRX_PRCRQ_SQL_TOO_MANY_PARA,
							0,
							(PARA_EXEC_INDIVIDUAL == limit_type) ?
									"INDIVIDUAL" : "GLOBAL",
							(PARA_SQL_SINGLE == sql_type) ?
									"SINGLE" : "TEMPLATE",
							para_limit->limit_para);

				} else if (para_limit->limit_para <= *running_num) {
					g_message(
							"[%s]:the running_num %d is bigger than the %s:%s para limit of %s is %d.",
							G_STRLOC, *running_num,
							(PARA_EXEC_INDIVIDUAL == limit_type) ?
									"INDIVIDUAL" : "GLOBAL",
							(PARA_SQL_SINGLE == sql_type) ?
									"SINGLE" : "TEMPLATE", found_key->str,
							para_limit->limit_para);
					ret = NETWORK_SOCKET_ERROR;
					/**
					 * @todo 向客户端发送明确的错误信息
					 */
					mpe_send_error(con->client, MPE_PRX_PRCRQ_SQL_TOO_MANY_PARA,
							*running_num,
							(PARA_EXEC_INDIVIDUAL == limit_type) ?
									"INDIVIDUAL" : "GLOBAL",
							(PARA_SQL_SINGLE == sql_type) ?
									"SINGLE" : "TEMPLATE",
							para_limit->limit_para);
				} else {
					g_debug(
							"[%s]:the running_num %d is smaller than the %s:%s para limit of %s is %d.",
							G_STRLOC, *running_num,
							(PARA_EXEC_INDIVIDUAL == limit_type) ?
									"INDIVIDUAL" : "GLOBAL",
							(PARA_SQL_SINGLE == sql_type) ?
									"SINGLE" : "TEMPLATE", found_key->str,
							para_limit->limit_para);

					con->para_limit_used[sql_type] = TRUE;
					*running_num += 1;
				}
				g_mutex_unlock(
						&(con->srv->para_running_statistic_dic->dic_lock[sql_type]));
			}

			if (PARA_SQL_TEMPLATE == sql_type) {
				// 如果是某类的sql语句执行结束，说明一类已经查找结束
				if (ret != NETWORK_SOCKET_SUCCESS) {
					// 不满足某类的sql并行限制，需要将某条语句的条数回滚
					if (con->para_limit_used[1 - PARA_SQL_TEMPLATE]) {
						dec_para_statistic_info(
								con->srv->para_running_statistic_dic,
								con->para_limit_user_db_key_used->str,
								con->normalized_sql[1 - PARA_SQL_TEMPLATE]->str,
								1 - PARA_SQL_TEMPLATE);
					}
					goto HAS_FOUND_RULE;
				}

				if (con->para_limit_used[0] || con->para_limit_used[1]) {
					// 已经在individual 或 普适的规则中找到了可用的规则，不需要再寻找
					goto HAS_FOUND_RULE;
				}
			}
		}
	}

HAS_FOUND_RULE:
	g_string_free(found_key, TRUE);
	para_exec_limit_free(para_limit);
	return ret;
}


gboolean process_sql_dura_rule(network_mysqld_con *con) {
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->dura_limit_rules);
	g_assert(con->client);
	con->max_dura_time = 0;

	gint sql_type = 0;
	gint limit_type = 0;

	char *user_name = NULL;
	char *db_name = NULL;

	if (NULL == con->client->response->username
			|| NULL == con->client->response->username->str) {
		user_name = "NULL";
	} else {
		user_name = con->client->response->username->str;
	}

	if (NULL == con->client->default_db
			|| NULL == con->client->default_db->str) {
		db_name = "NULL";
	} else {
		db_name = con->client->default_db->str;
	}

	gboolean tmp_ret = FALSE;
	dura_exec_limit *dura_limit = dura_exec_limit_new();

	// 先查找individual类别的超时限制规则
	// 在查找普适的超时限制规则

	for (limit_type = DURA_EXEC_INDIVIDUAL; limit_type <= DURA_EXEC_GLOBAL; limit_type++) {
		for(sql_type = DURA_SQL_SINGLE; sql_type <= DURA_SQL_TEMPLATE; sql_type++) {
			tmp_ret = get_sql_dura_rule(con->srv->dura_limit_rules, user_name,
					db_name, con->sql_sentence->str, con->tokens,
					con->normalized_sql[sql_type], limit_type,
					sql_type, dura_limit);

			if (tmp_ret && dura_limit->limit_switch) {
				con->max_dura_time = dura_limit->limit_dura;
				goto HAS_FOUND_RULE;
			}
		}
	}

HAS_FOUND_RULE:
	dura_exec_limit_free(dura_limit);
	return (0 < con->max_dura_time);
}

static void clean_read_query_timeout(network_mysqld_con *con) {

	/** 1.清空返回结果 */
	GString * result_packet = NULL;
	while (NULL != (result_packet = g_queue_pop_tail(con->server->recv_queue->chunks))) {
		g_string_free(result_packet, TRUE);
		result_packet = NULL;
	}

	while (NULL != (result_packet = g_queue_pop_tail(con->client->recv_queue->chunks))) {
		g_string_free(result_packet, TRUE);
		result_packet = NULL;
	}

	/** 2.清空执行语句 */
	// query queue
	GString *query_packet = NULL;
	while (NULL != (query_packet = g_queue_pop_tail(con->client->recv_queue->chunks))) {
		g_string_free(query_packet, TRUE);
		query_packet = NULL;
	}

	// 清空 prepare的上下文
	clean_prepare_context(con);

	/** 3.kill server端连接 */
	network_backend_t * bk_end = network_backends_get_by_name(
			con->srv->priv->backends,
			con->server->dst->name->str);

	client_desc(bk_end, con->type); // 将对应的backend的连接数减1

	update_conn_pool_status_in_state(bk_end->pool[con->type],
			con->server->response->username->str,
			POOL_STATUS_STATE_DISCONNECTED);
	kill_network_con(con->server);
	con->server = NULL;

	con->client->last_packet_id = 0;
	con->client->packet_id_is_reset = FALSE;

	/** 4.向client返回明确错误信息 */
	mpe_send_error(con->client, MPE_PRX_PRCRQ_SQL_EXECUTE_TOO_LONG,
			con->sql_sentence->str,
			chassis_get_rel_microseconds() - con->start_timestamp,
			con->max_dura_time);

	/** 设置con->state 为 */
	con->goto_next_state = TRUE;
	con->next_state = CON_STATE_READ_QUERY;

	con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
}

