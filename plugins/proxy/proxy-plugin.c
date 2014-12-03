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

/** 
 * @page page-plugin-proxy Proxy plugin
 *
 * The MySQL Proxy implements the MySQL Protocol in its own way. 
 *
 *   -# connect @msc
 *   client, proxy, backend;
 *   --- [ label = "connect to backend" ];
 *   client->proxy  [ label = "INIT" ];
 *   proxy->backend [ label = "CONNECT_SERVER", URL="\ref proxy_connect_server" ];
 * @endmsc
 *   -# auth @msc
 *   client, proxy, backend;
 *   --- [ label = "authenticate" ];
 *   backend->proxy [ label = "READ_HANDSHAKE", URL="\ref proxy_read_handshake" ];
 *   proxy->client  [ label = "SEND_HANDSHAKE" ];
 *   client->proxy  [ label = "READ_AUTH", URL="\ref proxy_read_auth" ];
 *   proxy->backend [ label = "SEND_AUTH" ];
 *   backend->proxy [ label = "READ_AUTH_RESULT", URL="\ref proxy_read_auth_result" ];
 *   proxy->client  [ label = "SEND_AUTH_RESULT" ];
 * @endmsc
 *   -# query @msc
 *   client, proxy, backend;
 *   --- [ label = "query result phase" ];
 *   client->proxy  [ label = "READ_QUERY", URL="\ref proxy_read_query" ];
 *   proxy->backend [ label = "SEND_QUERY" ];
 *   backend->proxy [ label = "READ_QUERY_RESULT", URL="\ref proxy_read_query_result" ];
 *   proxy->client  [ label = "SEND_QUERY_RESULT", URL="\ref proxy_send_query_result" ];
 * @endmsc
 *
 *   - network_mysqld_proxy_connection_init()
 *     -# registers the callbacks 
 *   - proxy_connect_server() (CON_STATE_CONNECT_SERVER)
 *     -# calls the connect_server() function in the lua script which might decide to
 *       -# send a handshake packet without contacting the backend server (CON_STATE_SEND_HANDSHAKE)
 *       -# closing the connection (CON_STATE_ERROR)
 *       -# picking a active connection from the connection pool
 *       -# pick a backend to authenticate against
 *       -# do nothing 
 *     -# by default, pick a backend from the backend list on the backend with the least active connctions
 *     -# opens the connection to the backend with connect()
 *     -# when done CON_STATE_READ_HANDSHAKE 
 *   - proxy_read_handshake() (CON_STATE_READ_HANDSHAKE)
 *     -# reads the handshake packet from the server 
 *   - proxy_read_auth() (CON_STATE_READ_AUTH)
 *     -# reads the auth packet from the client 
 *   - proxy_read_auth_result() (CON_STATE_READ_AUTH_RESULT)
 *     -# reads the auth-result packet from the server 
 *   - proxy_send_auth_result() (CON_STATE_SEND_AUTH_RESULT)
 *   - proxy_read_query() (CON_STATE_READ_QUERY)
 *     -# reads the query from the client 
 *   - proxy_read_query_result() (CON_STATE_READ_QUERY_RESULT)
 *     -# reads the query-result from the server 
 *   - proxy_send_query_result() (CON_STATE_SEND_QUERY_RESULT)
 *     -# called after the data is written to the client
 *     -# if scripts wants to close connections, goes to CON_STATE_ERROR
 *     -# if queries are in the injection queue, goes to CON_STATE_SEND_QUERY
 *     -# otherwise goes to CON_STATE_READ_QUERY
 *     -# does special handling for COM_BINLOG_DUMP (go to CON_STATE_READ_QUERY_RESULT) 

 */

#ifdef HAVE_SYS_FILIO_H
/**
 * required for FIONREAD on solaris
 */
#include <sys/filio.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <math.h> /* floor() */

#include <errno.h>

#include <glib.h>

#ifdef HAVE_LUA_H
/**
 * embedded lua support
 */
//#include <lua.h>
//#include <lauxlib.h>
//#include <lualib.h>
#endif

/* for solaris 2.5 and NetBSD 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif


#include <mysqld_error.h> /** for ER_UNKNOWN_ERROR */

#include "network-connection-scaler.h"

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"

// added by jinxuan hou
#include "network-socket.h"
#include "sql-tokenizer.h"

#include "network-mysqld-t.h"

#include "network-conn-pool.h"
//#include "network-conn-pool-lua.h"

#include "sys-pedantic.h"
#include "network-injection.h"
//#include "network-injection-lua.h"
#include "network-backend.h"
#include "glib-ext.h"
//#include "lua-env.h"
#include "network-detection-event-thread.h"

#include "proxy-plugin.h"

//#include "lua-load-factory.h"

#include "chassis-timings.h"
#include "chassis-gtimeval.h"
#include "chassis-regex.h"
#include "network-security-sqlmode.h"
#include "chassis-config-xml-admin.h"
#include "network-sql-statistics.h"

#include "slow-query-log.h"
#include "network-inbytes-statistic.h"
#include "network-outbytes-statistic.h"
#include "network-query-rate.h"
#include "network-check-DMLsql.h"
#include "network-dml-statistic.h"

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

/* backward compat with MySQL pre-5.5.7 */
#ifndef CLIENT_PLUGIN_AUTH
#define CLIENT_PLUGIN_AUTH (1 << 19)
#endif

#define HASH_INSERT(hash, key, expr) \
		do { \
			GString *hash_value; \
			if ((hash_value = g_hash_table_lookup(hash, key))) { \
				expr; \
			} else { \
				hash_value = g_string_new(NULL); \
				expr; \
				g_hash_table_insert(hash, g_strdup(key), hash_value); \
			} \
		} while(0);

#define CRASHME() do { char *_crashme = NULL; *_crashme = 0; } while(0);

struct chassis_plugin_config {
	gchar *address;                   /**< listening address of the proxy */

	// @author sohu-inc.com
	gchar *rw_address;                /**< rw_address */
	gchar *ro_address;

	// @author sohu-inc.com
        struct chassis_plugin_config *rw_config;
        struct chassis_plugin_config *ro_config;
        GPtrArray *listen_configs[2];

        // @author sohu-inc.com
        proxy_rw proxy_type;

	gchar **backend_addresses;        /**< read-write backends */
	gchar **read_only_backend_addresses; /**< read-only  backends */

	gint fix_bug_25371;               /**< suppress the second ERR packet of bug #25371 */

	gint profiling;                   /**< skips the execution of the read_query() function */
	
	#if 0
	gchar *lua_script;                /**< script to load at the start the connection */
	#endif

	gint pool_change_user;            /**< don't reset the connection, when a connection is taken from the pool
					       - this safes a round-trip, but we also don't cleanup the connection
					       - another name could be "fast-pool-connect", but that's too friendly
					       */

	gint start_proxy;
	gint multiplex; /** 标志是否启动连接复用 , added by sohu-inc.com */

	network_mysqld_con *listen_con;

	gdouble connect_timeout_dbl; /* exposed in the config as double */
	gdouble read_timeout_dbl; /* exposed in the config as double */
	gdouble write_timeout_dbl; /* exposed in the config as double */

	chassis *chas; /* apply_config时赋值，指到chas */
};

/**
 * handle event-timeouts on the different states
 *
 * @note con->state points to the current state
 *
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_timeout) {
	network_mysqld_con_t *st = con->plugin_con_state;

	if (st == NULL) return NETWORK_SOCKET_ERROR;

	switch (con->state) {
	case CON_STATE_CONNECT_SERVER:
		if (con->server) {
			double timeout = con->connect_timeout.tv_sec +
				con->connect_timeout.tv_usec / 1000000.0;

			g_debug("%s: connecting to %s timed out after %.2f seconds. Trying another backend.",
					G_STRLOC,
					con->server->dst->name->str,
					timeout);

			//st->backend->state = BACKEND_STATE_DOWN;
			//chassis_gtime_testset_now(&st->backend->state_since, NULL);
			network_socket_free(con->server);
			con->server = NULL;

			/* stay in this state and let it pick another backend */

			return NETWORK_SOCKET_SUCCESS;
		}
		/* fall through */
	case CON_STATE_SEND_AUTH:
		if (con->server) {
			/* we tried to send the auth data to the server, but that timed out.
			 * send the client and error
			 */
			network_mysqld_con_send_error(con->client, C("backend timed out"));
			con->state = CON_STATE_SEND_AUTH_RESULT;
			return NETWORK_SOCKET_SUCCESS;
		}
		/* fall through */
	default:
		/* the client timed out, close the connection */
		con->state = CON_STATE_ERROR;
		return NETWORK_SOCKET_SUCCESS;
	}
}
	
static network_mysqld_stmt_ret proxy_t_read_query_result(network_mysqld_con *con) {
	network_socket *send_sock = con->client;
	network_socket *recv_sock = con->server;
	injection *inj = NULL;
	network_mysqld_con_t *st = con->plugin_con_state;
	network_mysqld_stmt_ret ret = PROXY_NO_DECISION;

	/**
	 * check if we want to forward the statement to the client 
	 *
	 * if not, clean the send-queue 
	 */

	if (0 == st->injected.queries->length) return PROXY_NO_DECISION;

	inj = g_queue_pop_head(st->injected.queries);

#if 0
#ifdef HAVE_LUA_H
	/* call the lua script to pick a backend
	 * */
	switch(network_mysqld_con_lua_register_callback(con, con->config->lua_script)) {
		case REGISTER_CALLBACK_SUCCESS:
			break;
		case REGISTER_CALLBACK_LOAD_FAILED:
			network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to load. Check the error log."));
			con->state = CON_STATE_SEND_ERROR;
			return PROXY_SEND_RESULT;
		case REGISTER_CALLBACK_EXECUTE_FAILED:
			network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to execute. Check the error log."));
			con->state = CON_STATE_SEND_ERROR;
			return PROXY_SEND_RESULT;
	}
	

	if (st->L) {
		lua_State *L = st->L;

		g_assert(lua_isfunction(L, -1));
		lua_getfenv(L, -1);
		g_assert(lua_istable(L, -1));
		
		lua_getfield_literal(L, -1, C("read_query_result"));
		if (lua_isfunction(L, -1)) {
			injection **inj_p;
			GString *packet;

			inj_p = lua_newuserdata(L, sizeof(inj));
			*inj_p = inj;

			inj->result_queue = con->server->recv_queue->chunks;

			proxy_getinjectionmetatable(L);
			lua_setmetatable(L, -2);

			if (lua_pcall(L, 1, 1, 0) != 0) {
				g_critical("(read_query_result) %s", lua_tostring(L, -1));

				lua_pop(L, 1); /* err-msg */

				ret = PROXY_NO_DECISION;
			} else {
				if (lua_isnumber(L, -1)) {
					ret = lua_tonumber(L, -1);
				}
				lua_pop(L, 1);
			}

			if (!con->resultset_is_needed && (PROXY_NO_DECISION != ret)) {
				/* if the user asks us to work on the resultset, but hasn't buffered it ... ignore the result */
				g_critical("%s: read_query_result() in %s tries to modify the resultset, but hasn't asked to buffer it in proxy.query:append(..., { resultset_is_needed = true }). We ignore the change to the result-set.", 
						G_STRLOC,
						con->config->lua_script);

				ret = PROXY_NO_DECISION;
			}

			switch (ret) {
			case PROXY_SEND_RESULT:
				g_assert_cmpint(con->resultset_is_needed, ==, TRUE); /* we can only replace the result, if we buffer it */
				/**
				 * replace the result-set the server sent us 
				 */
				while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(packet, TRUE);
				
				/**
				 * we are a response to the client packet, hence one packet id more 
				 */
				if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet in case there was no result-set sent yet
					 */
			
					if (!st->injected.sent_resultset) {
						network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
					}
				}

				/* fall through */
			case PROXY_NO_DECISION:
				if (!st->injected.sent_resultset) {
					/**
					 * make sure we send only one result-set per client-query
					 */
					while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) {
						network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, packet);
					}
					st->injected.sent_resultset++;
					break;
				}
				g_critical("%s.%d: got asked to send a resultset, but ignoring it as we already have sent %d resultset(s). injection-id: %d",
						__FILE__, __LINE__,
						st->injected.sent_resultset,
						inj->id);

				st->injected.sent_resultset++;

				/* fall through */
			case PROXY_IGNORE_RESULT:
				/* trash the packets for the injection query */

				if (!con->resultset_is_needed) {
					/* we can only ignore the result-set if we haven't forwarded it to the client already
					 *
					 * we can end up here if the lua script loops and sends more than one query and is 
					 * not buffering the resultsets. In that case we have to close the connection to
					 * the client as we get out of sync ... actually, if that happens it is already
					 * too late
					 * */

					g_critical("%s: we tried to send more than one resultset to the client, but didn't had them buffered. Now the client is out of sync may have closed the connection on us. Please use proxy.queries:append(..., { resultset_is_needed = true }); to fix this.", G_STRLOC);

					break;
				}

				while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(packet, TRUE);

				break;
			default:
				/* invalid return code */
				g_message("%s.%d: return-code for read_query_result() was neither PROXY_SEND_RESULT or PROXY_IGNORE_RESULT, will ignore the result",
						__FILE__, __LINE__);

				while ((packet = g_queue_pop_head(send_sock->send_queue->chunks))) g_string_free(packet, TRUE);

				break;
			}
		} else if (lua_isnil(L, -1)) {
			/* no function defined, let's send the result-set */
			lua_pop(L, 1); /* pop the nil */
		} else {
			g_message("%s.%d: (network_mysqld_con_handle_proxy_resultset) got wrong type: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
			lua_pop(L, 1); /* pop the nil */
		}
		lua_pop(L, 1); /* fenv */

		g_assert(lua_isfunction(L, -1));
	}
#endif
#endif

	injection_free(inj);

	return ret;
}

#if 0
/**
 * call the lua function to intercept the handshake packet
 *
 * @return PROXY_SEND_QUERY  to send the packet from the client
 *         PROXY_NO_DECISION to pass the server packet unmodified
 */
static network_mysqld_lua_stmt_ret proxy_lua_read_handshake(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION; /* send what the server gave us */
#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;

	lua_State *L;

	/* call the lua script to pick a backend
	   ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
	   it would always show up as ERROR 2013, which is not helpful.
	 */
	(void)network_mysqld_con_lua_register_callback(con, con->config->lua_script);

	if (!st->L) return ret;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("read_handshake"));
	if (lua_isfunction(L, -1)) {
		/* export
		 *
		 * every thing we know about it
		 *  */

		if (lua_pcall(L, 0, 1, 0) != 0) {
			g_critical("(read_handshake) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}
	
		switch (ret) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_QUERY:
			g_warning("%s.%d: (read_handshake) return proxy.PROXY_SEND_QUERY is deprecated, use PROXY_SEND_RESULT instead",
					__FILE__, __LINE__);

			ret = PROXY_SEND_RESULT;
		case PROXY_SEND_RESULT:
			/**
			 * proxy.response.type = ERR, RAW, ...
			 */

			if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
				/**
				 * handling proxy.response failed
				 *
				 * send a ERR packet
				 */
		
				network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
			}

			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}
	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */
	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}
#endif

/**
 * parse the hand-shake packet from the server
 *
 *
 * @note the SSL and COMPRESS flags are disabled as we can't 
 *       intercept or parse them.
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_handshake) {
#if 0
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_auth_challenge *challenge;
	GString *challenge_packet;
	guint8 status = 0;
	int err = 0;

	send_sock = con->client;
	recv_sock = con->server;

 	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;
	
	err = err || network_mysqld_proto_skip_network_header(&packet);
	if (err) return NETWORK_SOCKET_ERROR;

	err = err || network_mysqld_proto_peek_int8(&packet, &status);
	if (err) return NETWORK_SOCKET_ERROR;

	/* handle ERR packets directly */
	if (status == 0xff) {
		/* move the chunk from one queue to the next */
		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, g_queue_pop_tail(recv_sock->recv_queue->chunks));

		return NETWORK_SOCKET_ERROR; /* it sends what is in the send-queue and hangs up */
	}

	challenge = network_mysqld_auth_challenge_new();
	if (network_mysqld_proto_get_auth_challenge(&packet, challenge)) {
 		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

		network_mysqld_auth_challenge_free(challenge);

		return NETWORK_SOCKET_ERROR;
	}

 	con->server->challenge = challenge;

	/* we can't sniff compressed packets nor do we support SSL */
	challenge->capabilities &= ~(CLIENT_COMPRESS);
	challenge->capabilities &= ~(CLIENT_SSL);

	switch (proxy_lua_read_handshake(con)) {
	case PROXY_NO_DECISION:
		break;
	case PROXY_SEND_RESULT:
		/* the client overwrote and wants to send its own packet
		 * it is already in the queue */

 		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

		return NETWORK_SOCKET_ERROR;
	default:
		g_critical("%s.%d: ...", __FILE__, __LINE__);
		break;
	}

	challenge_packet = g_string_sized_new(packet.data->len); /* the packet we generate will be likely as large as the old one. should save some reallocs */
	network_mysqld_proto_append_auth_challenge(challenge_packet, challenge);
	network_mysqld_queue_sync(send_sock, recv_sock);
	network_mysqld_queue_append(send_sock, send_sock->send_queue, S(challenge_packet));

	g_string_free(challenge_packet, TRUE);

	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

	/* copy the pack to the client */
	g_assert(con->client->challenge == NULL);
	con->client->challenge = network_mysqld_auth_challenge_copy(challenge);
	
	con->state = CON_STATE_SEND_HANDSHAKE;
#endif

	return NETWORK_SOCKET_SUCCESS;
}

#if 0
static network_mysqld_lua_stmt_ret proxy_lua_read_auth(network_mysqld_con *con) __attribute__((unused));
static network_mysqld_lua_stmt_ret proxy_lua_read_auth(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	lua_State *L;

	/* call the lua script to pick a backend
	   ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
	   it would always show up as ERROR 2013, which is not helpful.	
	*/
	(void)network_mysqld_con_lua_register_callback(con, con->config->lua_script);

	if (!st->L) return 0;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("read_auth"));
	if (lua_isfunction(L, -1)) {

		/* export
		 *
		 * every thing we know about it
		 *  */

		if (lua_pcall(L, 0, 1, 0) != 0) {
			g_critical("(read_auth) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}

		switch (ret) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_RESULT:
			/* answer directly */

			if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
				/**
				 * handling proxy.response failed
				 *
				 * send a ERR packet
				 */
		
				network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
			}

			break;
		case PROXY_SEND_QUERY:
			/* something is in the injection queue, pull it from there and replace the content of
			 * original packet */

			if (st->injected.queries->length) {
				ret = PROXY_SEND_INJECTION;
			} else {
				ret = PROXY_NO_DECISION;
			}
			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}
#endif

/**
 * modified by jinxuan hou, 2013/04/10
 * most of this function evolved from admin.c server_read_auth
 * here we should init the auth response, check limitation, check ip/username/password
 * next state is send_auth_result
 *
 *  Read the client authentication response and create a an authentication
 *      response to be sent back to the client
 *
 *      Result Format:
 *              4 byte CLIENT_FLAGS
 *              4 byte PACKET LENGTH
 *              1 byte CHARSET
 *              23 byte Filler
 *              N bytes USERNAME
 *              N bytes SCRAMBLED PASSWORD      
 * (opt) N bytes DEFAULT_DB
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
 *
 *      SERVER AUTHENTICATION RESPONSE
 *
 *              4 byte header
 *              1 field count - always 0
 *              1 affected rows = 0
 *              1 insert_id = 0
 *              2 server_status = SERVER_STATUS_AUTOCOMMIT
 *              2 warning_count = 0
 *
 *      Success Example:
 *              07 00 00 02 00 00 00 02  . . . . . . . .
 *              00 00 00  . . .
 *
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth) {
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_auth_response *auth;
	GString *excepted_response;
	GString *hashed_password;

	recv_sock = con->client;
	send_sock = con->client;

	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	/* decode the packet */
	network_mysqld_proto_skip_network_header(&packet);

	auth = network_mysqld_auth_response_new(con->client->challenge->capabilities);
	if (network_mysqld_proto_get_auth_response(&packet, auth)) {
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}
	if (!(auth->client_capabilities & CLIENT_PROTOCOL_41)) {
		/* should use packet-id 0 */
		g_critical("[%s]: the version of the client is too low.", G_STRLOC);
		network_mysqld_queue_append(con->client, con->client->send_queue, C("\xff\xd7\x07" "4.0 protocol is not supported"));
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}

	con->client->response = auth;

	/** 
	 * added by jinxuan hou, 2013/04/10
	 * we should check mysql-client ip is allowed to access
	 * first prepare the ip information of client peer.
	 * 
	 * @@jinxuanhou
	 */

	//1. prepare the ip information of client peer
	network_address *client_address = con->client->src;
	guint numofip;

	guint len = 0;
	gchar *idx = g_strstr_len (S(client_address->name), ":");

	if(!idx)
		len = client_address->name->len;
	else
		len = (gint)(idx - client_address->name->str);

	gchar *client_ip = g_strndup(client_address->name->str, len);

	con->client->ip = create_ip_range_from_str(client_ip);

	numofip = con->client->ip->minip;

	g_debug("[%s]: client ip is %s, guint format is %u", G_STRLOC, client_ip, numofip);	
	if (client_ip) g_free(client_ip);

	// 2. get the con->client->response->username related user info

	struct user_info * config_user = get_user_info_for_user(con->srv,
			con->client->response->username->str);
			//g_hash_table_lookup (con->srv->user_infos, con->client->response->username);

	// 没有找到相应的用户注册信息，返回错误，向用户端返回错误包，记录日志，关闭相应连接。
	if (!config_user) {
		//network_mysqld_con_send_error_full(send_sock, C("unknown user"), 1045, "28000");
		mpe_send_error(send_sock, MPE_PRX_RAUTH_UNKNOWN_USER);
		g_critical("[%s]: username unknown, %s", G_STRLOC, con->client->response->username->str);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
		return NETWORK_SOCKET_ERROR;
	}

	// 3. now we will check related informations like ip, username, password, connection limitation.

	// ip check
	con->client->ip_region = get_ip_range(numofip, config_user);
	if(!con->client->ip_region) {
		//network_mysqld_con_send_error_full(send_sock, C("client ip is not allowed"), 1045, "28000");
		mpe_send_error(send_sock, MPE_PRX_RAUTH_IP_NOT_ALLOWED);
		g_critical("[%s] :client %s is forbidden to access proxy", G_STRLOC, con->client->ip->ip->str);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
		return NETWORK_SOCKET_SUCCESS;
	}

	/* check whether the username and password matches or not*/

	excepted_response = g_string_new(NULL);
	hashed_password = g_string_new(NULL);

	if (!strleq(S(con->client->response->username), S(config_user->username))) {
		//network_mysqld_con_send_error_full(send_sock, C("unknown user"), 1045, "28000");
		mpe_send_error(send_sock, MPE_PRX_RAUTH_UNKNOWN_USER);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else if (network_mysqld_proto_password_hash(hashed_password, S(config_user->passwd))) {
	} else if (network_mysqld_proto_password_scramble(excepted_response,
			S(recv_sock->challenge->auth_plugin_data),
			S(hashed_password))) {
		//network_mysqld_con_send_error_full(send_sock, C("scrambling failed"), 1045, "28000");
		mpe_send_error(send_sock, MPE_PRX_RAUTH_PWD_SCRAMBLE_FAILED);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else if (!g_string_equal(excepted_response, auth->auth_plugin_data)) {
		//network_mysqld_con_send_error_full(send_sock, C("password doesn't match"), 1045, "28000");
		mpe_send_error(send_sock, MPE_PRX_RAUTH_PWD_NOT_MATCHED);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else {

		// 接下来，我们需要判断连接的用户数是否超过配置的最大连接数
		gint *tmp_limit;
		tmp_limit = get_conn_limit(con->srv, con->type, con->client->response->username->str, con->client->ip_region);
		if (NULL == tmp_limit) {
			g_message("[%s]:limit of %s@%s is not setted, will use default limit %d", G_STRLOC,con->client->response->username->str, con->client->ip_region, chas->default_conn_limit[con->type]);
			tmp_limit = &(chas->default_conn_limit[con->type]);
		}

		if (0 == *tmp_limit) {
			g_message("[%s]:limit of %s@%s is unlimit", G_STRLOC, con->client->response->username->str, con->client->ip_region);
		} else {
			g_message("[%s]: limit of %s@%s is %d", G_STRLOC, con->client->response->username->str, con->client->ip_region, *tmp_limit);
		}

		/*获得用户当前连接数*/
		gint *conn_in_use = get_login_users(con->srv, con->type,
				con->client->response->username->str, con->client->ip_region);
		if (conn_in_use == NULL ) {
			/*加写锁后，再复查用户当前连接数*/
			GString *key = NULL;
			gint *tmp_value = NULL;

			key = g_string_new(con->client->response->username->str);
			g_string_append_c(key, ':');
			g_string_append(key, con->client->ip_region);

			g_rw_lock_writer_lock(&con->srv->login_lock[con->type]);
			tmp_value = g_hash_table_lookup(con->srv->conn_used[con->type],
					key);
			if (tmp_value == NULL ) {
				gint *value = NULL;
				value = g_new0(gint, 1);
				*value = (gint) 1;
				g_hash_table_insert(con->srv->conn_used[con->type], key, value);
				con->client_is_authed = TRUE;
			} else {
				if (0 == *tmp_limit || *tmp_value < *tmp_limit) { /*0表示无限制*/
					g_atomic_int_inc(tmp_value);
					con->client_is_authed = TRUE;
				} else {
					con->client_is_authed = FALSE;
				}
				g_string_free(key, TRUE);
			}
			g_rw_lock_writer_unlock(&con->srv->login_lock[con->type]);

		} else {
			if (0 == *tmp_limit || *conn_in_use < *tmp_limit) { /*0表示无限制*/
				g_atomic_int_inc(conn_in_use);
				con->client_is_authed = TRUE;
			} else {
				con->client_is_authed = FALSE;
			}
		}
		if (con->client_is_authed == TRUE) {
			network_mysqld_con_send_ok(send_sock);
			con->state = CON_STATE_SEND_AUTH_RESULT;
		} else {
			mpe_send_error(send_sock, MPE_PRX_RAUTH_TOO_MANY_FE_LOGINS,
					con->client->response->username->str,
					con->client->ip_region, *conn_in_use, *tmp_limit);
			g_warning("[%s]:too many logins for user:%s@%s, login is %d > limit is %d",
					G_STRLOC,
					con->client->response->username->str,
					con->client->ip_region,
					*conn_in_use,
					*tmp_limit);
			con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
		}

		if(con->client->response->database) {
			g_debug("[%s]: the default database is setted to be %s", G_STRLOC, con->client->response->database->str);
			//con->client->default_db = g_string_new(con->client->response->database->str);
			g_string_truncate(con->client->default_db, 0);
			g_string_append_len(con->client->default_db, S(con->client->response->database));
		} else {
			g_debug("[%s]: the default database is setted to be %s", G_STRLOC, "NULL");
		}
		// 接下来根据client端的字符集设置，连接的字符集
		const gchar *charset = charset_dic[con->client->response->charset];
		/**
		 * 注意auth包里面的编码方式只是影响到con->client->character_set_client
		 * 因而这里将connection 和 result 的修改注释掉！！！
		 */
		if (0 != g_ascii_strcasecmp(con->client->character_set_client->str, charset)) {
			g_string_truncate(con->client->character_set_client, 0);
			g_string_append(con->client->character_set_client, charset);
		}

		if (0 != g_ascii_strcasecmp(con->client->character_set_connection->str, charset)) {
			g_string_truncate(con->client->character_set_connection, 0);
			g_string_append(con->client->character_set_connection, charset);
		}

		if (0 != g_ascii_strcasecmp(con->client->character_set_results->str, charset)) {
			g_string_truncate(con->client->character_set_results, 0);
			g_string_append(con->client->character_set_results, charset);
		}

		// 修改对应的connection collation,初始化的！！
		if (0 != g_ascii_strcasecmp(con->client->collection_connect->str, collation_dic[con->client->response->charset])) {
			g_string_truncate(con->client->collection_connect, 0);
			g_string_append(con->client->collection_connect, collation_dic[con->client->response->charset]);
		}

		network_mysqld_queue_reset(con->client);
	}

	g_string_free(hashed_password, TRUE);
	g_string_free(excepted_response, TRUE);
	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

	return NETWORK_SOCKET_SUCCESS;
}

#if 0
static network_mysqld_lua_stmt_ret proxy_lua_read_auth_result(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	network_socket *recv_sock = con->server;
	GList *chunk = recv_sock->recv_queue->chunks->tail;
	GString *packet = chunk->data;
	lua_State *L;

	/* call the lua script to pick a backend
	   ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
	   it would always show up as ERROR 2013, which is not helpful.	
	*/
	(void)network_mysqld_con_lua_register_callback(con, con->config->lua_script);

	if (!st->L) return 0;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("read_auth_result"));
	if (lua_isfunction(L, -1)) {

		/* export
		 *
		 * every thing we know about it
		 *  */

		lua_newtable(L);

		lua_pushlstring(L, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);
		lua_setfield(L, -2, "packet");

		if (lua_pcall(L, 1, 1, 0) != 0) {
			g_critical("(read_auth_result) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}

		switch (ret) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_RESULT:
			/* answer directly */

			if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
				/**
				 * handling proxy.response failed
				 *
				 * send a ERR packet
				 */
		
				network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
			}

			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}
#endif

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth_result) {
#if 0
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;

	recv_sock = con->server;
	send_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = chunk->data;

	/* send the auth result to the client */
	if (con->server->is_authed) {
		/**
		 * we injected a COM_CHANGE_USER above and have to correct to 
		 * packet-id now 
		 */
		packet->str[3] = 2;
	}

	/**
	 * copy the 
	 * - default-db, 
	 * - username, 
	 * - scrambed_password
	 *
	 * to the server-side 
	 */
	g_string_assign_len(recv_sock->default_db, S(send_sock->default_db));

	if (con->server->response) {
		/* in case we got the connection from the pool it has the response from the previous auth */
		network_mysqld_auth_response_free(con->server->response);
		con->server->response = NULL;
	}
	con->server->response = network_mysqld_auth_response_copy(con->client->response);

	/**
	 * recv_sock still points to the old backend that
	 * we received the packet from. 
	 *
	 * backend_ndx = 0 might have reset con->server
	 */

	switch (proxy_lua_read_auth_result(con)) {
	case PROXY_SEND_RESULT:
		/**
		 * we already have content in the send-sock 
		 *
		 * chunk->packet is not forwarded, free it
		 */

		g_string_free(packet, TRUE);
		
		break;
	case PROXY_NO_DECISION:
		network_mysqld_queue_append_raw(
				send_sock,
				send_sock->send_queue,
				packet);

		break;
	default:
		g_error("%s.%d: ... ", __FILE__, __LINE__);
		break;
	}

	/**
	 * we handled the packet on the server side, free it
	 */
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
	
	/* the auth phase is over
	 *
	 * reset the packet-id sequence
	 */
	network_mysqld_queue_reset(send_sock);
	network_mysqld_queue_reset(recv_sock);
	
	con->state = CON_STATE_SEND_AUTH_RESULT;
#endif
	return NETWORK_SOCKET_SUCCESS;
}

#if 0
static network_mysqld_lua_stmt_ret proxy_lua_read_query(network_mysqld_con *con) __attribute__((unused));
static network_mysqld_lua_stmt_ret proxy_lua_read_query(network_mysqld_con *con) {
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	network_socket *recv_sock = con->client;
	GList   *chunk  = recv_sock->recv_queue->chunks->head;
	GString *packet = chunk->data;
	chassis_plugin_config *config  __attribute__((unused)) = con->config;
	
	network_injection_queue_reset(st->injected.queries);

	/* ok, here we go */

#ifdef HAVE_LUA_H
	switch(network_mysqld_con_lua_register_callback(con, con->config->lua_script)) {
		case REGISTER_CALLBACK_SUCCESS:
			break;
		case REGISTER_CALLBACK_LOAD_FAILED:
			network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to load. Check the error log."));
			con->state = CON_STATE_SEND_ERROR;
			return PROXY_SEND_RESULT;
		case REGISTER_CALLBACK_EXECUTE_FAILED:
			network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to execute. Check the error log."));
			con->state = CON_STATE_SEND_ERROR;
			return PROXY_SEND_RESULT;
	}

	if (st->L) {
		lua_State *L = st->L;
		network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

		g_assert(lua_isfunction(L, -1));
		lua_getfenv(L, -1);
		g_assert(lua_istable(L, -1));

		/**
		 * reset proxy.response to a empty table 
		 */
		lua_getfield(L, -1, "proxy");
		g_assert(lua_istable(L, -1));

		lua_newtable(L);
		lua_setfield(L, -2, "response");

		lua_pop(L, 1);
		
		/**
		 * get the call back
		 */
		lua_getfield_literal(L, -1, C("read_query"));
		if (lua_isfunction(L, -1)) {
			luaL_Buffer b;
			int i;

			/* pass the packet as parameter */
			luaL_buffinit(L, &b);
			/* iterate over the packets and append them all together */
			for (i = 0; NULL != (packet = g_queue_peek_nth(recv_sock->recv_queue->chunks, i)); i++) {
				luaL_addlstring(&b, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);
			}
			luaL_pushresult(&b);

			if (lua_pcall(L, 1, 1, 0) != 0) {
				/* hmm, the query failed */
				g_critical("(read_query) %s", lua_tostring(L, -1));

				lua_pop(L, 2); /* fenv + errmsg */

				/* perhaps we should clean up ?*/

				return PROXY_SEND_QUERY;
			} else {
				if (lua_isnumber(L, -1)) {
					ret = lua_tonumber(L, -1);
				}
				lua_pop(L, 1);
			}

			switch (ret) {
			case PROXY_SEND_RESULT:
				/* check the proxy.response table for content,
				 *
				 */
	
				if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet
					 */
			
					network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
				}
	
				break;
			case PROXY_NO_DECISION:
				/* send on the data we got from the client unchanged
				 */

				if (st->injected.queries->length) {
					injection *inj;

					g_critical("%s: proxy.queue:append() or :prepend() used without 'return proxy.PROXY_SEND_QUERY'. Discarding %d elements from the queue.",
							G_STRLOC,
							st->injected.queries->length);

					while ((inj = g_queue_pop_head(st->injected.queries))) injection_free(inj);
				}
			
				break;
			case PROXY_SEND_QUERY:
				/* send the injected queries
				 *
				 * injection_new(..., query);
				 * 
				 *  */

				if (st->injected.queries->length == 0) {
					g_critical("%s: 'return proxy.PROXY_SEND_QUERY' used without proxy.queue:append() or :prepend(). Assuming 'nil' was returned",
							G_STRLOC);
				} else {
					ret = PROXY_SEND_INJECTION;
				}
	
				break;
			default:
				break;
			}
			lua_pop(L, 1); /* fenv */
		} else {
			lua_pop(L, 2); /* fenv + nil */
		}

		g_assert(lua_isfunction(L, -1));

		if (ret != PROXY_NO_DECISION) {
			return ret;
		}
	}
#endif
	return PROXY_NO_DECISION;
}
#endif

/**
 * gets called after a query has been read
 *
 * - calls the lua script via network_mysqld_con_handle_proxy_stmt()
 * 这里我们做一个状态的转换，即在con_state_read_query阶段只是实现将query
 * 读取到client->recv_queue中，不在通过路脚本对sql语句做进一步的解析
 * 语句解析迁移到了process_read_query及get_server_list中实现
 * @see network_mysqld_con_handle_proxy_stmt
 */

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query) {
	g_assert(con);

	/** 将变转化的sql清空 */
	g_string_truncate(con->normalized_sql[0], 0);
	g_string_truncate(con->normalized_sql[1], 0);
	con->max_dura_time = 0;

	con->state = CON_STATE_PROCESS_READ_QUERY;
	return NETWORK_SOCKET_SUCCESS;
}

/**
 * @author sohu-inc.com
 *  tokenize the sql to tokens
 */
static int get_sql_tokenizer(network_mysqld_con *con) {
	guint i = 0;
	sql_token *token;

	if (con->tokens) {
		//初始化token列表
		sql_tokens_free(con->tokens);
	}
	con->tokens = sql_tokens_new();

	sql_tokenizer(con->tokens, S(con->sql_sentence));

	g_debug("[%s]: printing sql tokens, sql sentence is %s", G_STRLOC,
			con->sql_sentence->str);
	for (i = 0; i < con->tokens->len; i++) {
		token = con->tokens->pdata[i];
		g_debug("[%s]: token[%d] is %s, token_id is %d", G_STRLOC, i, token->text->str, token->token_id);
	}

	return 0;
}

#define MAX_TOKEN_LEN 2
#define MAX_VERSION_LEN 5
static int begin_index_without_version(const char * token_str){
	if (NULL == token_str) {
		return -1;
	}

	int index = 0;
	while (index < MAX_VERSION_LEN && '0' <= token_str[index] && '9' >= token_str[index]) {
		index++;
	}

	if (index == MAX_VERSION_LEN) {
		 return index;
	}

	return 0;
}

/**
 * 用于判定查询是否在黑名单中
 * @param tokens 查询的分词列表
 * @param cmd_type 查询的类型（我们的黑名单只有两个属于com_query）
 * @return
 */
gboolean is_in_black_list(GPtrArray *tokens,
		enum enum_server_command cmd_type){
	if (cmd_type != COM_QUERY) {
		return FALSE;
	}

	gboolean result = FALSE;

	if (NULL == tokens || tokens->len <= 0 ) {
		return result;
	}

	GString *tmp_sql = g_string_new("");

	int count = 0;
	int index = 0;
	int index_without_version = 0;

	for (index = 0; index < (int)tokens->len; index++) {
		if (count >= MAX_TOKEN_LEN) {
			break;
		}

		if (((sql_token *)tokens->pdata[index])->token_id == TK_COMMENT) {
			continue;
		}

		if (((sql_token *)tokens->pdata[index])->token_id == TK_COMMENT_MYSQL) {
			index_without_version = begin_index_without_version(((sql_token *)tokens->pdata[index])->text->str);
		}

		if (index_without_version == -1) {
			continue;
		} else {
			count++;
			if ((int)((sql_token *)tokens->pdata[index])->text->len - index_without_version - 1 >= 0) {
				g_string_append_len(tmp_sql,
						((sql_token *)tokens->pdata[index])->text->str + index_without_version,
						((sql_token *)tokens->pdata[index])->text->len - index_without_version);
				g_string_append(tmp_sql, " ");
			}
		}
		index++;
	}

	GPtrArray *tokens_tmp = sql_tokens_new();
	sql_tokenizer(tokens_tmp, S(tmp_sql));

	if (tokens_tmp->len > 0 && ((sql_token *)tokens_tmp->pdata[0])->token_id == TK_SQL_SET) {
		if (tokens_tmp->len >= 2) {
			if (0 == g_ascii_strcasecmp(((sql_token *)tokens_tmp->pdata[1])->text->str, "password")) {
				result = TRUE;
			}
		}
	} else if (tokens_tmp->len > 0 && ((sql_token *)tokens_tmp->pdata[0])->token_id == TK_SQL_DROP) {
		if (tokens_tmp->len >= 2 && (((sql_token *)tokens_tmp->pdata[1])->token_id == TK_SQL_DATABASE ||
				((sql_token *)tokens_tmp->pdata[1])->token_id == TK_SQL_SCHEMA)) {
			result = TRUE;
		}
	}

	g_string_free(tmp_sql, TRUE);
	sql_tokens_free(tokens_tmp);

	return result;
}


///////////////
/*** 表引擎替换相关 */
//////////////////////////

static gboolean is_forb_engine(const char *engine) {

	if (NULL == engine) {
		return FALSE;
	}

	return (0 == g_ascii_strcasecmp(engine, "myisam")) || (0 == g_ascii_strcasecmp(engine, "csv"));
}

gboolean is_table_alter_or_reate_with_myisam(GPtrArray *tokens){
	if (NULL == tokens || tokens->len <= 0){
		return FALSE;
	}

	GString *tmp_sql = g_string_new("");
	gboolean result = FALSE;

	int count = 0;
	int index = 0;
	int index_without_version = 0;

	for (index = 0; index < (int)tokens->len; index++) {

		if (((sql_token *)tokens->pdata[index])->token_id == TK_COMMENT) {
			continue;
		}

		if (((sql_token *)tokens->pdata[index])->token_id == TK_COMMENT_MYSQL) {
			index_without_version = begin_index_without_version(((sql_token *)tokens->pdata[index])->text->str);
		}

		if (index_without_version == -1) {
			continue;
		} else {
			count++;
			if ((int)((sql_token *)tokens->pdata[index])->text->len - index_without_version - 1 >= 0) {
				g_string_append_len(tmp_sql,
						((sql_token *)tokens->pdata[index])->text->str + index_without_version,
						((sql_token *)tokens->pdata[index])->text->len - index_without_version);
				g_string_append(tmp_sql, " ");
			}
		}
		index++;
	}

	GPtrArray *tokens_tmp = sql_tokens_new();
	sql_tokenizer(tokens_tmp, S(tmp_sql));

	if (tokens_tmp->len > 0 && (((sql_token *)tokens_tmp->pdata[0])->token_id == TK_SQL_CREATE ||
			((sql_token *)tokens_tmp->pdata[0])->token_id == TK_SQL_ALTER)) {
		if (tokens_tmp->len >= 2 && ((sql_token *)tokens_tmp->pdata[1])->token_id == TK_SQL_TABLE) {
			result = TRUE;
		}
	}

	if (result) {
		// 定位到语句是create table 和 alter table 语句，接下来看是否有engine = myisam的字段
		// 为了避免漏掉/*! engin = myisam*/  的语句，需要对语句进行重新组合，在进行分词
		// 发现很不好替换啊！
		result = FALSE;
		guint index = 0;

		index = 1;
		while (index < tokens_tmp->len - 1) {
			if (((sql_token *)tokens_tmp->pdata[index])->token_id == TK_EQ) {
				if (0 == g_ascii_strcasecmp(((sql_token *)tokens_tmp->pdata[index - 1])->text->str, "engine") &&
						is_forb_engine(((sql_token *)tokens_tmp->pdata[index + 1])->text->str)) {
					result = TRUE;
					break;
				}
			}
			index++;
		}
	}

	sql_tokens_free(tokens_tmp);
	g_string_free(tmp_sql, TRUE);

	return result;
}

#define DML_MAX_TOKEN_NUM 2
// 用于处理判定对应的操作是不是被禁止的dml 操作
static gboolean process_dml_ops(network_mysqld_con *con){
	if (NULL == con || NULL == con->srv) {
		return FALSE;
	}

	if (NULL == con->tokens || con->tokens->len <= 0) {
		return FALSE;
	}
	gboolean result = FALSE;

	int index = 0;
	int count =  0;
	int index_without_version = 0;
	GString *tmp_sql = g_string_new(NULL);
	for (index = 0; index < (int)con->tokens->len; index++) {
		if (count >= DML_MAX_TOKEN_NUM) {
			break;
		}

		if (((sql_token *)con->tokens->pdata[index])->token_id == TK_COMMENT) {
			continue;
		}

		if (((sql_token *)con->tokens->pdata[index])->token_id == TK_COMMENT_MYSQL) {
			index_without_version = begin_index_without_version(((sql_token *)con->tokens->pdata[index])->text->str);
		}

		if (index_without_version == -1) {
			continue;
		} else {
			count++;
			if ((int)((sql_token *)con->tokens->pdata[index])->text->len - index_without_version - 1 >= 0) {
				g_string_append_len(tmp_sql,
						((sql_token *)con->tokens->pdata[index])->text->str + index_without_version,
						((sql_token *)con->tokens->pdata[index])->text->len - index_without_version);
				g_string_append(tmp_sql, " ");
			}
		}
		index++;
	}

	GPtrArray *tokens_tmp = sql_tokens_new();
	sql_tokenizer(tokens_tmp, S(tmp_sql));

	index = 0;
	for (index = DML_ALTER; index <= DML_UPDATE; index ++) {
		if (con->srv->dml_ops[index]) {
			if (is_dml_operation(tokens_tmp, index)) {
				result = TRUE;
				break;
			}
		}
	}

	sql_tokens_free(tokens_tmp);
	g_string_free(tmp_sql, TRUE);

	return result;
}

/**
 * @author sohu-inc.com
 * 这里简单实现，应该做的是与安全组的接口。决定是否阻断sql
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_process_read_query) {
	g_assert(con);
	g_assert(con->srv);

	chassis *srv =  con->srv;
	get_sql_tokenizer(con);
	network_socket_retval_t ret = NETWORK_SOCKET_SUCCESS;
	enum enum_server_command server_command = ((GString *)con->client->recv_queue->chunks->head->data)->str[NET_HEADER_SIZE + 0];

	if (server_command == COM_STMT_EXECUTE
			|| server_command == COM_STMT_SEND_LONG_DATA
			|| server_command == COM_CHANGE_USER) {
		con->need_record = FALSE; /** <如果执行的语句是绑定变量及prepare的execute语句，
								               则不需要记录sql语句的执行时间 */
	}

	/**
	 * 这里判断语句是否在黑名单中，如果是则给客户端返回明确的错误信息
	 * 同时丢弃sql查询语句
	 **/
	if (con->srv->is_black_list_enable) {
		if (server_command == COM_QUERY && is_in_black_list(con->tokens, server_command)) {
			g_warning(
					"[%s]: query '%s' from client %s@%s is droped because of in black list.",
					G_STRLOC, con->sql_sentence->str,
					con->client->response->username->str,
					con->client->src->name->str);
			mpe_send_error(con->client, MPE_PRX_PRCRQ_SQL_NOT_SUPPORT);

			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_ERROR;
		}
	}

	if (chas->table_engine_replaceable) {
		if (server_command == COM_QUERY && is_table_alter_or_reate_with_myisam(con->tokens)) {
			g_warning(
					"[%s]: query '%s' from client %s@%s is droped because of table engine is MYISAM.",
					G_STRLOC, con->sql_sentence->str,
					con->client->response->username->str,
					con->client->src->name->str);
			mpe_send_error(con->client, MPE_PRX_PRCRQ_SQL_NOT_SUPPORT);

			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_ERROR;
		}
	}

	/**
	 * 测试一下SQL是否合法
	 * 是否是只需要对COM_QUERY语句才做判断,这里首先只是对COM_QUERY语句做判断
	 */
	if ((con->tokens != NULL && con->tokens->len > 0) && COM_QUERY == ((GString *)con->client->recv_queue->chunks->head->data)->str[NET_HEADER_SIZE + 0]) {
		char *dbname = NULL;
		char *user = NULL;

		if (con->client && con->client->default_db) {
			dbname = g_strdup((con->client->default_db->len > 0)?con->client->default_db->str:"NULL");
		} else {
			dbname = g_strdup("NULL");
		}

		if (con->client && con->client->response) {
			user = g_strdup(con->client->response->username->str);
		}

		switch(sql_security_rule_match_process(srv->rule_table,
				con->tokens,
				con->sql_sentence->str,
				dbname,
				user)) {
		case ACTION_SAFE:
			g_debug("[%s]: security level of sql %s is safe",
					G_STRLOC,
					con->sql_sentence->str);
			break;
		case ACTION_LOG:
			g_message("[%s]: security level of sql %s is log",
					G_STRLOC,
					con->sql_sentence->str);
			break;
		case ACTION_WARNING:
			g_warning("[%s]: security level of sql %s is warning",
					G_STRLOC,
					con->sql_sentence->str);
			break;
		case ACTION_BLOCK:
			g_critical("[%s]: security level of sql %s is block, client is %s@%s",
					G_STRLOC,
					con->sql_sentence->str,
					con->client->response->username->str,
					con->client->src->name->str);
			mpe_send_error(con->client, MPE_PRX_PRCRQ_SQL_UNSAFE);
			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			ret = NETWORK_SOCKET_ERROR;
			break;
		default :
			g_assert_not_reached();
		}
		if (dbname) {
			g_free(dbname);
			dbname = NULL;
		}
		if (user) {
			g_free(user);
			user = NULL;
		}
	}

	if (NETWORK_SOCKET_ERROR == ret) {
		return NETWORK_SOCKET_ERROR;
	}

	/** 如果开启了dml 封禁标志，需要查询对应的用户是否被封禁，然后对语句做相应的判断 */
	if (chas->is_dml_check_enable) {
		if (get_query_dml_switch(chas->query_dml_list,
				con->client->response->username->str)) {
			if (process_dml_ops(con)) {
				g_warning(
						"[%s]: query '%s' from client %s@%s is droped because of size of db is out of limit or other reason.",
						G_STRLOC, con->sql_sentence->str,
						con->client->response->username->str,
						con->client->src->name->str);
				mpe_send_error(con->client, MPE_PRX_PRCRQ_DB_SIZE_OUT_OF_LIMIT);

				con->goto_next_state = TRUE;
				con->next_state = CON_STATE_READ_QUERY;
				con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
				return NETWORK_SOCKET_ERROR;
			}
		}
	}

	/** 如果开启了输入流量统计功能，需要更具对应用户的流量是否超标做相应的动作 */
	if (chas->is_outbytes_r_enabled) {
		if (get_query_outbytes_switch(chas->outbytes_list,
				con->client->response->username->str)) {
			// 如果用户请求因为流量超标，会向客户端返回对应的错误信息，并将用户的请求丢弃
			gint64 total_outbytes = get_query_outbytes_num_total(
					chas->outbytes_list, con->client->response->username->str);
			g_warning(
					"[%s]: query '%s' from client %s@%s is droped because of too many result in bytes.total in bytes is %ld.",
					G_STRLOC, con->sql_sentence->str,
					con->client->response->username->str,
					con->client->src->name->str, total_outbytes);
			mpe_send_error(con->client, MPE_PRX_PRCRQ_TOO_MANY_QUERY_OUT_BYTES,
					total_outbytes);

			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_ERROR;
		}
		// 输入流量的更新在想客户端写回结果时进行
	}

	/** 如果开启了sql语句执行统计功能，需要更具对饮给的用户的流量是否超标做相应的动作 */
	if (chas->is_query_r_enabled) {
		if (get_query_rate_switch(chas->query_rate_list, con->client->response->username->str)) {
			// 如果用户请求因为请求数超标， 会向客户端返回对应的错误信息，并将用户的请求丢弃
			gint64 total_query_num = get_query_rate_num(chas->query_rate_list, con->client->response->username->str);
			g_warning("[%s]: query '%s' from client %s@%s is droped because of too many querys.total is %ld.",
					G_STRLOC,
					con->sql_sentence->str,
					con->client->response->username->str,
					con->client->src->name->str,
					total_query_num);
			// 如果执行失败需要将对应的错误执行条数加1
			query_error_rate_inc(con->srv->query_rate_list, con->client->response->username->str,
					con->type);

			mpe_send_error(con->client, MPE_PRX_PRCRQ_TOO_MANY_QUERY_IN_NUM,
					total_query_num);
			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_ERROR;
		} else {
			query_rate_inc(con->srv->query_rate_list, con->client->response->username->str,
					con->type);
		}
	}

	/** 如果开启了流量统计功能，需要根据对应用户的流量是否超标做相应动作 */
	if (chas->is_inbytes_r_enabled) {
		if (get_query_inbytes_switch(chas->inbytes_list, con->client->response->username->str)) {
			// 如果用户请求因为流量超标，会向客户端返回对应的错误信息，并将用户的请求丢弃
			gint64 total_inbytes = get_query_inbytes_num_total(chas->inbytes_list, con->client->response->username->str);
			g_warning("[%s]: query '%s' from client %s@%s is droped because of too many querys in bytes.total in bytes is %ld.",
					G_STRLOC,
					con->sql_sentence->str,
					con->client->response->username->str,
					con->client->src->name->str,
					total_inbytes);
			mpe_send_error(con->client,
					MPE_PRX_PRCRQ_TOO_MANY_QUERY_IN_BYTES, total_inbytes);

			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_ERROR;
		} else {
			// 如果用户的流量没有超标，会放行用户的请求至后端，我们认为此时用户的流量可以算在正常的流量里面了
			query_inbytes_inc(
					chas->inbytes_list, con->client->response->username->str,
					(gint64)(con->sql_sentence->len + 4),
					con->type);
		}
	}

	/** 更新连接执行超时时间 */
	/** 如果超时限制规则启用，会查询相应的超时时间限制 */
	if (con->srv->dura_limit_on) {
		if (!process_sql_dura_rule(con)) {
			con->max_dura_time = (con->read_timeout.tv_sec * 1000000L + con->read_timeout.tv_usec);
			g_debug("[%s]:has not found dura limit rule for con->client:%d", G_STRLOC, con->client->fd);
		}
	}

	if(con->multiplex && con->tokens->len >0) {
		guint len = con->tokens->len;
		gchar *first_key = ((sql_token *)(con->tokens->pdata[0]))->text->str;

		if (0 == g_ascii_strcasecmp(first_key, "set")) {
			g_string_truncate(con->first_key, 0);
			g_string_truncate(con->last_key, 0);
			g_string_append(con->first_key, ((sql_token *)(con->tokens->pdata[0]))->text->str);
			g_string_append(con->last_key, ((sql_token *)(con->tokens->pdata[len-1]))->text->str);
		} else if (0 == g_ascii_strcasecmp(first_key, "prepare")) {
			g_string_truncate(con->first_key, 0);
			g_string_append(con->first_key, ((sql_token *)(con->tokens->pdata[0]))->text->str);
			if (len >= 2) {
				g_string_truncate(con->second_key, 0);
				g_string_append(con->second_key, ((sql_token *)(con->tokens->pdata[1]))->text->str);
			}
		} else if (0 == g_ascii_strcasecmp(first_key, "deallocate")) {
			g_string_truncate(con->first_key, 0);
			g_string_append(con->first_key, ((sql_token *)(con->tokens->pdata[0]))->text->str);
			if (len >= 2) {
				g_string_truncate(con->last_key, 0);
				g_string_append(con->last_key, ((sql_token *)(con->tokens->pdata[len-1]))->text->str);
			}
		} else if (0 == g_ascii_strcasecmp(first_key, "use")) {
			g_string_truncate(con->first_key, 0);
			g_string_append(con->first_key, ((sql_token *)(con->tokens->pdata[0]))->text->str);
			if (len >= 2) {
				g_string_truncate(con->last_key, 0);
				g_string_append(con->last_key, ((sql_token *)(con->tokens->pdata[len-1]))->text->str);
			}
		} else if (0 == g_ascii_strcasecmp(first_key, "drop")) {
			if (len > 2) {
				gchar *second_key = ((sql_token *)(con->tokens->pdata[1]))->text->str;
				if (0 == g_ascii_strcasecmp(second_key, "database") || 0 == g_ascii_strcasecmp(second_key, "schema")) {
					g_string_truncate(con->first_key, 0);
					g_string_append(con->first_key, ((sql_token *)(con->tokens->pdata[0]))->text->str);
					g_string_truncate(con->second_key, 0);
					g_string_append(con->second_key, ((sql_token *)(con->tokens->pdata[1]))->text->str);
					g_string_truncate(con->last_key, 0);
					g_string_append(con->last_key, ((sql_token *)(con->tokens->pdata[len-1]))->text->str);
				}
			}
		}
	}
    con->state = CON_STATE_GET_SERVER_LIST;
    return NETWORK_SOCKET_SUCCESS;
}


/**
 * 为在处理的client的请求分配一个合适的backend
 * @todo 在分配时需要对con变量中的cache server做同步处理
 *
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_get_server_list) {
	/* 该操作应该是在上述检测到cache server没有包括所有的需要的backend的连接？
	 *  应该不会出现这种情况，只要是需要连接保持的时候都是保有所有的连接，
	 *  即使是考虑分片的情况下，第一次发送的后端和接下来发送的后端也应该是相同的
	 * 不过虽然连接都保持了，但是不能确保不会出现保持的同一个session前后两条语句
	 * 需要发送到两个不同的backend的情况
	 *
	 * @note 简单起见，我们现在通过判断cache server  是否为空，来断定是否需要重新的分配backend
	 * 因为后续是通过不同的ip来区分请求时发向主库还是备库，因而需要为proxy的plugin增加一个
	 * 读写的属性。这里可以实现复杂的负载均衡算法，初步只是实现简单的模式。wip的请求，全部发往rw节点
	 * rip的请求，按权重发往某个后端节点可以是rw也可以是ro的。
	 * 这里还没有添加读写属性，只是考虑读的情况
	 */
	g_assert(con);
        
	network_socket * recv_sock = con->client;

    GList * chunk  __attribute__((unused)) = recv_sock->recv_queue->chunks->head;

    if (recv_sock->recv_queue->chunks->length != 1) {
    	g_warning("%s.%d: client-recv-queue-len = %d", __FILE__, __LINE__, recv_sock->recv_queue->chunks->length);
    }

    // reset the default server object,但是在不开启连接复用时，是没有必要的
    if (con->multiplex) {
    	g_assert(!con->server);
    }

    if (con->related_bk != NULL) {
    	free_gstring_ptr_array(con->related_bk);
    	//g_debug("related_bk length = %d", con->related_bk->len);
    	con->related_bk = NULL;
    }
	con->related_bk = g_ptr_array_new();

	//g_mutex_lock(&con->cache_server_mutex);
	//if (con->cache_server) {
	//	if(con->cache_server->event.ev_base)
	//		event_del(&(con->cache_server->event));
	//}
	//g_mutex_unlock(&con->cache_server_mutex);

	if (con->server) {

		g_assert(!con->multiplex);
		con->state = CON_STATE_GET_SERVER_CONNECTION_LIST;

	} else if (con->cache_server) {

		/* 如果缓存链接不为空，则将cache_server 上面的超时时间删除，将con的state设置为CON_STATE_GET_SERVER_CONNECTION_LIST
		 * 然后返回正确。
		 * @note 这个是否需要对cache server同步？因为可能随时收到超时时间，可以加时间变量减少这种情况的发生。可避免吗？
		 * 出于线程同步的考虑，将cache_server注册的超时事件放在前面，后续如果关闭连接的复用如何做？
		 */
		con->state = CON_STATE_GET_SERVER_CONNECTION_LIST;

	} else {
		/**
		 * 若是没有缓存连接可以使用，就根据一定的负载均衡策略指定
		 * 一个可用的backend。
		 *
		 * 这里调用loadbalance_lc_select或loadbalance_wrr_select选择一个后端
		 */
		GString *backend_name = NULL;
		backend_name = con->srv->lb_algo_func[con->type](con->srv, con->type);
		if (backend_name) {
			g_debug("load balancer selects backend (%s)%s", con->srv->lb_algo[con->type], backend_name->str);
			g_ptr_array_add(con->related_bk, backend_name);
		} else {
			g_debug("load balancer selects no backend available (%s)", con->srv->lb_algo[con->type]);
			return NETWORK_SOCKET_ERROR;
		}
	}
	
	return NETWORK_SOCKET_SUCCESS;

}


/**
 * @author sohu-inc
 * 实际从后端的backend中获取可用的连接，并将其对应的using连接数加1
 * @param[in] srv global chassis
 * @param[in] address backend的ip:port
 * @param[in] dbname 数据库名(没用？)
 * @param[in] username client 端用户名
 * @param[out] con 在处理的连接的地址
 * @param[in] type 读写类型
 * @return 是否成功
 */
//static network_socket *proxy_get_pooled_connection(chassis *srv, GString *address,
//		GString *dbname, GString *username, proxy_rw type, pool_connection_errno *pool_errno) {
static network_socket *proxy_get_pooled_connection(chassis *srv,
		const GString *address, const GString *username, proxy_rw type,
		pool_connection_errno *pool_errno) {
	network_backend_t * backend = NULL;
	user_pool_config user_pool_conf = { 0, 0, 0 };
	connection_scaler_pool_statistics pool_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	network_socket *server_sock = NULL;

	g_assert(srv);
	g_assert(address);
	g_assert(username);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);
	g_assert(srv->priv);
	g_assert(srv->priv->backends);

	backend = network_backends_get_by_name(srv->priv->backends, address->str);
	if (backend == NULL ) {
		g_critical("[%s]: unable to find the address in the backends %s",
				G_STRLOC, address->str);
		g_assert_not_reached()
		;
		return NULL ; // 难道backend被删除了？这个应该是不应该发生的
	}
	//g_debug("[%s]: address = %s, backend->addr = %s", G_STRLOC, address->str , backend->addr->name->str );

	get_pool_config_for_user_copy(srv, username, type, &user_pool_conf);
	network_connection_scaler_pool_statictics_init(&pool_stats);

//	server_sock = network_connection_pool_get(backend->pool[type], username, dbname);
	server_sock = network_connection_pool_get_new(srv, backend, type,
			backend->pool[type], username, &user_pool_conf, &pool_stats);
	if (NULL == server_sock) {
		if (pool_stats.conn_toomany > 0) {
			*pool_errno = POOL_CONNECTION_ERRNO_TOOMANY;
			g_debug("[%s]: too many connections in the pool %s", G_STRLOC,
					address->str);
		} else {
			if (pool_stats.conn_nopool > 0 || pool_stats.conn_zerosize > 0) {
				*pool_errno = POOL_CONNECTION_ERRNO_NOPOOL;
			} else {
				*pool_errno = POOL_CONNECTION_ERRNO_UNKNOWN;
			}
			/* no connections in the pool */
			g_debug("[%s]: unable to find a connection in the pool %s",
					G_STRLOC, address->str);
		}
	} else {
		*pool_errno = POOL_CONNECTION_ERRNO_SUCCESS;
		g_debug("[%s]: get fd %d from pool", G_STRLOC, server_sock->fd);
	}
	return server_sock;
}

/**
 * @author sohu-inc
 * 获取可用的连接，从server_hostnames中指定的backend的连接池中获取可用的连接
 * @param[IN] chassis *srv
 * @param[INOUT] network_mysqld_con *con
 * @param[IN] GPtrArray *server_hostnames
 * @param[IN] GString *UNUSED_PARAM(sql)
 */
static gboolean proxy_add_server_connection_array(chassis *srv,
		network_mysqld_con *con, const GPtrArray *server_hostnames,
		GString *UNUSED_PARAM(sql)) {
	GString *hostname;
	guint i = 0;

	if (server_hostnames == NULL ) {
		g_error(
				"Could not add server connections, please make sure the backend servers are properly configured.!");
		g_assert_not_reached()
		;
	}

	g_assert(con);
	g_assert(con->client);
	g_assert(con->client->response);

	for (i = 0; i < server_hostnames->len; i++) {
		hostname = (GString *) (server_hostnames->pdata[i]);
		// dbname 在获取连接的时候确实用不到,因而这里只是写个占位符？
		con->server = proxy_get_pooled_connection(srv, hostname,
				con->client->response->username, con->type,
				&(con->get_server_connection_errno));
		if ( con->server != NULL ) {
			return TRUE;
		}
	}
	return FALSE;
}

/** 判断语句是不是select row_count 或 found_rows */
static gboolean is_special_query(network_mysqld_con *con) {
	if (!con)
		return FALSE;
	gboolean ret = FALSE;
	GString *packet = con->client->recv_queue->chunks->head->data;
	if (packet->str[NET_HEADER_SIZE + 0] == COM_QUERY) {
		if (con->tokens && con->tokens->len >= 4) {
			if (0 == g_ascii_strcasecmp("select", ((sql_token *)(con->tokens->pdata[0]))->text->str) &&
					0 == g_ascii_strcasecmp("(", ((sql_token *)(con->tokens->pdata[2]))->text->str) &&
					( 0 == g_ascii_strcasecmp("row_count", ((sql_token *)(con->tokens->pdata[1]))->text->str) ||
							0 == g_ascii_strcasecmp("found_rows", ((sql_token *)(con->tokens->pdata[1]))->text->str))) {
				ret = TRUE;
			}
		}
	}
	return ret;
}

/**
 * 在分配的backend后端的连接池中取一个空闲的连接
 * 在指定的server中获取空闲的连接，若没有可用的连接返回错误
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_get_server_connection_list) {
	network_socket *recv_sock = con->client;
	GList *chunk = recv_sock->recv_queue->chunks->head;
	GString *packet = (GString *) (chunk->data);
	network_mysqld_con_t *st = con->plugin_con_state;
	/*
	 * 此时我们应该有两个选择，1.cache server 不为空时，直接实用cache server里面的连接
	 * 若cache server为空，则related_bk里面应该保存了提供服务的backend的ip:port
	 * 若为空则失败返回错误。
	 * need to lookup the databases to send the request to
	 */

//	_dump_injected_queries("injected", st->injected.queries);
//	_dump_injected_queries("pre_injected", st->pre_injected.queries);
//	_dump_injected_queries("post_injected", st->post_injected.queries);

	// 若cache server不为空，则将cache server赋值于con->server， 返回正常
	/**
	 * @note 在分配可用的连接之前，我们需要判断sql语句是否可以继续执行（并发sql限制来判断）
	 */
	if (con->srv->para_limit_on) {
		g_string_truncate(con->para_limit_user_db_key_used, 0);
		// sql并行限制是否启用
		if (NETWORK_SOCKET_SUCCESS != process_sql_para_rule(con)) {
			g_critical(
					"[%s]: Over the restrictions of concurrent execution,  will send error to client",
					G_STRLOC);
			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_ERROR;
		}
	}

	if (con->server != NULL) {
		if (con->multiplex == TRUE) {
			g_warning(
					"[%s]: this should not be happend only when no connection multiplex",
					G_STRLOC);
		}
		con->state = CON_STATE_SEND_QUERY;
		network_injection_queue_reset(st->pre_injected.queries);
		network_injection_queue_reset(st->post_injected.queries);
		return NETWORK_SOCKET_SUCCESS;
	}

	g_mutex_lock(&con->cache_server_mutex);
	if (con->cache_server) {
		con->server = con->cache_server;
		con->cache_server = NULL;
		con->state = CON_STATE_SEND_QUERY;
		network_injection_queue_reset(st->pre_injected.queries);
		network_injection_queue_reset(st->post_injected.queries);
		g_mutex_unlock(&con->cache_server_mutex);
		return NETWORK_SOCKET_SUCCESS;
	}
	g_mutex_unlock(&con->cache_server_mutex);

	// 判断第一个查询语句是不是 select row_count()\select found_rows()
	// 在连接分配之前先判断是不是第一条语句是不是特殊语句？
	if (is_special_query(con)) {
		g_critical("[%s]: first query of connection FD = %d is %s, that is not allowed!",
				G_STRLOC,
				con->client->fd,
				con->sql_sentence->str);


//		network_mysqld_con_send_error_full(con->client,
//				C("cache server timeout, "
//						"first query should not be select row_count() or select found_rows()!"),
//						3088,
//						"30080");
		mpe_send_error(con->client, MPE_PRX_GETCON_SPECIAL_QUERY);

		GString *query_packet = NULL;
		/** 将对应的连接里面的请求清空  */
		while ((query_packet = (GString *) g_queue_pop_head(
				recv_sock->recv_queue->chunks))) {
			g_string_free(query_packet, TRUE);
		}

		con->goto_next_state = TRUE;
		con->next_state = CON_STATE_READ_QUERY;

		con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
		return NETWORK_SOCKET_SUCCESS;
	}

	if (proxy_add_server_connection_array(con->srv, con, con->related_bk,
			packet) != TRUE) {
		g_warning("[%s]: we ran out of connections, try again later", G_STRLOC);
		// 没有获取到可用的连接我们会等待，一段时间再重试
		return NETWORK_SOCKET_WAIT_FOR_EVENT;	// try again after some time
	}

	//if (con->multiplex) {
	// 连接分配完成，需要将再使用的连接数加1，idle减1
	network_backend_t *bk_t = network_backends_get_by_name(
			con->srv->priv->backends, con->server->dst->name->str);
	g_assert(bk_t);
	g_assert(con->server->response);

	update_conn_pool_status_in_state(bk_t->pool[con->type],
			con->server->response->username->str,
			POOL_STATUS_STATE_GET_FROM_POOL);

	network_injection_queue_reset(st->pre_injected.queries);
	network_injection_queue_reset(st->post_injected.queries);

	/**
	 * 这里把if(con->srv->multiplex)注释掉了，解释如下
	 *
	 * 现象：proxy关闭了multiplex，客户端连接test数据库(mysql ... test)，执行select schema()发现返回空，当前默认数据库不对
	 * 分析：客户端在协议级设置的默认数据库是test；server端是从连接池取的，由后端异步连接创建，默认是空
	 *     + GDB跟踪结果也显示出 client->default_db=test，server->default_db=空
	 *     + 但因为multiplex=false，这里条件判断不满足，所以就没恢复上下文
	 * 解决：删除这个条件判断
	 */
//	if (con->srv->multiplex) {

	int inj_index = 0;
#define INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(NAME, ...) \
do { \
	injection *_inj = NULL; \
	_inj = network_mysqld_injection_new_##NAME ((inj_index), __VA_ARGS__); \
	if ( _inj != NULL ) { \
		g_queue_push_head( (st->pre_injected.queries), _inj ); \
		(inj_index)++; \
	} \
} while (0);

		// 判断client 与 server端连接的字符校验是否一致，不同需要将server端校验恢复成client端校验
		if ((con->client->collection_connect->len > 0)
				&& (0 == con->server->collection_connect->len ||
						0 != g_ascii_strcasecmp(con->server->collection_connect->str,
								con->client->collection_connect->str)
				)) {
			g_message(
					"[%s]:connect collation of client and server are not equal, "
					"going to amend connection collation of server: %s to client:%s",
					G_STRLOC, con->server->collection_connect->str,
					con->client->collection_connect->str);

			INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(collation_set,
					"collation_connection",
					con->client->collection_connect->str);
		}

		// 若client与server端连接的数据库不同，则需要将server端db恢复成client端db
		if ((con->client->default_db->len > 0)
				&& (0 == con->server->default_db->len
						|| 0
								!= g_ascii_strcasecmp(
										con->client->default_db->str,
										con->server->default_db->str))) {
			g_message(
					"[%s]:database names of client and server are not equal, going to amend db of server: %s to client:%s",
					G_STRLOC, con->server->default_db->str,
					con->client->default_db->str);

			INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(init_db, con->client->default_db);
		}

		// 判断autocommit 是否相等
		if (con->client->autocommit != con->server->autocommit) {
			g_message(
					"[%s]: autocommit of client and server are not equal, going to amend autocommit of server: %d to client: %d",
					G_STRLOC, con->server->autocommit, con->client->autocommit);

			INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(autocommit, con->client->autocommit);
		}

		/**
		 * 判断字符集是否对应
		 * 1. character_set_client
		 * 2. character_set_connection
		 * 3. character_set_results
		 */

		if ((con->client->character_set_client->len > 0)
				&& (0 == con->server->character_set_client->len
						|| 0
								!= g_ascii_strcasecmp(
										con->client->character_set_client->str,
										con->server->character_set_client->str))) {
			g_message(
					"[%s]: character_set_client of server: %s is not the same to client: %s",
					G_STRLOC, con->server->character_set_client->str,
					con->client->character_set_client->str);

			INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(character_set, "character_set_client", con->client->character_set_client->str);
		}

		if ((con->client->character_set_connection->len > 0)
				&& (0 == con->server->character_set_connection->len
						|| 0
								!= g_ascii_strcasecmp(
										con->client->character_set_connection->str,
										con->server->character_set_connection->str))) {
			g_message(
					"[%s]: character_set_connection of server: %s is not the same to client: %s",
					G_STRLOC, con->server->character_set_connection->str,
					con->client->character_set_connection->str);

			INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(character_set, "character_set_connection", con->client->character_set_connection->str);
		}

		if ((con->client->character_set_results->len > 0)
				&& (0 == con->server->character_set_results->len
						|| 0
								!= g_ascii_strcasecmp(
										con->client->character_set_results->str,
										con->server->character_set_results->str))) {
			g_message(
					"[%s]: character_set_results of server: %s is not the same to client: %s",
					G_STRLOC, con->server->character_set_results->str,
					con->client->character_set_results->str);

			INJECTION_NEW_PRE_QUEUE_PUSH_HEAD(character_set, "character_set_results", con->client->character_set_results->str);
		}
//	}
	return NETWORK_SOCKET_SUCCESS;
	/**
	 * 接下来需要在往mysql-server发送具体的查询语句之前恢复连接的上下文
	 * 包括dbname，charset等。
	 * @todo 这里需要增加代码实现连接上下文的恢复，1.需要实现一些特定的数据包的构造、发送
	 * 2.需要考虑注入的数据包对整个处理状态机的影响，特别是在从server端读取完结果、准备释放连接的阶段
	 * 3.需要上下文恢复失败的处理。
	 * 若连接是重新分配的话才需要恢复上下文，反之不需要。
	 */
	// 这里可以先将需要inject的数据包，构造好；接下来发送请求的阶段，检查inject数据包是否为空，
	// 一般新分配的连接才有可能注入数据包不为空。不为空则先发送上下文恢复数据包；反之发送正常数据包。
}

/**
 * @author sohu-inc.com
 * @note 这里我们实现将请求数据包写入到con->server的send_queue中，因为涉及到上下文的恢复
 * @note 所以没有直接将client端的请求写入到server的send_queue中，而是增加了一个plugin处理函数
 * 我们在向后端发送dbproxy的过程中，会判断并发执行的次数，应该放在发送真正的执行语句时吗？不好吧，毕竟都已经执行完了上下文回复语句！
 * 还是放在所有的语句发送之前，但是当有多条语句发送时，会导致重复记录，需要注意处理！
 * 还有可以放在get_server_connection_list中来处理？我们暂时放在get_server_connection_list之后处理。
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_query) {
	network_socket *recv_sock, *send_sock;
	network_mysqld_con_t *st;
	//GQueue *injection_queue __attribute__((unused)) = NULL;
	GQueue *pre_inject_queue = NULL;
	GQueue *post_inject_queue = NULL;
	GString *packet;

	g_assert(con);
	g_assert(con->client);
	g_assert(con->server);
	g_assert(con->plugin_con_state);

	recv_sock = con->client;
	send_sock = con->server;
	st = con->plugin_con_state;

	// 这里需要注意，若是有了上下文恢复的语句，packet_id该如何处理？
	// 还有就是有那种长的插叙，packet_id应该怎么办？
	/**
	 * @todo 这里数据包发送的顺序是应该是pre_injected/con->client_recv_queue/post_injected
	 * 当这三个里面的数据全部发送到后端标示数据包发送完成
	 * 但是pre_injected和post_injected里面的查询语句对应的结果不能发送给client
	 */
	send_sock->packet_id_is_reset = TRUE;
	pre_inject_queue = st->pre_injected.queries;
	post_inject_queue = st->post_injected.queries;

	// 这里我们首先是向server端发送pre_inject_queue里面的查询语句
	if (pre_inject_queue->length > 0) {
		g_debug("[%s]: sending Context Restore related SQL to MySQL server",
				G_STRLOC);
		// 上下文恢复的语句一次只能发送一条到后端,我们需要inject_queue里面是已将创建好的数据包
		// 包括真实的mysql数据和包头（即数据长度和packet_id，但是packet_id会重置！！！）
		packet = injection_queue_pop_head_injected_query(pre_inject_queue);
		send_sock->packet_id_is_reset = TRUE;
		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
				packet);
		g_string_truncate(con->sql_running, 0);
		g_string_append_len(con->sql_running, packet->str + NET_HEADER_SIZE + 1,
				packet->len - NET_HEADER_SIZE - 1);
		con->is_injection = 1;
		con->resultset_is_needed = TRUE;
		g_debug("[%s]:the transaction restore sql is :%s", G_STRLOC,
				con->sql_running->str);
	}
	/*
	 if (injection_queue) {
	 // 这里需要用injection_array 中的数据包对连接的上下文进行恢复
	 //if(injection_array->pdata) {
	 //	gpointer *inject_sql = injection_array->pdata[0];
	 //	g_ptr_array_remove (inject_sql);
	 //}
	 g_debug("[%s]: sending injecction packet to server for context recovery", G_STRLOC);
	 }

	 */	//接着发送client->recv_queue中的查询语句
	else if (recv_sock->recv_queue->chunks->length > 0) {
		g_debug("[%s]: sending query of client to MySQL server %s ", G_STRLOC,
				send_sock->dst->name->str);
		while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) {
			send_sock->packet_id_is_reset = TRUE;
			network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
					packet);
			g_string_truncate(con->sql_running, 0);
			g_string_append_len(con->sql_running,
					packet->str + NET_HEADER_SIZE + 1,
					packet->len - NET_HEADER_SIZE - 1);
		}

		con->is_injection = 0;
		con->resultset_is_needed = FALSE; /* 我们不需要保存请求返回的结果集 */
	} else if (post_inject_queue->length > 0) {
		g_debug("[%s]:sending transaction restore packet to server", G_STRLOC);
		packet = injection_queue_pop_head_injected_query(post_inject_queue);

		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
				packet);
		g_string_truncate(con->sql_running, 0);
		g_string_append_len(con->sql_running, packet->str + NET_HEADER_SIZE + 1,
				packet->len - NET_HEADER_SIZE - 1);
		con->is_injection = 1;
		con->resultset_is_needed = TRUE;
		g_debug("[%s]:the transaction restore sql is :%s", G_STRLOC,
				con->sql_running->str);
	} else {
		g_critical(
				"[%s] this can happen, when the chunk is too big. "
				"No query to send in recv_queue but send_queue, so con->state is CON_STATE_SEND_QUERY",
				G_STRLOC);
		//return NETWORK_SOCKET_ERROR;
	}
	return NETWORK_SOCKET_SUCCESS;
}

gint slow_query_log_print(slow_query_log_config_t *config, network_mysqld_con *con) {
	gint rc = -1;
	slow_query_log_entry_t *entry = NULL;

	g_assert(config);
	g_rw_lock_reader_lock ( &(config->rwlock) );
	do {
		if (config->is_enabled != TRUE) {
			g_debug("slow log is disabled");
			break;
		}
		if (config->log_file == NULL ) {
			g_debug("slow log is not open");
			break;
		}
		if (config->log_file->log_file_fd == -1 ) {
			g_debug("slow log fd is not open");
			break;
		}

		g_mutex_lock ( &(config->log_file->mlock) );

		entry = config->log_file->log_entry;
		entry->service_type = ( (con->type == PROXY_TYPE_WRITE) ? "rw" : "ro" );
		entry->service_address = (con->client!=NULL) ? (con->client->dst->name->str) : ("NULL");
		entry->backend_address = (con->server!=NULL) ? (con->server->dst->name->str) : ("NULL");
		entry->frontend_address = (con->client!=NULL) ? (con->client->src->name->str) : ("NULL");
		entry->start_time = con->start_timestamp;
		entry->finish_time = con->end_timestamp;
		entry->execute_time = con->execute_time_us;
		//entry->thread_id = con->connection_id;
		entry->thread_id = (con->server!=NULL) ? (con->server->challenge->thread_id) : (0);
		entry->database_account = (con->client!=NULL) ? (con->client->response->username->str) : ("NULL");
		entry->database_schema = (con->client!=NULL) ? (con->client->default_db->str) : ("NULL");
		entry->command_type = con->parse.command;
		if(con->parse.data != NULL)
		{
		entry->result_set_rows = ((network_mysqld_com_query_result_t *)(con->parse.data))->rows;
		entry->result_set_bytes = ((network_mysqld_com_query_result_t *)(con->parse.data))->bytes;
		}
		else
		{
			entry->result_set_rows = 0;
			entry->result_set_bytes = 0;
		}

		/*是否符合慢查询过滤条件*/
		if (config->filter != NULL
				&& entry->execute_time < config->filter->time_threshold_us) {
			g_mutex_unlock ( &(config->log_file->mlock) );
			g_debug("slow log filter not match");
			break;
		}

		g_debug("write slow log");
		/*记日志*/

		get_normalized_sql(con->sql_sentence->str, con->tokens, con->normalized_sql[NORMALIZE_FOR_TEMPLATE], NORMALIZE_FOR_TEMPLATE);
		entry->command_text = con->normalized_sql[NORMALIZE_FOR_TEMPLATE]->str;
		get_normalized_sql(con->sql_sentence->str, con->tokens, con->normalized_sql[NORMALIZE_FOR_SINGLE], NORMALIZE_FOR_SINGLE);
		entry->command_full_text = con->normalized_sql[NORMALIZE_FOR_SINGLE]->str;
		time_us_to_str(entry->start_time, entry->start_time_str);
		time_us_to_str(entry->finish_time, entry->finish_time_str);

#define nvl(s,t)    ( (s != NULL) ? ( (*s != '\0') ? (s) : (t) ) : (t) )
		slow_query_log_update_timestamp(config->log_file);
		g_string_append_printf(config->log_file->log_ts_str,
				"\t%s\t%s\t%s\t%s" "\t%s\t%ld\t%s\t%ld\t%ld" "\t%u" "\t%s\t%s" "\t%ld\t%ld" "\t%d\t%s\t%s",
				nvl(entry->service_type, "NULL"),
				nvl(entry->service_address, "NULL"),
				nvl(entry->frontend_address, "NULL"),
				nvl(entry->backend_address, "NULL"),
				entry->start_time_str->str, entry->start_time,
				entry->finish_time_str->str, entry->finish_time,
				entry->execute_time, entry->thread_id,
				nvl(entry->database_account, "NULL"),
				nvl(entry->database_schema, "NULL"),
				entry->result_set_rows, entry->result_set_bytes,
				entry->command_type,
				nvl(entry->command_text, "NULL"),
				nvl(entry->command_full_text, "NULL")
				);
		rc = slow_query_log_file_write(config->log_file, config->log_file->log_ts_str);

		g_mutex_unlock ( &(config->log_file->mlock) );

	} while (0);
	g_rw_lock_reader_unlock ( &(config->rwlock) );

	return rc;
}

/**
 * decide about the next state after the result-set has been written 
 * to the client
 * 
 * if we still have data in the queue, back to proxy_send_query()
 * otherwise back to proxy_read_query() to pick up a new client query
 *
 * @note we should only send one result back to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_query_result) {
	network_socket *recv_sock, *send_sock;
	injection *inj;
	network_mysqld_con_t *st = con->plugin_con_state;

	send_sock = con->server;
	recv_sock = con->client;

	if (st->connection_close) {
		con->state = CON_STATE_ERROR;

		return NETWORK_SOCKET_SUCCESS;
	}

	if (con->parse.command == COM_BINLOG_DUMP) {
		/**
		 * the binlog dump is different as it doesn't have END packet
		 *
		 * @todo in 5.0.x a NON_BLOCKING option as added which sends a EOF
		 */
		con->state = CON_STATE_READ_QUERY_RESULT;

		return NETWORK_SOCKET_SUCCESS;
	}

	/* if we don't have a backend, don't try to forward queries
	 */
	if (!send_sock) {
		network_injection_queue_reset(st->injected.queries);
	}

	/**
	 * 接下来我们判断是否还需要向server端发送查询请求
	 * 为了较好的兼容mysql-proxy原先的代码，保持了mysql-proxy中对st->injected.queries的判断
	 * 判断的次序依次为：
	 * 1. st->injected.queries
	 * 2. st->pre_injected
	 * 3. con->client->recv_queue
	 * 4. st->post_injected
	 */
	if (st->injected.queries->length != 0) {
		/* looks like we still have queries in the queue,
		 * push the next one
		 */
		inj = g_queue_peek_head(st->injected.queries);
		con->resultset_is_needed = inj->resultset_is_needed;

		if (!inj->resultset_is_needed && st->injected.sent_resultset > 0) {
			/* we already sent a resultset to the client and the next query wants to forward it's result-set too, that can't work */
			g_critical(
					"%s: proxy.queries:append() in %s can only have one injected query without { resultset_is_needed = true } set. We close the client connection now.",
					G_STRLOC, "NULL"/*con->config->lua_script*/);
			return NETWORK_SOCKET_ERROR;
		}
		g_assert(inj);
		g_assert(send_sock);

		network_mysqld_queue_reset(send_sock);
		network_mysqld_queue_append(send_sock, send_sock->send_queue,
				S(inj->query));

		network_mysqld_con_reset_command_response_state(con);

		con->state = CON_STATE_SEND_QUERY;

	} else if (st->pre_injected.queries->length > 0) {
		g_message(
				"[%s]: there are more pre inject query to send, next state will be setted to be CON_STATE_SEND_QUERY",
				G_STRLOC);
		con->state = CON_STATE_SEND_QUERY;
	} else if (recv_sock->recv_queue->chunks->length > 0) {
		g_debug(
				"[%s]: there are more client query to send, next state will be setted to be CON_STATE_SEND_QUERY",
				G_STRLOC);
		con->state = CON_STATE_SEND_QUERY;
	} else if (st->post_injected.queries->length > 0) {
		g_debug(
				"[%s]:there are more post inject query to send, next state will be setted to be CON_STATE_SEND_QUERY",
				G_STRLOC);
		con->state = CON_STATE_SEND_QUERY;
	} else {
		if (con->client)
			network_mysqld_queue_reset(con->client);
		if (con->server)
			network_mysqld_queue_reset(con->server);

		/** 已经向client 端返回了所有的查询结果， 需要将并行统计信息更新（相应的某条的或某类的语句的执行条数减1） */
		gint index = NORMALIZE_FOR_SINGLE;
		for (index = NORMALIZE_FOR_SINGLE; index <= NORMALIZE_FOR_TEMPLATE; index++) {
			if (con->para_limit_used[index]) {
				// 如果前面匹配到了对应的规则，才回去更新统计值
				dec_para_statistic_info(
						con->srv->para_running_statistic_dic,
						con->para_limit_user_db_key_used->str,
						con->normalized_sql[index]->str,
						index);
			}
		}

		con->execute_time_us = chassis_calc_rel_microseconds(con->start_timestamp, con->end_timestamp);

		/**
		 * 开启了sql直方图统计功能，
		 * @note 只有在所有的语句执行结束之后才会将执行语句的执行信息更新到直方图中，避免了时间的多次累加。
		 *       现在计算的时间是读查询语句的第一个包，到向client发送了所有的结果集
		 */
		if (con->srv->is_sql_statistics && con->need_record) {
			gboolean is_under_limit = con->srv->tmi->sql_staitistics_record_count <= con->srv->sql_staitistics_record_limit;
			// 计算以s为单位的sql运行时间
			//guint64 running_time_us = chassis_calc_rel_microseconds(con->start_timestamp, con->end_timestamp);
			gdouble running_time_s = (gdouble) con->execute_time_us / 1000000L;
			// 找到sql运行时间对应的section
			int index = get_section_index_by_running_time(con->srv->tmi->base, running_time_s);
			// 拼接user_db字符串作为key
			GString *user_db_name = g_string_new(con->client->response->username->str);
			g_string_append(user_db_name, "&dprxy;");
			g_string_append(user_db_name, con->client->default_db->str);
			// 标准化sql
			get_normalized_sql(con->sql_sentence->str, con->tokens, con->normalized_sql[NORMALIZE_FOR_TEMPLATE], NORMALIZE_FOR_TEMPLATE);
			// 插入最终的hash_table
			insert_info_to_user_db_sql_info(con->srv->tmi->time_section_statistics_array->pdata[index], user_db_name->str,
											con->normalized_sql[NORMALIZE_FOR_TEMPLATE]->str, running_time_s, is_under_limit);
			((time_section_statistics *)con->srv->tmi->time_section_statistics_array->pdata[index])->total_count += 1;
			((time_section_statistics *)con->srv->tmi->time_section_statistics_array->pdata[index])->total_time += running_time_s;
			g_string_free(user_db_name, TRUE);
		}

		g_debug("slow_query_log_print");
		slow_query_log_print(con->srv->slow_query_log_config, con);

		if (con->multiplex) {
			g_debug("[%s]:connection multiplex enable, caching server",
					G_STRLOC);
			cache_server_connection(con->srv, con);
		}

		con->need_record = TRUE;
		con->state = CON_STATE_READ_QUERY;
	}
	
	return NETWORK_SOCKET_SUCCESS;
}

/**
 * @author sohu-inc.com
 * 从ok数据包中获取到server status
 */

static int network_mysqld_proto_decode_ok_packet(GString *s, guint64 *UNUSED_PARAM(affected), guint64 *UNUSED_PARAM(insert_id), int *UNUSED_PARAM(server_status), int *UNUSED_PARAM(warning_count), char **msg) __attribute__((unused));
static int network_mysqld_proto_decode_ok_packet(GString *s, guint64 *UNUSED_PARAM(affected), guint64 *UNUSED_PARAM(insert_id), int *UNUSED_PARAM(server_status), int *UNUSED_PARAM(warning_count), char **msg) {
        guint off = 0;                                  
        //guint64 dest __attribute__((unused));
        g_assert(s->str[0] == 0);                       
                                                        
        off++;                                          

        //dest = network_mysqld_proto_decode_lenenc(s, &off); if (affected) *affected = dest;
        //dest = network_mysqld_proto_decode_lenenc(s, &off); if (insert_id) *insert_id = dest;

        //dest = network_mysqld_proto_get_int16(s, &off);     if (server_status) *server_status = dest;
        //dest = network_mysqld_proto_get_int16(s, &off);     if (warning_count) *warning_count = dest;
                                                                                
        if (msg) *msg = NULL;
                                                        
        return 0;                                       
}



/**
 * handle the query-result we received from the server
 *
 * - decode the result-set to track if we are finished already
 * - handles BUG#25371 if requested
 * - if the packet is finished, calls the network_mysqld_con_handle_proxy_resultset
 *   to handle the resultset in the lua-scripts
 *
 * @see network_mysqld_con_handle_proxy_resultset
 */
/**
 * 从后端读取server端返回结果，根据如下条件，做出下一步状态的赋予
 * 1. 在查询语句是上下文恢复语句的情况下，
 *	返回成功，将状态设置为send_query，
 *	返回失败，将状态设置为state_error,
 *   以上两种情况都需要清空server端的recv_queue
 * 2. 查询语句是普通的查询语句的情况下，只需要按照mysql-proxy现有的做法进行
 *    不过需要根据返回结果的server status 确定连接的缓存状态
 */
/**
 * @note 在读取结果集的时候我们需要判定现在时间与开始时间之差是否超过了设定的
 * 		 超时限制时间，若是则需要将server端连接kill掉，并且将client端的返回结果清空！！
 * 		 这个地方一定要：注意client端数据的清空避免内存泄露！！
 * @param proxy_read_query_result
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query_result) {
	int is_finished = 0;
	int transaction_flag = 0;
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_con_t *st = con->plugin_con_state;
	injection *inj = NULL;

	GString *result_packet = NULL;
	GString *query_packet = NULL;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter");

	recv_sock = con->server;
	send_sock = con->client;

	/* check if the last packet is valid */
	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	if (0 != st->injected.queries->length) {
		inj = g_queue_peek_head(st->injected.queries);
	}

	if (inj && inj->ts_read_query_result_first == 0) {
		/**
		 * log the time of the first received packet
		 */
		inj->ts_read_query_result_first = chassis_get_rel_microseconds();
		/* g_get_current_time(&(inj->ts_read_query_result_first)); */
	}

	is_finished = network_mysqld_proto_get_query_result(&packet, con);
	if (is_finished == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

	if (con->multiplex) {
		// 开始通过结果集判断连接是否在事务中
		packet.offset = 0;
		transaction_flag = network_mysqld_proto_get_trans_flag(&packet, con);
		if (transaction_flag == -1) {
			g_critical("[%s]:get transaction flag error", G_STRLOC);
			return NETWORK_SOCKET_ERROR;
		} else if(transaction_flag == 2) {
			g_debug("[%s]: connection transaction flag keeps in: %s", G_STRLOC, con->tx_flag?"YES":"NO");
		} else {
			g_debug("[%s]:connection is in transaction? %s",G_STRLOC, transaction_flag?"YES":"NO");
			con->tx_flag = transaction_flag;
		}
	}

	/** 若超时限制启用，则将判断结果读取时间是否超时 */
	if (con->srv->dura_limit_on && con->max_dura_time > 0) {
		guint64 now_in_usec = chassis_get_rel_microseconds();
		if ((now_in_usec - con->start_timestamp) > con->max_dura_time) {
			g_warning("[%s]:sql has run for %ld us longger than the max exec time %ld",
					G_STRLOC,
					now_in_usec - con->start_timestamp,
					con->max_dura_time);
			/**
			 * 接下来需要将返回结果清空,
			 * 同时需要将执行语句清空,
			 * server端连接kill掉,
			 * 同时向client端返回明确的错误信息
			 * 2013-12-10： 返回结果出错的情况下，需要将后端backend 对应的连接数减1
			 */
			/** 1.清空返回结果 */
			result_packet = NULL;
			while (NULL != (result_packet = g_queue_pop_tail(recv_sock->recv_queue->chunks))) {
				g_string_free(result_packet, TRUE);
				result_packet = NULL;
			}

			/** 2.清空执行语句 */
			// pre_injection
			network_injection_queue_reset(st->pre_injected.queries);
			// query queue
			query_packet = NULL;
			while (NULL != (query_packet = g_queue_pop_tail(send_sock->recv_queue->chunks))) {
				g_string_free(query_packet, TRUE);
				query_packet = NULL;
			}
			// post queue
			network_injection_queue_reset(st->post_injected.queries);

			// 清空 prepare的上下文
			clean_prepare_context(con);

			/** 3.kill server端连接 */
			network_backend_t * bk_end = network_backends_get_by_name(
					con->srv->priv->backends,
					con->server->dst->name->str);
			// 将client backend 对应的连接数减 1
			client_desc(bk_end, con->type);

			update_conn_pool_status_in_state(bk_end->pool[con->type],
					con->server->response->username->str,
					POOL_STATUS_STATE_DISCONNECTED);
			kill_network_con(con->server);
			con->server = NULL;
		
		    con->client->last_packet_id = 0;
		    con->client->packet_id_is_reset = FALSE;
		
			/** 4.向client返回明确错误信息 */
			mpe_send_error(send_sock, MPE_PRX_PRCRQ_SQL_EXECUTE_TOO_LONG, con->sql_sentence->str,
					now_in_usec - con->start_timestamp,
					con->max_dura_time);

			/** 设置con->state 为 */
			con->goto_next_state = TRUE;
			con->next_state = CON_STATE_READ_QUERY;

			con->state = CON_STATE_SEND_ERROR_TO_CLIENT;
			return NETWORK_SOCKET_SUCCESS;
		}
	}
	/**
	 * @todo 这里我们需要判断，结果是否为上下文恢复的语句的结果。
	 *	1. 若是需要判断是否执行正确，是否正确执行如何判断呢？
	 *
	 *  2. 反之，向客户端返回结果。
	 *  @todo 需要能够区分好是注入的语句执行错误还是用户语句执行错误！！！
	 */
	if (con->is_injection) {
		if (!con->inj_execute_correctly) {
			g_critical("[%s]:context injection: %s executed error", G_STRLOC, con->sql_running->str);
			/** @todo 对错误信息进行规整 */
//			char buffer[1024];
//			snprintf(buffer, 1024, "DBProxy context recovery error on sql:%s", con->sql_running->str);
//			network_mysqld_con_send_error_full(send_sock, buffer, strlen(buffer), 3089, "28000");
			mpe_send_error(send_sock, MPE_PRX_RQRESULT_CONTEXT_RESTORE_FAILED, con->sql_running->str);

			/** 清空上下文恢复语句，接收到的结果及真正的sql语句  */
			// pre_injection
			network_injection_queue_reset(st->pre_injected.queries);
			// query queue
			query_packet = NULL;
			while (NULL != (query_packet = g_queue_pop_tail(send_sock->recv_queue->chunks))) {
				g_string_free(query_packet, TRUE);
				query_packet = NULL;
			}
			// post queue
			network_injection_queue_reset(st->post_injected.queries);

			if (con->server->event.ev_base) {
				g_critical("%s: why con->server still has event_base, Will delete it!", G_STRLOC);
				event_del(&con->server->event);
			}
			// 将server端连接返回到连接池中
			network_mysqld_pool_con_add_soket(con, con->server); // 里面已经有了将backend 对应的连接数减1
			con->server = NULL;

			// 清空 prepare的上下文
			clean_prepare_context(con);

			con->state = CON_STATE_SEND_QUERY_RESULT;
			return NETWORK_SOCKET_SUCCESS;
		}
	}

	con->resultset_is_finished = is_finished;

	// 接下来若结果需要直接发送给客户端，则将结果添加到client的send_queue中
	/* copy the packet over to the send-queue if we don't need it */
	if (!con->resultset_is_needed) {
		GString * result_data = g_queue_pop_tail(recv_sock->recv_queue->chunks);;
		// 当开启输入流量统计的功能时，会在这里将输入流量更新
		if (con->srv->is_outbytes_r_enabled) {
			query_outbytes_inc(con->srv->outbytes_list,
					con->client->response->username->str,
					(gint64)result_data->len,
					con->type);
		}
		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, result_data);
	} else {
		// 若不需要将接收到的返回结果清空！！
		result_packet = NULL;
		while (NULL != (result_packet = g_queue_pop_tail(recv_sock->recv_queue->chunks))) {
			g_string_free(result_packet, TRUE);
			result_packet = NULL;
		}
	}

	if (is_finished) {
		network_mysqld_stmt_ret ret;

		/**
		 * the resultset handler might decide to trash the send-queue
		 * 
		 **/

		if (inj) {
			if (con->parse.command == COM_QUERY || con->parse.command == COM_STMT_EXECUTE) {
				network_mysqld_com_query_result_t *com_query = con->parse.data;

				inj->bytes = com_query->bytes;
				inj->rows  = com_query->rows;
				inj->qstat.was_resultset = com_query->was_resultset;
				inj->qstat.binary_encoded = com_query->binary_encoded;

				/* INSERTs have a affected_rows */
				if (!com_query->was_resultset) {
					inj->qstat.affected_rows = com_query->affected_rows;
					inj->qstat.insert_id     = com_query->insert_id;
				}
				inj->qstat.server_status = com_query->server_status;
				inj->qstat.warning_count = com_query->warning_count;
				inj->qstat.query_status  = com_query->query_status;
			}
			inj->ts_read_query_result_last = chassis_get_rel_microseconds();
			/* g_get_current_time(&(inj->ts_read_query_result_last)); */
		}
		
		network_mysqld_queue_reset(recv_sock); /* reset the packet-id checks as the server-side is finished */

		NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter_lua");
		ret = proxy_t_read_query_result(con);
		NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::leave_lua");

		if (PROXY_IGNORE_RESULT != ret) {
			/* reset the packet-id checks, if we sent something to the client */
			network_mysqld_queue_reset(send_sock);
		}

		/**
		 * if the send-queue is empty, we have nothing to send
		 * and can read the next query */
		//这里需要进行修改，如果返回结果是上下文恢复语句的结果。则将状态设置为send_query
		// 反之按照下面的方式进行，但是切记需要根据连接的状态，按照具体情况归还连接至连接池中。
		if (send_sock->send_queue->chunks->length > 0) {
			/**
			 * 如果有结果需要返回则将结果返回给client端
			 */
			con->state = CON_STATE_SEND_QUERY_RESULT;
		} else {
			/**
			 * 若不需要返回结果至client端，
			 * 需要判断query是否全部发送到了server端，
			 * 若仍然有query, 则返回至send_query阶段；
			 * 若没有query，则将连接缓存起来，接着读后面的查询语句
			 */
			g_assert_cmpint(con->resultset_is_needed, ==, 1);
			if (st->pre_injected.queries->length > 0) {
				g_message("[%s]: there are more pre inject query to send, next state will be setted to be CON_STATE_SEND_QUERY", G_STRLOC);
				con->state = CON_STATE_SEND_QUERY;
			} else if(send_sock->recv_queue->chunks->length > 0) {
				g_debug("[%s]: there are more client query to send, next state will be setted to be CON_STATE_SEND_QUERY", G_STRLOC);
				con->state = CON_STATE_SEND_QUERY;
			} else if (st->post_injected.queries->length > 0) {
				g_debug("[%s]:there are more post inject query to send, next state will be setted to be CON_STATE_SEND_QUERY", G_STRLOC);
				con->state = CON_STATE_SEND_QUERY;
			} else {
				if(con->client)
					network_mysqld_queue_reset(con->client);
				if(con->server)
					network_mysqld_queue_reset(con->server);
				if (con->multiplex) {
					g_debug("[%s]:connection multiplex enable, caching server", G_STRLOC);
					cache_server_connection(con->srv, con);
				}
				con->state = CON_STATE_READ_QUERY;
			}
			//g_assert_cmpint(con->resultset_is_needed, ==, 1); /* we already forwarded the resultset, no way someone has flushed the resultset-queue */
			//cache_server_connection(con->srv, con);
			//con->state = CON_STATE_READ_QUERY;
		}
	}
	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::leave");
	
	return NETWORK_SOCKET_SUCCESS;
}

#if 0
static network_mysqld_lua_stmt_ret proxy_lua_connect_server(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	lua_State *L;

	/**
	 * if loading the script fails return a new error 
	 */
	switch (network_mysqld_con_lua_register_callback(con, con->config->lua_script)) {
	case REGISTER_CALLBACK_SUCCESS:
		break;
	case REGISTER_CALLBACK_LOAD_FAILED:
		/* send packet-id 0 */
		network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to load. Check the error log."));
		return PROXY_SEND_RESULT;
	case REGISTER_CALLBACK_EXECUTE_FAILED:
		/* send packet-id 0 */
		network_mysqld_con_send_error(con->client, C("MySQL Proxy Lua script failed to execute. Check the error log."));
		return PROXY_SEND_RESULT;
	}

	if (!st->L) return PROXY_NO_DECISION;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("connect_server"));
	if (lua_isfunction(L, -1)) {
		if (lua_pcall(L, 0, 1, 0) != 0) {
			g_critical("%s: (connect_server) %s", 
					G_STRLOC,
					lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}

		switch (ret) {
		case PROXY_NO_DECISION:
		case PROXY_IGNORE_RESULT:
			break;
		case PROXY_SEND_RESULT:
			/* answer directly */

			if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
				/**
				 * handling proxy.response failed
				 *
				 * send a ERR packet
				 */
		
				/* send packet-id 0 */
				network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
			} else {
				network_queue *q;
				network_packet packet;
				int err = 0;
				guint8 packet_type;

				/* we should have a auth-packet or a err-packet in the queue */
				q = con->client->send_queue;

				packet.data = g_queue_peek_head(q->chunks);
				packet.offset = 0;

				err = err || network_mysqld_proto_skip_network_header(&packet);
				err = err || network_mysqld_proto_peek_int8(&packet, &packet_type);
				if (!err && packet_type == 0x0a) {
					network_mysqld_auth_challenge *challenge;

					challenge = network_mysqld_auth_challenge_new();

					err = err || network_mysqld_proto_get_auth_challenge(&packet, challenge);

					if (!err) {
						g_assert(con->client->challenge == NULL); /* make sure we don't leak memory */
						con->client->challenge = challenge;
					} else {
						network_mysqld_auth_challenge_free(challenge);
					}
				}
			}

			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}

#endif

/**
 * connect to a backend
 *
 * @return
 *   NETWORK_SOCKET_SUCCESS        - connected successfully
 *   NETWORK_SOCKET_ERROR_RETRY    - connecting backend failed, call again to connect to another backend
 *   NETWORK_SOCKET_ERROR          - no backends available, adds a ERR packet to the client queue
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_connect_server) {
#if 0
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	chassis_private *g = con->srv->priv;
	guint min_connected_clients = G_MAXUINT;
	guint i;
	gboolean use_pooled_connection = FALSE;
	network_backend_t *cur;

	if (con->server) {
		switch (network_socket_connect_finish(con->server)) {
		case NETWORK_SOCKET_SUCCESS:
			break;
		case NETWORK_SOCKET_ERROR:
		case NETWORK_SOCKET_ERROR_RETRY:
			g_message("%s.%d: connect(%s) failed: %s. Retrying with different backend.", 
					__FILE__, __LINE__,
					con->server->dst->name->str, g_strerror(errno));

			/* mark the backend as being DOWN and retry with a different one */
			st->backend->state = BACKEND_STATE_DOWN;
			chassis_gtime_testset_now(&st->backend->state_since, NULL);
			network_socket_free(con->server);
			con->server = NULL;

			return NETWORK_SOCKET_ERROR_RETRY;
		default:
			g_assert_not_reached();
			break;
		}

		if (st->backend->state != BACKEND_STATE_UP) {
			st->backend->state = BACKEND_STATE_UP;
			chassis_gtime_testset_now(&st->backend->state_since, NULL);
		}

		con->state = CON_STATE_READ_HANDSHAKE;

		return NETWORK_SOCKET_SUCCESS;
	}

	st->backend = NULL;
	st->backend_ndx = -1;

	network_backends_check(g->backends);

	switch (proxy_lua_connect_server(con)) {
	case PROXY_SEND_RESULT:
		/* we answered directly ... like denial ...
		 *
		 * for sure we have something in the send-queue 
		 *
		 */
		
		return NETWORK_SOCKET_SUCCESS;
	case PROXY_NO_DECISION:
		/* just go on */

		break;
	case PROXY_IGNORE_RESULT:
		use_pooled_connection = TRUE;

		break;
	default:
		g_error("%s.%d: ... ", __FILE__, __LINE__);
		break;
	}

	/* protect the typecast below */
	g_assert_cmpint(g->backends->backends->len, <, G_MAXINT);

	/**
	 * if the current backend is down, ignore it 
	 */
	cur = network_backends_get(g->backends, st->backend_ndx);

	if (cur) {
		if (cur->state == BACKEND_STATE_DOWN) {
			st->backend_ndx = -1;
		}
	}

	if (con->server && !use_pooled_connection) {
		gint bndx = st->backend_ndx;
		/* we already have a connection assigned, 
		 * but the script said we don't want to use it
		 */

		network_connection_pool_lua_add_connection(con);

		st->backend_ndx = bndx;
	}

	if (st->backend_ndx < 0) {
		/**
		 * we can choose between different back addresses 
		 *
		 * prefer SQF (shorted queue first) to load all backends equally
		 */ 

		for (i = 0; i < network_backends_count(g->backends); i++) {
			cur = network_backends_get(g->backends, i);
	
			/**
			 * skip backends which are down or not writable
			 */	
			if (cur->state == BACKEND_STATE_DOWN ||
			    cur->type != BACKEND_TYPE_RW) continue;
	
			if (cur->connected_clients[con->type] < min_connected_clients) {
				st->backend_ndx = i;
				min_connected_clients = cur->connected_clients[con->type];
			}
		}

		if ((cur = network_backends_get(g->backends, st->backend_ndx))) {
			st->backend = cur;
		}
	} else if (NULL == st->backend) {
		if ((cur = network_backends_get(g->backends, st->backend_ndx))) {
			st->backend = cur;
		}
	}

	if (NULL == st->backend) {
		network_mysqld_con_send_error_pre41(con->client, C("(proxy) all backends are down"));
		g_critical("%s.%d: Cannot connect, all backends are down.", __FILE__, __LINE__);
		return NETWORK_SOCKET_ERROR;
	}

	/**
	 * check if we have a connection in the pool for this backend
	 */
	if (NULL == con->server) {
		con->server = network_socket_new();
		network_address_copy(con->server->dst, st->backend->addr);
	
		st->backend->connected_clients[con->type]++;

		switch(network_socket_connect(con->server)) {
		case NETWORK_SOCKET_ERROR_RETRY:
			/* the socket is non-blocking already, 
			 * call getsockopt() to see if we are done */
			return NETWORK_SOCKET_ERROR_RETRY;
		case NETWORK_SOCKET_SUCCESS:
			break;
		default:
			g_message("%s.%d: connecting to backend (%s) failed, marking it as down for ...", 
					__FILE__, __LINE__, con->server->dst->name->str);

			st->backend->state = BACKEND_STATE_DOWN;
			chassis_gtime_testset_now(&st->backend->state_since, NULL);

			network_socket_free(con->server);
			con->server = NULL;

			return NETWORK_SOCKET_ERROR_RETRY;
		}

		if (st->backend->state != BACKEND_STATE_UP) {
			st->backend->state = BACKEND_STATE_UP;
			chassis_gtime_testset_now(&st->backend->state_since, NULL);
		}

		con->state = CON_STATE_READ_HANDSHAKE;
	} else {
		GString *auth_packet;

		/**
		 * send the old hand-shake packet
		 */

		auth_packet = g_string_new(NULL);
		network_mysqld_proto_append_auth_challenge(auth_packet, con->server->challenge);

		network_mysqld_queue_append(
				con->client,
				con->client->send_queue, 
				S(auth_packet));

		g_string_free(auth_packet, TRUE);

		g_assert(con->client->challenge == NULL);
		con->client->challenge = network_mysqld_auth_challenge_copy(con->server->challenge);

		con->state = CON_STATE_SEND_HANDSHAKE;

		/**
		 * connect_clients is already incremented 
		 */
	}
#endif
	return NETWORK_SOCKET_SUCCESS;
}

/**
 * convert a double into a timeval
 */
static gboolean
timeval_from_double(struct timeval *dst, double t) __attribute__((unused));
static gboolean
timeval_from_double(struct timeval *dst, double t) {
	g_return_val_if_fail(dst != NULL, FALSE);
	g_return_val_if_fail(t >= 0, FALSE);

	dst->tv_sec = floor(t);
	dst->tv_usec = floor((t - dst->tv_sec) * 1000000);

	return TRUE;
}

/**
 * modified by jinxuan hou, 2013/04/09
 * here we should generate a handshake packet
 * and then modify the con->state to send_handshake
 *
 * @@jinxuanhou
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_init) {
        network_mysqld_auth_challenge *challenge;
        GString *packet;

        challenge = network_mysqld_auth_challenge_new();
        if (PROXY_TYPE_WRITE == con->type) {
        	challenge->server_version_str = g_strdup("5.1.00-dbproxy-RW-proxy-port");
        } else {
        	challenge->server_version_str = g_strdup("5.1.00-dbproxy-RO-proxy-port");
        }

        challenge->server_version     = 50100;
        // added by jinxuan hou
        // firstly we assume that the charset of server is latin1
        // later we should use a charset same to server
        // to be added!

        challenge->charset            = con->srv->collation_index; /* latin1 */
        /** handshake 数据包里面的字符集影响到con->client->character_set_connection */
        const gchar *charset = charset_dic[challenge->charset];

		if (0 != g_ascii_strcasecmp(con->client->character_set_connection->str, charset)) {
			g_string_truncate(con->client->character_set_connection, 0);
			g_string_append(con->client->character_set_connection, charset);
		}

		/** results_set 的字符集默认和connection的字符集相同*/
		if (0 != g_ascii_strcasecmp(con->client->character_set_results->str, charset)) {
			g_string_truncate(con->client->character_set_results, 0);
			g_string_append(con->client->character_set_results, charset);
		}

        challenge->capabilities       = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD|CLIENT_CONNECT_WITH_DB;
        challenge->server_status      = SERVER_STATUS_AUTOCOMMIT;
        challenge->thread_id          = con->connection_id;
        challenge->capabilities &= ~CLIENT_MULTI_STATEMENTS;
        challenge->capabilities = challenge->capabilities | CLIENT_LONG_FLAG | CLIENT_INTERACTIVE | CLIENT_FOUND_ROWS | CLIENT_TRANSACTIONS | CLIENT_IGNORE_SPACE ;
        network_mysqld_auth_challenge_set_challenge(challenge); /* generate a random challenge */

        packet = g_string_new(NULL);
        network_mysqld_proto_append_auth_challenge(packet, challenge);
        con->client->challenge = challenge;

        network_mysqld_queue_append(con->client, con->client->send_queue, S(packet));

        g_string_free(packet, TRUE);

        con->state = CON_STATE_SEND_HANDSHAKE;

        g_assert(con->plugin_con_state == NULL);

        con->plugin_con_state = network_mysqld_con_t_new();

        return NETWORK_SOCKET_SUCCESS;
        //return NETWORK_SOCKET_SUCCESS;
}

#if 0
static network_mysqld_lua_stmt_ret proxy_lua_disconnect_client(network_mysqld_con *con) __attribute__((unused));
static network_mysqld_lua_stmt_ret proxy_lua_disconnect_client(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	lua_State *L;

	/* call the lua script to pick a backend
	 * */
	/* this error handling is different, as we no longer have a client. */
	switch(network_mysqld_con_lua_register_callback(con, con->config->lua_script)) {
		case REGISTER_CALLBACK_SUCCESS:
			break;
		case REGISTER_CALLBACK_LOAD_FAILED:
		case REGISTER_CALLBACK_EXECUTE_FAILED:
			return ret;
	}

	if (!st->L) return 0;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("disconnect_client"));
	if (lua_isfunction(L, -1)) {
		if (lua_pcall(L, 0, 1, 0) != 0) {
			g_critical("%s.%d: (disconnect_client) %s", 
					__FILE__, __LINE__,
					lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}

		switch (ret) {
		case PROXY_NO_DECISION:
		case PROXY_IGNORE_RESULT:
			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}
#endif

/**
 * cleanup the proxy specific data on the current connection 
 *
 * move the server connection into the connection pool in case it is a 
 * good client-side close
 *
 * @return NETWORK_SOCKET_SUCCESS
 * @see plugin_call_cleanup
 */
/**
 * @author sohu-inc.com
 * 我们在这里处理client端或server端的连接的失败
 * @todo 主要是完成一下工作：
 * 1. 当client正常的关闭连接时，
 * 		需要将con->server或cache->server上面的注册事件清楚并将其加入到连接池中
 * 		更新连接数目
 * 2. 若是server端连接关闭时，
 *		需要将两端的连接con->client及con->server
 * 3. con->cache_server关闭超时暂时不会触发该函数
 *
 * @attention 这里我们只是实现在client端征程关闭连接时，并且是连接不在prepare且不在事务中时将后端连接放回到连接池中
 * 			     其他的情况我们不会将con->server或con->cache_server放回到连接池中
 * 			     但是都会将con->server及con->cache_server注册事件删除。
 * @note 现在连接数的维持是在network_mysqld_con_handle的对应状态中实现，也可以放在这里！！
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_disconnect_client) {
	network_mysqld_con_t *st = con->plugin_con_state;
	//lua_scope  *sc = con->srv->priv->sc;
	//gboolean use_pooled_connection __attribute__((unused)) = FALSE;

	if (con->tokens != NULL) {
		//g_debug("freeing tokens is a good habit");
		sql_tokens_free(con->tokens);
		con->tokens = NULL;
	}

	if (st == NULL) return NETWORK_SOCKET_SUCCESS;
	gboolean is_client_authed = con->client_is_authed;

	// 如果不启用连接复用的话，我们不对连接的client和server做处理，直接放回成功，
	// 后续调用free函数将结构内存释放
	if (!con->multiplex) {
		g_debug("[%s]:multiplex of connection disabled, will close client and server connection.", G_STRLOC);

		// 在这之前我们需要更新用户连接的统计数据
		if (con->client && is_client_authed) {
			if (con->client->response && con->client->ip_region) {
				gint *user_log_in = get_login_users(con->srv, con->type, con->client->response->username->str, con->client->ip_region);
				if(user_log_in) {
					g_atomic_int_dec_and_test(user_log_in);
				} else {
					g_warning("[%s]: cannot get user login count: %s, %s",
							G_STRLOC, con->client->response->username->str,
							con->client->ip_region);
				}
			}
		}

		// 如果后端有server，则将backend上面的连接数减1
		// 同时将连接池的统计信息更新
		g_mutex_lock(&con->server_mutex);
		if (con->server) {
			// 连接数减 1
			network_backend_t * bk_tmp = network_backends_get_by_name(
					con->srv->priv->backends,
					con->server->dst->name->str);
			client_desc(bk_tmp, con->type);
			update_conn_pool_status_in_state(bk_tmp->pool[con->type],
					con->server->response->username->str,
					POOL_STATUS_STATE_DISCONNECTED);
		}
		g_mutex_unlock(&con->server_mutex);
		network_mysqld_con_t_free(st);
		return NETWORK_SOCKET_SUCCESS;
	}

	/**
	 * @fixme con_in_use connected_clients 没整明白，需要修改吗？
	 */
	/**
	 * 检查是否是client端主动关闭连接，若是执行相应的动作
	 */
	if (con->state == CON_STATE_CLOSE_CLIENT) {
		proxy_rw type = con->type;

		g_debug("CON_STATE_CLOSE_CLIENT");
		// 将前端的登陆数目减1（连接限制相关）
		if (is_client_authed) {
			if (con->client && con->client->response && con->client->ip_region) {
				gint *con_in_use = get_login_users(con->srv, con->type, con->client->response->username->str, con->client->ip_region);
				if(con_in_use) {
					g_atomic_int_dec_and_test(con_in_use);
				} else {
					g_warning("[%s]: cannot get user login count: %s, %s",
							G_STRLOC, con->client->response->username->str,
							con->client->ip_region);
				}
			}
		}

		/**
		 * 1.若con->server或con->cache_server非空，将上面注册事件删除(一定要注意会不会导致数据的乱序？？)
		 * 2.判断是否在事务中或prepare中，既不在事务中且不在prepare中时，才将con->server或con->cache_server回归连接池
		 */
		// 1. con->server 的处理
		network_socket *server = NULL;
		g_mutex_lock(&con->server_mutex);
		if (con->server) {
			server = con->server;
			con->server = NULL;
			g_message("[%s]:the client has close the con, and we should unregister the event handler of con->server, fd=%d", G_STRLOC, server->fd);
			event_del(&(server->event));
		}
		g_mutex_unlock(&con->server_mutex);

		if (server) {
			if(!(con->tx_flag) && !(is_in_prepare(con))) {
				g_message("[%s]:the connection is neither in transaction nor in prepare, we will put the con from proxy to backend to the pool.SOCKET = %d", G_STRLOC, server->fd);
				//network_backend_t * bk_end __attribute__((unused)) = network_backends_get_by_name(con->srv->priv->backends, server->dst->name->str);
				network_mysqld_pool_con_add_soket(con, server);
			} else {
				network_backend_t * bk_tmp = network_backends_get_by_name(con->srv->priv->backends, server->dst->name->str);
				// 2. 相应的连接池的统计数据更新：using--
				update_conn_pool_status_in_state(bk_tmp->pool[type],
						server->response->username->str,
						POOL_STATUS_STATE_DISCONNECTED);
				// 3. 将对应的backend的连接数减1
				client_desc(bk_tmp, con->type);

				// 反之，我们不将其加入到连接池中，sock会随着con被销毁
				g_message("[%s]:server of con will not be put back to pool, the client is %s", G_STRLOC, con->client->src->name->str);
				network_socket_free(server);
			}
			server = NULL;
		}

		// con->cache_server 的处理
		g_mutex_lock(&con->cache_server_mutex);
		if (con->cache_server) {
			server = con->cache_server;
			con->cache_server = NULL;
			g_message("[%s]:the client has close the con, and we should unregister the event handler of con->cache_server: fd=%d", G_STRLOC, server->fd);
			event_del(&(server->event));
		    con->cache_idle_timeout_flag = TRUE;
		}
		g_mutex_unlock(&con->cache_server_mutex);

		if (server) {
			if (!(con->tx_flag) && !(is_in_prepare(con))) {
				g_message("[%s]:the connection is neither in transaction nor in prepare, we will put the con from proxy to backend to the pool. SOCKET = %d", G_STRLOC, server->fd);
				network_mysqld_pool_con_add_soket (con, server);
			} else {
				network_backend_t * bk_tmp = network_backends_get_by_name(con->srv->priv->backends, server->dst->name->str);

				// 2. 相应的连接池的统计数据更新：using--
				update_conn_pool_status_in_state(bk_tmp->pool[type],
						server->response->username->str,
						POOL_STATUS_STATE_DISCONNECTED);
				// 3. 将对应的backend的连接数减1
				client_desc(bk_tmp, con->type);

				// 反之，我们不将其加入到连接池中，sock会随着con被销毁
				g_message("[%s]:server of con will not be put back to pool, the client is %s", G_STRLOC, con->client->src->name->str);
				network_socket_free(server);
			}
			server = NULL;
		}

	} else if (con->state == CON_STATE_CLOSE_SERVER) {
		g_debug("CON_STATE_CLOSE_SERVER");

		proxy_rw type = con->type;
		network_socket *server = NULL;
		// 若是CON_STATE_CLOSE_SERVER,只需要将连接池统计数更新即可
		g_mutex_lock(&con->server_mutex);
		if (con->server) {
			server = con->server;
			con->server = NULL;
		}
		g_mutex_unlock(&con->server_mutex);

		if (server && server->dst->name) {
			// 1. 相应的backend连接数--
			network_backend_t * bk_tmp = network_backends_get_by_name(con->srv->priv->backends, server->dst->name->str);
			g_assert(bk_tmp);
			if (con->client) {
				// 如果有对应的client, 则将对应的backend的连接数减1
				client_desc(bk_tmp, con->type);
			}

			// 2. 相应的连接池的统计数据更新：using--
			update_conn_pool_status_in_state(bk_tmp->pool[type],
					server->response->username->str,
					POOL_STATUS_STATE_DISCONNECTED);

			// 3.释放掉该后端连接
			network_socket_free(server);
			server = NULL;
		}

		network_socket *client_tmp = NULL;
		g_mutex_lock(&con->client_mutex);
		if (con->client) {
			client_tmp = con->client;
			if(client_tmp->event.ev_base) {
				g_message("[%s]:the server has close the con, and we should unregister the event handler of con->client", G_STRLOC);
				event_del(&(client_tmp->event));
			}
			con->client = NULL;
		}
		g_mutex_unlock(&con->client_mutex);
		if (client_tmp) {
			// 连接数减1
			if (is_client_authed) {
				if (client_tmp->response && client_tmp->ip_region) {
					gint *con_in_use = get_login_users(con->srv, con->type, client_tmp->response->username->str, client_tmp->ip_region);
					if(con_in_use) {
						g_atomic_int_dec_and_test(con_in_use);
					} else {
						g_warning("[%s]: cannot get user login count: %s, %s",
								G_STRLOC, con->client->response->username->str,
								con->client->ip_region);
					}
				}
			}
			// 释放前段连接
			network_socket_free(client_tmp);
		}

	} else {
		g_message("[%s]:error occured, will kill client SOCKET = %d, server SCOKET = %d", G_STRLOC, con->client?con->client->fd:0, con->server?con->server->fd:0);
		// CON_STATE_ERROR
		// 这里需要将连接从连接池中删除？？
		network_socket *sock = NULL;
		proxy_rw type = con->type;
		gboolean with_client = FALSE;

		// 处理客户端socket:client
		g_mutex_lock(&con->client_mutex);
		if (con->client) {
			sock = con->client;
			with_client = TRUE;
			con->client = NULL;
		}
		g_mutex_unlock(&con->client_mutex);
		if (sock) {
			// 连接数减1
			if (is_client_authed) {
				if (sock->response && sock->ip_region) {
					gint *con_in_use = get_login_users(con->srv, con->type, sock->response->username->str, sock->ip_region);
					if(con_in_use) {
						g_atomic_int_dec_and_test(con_in_use);
					} else {
						g_warning("[%s]: cannot get user login count: %s, %s",
								G_STRLOC, con->client->response->username->str,
								con->client->ip_region);
					}
				}
			}
			// 释放前段连接
			network_socket_free(sock);
			sock = NULL;
		}

		// 处理服务器端socket:server
		g_mutex_lock(&con->server_mutex);
		if (con->server) {
			sock = con->server;
			con->server = NULL;
		}
		g_mutex_unlock(&con->server_mutex);

		if (sock && sock->dst->name) {
			// 1. 相应的backend连接数--
			network_backend_t * bk_tmp = network_backends_get_by_name(con->srv->priv->backends, sock->dst->name->str);
			g_assert(bk_tmp);
			if (with_client) {
				// 如果有对应的client，则将对应的连接数减1
				client_desc(bk_tmp, con->type);
			}

			// 2. 相应的连接池的统计数据更新：using--
			update_conn_pool_status_in_state(bk_tmp->pool[type],
					sock->response->username->str,
					POOL_STATUS_STATE_DISCONNECTED);

			// 3.释放掉该后端连接
			network_socket_free(sock);
			sock = NULL;
		}
	}
#ifdef HAVE_LUA_H
	/* remove this cached script from registry */
	#if 0
	if (st->L_ref > 0) {
		luaL_unref(sc->L, LUA_REGISTRYINDEX, st->L_ref);
	}
	#endif
#endif

	network_mysqld_con_t_free(st);

	con->plugin_con_state = NULL;

	/**
	 * walk all pools and clean them up
	 */

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * read the load data infile data from the client
 *
 * - decode the result-set to track if we are finished already
 * - gets called once for each packet
 *
 * @FIXME stream the data to the backend
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_local_infile_data) {
	int query_result = 0;
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_com_query_result_t *com_query = con->parse.data;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter");
	
	recv_sock = con->client;
	send_sock = con->server;

	/* check if the last packet is valid */
	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	/* if we get here from another state, src/network-mysqld.c is broken */
	g_assert_cmpint(con->parse.command, ==, COM_QUERY);
	g_assert_cmpint(com_query->state, ==, PARSE_COM_QUERY_LOCAL_INFILE_DATA);

	query_result = network_mysqld_proto_get_query_result(&packet, con);

	/* set the testing flag for all data received or not */ 
	con->local_file_data_is_finished = (query_result == 1);

	if (query_result == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

	if (con->server) {
		/* we haven't received all data from load data infile, so let's continue reading and writing to the backend */
		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
				g_queue_pop_tail(recv_sock->recv_queue->chunks));
	} else {
		GString *s;
		/* we don't have a backend
		 *
		 * - free the received packets early
		 * - send a OK later 
		 */
		while ((s = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(s, TRUE);
	}

	if (query_result == 1) {
		if (con->server) { /* we have received all data, lets move forward reading the result from the server */
			con->state = CON_STATE_SEND_LOCAL_INFILE_DATA;
		} else {
			network_mysqld_con_send_ok(con->client);
			con->state = CON_STATE_SEND_LOCAL_INFILE_RESULT;
		}
		g_assert_cmpint(com_query->state, ==, PARSE_COM_QUERY_LOCAL_INFILE_RESULT);
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * read the load data infile result from the server
 *
 * - decode the result-set to track if we are finished already
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_local_infile_result) {
	int query_result = 0;
	network_packet packet;
	network_socket *recv_sock, *send_sock;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_local_infile_result::enter");

	recv_sock = con->server;
	send_sock = con->client;

	/* check if the last packet is valid */
	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;
	
	query_result = network_mysqld_proto_get_query_result(&packet, con);
	if (query_result == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

	network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
			g_queue_pop_tail(recv_sock->recv_queue->chunks));

	if (query_result == 1) {
		con->state = CON_STATE_SEND_LOCAL_INFILE_RESULT;
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup after we sent to result of the LOAD DATA INFILE LOCAL data to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_local_infile_result) {
	network_socket *recv_sock, *send_sock;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::send_local_infile_result::enter");

	recv_sock = con->server;
	send_sock = con->client;

	/* reset the packet-ids */
	if (send_sock) network_mysqld_queue_reset(send_sock);
	if (recv_sock) network_mysqld_queue_reset(recv_sock);

	con->state = CON_STATE_READ_QUERY;

	return NETWORK_SOCKET_SUCCESS;
}


int network_mysqld_proxy_connection_init(network_mysqld_con *con) {
	con->plugins.con_init                      = proxy_init;
	con->plugins.con_connect_server            = proxy_connect_server;
	con->plugins.con_read_handshake            = proxy_read_handshake;
	con->plugins.con_read_auth                 = proxy_read_auth;
	con->plugins.con_read_auth_result          = proxy_read_auth_result;
	con->plugins.con_read_query                = proxy_read_query;
	con->plugins.con_read_query_result         = proxy_read_query_result;
	con->plugins.con_send_query_result         = proxy_send_query_result;
	con->plugins.con_read_local_infile_data = proxy_read_local_infile_data;
	con->plugins.con_read_local_infile_result = proxy_read_local_infile_result;
	con->plugins.con_send_local_infile_result = proxy_send_local_infile_result;
	con->plugins.con_cleanup                   = proxy_disconnect_client;
	con->plugins.con_timeout                   = proxy_timeout;

	// added by sohu-inc.com
	con->plugins.con_process_read_query = proxy_process_read_query;
	con->plugins.con_get_server_list = proxy_get_server_list;
	con->plugins.con_get_server_connection_list = proxy_get_server_connection_list;
	con->plugins.con_send_query = proxy_send_query;
	return 0;
}

/**
 * free the global scope which is shared between all connections
 *
 * make sure that is called after all connections are closed
 */
void network_mysqld_proxy_free(network_mysqld_con G_GNUC_UNUSED *con) {
}

chassis_plugin_config * network_mysqld_proxy_plugin_new(void) {
	chassis_plugin_config *config;

	config = g_new0(chassis_plugin_config, 1);
	config->fix_bug_25371   = 0; /** double ERR packet on AUTH failures */
	config->profiling       = 1;
	config->start_proxy     = 1;
	config->pool_change_user = 1; /* issue a COM_CHANGE_USER to cleanup the connection 
					 when we get back the connection from the pool */
	config->multiplex = 1; // 默认启用连接的复用
	//config->lb_algo[PROXY_TYPE_WRITE] = NULL; // 默认最少连接
	//config->lb_algo[PROXY_TYPE_READ] = NULL; // 默认最少连接
	//config->lb_algo_func[PROXY_TYPE_WRITE] = loadbalance_lc_select; // 默认最少连接
	//config->lb_algo_func[PROXY_TYPE_READ] = loadbalance_lc_select; // 默认最少连接
	config->ro_address = NULL;
	config->rw_address = NULL;
	config->ro_config = NULL;
	config->rw_config = NULL;

	/* use negative values as defaults to make them ignored */
	config->connect_timeout_dbl = -1.0;
	config->read_timeout_dbl = -1.0;
	config->write_timeout_dbl = -1.0;

	/* config->chas 初始化为 NULL*/
	config->chas = NULL;

	/** config 的 */
	config->listen_configs[0] = NULL;
	config->listen_configs[1] = NULL;

	return config;
}

void network_mysqld_proxy_plugin_free(chassis_plugin_config *config) {
	// @author sohu-inc.com
	chassis *chas = NULL;
	gsize i;

	if (!config)
		return;

	/* join connection scaler thread, free the pointer */
	chas = config->chas;
	if (chas != NULL ) {
		if (chas->connection_scaler_thread != NULL ) {
			connection_scaler_thread_free(chas->connection_scaler_thread);
			chas->connection_scaler_thread = NULL;
		}
	}
	
	if (chas != NULL ) {
		if (chas->sql_statistics_thread != NULL ) {
			sql_statistics_thread_free(chas->sql_statistics_thread);
			chas->sql_statistics_thread = NULL;
		}
	}

//	if(!config)
//		return;
	/**
	 * 回收所有的检测线程的资源
	 */
	//chassis *chas = config->chas;
	
	if (chas && chas->detect_threads) {
//		backend_detect_thread_t *thread = NULL;
//		while (chas->detect_threads->len > 0) {
//			thread = g_ptr_array_remove_index (chas->detect_threads, 0);
//			backend_detect_thread_free(thread);
//		}
//		g_ptr_array_free(chas->detect_threads, TRUE);
		backend_detect_threads_free(chas->detect_threads);
		chas->detect_threads = NULL;
	}

	/**
	 * 释放规则列表内存
	 */
	if (chas && chas->rule_table) {
		user_db_sql_rule_table_free(chas->rule_table);
		chas->rule_table = NULL;
	}
	
	/**
	 * 释放sql直方图统计结构
	 */
	if (chas && chas->tmi) {
		time_section_index_free(chas->tmi);
	}

	if (chas && chas->para_limit_rules) {
		para_exec_limit_rules_free(chas->para_limit_rules);
		chas->para_limit_rules = NULL;
	}

	if (chas && chas->para_running_statistic_dic) {
		statistic_dic_free(chas->para_running_statistic_dic);
		chas->para_running_statistic_dic = NULL;
	}

	if (chas && chas->dura_limit_rules) {
		dura_exec_limit_rules_free(chas->dura_limit_rules);
		chas->dura_limit_rules = NULL;
	}

	if (chas && chas->inbytes_list) {
		query_inbytes_list_free(chas->inbytes_list);
		chas->inbytes_list = NULL;
	}

	if (chas && chas->outbytes_list) {
		query_outbytes_list_free(chas->outbytes_list);
		chas->outbytes_list = NULL;
	}

	if (chas && chas->query_rate_list) {
		query_rate_list_free(chas->query_rate_list);
		chas->query_rate_list = NULL;
	}

	if (chas && chas->query_dml_list) {
		query_dml_list_free(chas->query_dml_list);
		chas->query_dml_list = NULL;
	}

	if (config->rw_config) {
		config->rw_config->backend_addresses = NULL;
		network_mysqld_proxy_plugin_free(config->rw_config);
		config->rw_config = NULL;
	}

	if (config->ro_config) {
		config->ro_config->backend_addresses = NULL;
		network_mysqld_proxy_plugin_free(config->ro_config);
		config->ro_config = NULL;
	}

	if (config->listen_con) {
		/**
		 * the connection will be free()ed by the network_mysqld_free()
		 */
#if 0
event_del(&(config->listen_con->server->event));
network_mysqld_con_free(config->listen_con);
config->listen_con = NULL;
#endif
	}

	if (config->backend_addresses) {
		for (i = 0; config->backend_addresses[i]; i++) {
			g_free(config->backend_addresses[i]);
		}
		g_free(config->backend_addresses);
		config->backend_addresses = NULL;
	}

	if (config->address) {
		/* free the global scope */
		network_mysqld_proxy_free(NULL );

		g_free(config->address);
		config->address = NULL;
	}
	// @author sohu-inc.com
	if (config->rw_address) {
		g_free(config->rw_address);
		config->rw_address = NULL;
	}
	if (config->ro_address) {
		g_free(config->ro_address);
		config->ro_address = NULL;
	}

	#if 0
	if (config->lua_script) {
		g_free(config->lua_script);
		config->lua_script = NULL;
	}
	#endif

	guint index = 0;
	chassis_plugin_config * tmp_config = NULL;
	proxy_rw type = 0;

	for (type = PROXY_TYPE_WRITE; type <= PROXY_TYPE_READ; type++) {
		if (config->listen_configs[type]) {
			for (index = 0; index < config->listen_configs[type]->len; index++) {
				tmp_config = config->listen_configs[type]->pdata[index];
				tmp_config->backend_addresses = NULL;
				network_mysqld_proxy_plugin_free(tmp_config);
				tmp_config = NULL;
			}
			g_ptr_array_free(config->listen_configs[type], TRUE);
			config->listen_configs[type] = NULL;
		}
	}

	g_free(config);
}

/**
 * plugin options 
 */
static GOptionEntry * network_mysqld_proxy_plugin_get_options(chassis_plugin_config *config) {
	guint i;

	/* make sure it isn't collected */
	static GOptionEntry config_entries[] = 
	{
		{ "proxy-address",            'P', 0, G_OPTION_ARG_STRING, NULL, "(will be depressed !)listening address:port of the proxy-server (default: :4040)", "<host:port>" },
		{ "rw-address",            'P', 0, G_OPTION_ARG_STRING, NULL, "listening address:port of the proxy-server (default: :4040)", "<host:port>" },
        { "ro-address",            'P', 0, G_OPTION_ARG_STRING, NULL, "listening address:port of the proxy-server (default: :4242)", "<host:port>" },
		{ "proxy-read-only-backend-addresses", 
					      'r', 0, G_OPTION_ARG_STRING_ARRAY, NULL, "address:port of the remote slave-server (default: not set)", "<host:port>" },
		{ "proxy-backend-addresses",  'b', 0, G_OPTION_ARG_STRING_ARRAY, NULL, "address:port of the remote backend-servers (default: 127.0.0.1:3306)", "<host:port>" },
		
		{ "proxy-skip-profiling",     0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "disables profiling of queries (default: enabled)", NULL },

		{ "proxy-fix-bug-25371",      0, 0, G_OPTION_ARG_NONE, NULL, "fix bug #25371 (mysqld > 5.1.12) for older libmysql versions", NULL },
		#if 0
		{ "proxy-lua-script",         's', 0, G_OPTION_ARG_FILENAME, NULL, "filename of the lua script (default: not set)", "<file>" },
		#endif
		
		{ "no-proxy",                 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "don't start the proxy-module (default: enabled)", NULL },
		
		{ "proxy-pool-no-change-user", 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "don't use CHANGE_USER to reset the connection coming from the pool (default: enabled)", NULL },

		{ "proxy-connect-timeout",    0, 0, G_OPTION_ARG_DOUBLE, NULL, "connect timeout in seconds (default: 2.0 seconds)", NULL },
		{ "proxy-read-timeout",    0, 0, G_OPTION_ARG_DOUBLE, NULL, "read timeout in seconds (default: 8 hours)", NULL },
		{ "proxy-write-timeout",    0, 0, G_OPTION_ARG_DOUBLE, NULL, "write timeout in seconds (default: 8 hours)", NULL },
		{ "proxy-connect-no-multiplex", 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "don't support multiplex of connection from proxy to backends (default: enabled)", NULL },

		{ "proxy-rw-load-balance-algorithm", 0, 0, G_OPTION_ARG_STRING, NULL, "load balancer algorithm for rw, lc(least connection) or wrr(weighted round robin). (default: lc)", NULL },
		{ "proxy-ro-load-balance-algorithm", 0, 0, G_OPTION_ARG_STRING, NULL, "load balancer algorithm for ro. (default: lc)", NULL },

		{ NULL,                       0, 0, G_OPTION_ARG_NONE,   NULL, NULL, NULL }
	};

	i = 0;
	config_entries[i++].arg_data = &(config->address);
	// added by sohu-inc.com
	config_entries[i++].arg_data = &(config->rw_address);
    config_entries[i++].arg_data = &(config->ro_address);

	config_entries[i++].arg_data = &(config->read_only_backend_addresses);
	config_entries[i++].arg_data = &(config->backend_addresses);

	config_entries[i++].arg_data = &(config->profiling);

	config_entries[i++].arg_data = &(config->fix_bug_25371);
	#if 0
	config_entries[i++].arg_data = &(config->lua_script);
	#endif
	config_entries[i++].arg_data = &(config->start_proxy);
	config_entries[i++].arg_data = &(config->pool_change_user);
	config_entries[i++].arg_data = &(config->connect_timeout_dbl);
	config_entries[i++].arg_data = &(config->read_timeout_dbl);
	config_entries[i++].arg_data = &(config->write_timeout_dbl);
	config_entries[i++].arg_data = &(config->multiplex);
//	config_entries[i++].arg_data = &(config->lb_algo[PROXY_TYPE_WRITE]);
//	config_entries[i++].arg_data = &(config->lb_algo[PROXY_TYPE_READ]);

	return config_entries;
}

/**
 * (为读写服务)构造、初始化chassis_plugin_config
 * @param[IN] const struct chassis_plugin_config *config 全局的配置
 * @param[IN] proxy_rw type (读或写)类型
 * @param[IN] chassis *chas 基础结构
 * @return struct chassis_plugin_config * 新构造的配置
 * @return struct chassis_plugin_config *NULL 构造失败
 */
struct chassis_plugin_config *chassis_plugin_config_new_init_2(
		const struct chassis_plugin_config *config,
		const gchar *ip_port, proxy_rw type,
		chassis *chas) {

	g_assert(ip_port);
	g_assert(chas);
	struct chassis_plugin_config *new_config = NULL;

	network_mysqld_con *con = NULL;

	new_config = network_mysqld_proxy_plugin_new();
	//new_config = g_new0(struct chassis_plugin_config ,1);
	g_assert(new_config);

	con = network_mysqld_con_new();
	g_assert(con);
	network_mysqld_add_connection(chas, con);

	new_config->connect_timeout_dbl = config->connect_timeout_dbl;
	new_config->read_timeout_dbl = config->read_timeout_dbl;
	new_config->write_timeout_dbl = config->write_timeout_dbl;
	new_config->fix_bug_25371 = config->fix_bug_25371;
	new_config->profiling = config->profiling;
	new_config->pool_change_user = config->pool_change_user;

	new_config->start_proxy = config->start_proxy;
	#if 0
	if (config->lua_script) {
		new_config->lua_script = g_strdup(config->lua_script);
	}
	#endif

	new_config->backend_addresses = config->backend_addresses;
	new_config->read_only_backend_addresses =
			config->read_only_backend_addresses;

	new_config->address = g_strdup(ip_port);

	new_config->proxy_type = type;
	new_config->chas = NULL;

	// 设置连接的读写属性
	con->type = type;
	con->config = new_config;
	new_config->listen_con = con;

	// 创建写的socket监听
	con->server = network_socket_new();

	network_mysqld_proxy_connection_init(con);
	// 设置后端的监听地址
	if (0 != network_address_set_address(con->server->dst,
					new_config->address)) {
		return NULL;
	}

	if (0 != network_socket_bind(con->server)) {
		return NULL;
	}
	g_message("[%s]: %s proxy listen on port %s", G_STRLOC,
			(type == PROXY_TYPE_WRITE) ? "rw" : "ro", new_config->address);

	/**
	 * call network_mysqld_con_accept() with this connection when we are done
	 */

//		event_set(&(con->server->event), con->server->fd, EV_READ | EV_PERSIST,
//				network_mysqld_con_accept, con);
//		event_base_set(chas->event_base, &(con->server->event));
	event_assign(&(con->server->event), chas->event_base, con->server->fd, EV_READ | EV_PERSIST,
			network_mysqld_con_accept, con);
	event_add(&(con->server->event), NULL);

	/** 将监听连接添加到监听索引列表中 */
	GString *listen_key = g_string_new(ip_port);
	g_hash_table_insert(chas->listen_cons[type], listen_key, con);

	return new_config;
}


/**
 * (为读写服务)构造、初始化chassis_plugin_config
 * @param[IN] const struct chassis_plugin_config *config 全局的配置
 * @param[IN] proxy_rw type (读或写)类型
 * @param[IN] chassis *chas 基础结构
 * @return struct chassis_plugin_config * 新构造的配置
 * @return struct chassis_plugin_config *NULL 构造失败
 */
struct chassis_plugin_config *chassis_plugin_config_new_init(
		const struct chassis_plugin_config *config, proxy_rw type,
		chassis *chas) {
	struct chassis_plugin_config *new_config = NULL;
	network_mysqld_con *con = NULL;

	new_config = g_new0(struct chassis_plugin_config ,1);
	g_assert(new_config);

	con = network_mysqld_con_new();
	g_assert(con);
	network_mysqld_add_connection(chas, con);

	new_config->connect_timeout_dbl = config->connect_timeout_dbl;
	new_config->read_timeout_dbl = config->read_timeout_dbl;
	new_config->write_timeout_dbl = config->write_timeout_dbl;
	new_config->fix_bug_25371 = config->fix_bug_25371;
	new_config->profiling = config->profiling;
	new_config->pool_change_user = config->pool_change_user;

	new_config->start_proxy = config->start_proxy;
	#if 0
	if (config->lua_script) {
		new_config->lua_script = g_strdup(config->lua_script);
	}
	#endif

	new_config->backend_addresses = config->backend_addresses;
	new_config->read_only_backend_addresses =
			config->read_only_backend_addresses;

	if (type == PROXY_TYPE_WRITE) {
		new_config->address = g_strdup(config->rw_address);
	} else {
		new_config->address = g_strdup(config->ro_address);
	}

	new_config->proxy_type = type;

	//new_config->lb_algo[0] = config->lb_algo[type];
	//new_config->lb_algo_func[0] = config->lb_algo_func[type];
	//new_config->lb_algo[1] = config->lb_algo[type];
	//new_config->lb_algo_func[1] = config->lb_algo_func[type];

	// 设置连接的读写属性
	con->type = type;
	con->config = new_config;
	new_config->listen_con = con;

	// 创建写的socket监听
	con->server = network_socket_new();

	network_mysqld_proxy_connection_init(con);
	// 设置后端的监听地址
	if (0 != network_address_set_address(con->server->dst,
					new_config->address)) {
		return NULL;
	}

	if (0 != network_socket_bind(con->server)) {
		return NULL;
	}
	g_message("[%s]: %s proxy listen on port %s", G_STRLOC,
			(type == PROXY_TYPE_WRITE) ? "rw" : "ro", new_config->address);

	/**
	 * call network_mysqld_con_accept() with this connection when we are done
	 */

//		event_set(&(con->server->event), con->server->fd, EV_READ | EV_PERSIST,
//				network_mysqld_con_accept, con);
//		event_base_set(chas->event_base, &(con->server->event));
	event_assign(&(con->server->event), chas->event_base, con->server->fd, EV_READ | EV_PERSIST,
			network_mysqld_con_accept, con);
	event_add(&(con->server->event), NULL);

	return new_config;
}

static int get_num_of_ips(const gchar * addresses) {

	int ret = 0;
	const gchar *tmp = addresses;

	while (tmp != NULL && *tmp != '\0') {
		if (*tmp == ',') {
			ret++;
		}

		tmp++;
	}

	ret++;

	return ret;
}

/**
 * init the plugin with the parsed config
 */
int network_mysqld_proxy_plugin_apply_config(chassis *chas, chassis_plugin_config *config) {
	//network_socket *listen_sock __attribute__((unused));
	chassis_private *g = chas->priv;

	if (!config->start_proxy) {
		return 0;
	}

	config->chas = chas;

	/**
	 * added by zhenfan, 2013/08/24
	 * 将DOM树中相关multiplex信息初始化到chas中
	 */
	g_debug("[%s]: init global multiplex from xml", G_STRLOC);
	if (!config_multiplex_load(chas)) {
		g_critical("Load multiplex option in %s error", chas->xml_filename);
		return -1;
	}

	/**
	 * 设置负载均衡算法
	 */
	/**
	 * added by zhenfan, 2013/08/24
	 * 将DOM树中相关lb_algorithm信息初始化到config中
	 */
	gchar *lb_str = NULL;
	// PROXY_TYPE_WRITE
	g_debug("[%s]: init PROXY_TYPE_WRITE lb algorithm from xml", G_STRLOC);
	if (NULL == (lb_str = config_lb_algorithm_load(chas, PROXY_TYPE_WRITE))) {
		g_critical("Load PROXY_TYPE_WRITE lb algorithm in %s error", chas->xml_filename);
		return -1;
	}
	if ( g_ascii_strcasecmp(lb_str, "lc") == 0 ) {
		g_message("[%s]: load balance algorithm for rw is lc.", G_STRLOC);
		chas->lb_algo[PROXY_TYPE_WRITE] = "lc";
		chas->lb_algo_func[PROXY_TYPE_WRITE] = loadbalance_lc_select;
	} else if ( g_ascii_strcasecmp(lb_str, "wrr") == 0 ) {
		g_message("[%s]: load balance algorithm for rw is wrr.", G_STRLOC);
		chas->lb_algo[PROXY_TYPE_WRITE] = "wrr";
		chas->lb_algo_func[PROXY_TYPE_WRITE] = loadbalance_wrr_select;
	} else {
		g_warning("[%s]: load balance algorithm for rw is not specified, default will be lc.", G_STRLOC);
		chas->lb_algo[PROXY_TYPE_WRITE] = "lc";
		chas->lb_algo_func[PROXY_TYPE_WRITE] = loadbalance_lc_select;
	}
	g_free(lb_str);
	lb_str = NULL;
	g_debug("lb_algo %s %s", chas->lb_algo[PROXY_TYPE_WRITE], chas->lb_algo[PROXY_TYPE_WRITE]);
	g_debug("lb_algo_func %p %p", chas->lb_algo_func[PROXY_TYPE_WRITE], chas->lb_algo_func[PROXY_TYPE_WRITE]);
	
	// PROXY_TYPE_READ
	g_debug("[%s]: init PROXY_TYPE_READ lb algorithm from xml", G_STRLOC);
	if (NULL == (lb_str = config_lb_algorithm_load(chas, PROXY_TYPE_READ))) {
		g_critical("Load PROXY_TYPE_READ lb algorithm in %s error", chas->xml_filename);
		return -1;
	}
	if ( g_ascii_strcasecmp(lb_str, "lc") == 0 ) {
		g_message("[%s]: load balance algorithm for ro is lc.", G_STRLOC);
		chas->lb_algo[PROXY_TYPE_READ] = "lc";
		chas->lb_algo_func[PROXY_TYPE_READ] = loadbalance_lc_select;
	} else if ( g_ascii_strcasecmp(lb_str, "wrr") == 0 ) {
		g_message("[%s]: load balance algorithm for ro is wrr.", G_STRLOC);
		chas->lb_algo[PROXY_TYPE_READ] = "wrr";
		chas->lb_algo_func[PROXY_TYPE_READ] = loadbalance_wrr_select;
	} else {
		g_warning("[%s]: load balance algorithm for ro is not specified, default will be lc.", G_STRLOC);
		chas->lb_algo[PROXY_TYPE_READ] = "lc";
		chas->lb_algo_func[PROXY_TYPE_READ] = loadbalance_lc_select;
	}
	g_free(lb_str);
	lb_str = NULL;
	g_debug("lb_algo %s %s", chas->lb_algo[PROXY_TYPE_READ], chas->lb_algo[PROXY_TYPE_READ]);
	g_debug("lb_algo_func %p %p", chas->lb_algo_func[PROXY_TYPE_READ], chas->lb_algo_func[PROXY_TYPE_READ]);

	/** 没有设置后端，默认后端是127.0.0.1:3306 */
	if (!config->backend_addresses) {
		config->backend_addresses = g_new0(char *, 2);
		config->backend_addresses[0] = g_strdup("127.0.0.1:3306");
	}

	/**
	 * @author sohu-inc.com
	 * 加载dbproxy后端设置的绑定端口
	 * 设置 chas->rw_addresses 及 chas->rw_addresses的值
	 */
	/** 设置connection init的函数指针 */
	chas->proxy_connection_init_ptr = network_mysqld_proxy_connection_init;

	if (!config_listen_addresses_load(chas, PROXY_TYPE_WRITE)) {
		g_message("[%s]: load rw_addresses failed, none was found", G_STRLOC);
	}

	if (!config_listen_addresses_load(chas, PROXY_TYPE_READ)) {
		g_message("[%s]: load ro_addresses failed, none was found", G_STRLOC);
	}

	/**
	 * 如果没有配置读写端口时会设置默认的读写端口
	 * 默认的写端口设置为:4040
	 * 默认的读端口设置为:4242
	 */
	if(0 == chas->listen_addresses[PROXY_TYPE_WRITE]->len && 0 == chas->listen_addresses[PROXY_TYPE_READ]->len ) {
		g_string_append(chas->listen_addresses[PROXY_TYPE_WRITE], ":4040");
		g_string_append(chas->listen_addresses[PROXY_TYPE_READ], ":4242");
	}

	if(!config->rw_address && !config->ro_address ) {
		config->rw_address = g_strdup(":4040");
		config->ro_address = g_strdup(":4242");
	}

	config->listen_configs[0] = g_ptr_array_new();
	config->listen_configs[1] = g_ptr_array_new();

	/**
	 * 接下来遍历rw_addresses 和 ro_addresses
	 * 启动监听端口
	 */

	int max_ips = 0;
	gchar **ip_ports = NULL;
	proxy_rw type = 0;
	struct chassis_plugin_config * tmp_config = NULL;

	for (type = PROXY_TYPE_WRITE; type <= PROXY_TYPE_READ; type++) {
		max_ips = get_num_of_ips(chas->listen_addresses[type]->str);
		ip_ports = g_strsplit (chas->listen_addresses[type]->str, ",", max_ips);

		if (NULL == ip_ports) {
			continue;
		}

		int index = 0;
		for (index = 0;  ip_ports[index]; index++) {
			// 将自己添加的占位符" "去掉，将","导致的默认绑定0.0.0.0:3306的问题去掉
			if (ip_ports[index] == NULL ||
					ip_ports[index][0] == '\0' ||
					0 == strcmp(" ",ip_ports[index])) {
				continue;
			}
			tmp_config = chassis_plugin_config_new_init_2(config, ip_ports[index], type, chas);
			if (NULL ==  tmp_config) {
				g_critical("[%s]: bind socket on %s error, will exit with error",
						G_STRLOC,
						ip_ports[index]);
				if (ip_ports) {
					g_strfreev(ip_ports);
					ip_ports = NULL;
				}

				return -1;
			}

			g_ptr_array_add(config->listen_configs[type], tmp_config);
			tmp_config = NULL;
		}

		if (ip_ports) {
			g_strfreev(ip_ports);
			ip_ports = NULL;
		}
	}

	/**
	 * added by zhenfan, 2013/08/27
	 * 将DOM树中相关backends信息初始化到chas->priv->backends中
	 */
	g_debug("[%s]: init default backend config from xml", G_STRLOC);
	if (!config_default_backends_load(chas)) {
		g_critical("Load default backend config in %s error", chas->xml_filename);
		return -1;
	}
	g_debug("[%s]: init PROXY_TYPE_WRITE backends from xml", G_STRLOC);
	if (!config_backends_load(chas, PROXY_TYPE_WRITE)) {
		g_critical("Load PROXY_TYPE_WRITE backends in %s error", chas->xml_filename);
		return -1;
	}
	g_debug("[%s]: init PROXY_TYPE_READ backends from xml", G_STRLOC);
	if (!config_backends_load(chas, PROXY_TYPE_READ)) {
		g_critical("Load PROXY_TYPE_READ backends in %s error", chas->xml_filename);
		g_critical("Although PROXY_TYPE_READ backends not in %s, we still start up!", chas->xml_filename);
		//return -1;
	}

	/* load the script and setup the global tables */
	//network_mysqld_lua_setup_global(chas->priv->sc->L, g);

	/** 初始化负载均衡加权轮询的结构 */
	loadbalance_wrr_new(chas->priv->backends, PROXY_TYPE_WRITE);
	loadbalance_wrr_new(chas->priv->backends, PROXY_TYPE_READ);
	loadbalance_wrr_calc(chas->priv->backends, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(chas->priv->backends, PROXY_TYPE_READ);


	/**
	 * 为了在添加backend时，方便的增加后端检测线程，现将detect_threads放在了chas里面
	 */
	chas->detect_threads = backend_detect_threads_new();

	/** 为每个backend创建一个可行的线程对其状态进行检测 */
	guint index = 0;
	g_mutex_lock(chas->priv->backends->backends_mutex);
	for (index = 0; index < chas->priv->backends->backends->len; index++) {
		network_backend_t *backend = NULL;
		backend = chas->priv->backends->backends->pdata[index];
		if (backend) {
			backend_detect_thread_t *thread = NULL;
			thread = backend_detect_thread_new(chas->detect_threads->len);
			backend_detect_thread_init(thread, chas, backend);
			g_ptr_array_add (chas->detect_threads, thread);
		}
	}
	g_mutex_unlock(chas->priv->backends->backends_mutex);

	// 启动检测线程
	for (index = 0; index < chas->detect_threads->len; index++) {
		backend_detect_thread_t *thread = NULL;
		thread = (backend_detect_thread_t *)(chas->detect_threads->pdata[index]);
		if (thread) {
			g_message("[%s]: start detect thread for backend->%s", G_STRLOC, thread->backend->addr->name->str);
			backend_detect_thread_start(thread);
		}
	}
	
	/**
	 * added by zhenfan, 2013/08/27
	 * 将DOM树中相关pool_config信息初始化到chas->pool_config_per_user[2]中
	 */
	g_debug("[%s]: init PROXY_TYPE_WRITE pool config from xml", G_STRLOC);
	if (!config_pool_config_load(chas, PROXY_TYPE_WRITE)) {
		g_critical("Load PROXY_TYPE_WRITE pool config in %s error", chas->xml_filename);
		return -1;
	}
	g_debug("[%s]: init PROXY_TYPE_READ pool config from xml", G_STRLOC);
	if (!config_pool_config_load(chas, PROXY_TYPE_READ)) {
		g_critical("Load PROXY_TYPE_READ pool config in %s error", chas->xml_filename);
		return -1;
	}

	/*初始化并启动连接池维护线程*/
	chas->connection_scaler_thread = connection_scaler_thread_new();

	/* start the connection scaler thread */
	connection_scaler_thread_init_thread(chas->connection_scaler_thread, chas);
	connection_scaler_thread_start(chas->connection_scaler_thread);

	/**
	 * 初始化连接池
	 * 这时后端可能还是未知状态，初始化可能不能成功
	 * thread_start后，会init一次，所以这里就不用了
	 */
	//connection_pool_init(chas);

	/** 初始化连接限制的代码  */
	chas->rule_table = user_db_sql_rule_table_new();
	chas->para_limit_rules = para_exec_limit_rules_new();
	chas->para_running_statistic_dic = statistic_dic_new();
	chas->dura_limit_rules = dura_exec_limit_rules_new();
	chas->inbytes_list = query_inbytes_list_new();
	chas->outbytes_list = query_outbytes_list_new();
	chas->query_rate_list = query_rate_list_new();
	chas->query_dml_list = query_dml_list_new();

	/** 初始化sql直方图的base*/
	g_debug("[%s]: init global sql statistics base from xml", G_STRLOC);
	if (!config_sql_statistics_base_load(chas)) {
		g_critical("Load sql statistics base in %s error", chas->xml_filename);
		return -1;
	}
	/** 初始化sql直方图统计结构*/
	chas->tmi = time_section_index_new(chas->sql_statistics_base);
	
	/** 初始化sql直方图的开关*/
	g_debug("[%s]: init global sql statistics switch from xml", G_STRLOC);
	if (!config_sql_statistics_switch_load(chas)) {
		g_critical("Load sql statistics switch in %s error", chas->xml_filename);
		return -1;
	}
	
	/** 初始化并启动sql限制统计内存线程*/
	chas->sql_statistics_thread = sql_statistics_thread_new();

	sql_statistics_thread_init(chas->sql_statistics_thread, chas);
	sql_statistics_thread_start(chas->sql_statistics_thread);
	
	/**
	 * added by zhenfan, 2013/08/30
	 */
	g_debug("[%s]: init global single sql rules from xml", G_STRLOC);
	if (!config_sqlrules_load(chas, SQL_SINGLE)) {
		g_critical("Load single sql rules in %s error", chas->xml_filename);
		return -1;
	}
	g_debug("[%s]: init global template sql rules from xml", G_STRLOC);
	if (!config_sqlrules_load(chas, SQL_TEMPLATE)) {
		g_critical("Load template sql rules in %s error", chas->xml_filename);
		return -1;
	}

	if (config_slow_query_log_load(chas) != TRUE) {
		g_critical("Load slow log config in %s error", chas->xml_filename);
		return -1;
	}
	if (chas->slow_query_log_config->is_enabled == TRUE) {
		g_debug("enable slow query log");
		slow_query_log_enable(chas->slow_query_log_config);
	}

	if (!config_table_engine_replaceable_flag_load(chas)) {
		g_critical("Load table engin repalceable config in %s error", chas->xml_filename);
		return -1;
	}

	if (!config_balck_list_flag_load(chas)) {
		g_critical("Load black list config in %s error", chas->xml_filename);
		return -1;
	}

	if (!config_limit_flag_load(chas)) {
		g_critical("Load black list config in %s error. Where go!", chas->xml_filename);
	}

	if (!config_dml_kind_load(chas)) {
		g_critical("Load black list config in %s error. Where go!", chas->xml_filename);
	}

	return 0;
}

G_MODULE_EXPORT int plugin_init(chassis_plugin *p) {
	p->magic        = CHASSIS_PLUGIN_MAGIC;
	p->name         = g_strdup("proxy");
	p->version		= g_strdup(PACKAGE_VERSION);

	p->init         = network_mysqld_proxy_plugin_new;
	p->get_options  = network_mysqld_proxy_plugin_get_options;
	p->apply_config = network_mysqld_proxy_plugin_apply_config;
	p->destroy      = network_mysqld_proxy_plugin_free;

	//p->connection_init_ptr = network_mysqld_proxy_connection_init;

	return 0;
}



/*eof*/
