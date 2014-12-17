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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef _WIN32
#include <winsock2.h> /* mysql.h needs SOCKET */
#endif

#include <mysql.h>
#include <mysqld_error.h>
#include <errno.h>
#include <string.h>


#include "network-backend.h"
#include "glib-ext.h"
//#include "lua-env.h"

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-t.h"
//#include "network-socket-lua.h"
//#include "network-backend-lua.h"
#include "network-conn-pool.h"
//#include "network-conn-pool-lua.h"
//#include "network-injection-lua.h"

#define C(x) x, sizeof(x) - 1

network_mysqld_con_t *network_mysqld_con_t_new() {
	network_mysqld_con_t *st;

	st = g_new0(network_mysqld_con_t, 1);

	st->injected.queries = network_injection_queue_new();
	/**
	 * @author sohu-inc.com
	 * 上下文恢复的语句和mysql server状态更正的语句
	 */
	st->pre_injected.queries = network_injection_queue_new();
	st->post_injected.queries = network_injection_queue_new();
	return st;
}

void network_mysqld_con_t_free(network_mysqld_con_t *st) {
	if (!st) return;

	network_injection_queue_free(st->injected.queries);
	network_injection_queue_free(st->pre_injected.queries);
	network_injection_queue_free(st->post_injected.queries);

	st->injected.queries = NULL;
	st->pre_injected.queries = NULL;
	st->post_injected.queries = NULL;

	g_free(st);
}


