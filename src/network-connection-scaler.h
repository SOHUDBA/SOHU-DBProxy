/* $%BEGINLICENSE%$
 Copyright (c) 2013, Sohu and/or its affiliates. All rights reserved.

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

#ifndef _NETWORK_CONNECTION_SCALER_H_
#define _NETWORK_CONNECTION_SCALER_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <event.h>     /* struct event_base */

#include "chassis-mainloop.h"
#include "network-backend.h"
#include "network-mysqld.h"
#include "network-conn-pool.h"

struct connection_scaler_thread_t {
	GThread *thr;
	struct event_base *event_base;
	GAsyncQueue *event_queue;
	chassis *chas;
};
/*
typedef struct connection_scaler_thread_t connection_scaler_thread_t;
*/


connection_scaler_thread_t *connection_scaler_thread_new(void);
void connection_scaler_thread_free(
		connection_scaler_thread_t *connection_scaler_thread);
void connection_scaler_thread_init_thread(
		connection_scaler_thread_t *connection_scaler_thread, chassis *chas);
void connection_scaler_thread_start(
		connection_scaler_thread_t *connection_scaler_thread);
void *connection_scaler_thread_loop(
		connection_scaler_thread_t *connection_scaler_thread);



void connection_pool_init (chassis *chas);




#endif /*_NETWORK_CONNECTION_SCALER_H_*/



/*eof*/
