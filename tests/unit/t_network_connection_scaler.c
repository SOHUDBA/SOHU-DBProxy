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

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <unistd.h>
#include "chassis-mainloop.h"
#include "network-connection-scaler.h"
#include "glib-ext.h"

chassis *srv1 = NULL;


#if GLIB_CHECK_VERSION(2, 32, 0)

void test_network_connection_scaler_thread_new(void) {
	srv1->connection_scaler_thread = connection_scaler_thread_new();
	g_assert(srv1->connection_scaler_thread);

	/* start the connection scaler thread */
	connection_scaler_thread_init_thread(srv1->connection_scaler_thread, srv1);
	g_assert(srv1->connection_scaler_thread->event_base);

	connection_scaler_thread_start(srv1->connection_scaler_thread);
	g_assert(srv1->connection_scaler_thread->thr);

	g_usleep(2000000);
	g_assert(chassis_is_shutdown() == FALSE);

	chassis_set_shutdown_location(G_STRLOC);
	g_assert(chassis_is_shutdown() == TRUE);

	/* join connection scaler thread, free the pointer */
	if (srv1->connection_scaler_thread)
		connection_scaler_thread_free(srv1->connection_scaler_thread);

	return;
}


void test_network_connection_scaler_connection_pool_init(void) {
	connection_pool_init(srv1);
	return;
}

void testinit() {
	srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306", BACKEND_TYPE_RW);
	network_backends_add(srv1->priv->backends, "X.X.X.X:3306", BACKEND_TYPE_RO);
	network_backends_add(srv1->priv->backends, "X.X.X.X:3306", BACKEND_TYPE_RO);

	srv1->pool_config_per_user[PROXY_TYPE_WRITE]= g_hash_table_new_full(g_str_hash, g_str_equal, g_hash_table_string_free, g_hash_table_pool_config_free);
	srv1->pool_config_per_user[PROXY_TYPE_READ] = g_hash_table_new_full(g_str_hash, g_str_equal, g_hash_table_string_free, g_hash_table_pool_config_free);

	srv1->default_pool_config[PROXY_TYPE_WRITE] = g_new0(user_pool_config, 1);
	srv1->default_pool_config[PROXY_TYPE_WRITE]->max_connections = 20;
	srv1->default_pool_config[PROXY_TYPE_WRITE]->min_connections = 2;
	srv1->default_pool_config[PROXY_TYPE_WRITE]->max_idle_interval = 36;
	srv1->default_pool_config[PROXY_TYPE_READ] = g_new0(user_pool_config, 1);
	srv1->default_pool_config[PROXY_TYPE_READ]->max_connections = 10;
	srv1->default_pool_config[PROXY_TYPE_READ]->min_connections = 1;
	srv1->default_pool_config[PROXY_TYPE_READ]->max_idle_interval = 36;

	return;
}

void testclear() {
	g_free(srv1->default_pool_config[PROXY_TYPE_WRITE]);
	g_free(srv1->default_pool_config[PROXY_TYPE_READ]);

	g_hash_table_destroy(srv1->pool_config_per_user[PROXY_TYPE_WRITE]);
	g_hash_table_destroy(srv1->pool_config_per_user[PROXY_TYPE_READ]);

	network_backends_free(srv1->priv->backends);

	g_free(srv1->priv);
	g_free(srv1);
	return;
}

int main(int argc, char **argv) {
	gint r = 0;
	chassis_log *log = NULL;

	/*g_thread_init(NULL);*/
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG;
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;
	g_log_set_always_fatal (G_LOG_LEVEL_ERROR);

	testinit();

	g_test_add_func("/core/network_connection_scaler_thread_new", test_network_connection_scaler_thread_new);
	g_test_add_func("/core/network_connection_scaler_connection_pool_init", test_network_connection_scaler_connection_pool_init);

	r = g_test_run();

	testclear();
	chassis_log_free(log);

	return r;
}
#else
int main() {
	return 77;
}
#endif



/*eof*/
