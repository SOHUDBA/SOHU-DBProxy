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
#include "network-detection-event-thread.h"

chassis *srv1 = NULL;

void testinit() {
	srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

}

void testclear() {
	if (srv1 != NULL && srv1->priv != NULL && srv1->priv->backends != NULL) {
		network_backends_free(srv1->priv->backends);
		srv1->priv->backends = NULL;
	}

	if (srv1 != NULL && srv1->priv != NULL) {
		g_free(srv1->priv);
		srv1->priv = NULL;
	}

	if (srv1 != NULL) {
		g_free(srv1);
		srv1 = NULL;
	}

	return;
}

void test_adjust_backend(void) {
	network_backend_t *b = NULL;
	guint health = 0;

	network_backends_add(srv1->priv->backends, "192.168.x.x:3306#2#UN", BACKEND_TYPE_RO);
	network_backends_add(srv1->priv->backends, "192.168.x.x:3306#4#UN", BACKEND_TYPE_RO);
	network_backends_add(srv1->priv->backends, "192.168.x.x:3306#1#UN", BACKEND_TYPE_RO);

	b = network_backends_get(srv1->priv->backends, 0);
	adjust_backend(BACKEND_STATE_UP, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_UP);
	health = b->health_check.rise + b->health_check.fall - 1;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RW);

	adjust_backend(BACKEND_STATE_DOWN, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_UP);
	health--;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RW);

	adjust_backend(BACKEND_STATE_UP, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_UP);
	health = b->health_check.rise + b->health_check.fall - 1;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RW);

	adjust_backend(BACKEND_STATE_DOWN, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_UP);
	health--;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RW);

	adjust_backend(BACKEND_STATE_DOWN, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_UP);
	health--;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RW);

	adjust_backend(BACKEND_STATE_DOWN, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_DOWN);
	health = 0;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RO);

	adjust_backend(BACKEND_STATE_UP, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_DOWN);
	health++;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RO);

	adjust_backend(BACKEND_STATE_DOWN, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_DOWN);
	health = 0;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RO);

	adjust_backend(BACKEND_STATE_UP, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_DOWN);
	health++;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RO);

	adjust_backend(BACKEND_STATE_UP, srv1, b);
	g_assert_cmpint(b->state, ==, BACKEND_STATE_UP);
	health = b->health_check.rise + b->health_check.fall - 1;
	g_assert_cmpint(b->health_check.health, == , health);
	g_assert_cmpint(b->type, ==, BACKEND_TYPE_RW);

	network_backends_free(srv1->priv->backends);
	srv1->priv->backends = NULL;
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

	g_test_add_func("/core/backend/test_adjust_backend", test_adjust_backend);

	r = g_test_run();

	testclear();
	chassis_log_free(log);

	return r;
}



/*eof*/
