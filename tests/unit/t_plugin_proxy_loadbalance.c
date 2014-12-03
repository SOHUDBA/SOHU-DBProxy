/* $%BEGINLICENSE%$
 Copyright (c) 2013, Sohu and/or its affiliates. All rights reserved.

 $%ENDLICENSE%$ */

/** @addtogroup unittests Unit tests */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <glib.h>

#include "chassis-mainloop.h"
#include "network-mysqld.h"
#include "network-backend.h"


chassis *srv1 = NULL;
network_mysqld_con *con1 = NULL;
network_backends_t *bs1 = NULL;
network_backend_t *b0 = NULL;
network_backend_t *b1 = NULL;
network_backend_t *b2 = NULL;

void test_loadbalance_lc_select(void) {
	GString *s = NULL;

	//printf("begin test_loadbalance_lc_select\n");
	b0->type = BACKEND_TYPE_RW;
	b1->type = BACKEND_TYPE_RO;
	b2->type = BACKEND_TYPE_RO;
	b0->state = BACKEND_STATE_UP;
	b1->state = BACKEND_STATE_UP;
	b2->state = BACKEND_STATE_UP;
	b0->connected_clients[PROXY_TYPE_WRITE] = 10;
	b1->connected_clients[PROXY_TYPE_WRITE] = 0;
	b2->connected_clients[PROXY_TYPE_WRITE] = 0;
	b0->connected_clients[PROXY_TYPE_READ] = 0;
	b1->connected_clients[PROXY_TYPE_READ] = 10;
	b2->connected_clients[PROXY_TYPE_READ] = 0;

	/**
	 * PROXY_TYPE_WRITE: *rw=10 ro=0 ro=0
	 * PROXY_TYPE_READ: rw=0 ro=10 *ro=0
	 */
	s = loadbalance_lc_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_lc_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	/**
	 * PROXY_TYPE_WRITE: *rw=10 ro=0 ro=0(down)
	 * PROXY_TYPE_READ: rw=0 *ro=10 ro=0(down)
	 */
	b2->state = BACKEND_STATE_DOWN;
	s = loadbalance_lc_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_lc_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	/**
	 * PROXY_TYPE_WRITE: *rw=10 ro=0(down) ro=0(down)
	 * PROXY_TYPE_READ: *rw=0 ro=10(down) ro=0(down)
	 */
	b1->state = BACKEND_STATE_DOWN;
	s = loadbalance_lc_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_lc_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	/**
	 * PROXY_TYPE_WRITE: rw=10(down) ro=0(down) ro=0(down)
	 * PROXY_TYPE_READ: rw=0(down) ro=10(down) ro=0(down)
	 */
	b0->state = BACKEND_STATE_DOWN;
	s = loadbalance_lc_select(srv1, PROXY_TYPE_WRITE);
	g_assert(s == NULL);
	s = loadbalance_lc_select(srv1, PROXY_TYPE_READ);
	g_assert(s == NULL);

	return;
}

void test_loadbalance_wrr_select(void) {
	GString *s = NULL;

	//printf("begin test_loadbalance_wrr_select\n");
	b0->type = BACKEND_TYPE_RW;
	b1->type = BACKEND_TYPE_RO;
	b2->type = BACKEND_TYPE_RO;
	b0->state = BACKEND_STATE_UP;
	b1->state = BACKEND_STATE_UP;
	b2->state = BACKEND_STATE_UP;
	b0->connect_w[PROXY_TYPE_WRITE] = 2;
	b1->connect_w[PROXY_TYPE_WRITE] = 3;
	b2->connect_w[PROXY_TYPE_WRITE] = 2;
	b0->connect_w[PROXY_TYPE_READ] = 2;
	b1->connect_w[PROXY_TYPE_READ] = 3;
	b2->connect_w[PROXY_TYPE_READ] = 2;

	/**
	 * PROXY_TYPE_WRITE: *rw=2 ro=3 ro=2
	 * PROXY_TYPE_READ: rw=2 *ro=3 *ro=2
	 */
	loadbalance_wrr_calc(bs1, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(bs1, PROXY_TYPE_READ);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	/**
	 * PROXY_TYPE_WRITE: *rw=2 ro=3 ro=2(down)
	 * PROXY_TYPE_READ: rw=2 *ro=3 ro=2(down)
	 */
	b2->state = BACKEND_STATE_DOWN;
	loadbalance_wrr_calc(bs1, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(bs1, PROXY_TYPE_READ);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	/**
	 * PROXY_TYPE_WRITE: *rw=2 ro=3(down) ro=2(down)
	 * PROXY_TYPE_READ: *rw=2 ro=3(down) ro=2(down)
	 */
	b1->state = BACKEND_STATE_DOWN;
	loadbalance_wrr_calc(bs1, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(bs1, PROXY_TYPE_READ);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);
	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert_cmpstr(s->str, ==, "X.X.X.X:3306");
	g_string_free(s, TRUE);

	/**
	 * PROXY_TYPE_WRITE: rw=2(down) ro=3(down) ro=2(down)
	 * PROXY_TYPE_READ: rw=2(down) ro=3(down) ro=2(down)
	 */
	b0->state = BACKEND_STATE_DOWN;
	loadbalance_wrr_calc(bs1, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(bs1, PROXY_TYPE_READ);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
	g_assert(s == NULL);

	s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
	g_assert(s == NULL);

	return;
}

/** 测试最少连接分配 */
void test_loadbalance_lc_select_a(void) {
	GString *s = NULL;
	guint i = 0;

	//printf("begin test_loadbalance_lc_select\n");
	b0->type = BACKEND_TYPE_RW;
	b1->type = BACKEND_TYPE_RO;
	b2->type = BACKEND_TYPE_RO;
	b0->state = BACKEND_STATE_UP;
	b1->state = BACKEND_STATE_UP;
	b2->state = BACKEND_STATE_UP;
	b0->connected_clients[PROXY_TYPE_WRITE] = 10;
	b1->connected_clients[PROXY_TYPE_WRITE] = 0;
	b2->connected_clients[PROXY_TYPE_WRITE] = 0;
	b0->connected_clients[PROXY_TYPE_READ] = 0;
	b1->connected_clients[PROXY_TYPE_READ] = 10;
	b2->connected_clients[PROXY_TYPE_READ] = 0;

	/**
	 * PROXY_TYPE_WRITE: *rw=10 ro=0 ro=0
	 * PROXY_TYPE_READ: rw=0 ro=10 *ro=0
	 */
	for (i=0; i<10000; i++) {
		s = loadbalance_lc_select(srv1, PROXY_TYPE_WRITE);
		g_string_free(s, TRUE);
	}
	printf("[loadbalance_lc_select][write][b0:%d b1:%d b2:%d]\n", b0->connected_clients[PROXY_TYPE_WRITE],
			b1->connected_clients[PROXY_TYPE_WRITE],
			b2->connected_clients[PROXY_TYPE_WRITE]);
	g_assert(b0->connected_clients[PROXY_TYPE_WRITE] == 10010);
	g_assert(b1->connected_clients[PROXY_TYPE_WRITE] == 0);
	g_assert(b2->connected_clients[PROXY_TYPE_WRITE] == 0);

	for (i=0; i<10000; i++) {
		s = loadbalance_lc_select(srv1, PROXY_TYPE_READ);
		g_string_free(s, TRUE);
	}
	printf("[loadbalance_lc_select][read][b0:%d b1:%d b2:%d]\n", b0->connected_clients[PROXY_TYPE_READ],
			b1->connected_clients[PROXY_TYPE_READ],
			b2->connected_clients[PROXY_TYPE_READ]);
	g_assert(b0->connected_clients[PROXY_TYPE_READ] == 0);
	g_assert(b1->connected_clients[PROXY_TYPE_READ] == 5005);
	g_assert(b2->connected_clients[PROXY_TYPE_READ] == 5005);

	return;
}

/** 测试加权轮询分配 */
void test_loadbalance_wrr_select_a(void) {
	GString *s = NULL;
	guint i = 0;

	//printf("begin test_loadbalance_wrr_select\n");
	b0->type = BACKEND_TYPE_RW;
	b1->type = BACKEND_TYPE_RO;
	b2->type = BACKEND_TYPE_RO;
	b0->state = BACKEND_STATE_UP;
	b1->state = BACKEND_STATE_UP;
	b2->state = BACKEND_STATE_UP;
	b0->connect_w[PROXY_TYPE_WRITE] = 2;
	b1->connect_w[PROXY_TYPE_WRITE] = 3;
	b2->connect_w[PROXY_TYPE_WRITE] = 2;
	b0->connect_w[PROXY_TYPE_READ] = 2;
	b1->connect_w[PROXY_TYPE_READ] = 3;
	b2->connect_w[PROXY_TYPE_READ] = 2;
	b0->connected_clients[PROXY_TYPE_WRITE] = 10;
	b1->connected_clients[PROXY_TYPE_WRITE] = 0;
	b2->connected_clients[PROXY_TYPE_WRITE] = 0;
	b0->connected_clients[PROXY_TYPE_READ] = 0;
	b1->connected_clients[PROXY_TYPE_READ] = 10;
	b2->connected_clients[PROXY_TYPE_READ] = 0;

	/**
	 * PROXY_TYPE_WRITE: *rw=2 ro=3 ro=2
	 * PROXY_TYPE_READ: rw=2 *ro=3 *ro=2
	 */
	loadbalance_wrr_calc(bs1, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(bs1, PROXY_TYPE_READ);

	for (i=0; i<10000; i++) {
		s = loadbalance_wrr_select(srv1, PROXY_TYPE_WRITE);
		g_string_free(s, TRUE);
	}
	printf("[loadbalance_wrr_select][write][b0:%d b1:%d b2:%d]\n", b0->connected_clients[PROXY_TYPE_WRITE],
			b1->connected_clients[PROXY_TYPE_WRITE],
			b2->connected_clients[PROXY_TYPE_WRITE]);
	g_assert(b0->connected_clients[PROXY_TYPE_WRITE] == 10010);
	g_assert(b1->connected_clients[PROXY_TYPE_WRITE] == 0);
	g_assert(b2->connected_clients[PROXY_TYPE_WRITE] == 0);

	for (i=0; i<10000; i++) {
		s = loadbalance_wrr_select(srv1, PROXY_TYPE_READ);
		g_string_free(s, TRUE);
	}
	printf("[loadbalance_wrr_select][read][b0:%d b1:%d b2:%d]\n", b0->connected_clients[PROXY_TYPE_READ],
			b1->connected_clients[PROXY_TYPE_READ],
			b2->connected_clients[PROXY_TYPE_READ]);
	g_assert(b0->connected_clients[PROXY_TYPE_READ] == 0);
	g_assert(b1->connected_clients[PROXY_TYPE_READ] == 6010);
	g_assert(b2->connected_clients[PROXY_TYPE_READ] == 4000);

	return;
}

void testinit() {
	network_backend_t *b = NULL;
	guint i = 0;
	/*
	srv1 = chassis_new();
	srv1->priv = network_mysqld_priv_init();
	*/
	srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2", BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3", BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2", BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 2);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));

	loadbalance_wrr_new(srv1->priv->backends, PROXY_TYPE_WRITE);
	loadbalance_wrr_new(srv1->priv->backends, PROXY_TYPE_READ);
	loadbalance_wrr_calc(srv1->priv->backends, PROXY_TYPE_WRITE);
	loadbalance_wrr_calc(srv1->priv->backends, PROXY_TYPE_READ);

	con1 = g_new0(network_mysqld_con, 1);

	bs1 = srv1->priv->backends;
	b0 = network_backends_get(bs1, 0);
	b1 = network_backends_get(bs1, 1);
	b2 = network_backends_get(bs1, 2);

	//printf("init ok\n");
	for (i = 0; i < network_backends_count(bs1); i++) {
		//g_debug("%s.%d: i=%d", __FILE__, __LINE__, i);
		b = network_backends_get(bs1, i);
		//g_debug("%s",b->addr->name->str);
	}

	return;
}

void testclear() {
	guint i = 0;
	network_backend_t *b = NULL;
	g_free(con1);
	for (i = 0; i < network_backends_count(srv1->priv->backends); i++) {
		b = network_backends_get(srv1->priv->backends, i);
		g_mutex_clear(&(b->mutex[0]));
		g_mutex_clear(&(b->mutex[1]));
	}
	loadbalance_wrr_free(srv1->priv->backends, PROXY_TYPE_WRITE);
	loadbalance_wrr_free(srv1->priv->backends, PROXY_TYPE_READ);
	network_backends_free(srv1->priv->backends);
	g_free(srv1->priv);
	g_free(srv1);
	return;
}

int main(int argc, char **argv) {
	gint r = 0;
	chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	testinit();

	g_test_add_func("/plugin/proxy/loadbalance_lc_select", test_loadbalance_lc_select);
	g_test_add_func("/plugin/proxy/loadbalance_wrr_select", test_loadbalance_wrr_select);
	g_test_add_func("/plugin/proxy/loadbalance_lc_select_a", test_loadbalance_lc_select_a);
	g_test_add_func("/plugin/proxy/loadbalance_wrr_select_a", test_loadbalance_wrr_select_a);

	r = g_test_run();

	testclear();
	chassis_log_free(log);

	return r;
}



/*eof*/
