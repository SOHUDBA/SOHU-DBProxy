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

void test_network_backends_get_by_name(void)
{
	network_backend_t *b = NULL;

	b = network_backends_get_by_name(bs1, "X.X.X.X:3306");
	g_assert(b == NULL);

	b = network_backends_get_by_name(bs1, "X.X.X.X:3306");
	g_assert(b == b0);
	g_assert_cmpstr(b->addr->name->str, == , "X.X.X.X:3306");

	b = network_backends_get_by_name(bs1, "X.X.X.X:3306");
	g_assert(b == b1);
	g_assert_cmpstr(b->addr->name->str, == , "X.X.X.X:3306");

	b = network_backends_get_by_name(bs1, "X.X.X.X:3306");
	g_assert(b == b2);
	g_assert_cmpstr(b->addr->name->str, == , "X.X.X.X:3306");

	return;
}

void test_full_address_split(void)
{
	int n = 0;
	gchar *addr_ip_port = NULL;
	gchar *addr_weight = NULL;
	gchar *addr_state = NULL;

	n = full_address_split("X.X.X.X:3306#4#UP", &addr_ip_port, &addr_weight, &addr_state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_weight, ==, "4");
	g_assert_cmpstr(addr_state, ==, "UP");
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split("X.X.X.X:3306#3", &addr_ip_port, &addr_weight, &addr_state);
	g_assert(n == 2);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_weight, ==, "3");
	g_assert(addr_state == NULL);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split("X.X.X.X:3306", &addr_ip_port, &addr_weight, &addr_state);
	g_assert(n == 1);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(addr_weight == NULL);
	g_assert(addr_state == NULL);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split("X.X.X.X:3306##DOWN", &addr_ip_port, &addr_weight, &addr_state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_weight, ==, "");
	g_assert_cmpstr(addr_state, ==, "DOWN");
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split("X.X.X.X:3306#6#", &addr_ip_port, &addr_weight, &addr_state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_weight, ==, "6");
	g_assert_cmpstr(addr_state, ==, "");
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split("X.X.X.X:3306##", &addr_ip_port, &addr_weight, &addr_state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_weight, ==, "");
	g_assert_cmpstr(addr_state, ==, "");
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	return;
}

void test_full_address_split_new(void)
{
	int n = 0;
	gchar *addr_ip_port = NULL;
	guint weight = 1;
	backend_state_t state = BACKEND_STATE_UNKNOWN;

	n = full_address_split_new("X.X.X.X:3306#4#UP", &addr_ip_port, &weight, &state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(weight == 4);
	g_assert(state == BACKEND_STATE_UP);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split_new("X.X.X.X:3306#3", &addr_ip_port, &weight, &state);
	g_assert(n == 2);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(weight == 3);
	g_assert(state == BACKEND_STATE_UNKNOWN);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split_new("X.X.X.X:3306", &addr_ip_port, &weight, &state);
	g_assert(n == 1);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(weight == 1);
	g_assert(state == BACKEND_STATE_UNKNOWN);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split_new("X.X.X.X:3306##DOWN", &addr_ip_port, &weight, &state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(weight == 1);
	g_assert(state == BACKEND_STATE_DOWN);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split_new("X.X.X.X:3306#6#", &addr_ip_port, &weight, &state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(weight == 6);
	g_assert(state == BACKEND_STATE_UNKNOWN);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	n = full_address_split_new("X.X.X.X:3306##", &addr_ip_port, &weight, &state);
	g_assert(n == 3);
	g_assert_cmpstr(addr_ip_port, ==, "X.X.X.X:3306");
	g_assert(weight == 1);
	g_assert(state == BACKEND_STATE_UNKNOWN);
	g_free(addr_ip_port);
	addr_ip_port = NULL;

	return;
}

void test_full_address_strsplit(void)
{
	gchar **addr_tokens = NULL;
	gchar **saved_addr_tokens = NULL;

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#2#3#10#5");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "2");
	g_assert_cmpstr(addr_tokens[4], ==, "3");
	g_assert_cmpstr(addr_tokens[5], ==, "10");
	g_assert_cmpstr(addr_tokens[6], ==, "5");
	g_assert(addr_tokens[7] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 7);
	saved_addr_tokens = addr_tokens;
	full_address_strsplit_free(addr_tokens);
	g_assert(saved_addr_tokens[0] == NULL);
	g_assert(saved_addr_tokens[1] == NULL);
	g_assert(saved_addr_tokens[2] == NULL);
	g_assert(saved_addr_tokens[3] == NULL);
	g_assert(saved_addr_tokens[4] == NULL);
	g_assert(saved_addr_tokens[5] == NULL);
	g_assert(saved_addr_tokens[6] == NULL);
	g_assert(saved_addr_tokens[7] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 0);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#2#3#10#5#a#b#c");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "2");
	g_assert_cmpstr(addr_tokens[4], ==, "3");
	g_assert_cmpstr(addr_tokens[5], ==, "10");
	g_assert_cmpstr(addr_tokens[6], ==, "5");
	g_assert_cmpstr(addr_tokens[7], ==, "a#b#c");
	g_assert(addr_tokens[8] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 8);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#2#3#10#5#");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "2");
	g_assert_cmpstr(addr_tokens[4], ==, "3");
	g_assert_cmpstr(addr_tokens[5], ==, "10");
	g_assert_cmpstr(addr_tokens[6], ==, "5");
	g_assert_cmpstr(addr_tokens[7], ==, "");
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 8);
	g_assert(addr_tokens[8] == NULL);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#2#3#10##");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "2");
	g_assert_cmpstr(addr_tokens[4], ==, "3");
	g_assert_cmpstr(addr_tokens[5], ==, "10");
	g_assert_cmpstr(addr_tokens[6], ==, "");
	g_assert_cmpstr(addr_tokens[7], ==, "");
	g_assert(addr_tokens[8] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 8);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#2#3#10#");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "2");
	g_assert_cmpstr(addr_tokens[4], ==, "3");
	g_assert_cmpstr(addr_tokens[5], ==, "10");
	g_assert_cmpstr(addr_tokens[6], ==, "");
	g_assert(addr_tokens[7] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 7);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#2#3#10");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "2");
	g_assert_cmpstr(addr_tokens[4], ==, "3");
	g_assert_cmpstr(addr_tokens[5], ==, "10");
	g_assert(addr_tokens[6] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 6);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert(addr_tokens[3] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 3);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP#");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "");
	g_assert(addr_tokens[4] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 4);
	full_address_strsplit_free(addr_tokens);

	addr_tokens = full_address_strsplit_new("X.X.X.X:3306#4#UP####");
	g_assert_cmpstr(addr_tokens[0], ==, "X.X.X.X:3306");
	g_assert_cmpstr(addr_tokens[1], ==, "4");
	g_assert_cmpstr(addr_tokens[2], ==, "UP");
	g_assert_cmpstr(addr_tokens[3], ==, "");
	g_assert_cmpstr(addr_tokens[4], ==, "");
	g_assert_cmpstr(addr_tokens[5], ==, "");
	g_assert_cmpstr(addr_tokens[6], ==, "");
	g_assert(addr_tokens[7] == NULL);
	g_assert_cmpuint(g_strv_length(addr_tokens), ==, 7);
	full_address_strsplit_free(addr_tokens);

	return;
}

void test_full_address_split_new2(void)
{
	int n = 0;
	backend_config_t *bc = NULL;
	backend_config_t bc_def;

	bc = backend_config_new();
	bc_def.ip_port = NULL;
	bc_def.weight = DEFAULT_BACKEND_WEIGHT;
	bc_def.state = BACKEND_STATE_UNKNOWN;
	bc_def.health_check.rise = DEFAULT_BACKEND_RISE;
	bc_def.health_check.fall = DEFAULT_BACKEND_FALL;
	bc_def.health_check.inter = DEFAULT_BACKEND_INTER;
	bc_def.health_check.fastdowninter = DEFAULT_BACKEND_INTER;
	bc_def.health_check.health = 0;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#2#3#10#5", bc, &bc_def);
	g_assert(n == 7);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 5);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#2#3#10#5#a#b#c", bc, &bc_def);
	g_assert(n == 8);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 5);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#2#3#10#5#", bc, &bc_def);
	g_assert(n == 8);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 5);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#2#3#10##", bc, &bc_def);
	g_assert(n == 8);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 10);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#2#3#10#", bc, &bc_def);
	g_assert(n == 7);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 10);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#2#3#10", bc, &bc_def);
	g_assert(n == 6);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 10);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP", bc, &bc_def);
	g_assert(n == 3);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 10);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#", bc, &bc_def);
	g_assert(n == 4);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 10);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP####", bc, &bc_def);
	g_assert(n == 7);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 2);
	g_assert_cmpuint(bc->health_check.fall, ==, 3);
	g_assert_cmpuint(bc->health_check.inter, ==, 10);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 10);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	n = full_address_split_new2("X.X.X.X:3306#4#UP#0#0#0#0", bc, &bc_def);
	g_assert(n == 7);
	g_assert_cmpstr(bc->ip_port, ==, "X.X.X.X:3306");
	g_assert_cmpuint(bc->weight, ==, 4);
	g_assert(bc->state == BACKEND_STATE_UP);
	g_assert_cmpuint(bc->health_check.rise, ==, 1);
	g_assert_cmpuint(bc->health_check.fall, ==, 1);
	g_assert_cmpuint(bc->health_check.inter, ==, 1);
	g_assert_cmpuint(bc->health_check.fastdowninter, ==, 1);
	g_free(bc->ip_port);
	bc->ip_port = NULL;

	backend_config_new(bc);
	bc = NULL;
	return;
}

void testinit(void) {
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

	//loadbalance_wrr_new(srv1->priv->backends, PROXY_TYPE_WRITE);
	//loadbalance_wrr_new(srv1->priv->backends, PROXY_TYPE_READ);
	//loadbalance_wrr_calc(srv1->priv->backends, PROXY_TYPE_WRITE);
	//loadbalance_wrr_calc(srv1->priv->backends, PROXY_TYPE_READ);

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

void testclear(void) {
	guint i = 0;
	network_backend_t *b = NULL;
	g_free(con1);
	for (i = 0; i < network_backends_count(srv1->priv->backends); i++) {
		b = network_backends_get(srv1->priv->backends, i);
		g_mutex_clear(&(b->mutex[0]));
		g_mutex_clear(&(b->mutex[1]));
	}
	//loadbalance_wrr_free(srv1->priv->backends, PROXY_TYPE_WRITE);
	//loadbalance_wrr_free(srv1->priv->backends, PROXY_TYPE_READ);
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

	g_test_add_func("/core/network_backends_get_by_name", test_network_backends_get_by_name);
	g_test_add_func("/core/network_backends_full_address_split", test_full_address_split);
	g_test_add_func("/core/network_backends_full_address_split_new", test_full_address_split_new);
	g_test_add_func("/core/network_backends_full_address_strsplit", test_full_address_strsplit);
	g_test_add_func("/core/network_backends_full_address_split_new2", test_full_address_split_new2);

	r = g_test_run();

	testclear();
	chassis_log_free(log);

	return r;
}



/*eof*/
