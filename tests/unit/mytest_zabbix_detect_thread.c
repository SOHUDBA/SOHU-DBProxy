/*
 * mytest_zabbix_detect_thread.c
 *
 *  Created on: 2013-6-28
 *      Author: jinxuanhou
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <signal.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#endif /* WIN32 */

#include <glib.h>
#include <glib/gstdio.h> /* for g_unlink */

#include "chassis-mainloop.h"
#include "network-zabbix-agentd.h"
#include "network-detection-event-thread.h"

#define C(x) x, sizeof(x) - 1

chassis *srv1;


void test_init(void) {
	srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends = network_backends_new();
}


void test_clear(void) {
	if (srv1->priv->backends != NULL) {
		network_backends_free(srv1->priv->backends);
		srv1->priv->backends = NULL;
	}
	if (srv1->priv != NULL) {
		g_free(srv1->priv);
		srv1->priv = NULL;
	}
	if (srv1 != NULL) {
		g_free(srv1);
		srv1 = NULL;
	}
}


/**
 * 测试zabbix没有启动的情况
 * @return
 */
void test_backend_detect_thread_loop_zabbix_not_exist(void) {
	network_backend_t *b = NULL;
	test_init();

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2",
			BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3",
			BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	b = network_backends_get(srv1->priv->backends, 0);
	backend_detect_thread_t *thread = backend_detect_thread_new(1);
	backend_detect_thread_init(thread, srv1, b);

	zabbix_socket_set_agentd_cmd(thread->task->sock, "test.a",
			"X.X.X.X", 3306, "test", "test");
	zabbix_socket_set_agentd_address(thread->task->sock, "X.X.X.X",
			10050);

	backend_detect_thread_start(thread);

	g_usleep(3000000);
	g_assert(FALSE == chassis_is_shutdown());

	chassis_set_shutdown_location(G_STRLOC);
	g_assert(TRUE == chassis_is_shutdown());

	backend_detect_thread_free(thread);
	test_clear();
	return;
}


void test_backend_detect_thread_loop_zabbix_cmd_NOT_CORRECT(void) {
	network_backend_t *b = NULL;
	test_init();

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2",
			BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3",
			BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	b = network_backends_get(srv1->priv->backends, 0);
	backend_detect_thread_t *thread = backend_detect_thread_new(1);
	backend_detect_thread_init(thread, srv1, b);

	// 设置socket 的地址
	zabbix_socket_set_agentd_cmd(thread->task->sock, "test.test",
			"X.X.X.X", 3306, "test", "test");
	zabbix_socket_set_agentd_address(thread->task->sock, "X.X.X.X",
			10050);

	chassis_set_startup_location(G_STRLOC);
	backend_detect_thread_start(thread);

	g_usleep(3000000);
	g_assert(FALSE == chassis_is_shutdown());

	chassis_set_shutdown_location(G_STRLOC);
	g_assert(TRUE == chassis_is_shutdown());

	backend_detect_thread_free(thread);
	test_clear();
	return;
}


void test_backend_detect_thread_loop_zabbix_cmd_CORRECT_UP(void) {
	network_backend_t *b = NULL;
	test_init();

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2",
			BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3",
			BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	b = network_backends_get(srv1->priv->backends, 0);
	backend_detect_thread_t *thread = backend_detect_thread_new(1);
	backend_detect_thread_init(thread, srv1, b);

	zabbix_socket_set_agentd_cmd(thread->task->sock, "test.up", "X.X.X.X",
			3306, "test", "test");
	zabbix_socket_set_agentd_address(thread->task->sock, "X.X.X.X",
			10050);

	chassis_set_startup_location(G_STRLOC);
	backend_detect_thread_start(thread);

	g_usleep(3000000);
	g_assert(FALSE == chassis_is_shutdown());

	chassis_set_shutdown_location(G_STRLOC);
	g_assert(TRUE == chassis_is_shutdown());

	backend_detect_thread_free(thread);
	test_clear();
	return;
}


void test_backend_detect_thread_loop_zabbix_cmd_CORRECT_DOWN(void) {
	network_backend_t *b = NULL;
	test_init();

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2",
			BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3",
			BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	b->health_check.inter = 2;
	b->health_check.fastdowninter = 2;

	b = network_backends_get(srv1->priv->backends, 0);
	backend_detect_thread_t *thread = backend_detect_thread_new(1);
	backend_detect_thread_init(thread, srv1, b);

	zabbix_socket_set_agentd_cmd(thread->task->sock, "test.down", "X.X.X.X",
			3306, "test", "test");
	zabbix_socket_set_agentd_address(thread->task->sock, "X.X.X.X",
			10050);

	chassis_set_startup_location(G_STRLOC);
	backend_detect_thread_start(thread);

	g_usleep(3000000);
	g_assert(FALSE == chassis_is_shutdown());

	chassis_set_shutdown_location(G_STRLOC);
	g_assert(TRUE == chassis_is_shutdown());

	backend_detect_thread_free(thread);
	test_clear();
	return;
}


int main(int argc, char **argv) {
	gint ret;
	chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;
	g_log_set_always_fatal(G_LOG_FATAL_MASK);

	g_test_add_func("/core/test_backend_detect_thread_loop_zabbix_not_exist", test_backend_detect_thread_loop_zabbix_not_exist);
	g_test_add_func("/core/test_backend_detect_thread_loop_zabbix_cmd_NOT_CORRECT", test_backend_detect_thread_loop_zabbix_cmd_NOT_CORRECT);
	g_test_add_func("/core/test_backend_detect_thread_loop_zabbix_cmd_CORRECT_UP", test_backend_detect_thread_loop_zabbix_cmd_CORRECT_UP);
	g_test_add_func("/core/test_backend_detect_thread_loop_zabbix_cmd_CORRECT_DOWN", test_backend_detect_thread_loop_zabbix_cmd_CORRECT_DOWN);
	//g_test_add_func("/core/test_zabbix_socket_length_transform", test_zabbix_socket_length_transform);

	ret = g_test_run();

	return ret;
}
