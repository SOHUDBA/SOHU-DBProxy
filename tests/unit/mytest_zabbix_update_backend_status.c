/*
 * mytest_zabbix_update_backend_status.c
 *
 *  Created on: 2013-7-1
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
#include "network-backend-status-updater.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)

/**
 * 测试zabbix没有启动的情况
 * @return
 */
START_TEST(test_update_status_from_up_to_down) {
	network_backend_t *b = NULL;
//	guint i = 0;

	chassis *srv1 = g_new0(chassis, 1);
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

	b = network_backends_get(srv1->priv->backends, 0);
	backend_status_update_worker *worker = backend_status_update_worker_new();

	worker->backend = b;
	worker->chas = srv1;
	worker->from = b->state;
	if (b->state == BACKEND_STATE_DOWN) {
		worker->to = BACKEND_STATE_UP;
	} else {
		worker->to = BACKEND_STATE_DOWN;
	}

	backend_status_update_worker_start(worker);
	backend_status_update_worker_free(worker);
}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;
	g_log_set_always_fatal(G_LOG_FATAL_MASK);
	g_test_add_func("/core/test_update_status_from_up_to_down",test_update_status_from_up_to_down);

	gint ret = g_test_run();

	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */

