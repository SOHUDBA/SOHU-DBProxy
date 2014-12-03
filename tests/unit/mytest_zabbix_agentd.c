/*
 * mytest_zabbix_agentd.c
 *
 *  Created on: 2013-6-27
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

#include "network-zabbix-socket.h"
#include "network-zabbix-agentd.h"
#include "network-detection-event-thread.h"

#define C(x) x, sizeof(x) - 1

void test_network_zabbix_result_process(void) {
	backend_result_check_status_t ret;
	GString *str = g_string_new(NULL);
	backend_result *result = backend_result_new();

	ret = network_zabbix_result_process(str, result);
	g_assert_cmpint(BACKEND_CHECK_RESULT_ERROR, ==, ret);

	g_string_append(str, "errno=1;status=down;errmsg=delay 3600 s");
	ret = network_zabbix_result_process(str, result);
	g_assert_cmpint(BACKEND_CHECK_DOWN, ==, ret);
	g_assert_cmpint(1, ==, result->bk_errno);
	g_assert_cmpstr("down", ==, result->bk_status->str);
	g_assert_cmpstr("delay 3600 s", ==, result->bk_errmsg->str);

	g_string_truncate(str, 0);
	g_string_append(str, "errno=0;status=up;errmsg=ok");
	ret = network_zabbix_result_process(str, result);
	g_assert_cmpint(BACKEND_CHECK_UP, ==, ret);
	g_assert_cmpint(0, ==, result->bk_errno);
	g_assert_cmpstr("up", ==, result->bk_status->str);
	g_assert_cmpstr("ok", ==, result->bk_errmsg->str);


	g_string_truncate(str, 0);
	g_string_append(str, "errno=1");
	ret = network_zabbix_result_process(str, result);
	g_assert_cmpint(BACKEND_CHECK_RESULT_ERROR, ==, ret);

	g_string_truncate(str, 0);
	g_string_append(str, "ZBX_NOTSUPPORTED");
	ret = network_zabbix_result_process(str, result);
	g_assert_cmpint(BACKEND_CHECK_NOTSUPPORT, ==, ret);

	g_string_truncate(str, 0);
	g_string_append(str, "ZBX_notsupported");
	ret = network_zabbix_result_process(str, result);
	g_assert_cmpint(BACKEND_CHECK_RESULT_ERROR, ==, ret);

	g_string_free(str, TRUE);
	backend_result_free(result);
}

void test_network_zabbix_status_check_SUCCESS(void) {
	backend_detect_thread_t *detect_thread = NULL;
	network_backend_t *backend = NULL;
	detection_task *task = NULL;
	zabbix_socket *sock = NULL;
	backend_result *bk_result = NULL;
	backend_state_t status;

	detect_thread = backend_detect_thread_new();
	backend = network_backend_new();
	detect_thread->backend = backend;
	task = detection_task_new(detect_thread);
	detect_thread->task = task;

	sock = task->sock;
	bk_result = task->backend_check_result;

	network_address_set_address(backend->addr, "X.X.X.X:3102");

	sock->is_over = FALSE;
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_SUCCESS;
	g_string_truncate(sock->result, 0);
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_SUCCESS;
	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "ZBX_NOTSUPPORTED");
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_SUCCESS;
	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "errno=1;status=down;errmsg=io thread stopped");
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_DOWN, ==, status);
	g_assert_cmpint(1, ==, bk_result->bk_errno);
	g_assert_cmpstr("down", ==, bk_result->bk_status->str);
	g_assert_cmpstr("io thread stopped", ==, bk_result->bk_errmsg->str);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_SUCCESS;
	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "errno=0;status=up;errmsg=replication is ok");
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UP, ==, status);
	g_assert_cmpint(0, ==, bk_result->bk_errno);
	g_assert_cmpstr("up", ==, bk_result->bk_status->str);
	g_assert_cmpstr("replication is ok", ==, bk_result->bk_errmsg->str);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_SUCCESS;
	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "errno=0;tus=up;errmsg=replication is ok");
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	network_backend_free(detect_thread->backend);
	backend_detect_thread_free(detect_thread);

	return;
}

void test_network_zabbix_status_check_OTHER(void) {
	backend_detect_thread_t *detect_thread = NULL;
	network_backend_t *backend = NULL;
	detection_task *task = NULL;
	zabbix_socket *sock = NULL;
	backend_result *bk_result = NULL;
	backend_state_t status;

	detect_thread = backend_detect_thread_new();
	backend = network_backend_new();
	detect_thread->backend = backend;
	task = detection_task_new(detect_thread);
	detect_thread->task = task;

	sock = task->sock;
	bk_result = task->backend_check_result;

	network_address_set_address(backend->addr, "X.X.X.X:3102");

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_TIMEOUT;
	g_string_truncate(sock->result, 0);
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_NETWORK_ERROR;
	g_string_truncate(sock->result, 0);
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_SERVER_CLOSE_CON;
	g_string_truncate(sock->result, 0);
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	sock->is_over = TRUE;
	sock->exit_status = ZABBIX_STATUS_MACHINE_NO_RESULT;
	g_string_truncate(sock->result, 0);
	status = network_zabbix_status_check(task, backend);
	g_assert_cmpint(BACKEND_STATE_UNKNOWN, ==, status);

	network_backend_free(detect_thread->backend);
	backend_detect_thread_free(detect_thread);

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

	g_test_add_func("/core/test_network_zabbix_result_process",test_network_zabbix_result_process);
	g_test_add_func("/core/test_network_zabbix_status_check_SUCCESS",test_network_zabbix_status_check_SUCCESS);
	g_test_add_func("/core/test_network_zabbix_status_check_OTHER",test_network_zabbix_status_check_OTHER);

	ret = g_test_run();

	return ret;
}



