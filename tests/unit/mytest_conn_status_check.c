/*
 * mytest_conn_status_check.c
 *
 *	实现对连接统计信息的测试
 *  Created on: 2013-6-4
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
#include "network-mysqld-packet.h"
#include "network-packet.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)

network_connection_pool *pool_test = NULL;

//测试初始的连接池状态
START_TEST(test_conn_status_init) {
	gint value = -1;

	pool_status *status = get_conn_pool_status(pool_test, "test");
	g_assert(!status);

	value = get_conn_pending_count(pool_test, "test");
	g_assert_cmpint(value, ==, 0);

	value = get_conn_using_count(pool_test, "test");
	g_assert_cmpint(value, ==, 0);

	value = get_conn_idle_count(pool_test, "root");
	g_assert_cmpint(value, ==, 0);
}

//测试连接池操作过程中的连接池的状态
START_TEST(test_conn_status_update) {
	pool_status *status = pool_status_new();

	g_mutex_lock(&status->status_mutex);
	status->conn_num_in_idle = 0;
	status->conn_num_in_pending = 0;
	status->conn_num_in_use = 1;
	g_mutex_unlock(&status->status_mutex);

	insert_conn_pool_status(pool_test, "test", status);

	status = NULL;
	status = get_conn_pool_status(pool_test, "test");
	g_assert(status);

	g_mutex_lock(&status->status_mutex);
	g_assert_cmpint(status->conn_num_in_idle, ==, 0);
	g_assert_cmpint(status->conn_num_in_pending, ==, 0);
	g_assert_cmpint(status->conn_num_in_use, ==, 1);
	g_mutex_unlock(&status->status_mutex);

}

//更新后单独的查询
START_TEST(test_conn_status_post_update) {
	gint value = -1;

	pool_status *status = get_conn_pool_status(pool_test, "test");
	g_assert(status);

	value = get_conn_pending_count(pool_test, "test");
	g_assert_cmpint(value, ==, 0);

	value = get_conn_using_count(pool_test, "test");
	g_assert_cmpint(value, ==, 1);

	value = get_conn_idle_count(pool_test, "test");
	g_assert_cmpint(value, ==, 0);
}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	pool_test = network_connection_pool_new();

	g_test_add_func("/core/test_conn_status_init",test_conn_status_init);
	g_test_add_func("/core/test_conn_status_update",test_conn_status_update);
	g_test_add_func("/core/test_conn_status_post_update",test_conn_status_post_update);

	gint ret = g_test_run();

	network_connection_pool_free(pool_test);
	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */

