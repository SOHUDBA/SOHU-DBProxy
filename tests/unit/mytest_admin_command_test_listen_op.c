/*
 * mytest_admin_command_test_listen_op.c
 *
 *  Created on: 2013-11-14
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

#include "glib-ext.h"
#include "chassis-mainloop.h"
#include "network-mysqld.h"
#include "network-mysqld-packet.h"

typedef enum command_process_result_t {
	COMMAND_PROCESS_SUCCESS,
	COMMAND_PROCESS_ERROR,
	COMMAND_NOT_SUPPORT,
	COMMAND_NO_QUERY_SPECIFIED
} command_process_result_t; /** < admin 命令处理的结果包括执行 */

typedef struct admin_command admin_command; /**< 保存解析后的用户命令 */

extern command_process_result_t admin_command_process(network_mysqld_con *con, gchar *query);

#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)
#define END_TEST(x)

START_TEST(test_listen_addr_manage_Add) {
	/** 初始化内存变量*/
	//network_backend_t *b = NULL;
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

	srv1->priv->cons = g_ptr_array_new();
	srv1->listen_addresses[0] = g_string_new(NULL);
	srv1->listen_addresses[1] = g_string_new(NULL);

	srv1->xml_filename = "test_config.xml";

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;

	gchar *cmd = NULL;

	/** 一些错误的命令 */
	cmd = g_strdup("addlistenaddr");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addlistenaddr --backend=127.0.0.1:3458");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addlistenaddr --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addlistenaddr --backend=127.0.0.1:589690 --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addlistenaddr --backend=127.0.0.1:3457 --bktype=rRw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addlistenaddra --backend=127.0.0.1:3457 --bktype=rw");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 添加已有的监听端口出错 */
	g_string_append(con->srv->listen_addresses[0], "127.0.0.1:3455");
	g_string_append(con->srv->listen_addresses[1], "127.0.0.1:3456");

	cmd = g_strdup("addlistenaddr --backend=127.0.0.1:3456 --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 添加成功 */
	cmd = g_strdup("addlistenaddr --backend=127.0.0.1:3457 --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));

	g_assert(strstr(con->srv->listen_addresses[0]->str, "127.0.0.1:3457"));

	g_free(cmd);
	cmd = NULL;

}
END_TEST(test_listen_addr_manage_Add)

START_TEST(test_listen_addr_manage_delete) {
	/** 初始化内存变量*/
	//network_backend_t *b = NULL;
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

	srv1->priv->cons = g_ptr_array_new();
	srv1->listen_addresses[0] = g_string_new(NULL);
	srv1->listen_addresses[1] = g_string_new(NULL);

	srv1->xml_filename = "test_config.xml";

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;

	gchar *cmd = NULL;

	/** 一些错误的命令 */
	cmd = g_strdup("dellistenaddr");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("dellistenaddr --backend=127.0.0.1:3458");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 添加成功 */
	cmd = g_strdup("addlistenaddr --backend=127.0.0.1:3458 --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));

	g_assert(strstr(con->srv->listen_addresses[0]->str, "127.0.0.1:3458"));

	g_free(cmd);
	cmd = NULL;

	/** 删除成功 */
	cmd = g_strdup("dellistenaddr --backend=127.0.0.1:3458 --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));

	g_free(cmd);
	cmd = NULL;
}
END_TEST(test_listen_addr_manage_delete)

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;
	g_log_set_always_fatal (G_LOG_LEVEL_ERROR);

	g_test_add_func("/core/test_listen_addr_manage_Add",test_listen_addr_manage_Add);
	g_test_add_func("/core/test_listen_addr_manage_delete",test_listen_addr_manage_delete);
	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}







