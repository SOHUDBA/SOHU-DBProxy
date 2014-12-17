/*
 * mytest_admin_command_conn_limit.c
 *
 *  Created on: 2013-7-12
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
#include "network-backend-status-updater.h"

typedef enum command_process_result_t {
	COMMAND_PROCESS_SUCCESS,
	COMMAND_PROCESS_ERROR,
	COMMAND_NOT_SUPPORT,
	COMMAND_NO_QUERY_SPECIFIED
} command_process_result_t; /** < admin 命令处理的结果包括执行 */
typedef struct admin_command admin_command; /**< 保存解析后的用户命令 */


extern command_process_result_t admin_command_process(network_mysqld_con *con, gchar *query);

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)

START_TEST(test_admin_conn_limit_mange) {
	/** 初始化内存变量*/
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	srv1->conn_limit[0] = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_int_free);
	srv1->conn_limit[1] = g_hash_table_new_full(g_hash_table_string_hash,
				g_hash_table_string_equal,
				g_hash_table_string_free,
				g_hash_table_int_free);
	srv1->default_conn_limit[0] = 5;
	srv1->default_conn_limit[1] = 6;

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
	gint *conn_limit = NULL;
//	ip_range *ip = NULL;
//	guint ipInint;
//	char *ip_str;
	srv1->xml_filename = "test_config.xml";
	gchar *cmd = NULL;

	/** 添加用户为删除做准备 */
	cmd = g_strdup("adduser --username=root --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root --passwd='root' --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=test --passwd='test' --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 各种错误的用户添加命令 */

	/** 选项不全 */
	cmd = g_strdup("setconnlimit");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root --conn-limit");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root --conn-limit=30 --port-type");
        g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
        g_free(cmd);
        cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("setcoonnlimit --username=root --conn-limit=20 --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("setconnlimit --userRname=root --conn-limit=20 --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root --connn-limit=20 --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root --conn-limit=20 --hosntip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root --conn-limit=20 --hostip=X.X.X.% --port-type=rr");
        g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
        g_free(cmd);
        cmd = NULL;

	/** ip格式错误 */
	cmd = g_strdup("setconnlimit --userRname=root --conn-limit=20 --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 设置的用户不存在 */
	cmd = g_strdup("setconnlimit --username=test1 --conn-limit=20 --hostip=X.X.%.% --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setconnlimit --username=root --conn-limit=20 --hostip=X.X.%.% --port-type=ro");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 设置错误的值 */
	cmd = g_strdup("setconnlimit --username=root --conn-limit=-3 --hostip=X.X.%.% --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 错误的添加都不会在内存更新用户的连接限制 */

	conn_limit = get_conn_limit(srv1, 0, "root", "X.X.X.%");
	g_assert(conn_limit == NULL);

	conn_limit = get_conn_limit(srv1, 0, "root", "X.X.%.%");
	g_assert(conn_limit == NULL);

	conn_limit = get_conn_limit(srv1, 0, "test", "X.X.%.%");
	g_assert(conn_limit == NULL);

	/** 正确添加用户能够查找得到 */
	cmd = g_strdup("setconnlimit --username=test --conn-limit=30 --hostip=X.X.%.% --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	conn_limit = get_conn_limit(srv1, 0, "test", "X.X.%.%");
	g_assert_cmpint(*conn_limit, ==, 30);

	cmd = g_strdup("setconnlimit --username=root --conn-limit=40 --hostip=X.X.X.% --port-type=ro");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	conn_limit = get_conn_limit(srv1, 1, "root", "X.X.X.%");
	g_assert_cmpint(*conn_limit, ==, 40);

	conn_limit = get_conn_limit(srv1, 1, "root", "X.X.%.%");
	g_assert(conn_limit == NULL);

	// 同时修改
	cmd = g_strdup("setconnlimit --username=root --conn-limit=50 --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	conn_limit = get_conn_limit(srv1, 0, "root", "X.X.X.%");
	g_assert_cmpint(*conn_limit, ==, 50);

	conn_limit = get_conn_limit(srv1, 0, "root", "X.X.%.%");
	g_assert(*conn_limit == 50);
}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/test_admin_conn_limit_mange",test_admin_conn_limit_mange);

	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */




