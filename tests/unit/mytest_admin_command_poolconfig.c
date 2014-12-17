/*
 * mytest_admin_command_poolconfig.c
 *
 *  Created on: 2013-7-14
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

START_TEST(test_admin_pool_config_mange) {
	/** 初始化内存变量*/
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();

	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	// 初始化读写端口的连接池配置信息
	srv1->pool_config_per_user[0]= g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_pool_config_free);

	srv1->pool_config_per_user[1] = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			g_hash_table_pool_config_free);
	srv1->xml_filename = "test_config.xml";

	g_rw_lock_init(&srv1->pool_conf_lock[0]);

	g_rw_lock_init(&srv1->pool_conf_lock[1]);

	srv1->default_pool_config[PROXY_TYPE_WRITE] = g_new0(user_pool_config, 1);
	srv1->default_pool_config[PROXY_TYPE_WRITE]->max_connections = 200;
	srv1->default_pool_config[PROXY_TYPE_WRITE]->min_connections = 50;
	srv1->default_pool_config[PROXY_TYPE_WRITE]->max_idle_interval = 3600;// 3600 sec

	srv1->default_pool_config[PROXY_TYPE_READ] = g_new0(user_pool_config, 1);
	srv1->default_pool_config[PROXY_TYPE_READ]->max_connections = 200;
	srv1->default_pool_config[PROXY_TYPE_READ]->min_connections = 50;
	srv1->default_pool_config[PROXY_TYPE_READ]->max_idle_interval = 3600; // 3600 sec

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
//	gint *conn_limit = NULL;

	user_pool_config *pool_config = NULL;

//	ip_range *ip = NULL;
//	guint ipInint;
//	char *ip_str;
	gchar *cmd = NULL;

	/** 添加用户为设置连接池的配置信息做准备 */
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
	cmd = g_strdup("setpoolconfig");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setpoolconfig --username=root");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setpoolconfig --username=root --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setpoolconfig --username=root --max-conn=30 --port-type");
        g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
        g_free(cmd);
        cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("setpooolconfig --username=root --max-conn=20");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("setpoolconfig --userRname=root --min-conn=20");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

//	cmd = g_strdup("setpoolconfig --username=root --max-interval=3600");
//	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
//	g_free(cmd);
//	cmd = NULL;

	cmd = g_strdup("setpoolconfig --username=root --min-conn=20 --port-ttype=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** port-type 取值非法 */
	cmd = g_strdup("setpoolconfig --username=root --min-conn=20 --port-type=ww");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 设置的用户不存在 */
	cmd = g_strdup("setpoolconfig --username=test1 --min-conn=20 --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 设置错误的值 */
	cmd = g_strdup("setpoolconfig --username=root --min-conn=-3 --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 错误的添加都不会在内存更新用户的连接限制 */

	pool_config = get_pool_config_for_user(srv1, "root", 0);
	g_assert(pool_config == NULL);

	pool_config = get_pool_config_for_user(srv1, "test", 0);
	g_assert(pool_config == NULL);

	/** 正确添加用户能够查找得到 */
	cmd = g_strdup("setpoolconfig --username=test --max-conn=300 --port-type=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	pool_config = get_pool_config_for_user(srv1, "test", 0);
	g_assert_cmpint(pool_config->max_connections, ==, 300);
	g_assert_cmpint(pool_config->min_connections, ==, 50);
	g_assert_cmpint(pool_config->max_idle_interval, ==, 3600);

	cmd = g_strdup("setpoolconfig --username=test --min-conn=30 --port-type=ro");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	pool_config = get_pool_config_for_user(srv1, "test", 1);
	g_assert_cmpint(pool_config->max_connections, ==, 200);
	g_assert_cmpint(pool_config->min_connections, ==, 30);
	g_assert_cmpint(pool_config->max_idle_interval, ==, 3600);

	cmd = g_strdup("setpoolconfig --username=test --max-conn=30 --min-conn=25 --max-interval=1800 --port-type=rw --save-option=all");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	pool_config = get_pool_config_for_user(srv1, "test", 0);
	g_assert_cmpint(pool_config->max_connections, ==, 30);
	g_assert_cmpint(pool_config->min_connections, ==, 25);
	g_assert_cmpint(pool_config->max_idle_interval, ==, 1800);

	cmd = g_strdup("setpoolconfig --username=root --max-conn=30 --min-conn=10 --max-interval=4500 --port-type=rw --save-option=mem");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	pool_config = get_pool_config_for_user(srv1, "root", 0);
	g_assert_cmpint(pool_config->max_connections, ==, 30);
	g_assert_cmpint(pool_config->min_connections, ==, 10);
	g_assert_cmpint(pool_config->max_idle_interval, ==, 4500);
}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/test_admin_pool_config_mange",test_admin_pool_config_mange);

	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */




