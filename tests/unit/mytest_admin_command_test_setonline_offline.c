/*
 * mytest_admin_command_test_setonline_offline.c
 *
 *  Created on: 2013-7-5
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
#include "network-mysqld.h"
#include "network-backend-status-updater.h"
#include "chassis-config-xml-admin.h"

typedef enum command_process_result_t {
	COMMAND_PROCESS_SUCCESS,
	COMMAND_PROCESS_ERROR,
	COMMAND_NOT_SUPPORT,
	COMMAND_NO_QUERY_SPECIFIED
} command_process_result_t; /** < admin 命令处理的结果包括执行 */
typedef struct admin_command admin_command; /**< 保存解析后的用户命令 */


command_process_result_t admin_command_process(network_mysqld_con *con, gchar *query);

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)

/**
 * 测试zabbix没有启动的情况
 * @return
 */
START_TEST(test_admin_backend_mange_SetOnLine) {
	/** 初始化内存变量*/
	network_backend_t *b = NULL;
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();
	srv1->xml_filename = "test_config.xml";
	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2", BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3", BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
	con->srv->detect_threads = g_ptr_array_new();
	//network_mysqld_add_connection(srv1, con);
	/** 初始化文件*/
	/** 初始化文件*/
    backend_config_t config1;
    config1.rw_weight = 2;
    config1.ro_weight = 2;
    config1.health_check.rise = 2;
    config1.health_check.fall = 3;
    config1.health_check.inter = 10;
    config1.health_check.fastdowninter = 10;

    backend_config_t config2;
    config2.rw_weight = 2;
    config2.ro_weight = 2;
    config2.health_check.rise = 2;
    config2.health_check.fall = 3;
    config2.health_check.inter = 10;
    config2.health_check.fastdowninter = 10;
    
    config_addbackend(con->srv->xml_filename, "X.X.X.X:3306", "rw", BACKEND_STATE_UP, &config1);
	config_addbackend(con->srv->xml_filename, "X.X.X.X:3306", "ro", BACKEND_STATE_UP, &config2);
	
	/** 成功*/
	gchar *cmd = g_strdup("setbkonline --backend=X.X.X.X:3306");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
	
	/** bktype没用*/
	cmd = g_strdup("setbkonline --backend=X.X.X.X:3306 --bktype=rw");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
	
	/** 缺少参数*/
	cmd = g_strdup("setbkonline");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(COMMAND_NO_QUERY_SPECIFIED == admin_command_process(con, NULL));
	
	/** 参数错误*/
	cmd = g_strdup("setbkonline --backend=X.X.X.X:3307");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setBKonline --backend=192.1968.x.xx:3308");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setBKonline --backends=X.X.X.X:3308");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setbkonline --backend=X.X.X.X:103307");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("setbkonlines --backend=X.X.X.X:3308");
	g_assert(COMMAND_NOT_SUPPORT == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	//g_ptr_array_free(con->srv->detect_threads, TRUE);
	//con->srv->detect_threads = NULL;

	//network_mysqld_con_free(con);
	//con = NULL;

//	network_backends_free(srv1->priv->backends);
//	srv1->priv->backends = NULL;
//
//	g_free(srv1->priv);
//	srv1->priv = NULL;

//	g_free(srv1);
//	srv1 = NULL;
}

START_TEST(test_admin_backend_mange_SetOffLine) {
	network_backend_t *b = NULL;

	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();
	srv1->xml_filename = "test_config.xml";
	
	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#2", BACKEND_TYPE_RW);
	b = network_backends_get(srv1->priv->backends, 0);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));

	network_backends_add(srv1->priv->backends, "X.X.X.X:3306#3", BACKEND_TYPE_RO);
	b = network_backends_get(srv1->priv->backends, 1);
	g_mutex_init(&(b->mutex[0]));
	g_mutex_init(&(b->mutex[1]));
	

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
	//network_mysqld_add_connection(srv1, con);
	
	/** 初始化文件*/
    backend_config_t config1;
    config1.rw_weight = 2;
    config1.ro_weight = 2;
    config1.health_check.rise = 2;
    config1.health_check.fall = 3;
    config1.health_check.inter = 10;
    config1.health_check.fastdowninter = 10;

    backend_config_t config2;
    config2.rw_weight = 2;
    config2.ro_weight = 2;
    config2.health_check.rise = 2;
    config2.health_check.fall = 3;
    config2.health_check.inter = 10;
    config2.health_check.fastdowninter = 10;
    
    config_addbackend(con->srv->xml_filename, "X.X.X.X:3306", "rw", BACKEND_STATE_UP, &config1);
	config_addbackend(con->srv->xml_filename, "X.X.X.X:3306", "ro", BACKEND_STATE_UP, &config2);
    	
	gchar *cmd = g_strdup("SetbkOffLine --backend=X.X.X.X:3306");
	g_assert(COMMAND_PROCESS_SUCCESS == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
		
	/** backend不存在*/
	cmd = g_strdup("SetbkOffLine --backend=X.X.X.X:3307");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
	
	/** 没有参数*/
	cmd = g_strdup("SetbkOffLine");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(COMMAND_NO_QUERY_SPECIFIED == admin_command_process(con, NULL));

	
	network_backend_t *backend = network_backends_get_by_name(srv1->priv->backends, "X.X.X.X:3306");

	g_assert(backend);
	g_assert(BACKEND_STATE_PENDING == backend->state);
	
	/** 参数错误*/
	cmd = g_strdup("SetbkOffLine --backend=192.1968.x.xx:3308");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("SetbkOffLine --backends=X.X.X.X:3308");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("SetbkOffLine --backend=X.X.X.X:103307");
	g_assert(COMMAND_PROCESS_ERROR == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("SetbkOffLines --backend=X.X.X.X:3308");
	g_assert(COMMAND_NOT_SUPPORT == admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

//	g_ptr_array_free(con->srv->detect_threads, TRUE);
//	con->srv->detect_threads = NULL;

	//network_mysqld_con_free(con);
	//con = NULL;

//	network_backends_free(srv1->priv->backends);
//	srv1->priv->backends = NULL;

//	g_free(srv1->priv);
//	srv1->priv = NULL;

//	g_free(srv1);
//	srv1 = NULL;
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

	g_test_add_func("/core/test_admin_backend_mange_SetOnLine",test_admin_backend_mange_SetOnLine);
	g_test_add_func("/core/test_admin_backend_mange_SetOffLine",test_admin_backend_mange_SetOffLine);

	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */



