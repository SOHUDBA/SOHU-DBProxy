/*
 * mytest_admin_command_test_user_op.c
 *
 *  Created on: 2013-7-10
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
extern gboolean process_passwd(gchar *pwd);

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)

START_TEST(test_process_passwd) {
	gchar *src = g_strdup("abcd");
	g_assert(!process_passwd(src));

	g_free(src);

	src = g_strdup("'abc\\\\\\'\\\\\\''");

	g_assert(process_passwd(src));

	g_assert(0 == strcmp("abc\\'\\'", src));

	g_free(src);

	src = g_strdup("\"a\"bc\\'\\''\"");

	g_assert(process_passwd(src));

	g_assert(0 == strcmp("a\"bc'''", src));

	g_free(src);
}

START_TEST(test_admin_user_mange_Add) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();
	srv1->xml_filename = "test_config.xml";
	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
	user_info *user = NULL;
	ip_range *ip = NULL;
	guint ipInint;
	char *ip_str;
	gchar *cmd = NULL;

	/** 各种错误的用户添加命令 */

	/** 选项不全 */
	cmd = g_strdup("adduser");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root --passwd");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root --passwd=root");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("addusers --username=root --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("adduser --usernames=root --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root --passwdw='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root --passwd='root' --host=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** ip地址错误 */
	cmd = g_strdup("adduser --username=root --passwd='root' --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 错误的添加都不会在内存新增用户 */
	user = get_user_info_for_user(srv1, "root");
	g_assert(!user);

	/** 正确添加用户能够查找得到 */
	cmd = g_strdup("adduser --username=root --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
	user = get_user_info_for_user(srv1, "root");
	g_assert(user);

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.X.%");
	g_free(ip_str);
	ip_str = NULL;

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert(ip_str == NULL);
	user = NULL;

	/** 重复添加可以正常执行 */
	cmd = g_strdup("adduser --username=root --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 添加新的用户，刚才不能查找得到的ip可以正常查找得到 */
	cmd = g_strdup("adduser --username=root --passwd='root' --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
	user = get_user_info_for_user(srv1, "root");
	g_assert(user);
	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.X.%");
	g_free(ip_str);
	ip_str = NULL;

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.%.%");
	g_free(ip_str);
	user = NULL;
}


START_TEST(test_admin_user_mange_Del) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();
	srv1->xml_filename = "test_config.xml";
	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
	user_info *user = NULL;
	ip_range *ip = NULL;
	guint ipInint;
	char *ip_str;
	gchar *cmd = NULL;

	/** 各种错误的用户添加命令 */

	/** 选项不全 */
	cmd = g_strdup("Deluser");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("delusers --username=root --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("Deluser --usernames=root --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("Deluser --username=root --host23=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** ip地址段错误 */
	cmd = g_strdup("Deluser --username=root --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 添加用户为删除做准备 */
	cmd = g_strdup("adduser --username=root1 --passwd='root' --hostip=X.X.X.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root1 --passwd='root' --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("adduser --username=root1 --passwd='root' --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	// 确认用户存在
	user = get_user_info_for_user(srv1, "root1");
	g_assert(user);

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.X.%");
	g_free(ip_str);
	ip_str = NULL;

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.%.%");
	g_free(ip_str);
	ip_str = NULL;

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.%.%");
	user = NULL;
	
	/** 删除用户指定IP*/
	cmd = g_strdup("deluser --username=root1 --hostip=X.X.%.%");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	user = get_user_info_for_user(srv1, "root1");
	g_assert(user);

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert(ip_str == NULL);

	ip = create_ip_range_from_str("X.X.X.X");
	ipInint = ip->maxip;
	ip_range_free(ip);
	ip = NULL;

	ip_str = get_ip_range(ipInint, user);
	g_assert_cmpstr(ip_str, ==, "X.X.X.%");
	g_free(ip_str);
	ip_str = NULL;
	
	/** 删除用户所有IP*/
	cmd = g_strdup("deluser --username=root1");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	user = get_user_info_for_user(srv1, "root1");
	g_assert(user == NULL);
}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/test_process_passwd", test_process_passwd);
	g_test_add_func("/core/test_admin_user_mange_Add",test_admin_user_mange_Add);
	g_test_add_func("/core/test_admin_user_mange_Del",test_admin_user_mange_Del);

	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */


