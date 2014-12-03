/*
 * mytest_admin_command_test_dura_limit.c
 *
 *  Created on: 2013-10-14
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
#include "network-dura-exec-limit.h"
#include "network-dura-exec-process.h"

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

START_TEST(test_dura_limit_mange_Add) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->xml_filename = "test_config.xml";
	srv1->dura_limit_rules = dura_exec_limit_rules_new();
    srv1->priv->backends  = network_backends_new();
	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;

	dura_exec_limit *limit = dura_exec_limit_new();

	gchar *cmd = NULL;

	/** 各种错误的用户添加命令 */

	/** 选项不全 */
	cmd = g_strdup("addduralimit");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addduralimit --limit=individual");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddDuraLimit --limit-type=individual --filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddDuraLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name ");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddDuraLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help'");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("AddDuraLimits --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --posi-limit=4");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("AddDuraLimit --limit_type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --posi-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddDuraLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --fillter-sql='select * from help' --posi-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddDuraLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --posi_limit=4");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;


	/** 正确添加用户能够查找得到 */

	cmd = g_strdup("AddDuraLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --posi-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_dura_rule(con->srv->dura_limit_rules, "user",
			"db_name", "select * from help", NULL,
			con->normalized_sql[DURA_SQL_SINGLE], DURA_EXEC_INDIVIDUAL,
			DURA_SQL_SINGLE, limit));


	g_assert(limit->limit_dura == 4);
	g_assert(limit->limit_switch);

	g_assert(!get_sql_dura_rule(con->srv->dura_limit_rules, NULL,
			NULL, "select * from help", NULL,
			con->normalized_sql[DURA_SQL_SINGLE], DURA_EXEC_GLOBAL,
			DURA_SQL_SINGLE, limit));


	cmd = g_strdup("AddDuraLimit --limit-type=global "
			"--filter-type=single --filter-sql='select * from help' --posi-limit=10 --rule-switch=off");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_dura_rule(con->srv->dura_limit_rules, NULL,
			NULL, "select * from help", NULL,
			con->normalized_sql[DURA_SQL_SINGLE], DURA_EXEC_GLOBAL,
			DURA_SQL_SINGLE, limit));

	g_assert(limit->limit_dura == 10);
	g_assert(!(limit->limit_switch));

}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/test_dura_limit_mange_Add",test_dura_limit_mange_Add);
	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}


