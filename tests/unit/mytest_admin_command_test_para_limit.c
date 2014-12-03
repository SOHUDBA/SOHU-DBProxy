/*
 * mytest_admin_command_test_para_limit.c
 *
 *  Created on: 2013-10-9
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
#include "network-para-exec-limit.h"
#include "network-para-exec-process.h"
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

START_TEST(test_para_limit_mange_Add) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->xml_filename = "test_config.xml";
	srv1->para_limit_rules = para_exec_limit_rules_new();
    srv1->priv->backends  = network_backends_new();
	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->client->response = network_mysqld_auth_response_new(0);
	g_string_append(con->client->response->username, "user");
	g_string_append(con->client->response->database, "db_name");
	con->srv = srv1;

	para_exec_limit *limit = para_exec_limit_new();

	gchar *cmd = NULL;

	/** 各种错误的用户添加命令 */

	/** 选项不全 */
	cmd = g_strdup("addparalimit");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addparalimit --limit=individual");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddParaLimit --limit-type=individual --filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name ");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help'");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("AddParaLimits --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --para-limit=4");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("AddParaLimit --limit_type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --para-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --fillter-sql='select * from help' --para-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --para_limit=4");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;


	/** 正确添加用户能够查找得到 */

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --para-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, "user",
			"db_name", "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_INDIVIDUAL,
			PARA_SQL_SINGLE, limit));


	g_assert(limit->limit_para == 4);
	g_assert(limit->limit_switch);

	g_assert(!get_sql_para_rule(con->srv->para_limit_rules, NULL,
			NULL, "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_GLOBAL,
			PARA_SQL_SINGLE, limit));


	cmd = g_strdup("AddParaLimit --limit-type=global "
			"--filter-type=single --filter-sql='select * from help' --para-limit=10 --rule-switch=off");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, NULL,
			NULL, "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_GLOBAL,
			PARA_SQL_SINGLE, limit));

	g_assert(limit->limit_para == 10);
	g_assert(!(limit->limit_switch));

}

START_TEST(test_para_limit_mange_EXEC) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->priv = g_new0(chassis_private, 1);
	srv1->xml_filename = "test_config.xml";
	srv1->para_limit_rules = para_exec_limit_rules_new();
    srv1->priv->backends  = network_backends_new();
	srv1->para_running_statistic_dic = statistic_dic_new();
	srv1->user_infos = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_user_info_free);
	g_rw_lock_init(&srv1->user_lock);

	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->client->response = network_mysqld_auth_response_new(0);
	g_string_append(con->client->response->username, "user");
	g_string_append(con->client->default_db, "db_name");
	con->srv = srv1;
	g_string_append(con->sql_sentence, "select * from help");

	para_exec_limit *limit = para_exec_limit_new();

	gchar *cmd = NULL;

	/**  1.添加限制规则 */

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=single --username=user "
			"--database=db_name --filter-sql='select * from help' --para-limit=4");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, "user",
			"db_name", "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_INDIVIDUAL,
			PARA_SQL_SINGLE, limit));


	g_assert(limit->limit_para == 4);
	g_assert(limit->limit_switch);

	cmd = g_strdup("AddParaLimit --limit-type=individual "
			"--filter-type=template --username=user "
			"--database=db_name --filter-sql='select * from help' --para-limit=8");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, "user",
			"db_name", "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_INDIVIDUAL,
			PARA_SQL_TEMPLATE, limit));


	g_assert(limit->limit_para == 8);
	g_assert(limit->limit_switch);

	cmd = g_strdup("AddParaLimit --limit-type=global "
			"--filter-type=single --filter-sql='select * from help' --para-limit=10");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, NULL,
			NULL, "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_GLOBAL,
			PARA_SQL_SINGLE, limit));


	g_assert(limit->limit_para == 10);
	g_assert(limit->limit_switch);


	cmd = g_strdup("AddParaLimit --limit-type=global "
			"--filter-type=template --filter-sql='select * from help' --para-limit=20");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, NULL,
			NULL, "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_GLOBAL,
			PARA_SQL_TEMPLATE, limit));


	g_assert(limit->limit_para == 20);
	g_assert(limit->limit_switch);

	g_assert(NETWORK_SOCKET_SUCCESS == process_sql_para_rule(con));

	modify_sql_para_rule_limit_para(con->srv->para_limit_rules, "user", "db_name",
			"select * from help", PARA_EXEC_INDIVIDUAL, PARA_SQL_SINGLE, -1);
	g_assert(get_sql_para_rule(con->srv->para_limit_rules, "user",
			"db_name", "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_INDIVIDUAL,
			PARA_SQL_SINGLE, limit));


	g_assert(limit->limit_para == -1);
	g_assert(limit->limit_switch);


	modify_sql_para_rule_limit_para(con->srv->para_limit_rules, "user", "db_name",
				"select * from help", PARA_EXEC_GLOBAL, PARA_SQL_SINGLE, -1);
	g_assert(get_sql_para_rule(con->srv->para_limit_rules, "user",
				"db_name", "select * from help", NULL,
				con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_GLOBAL,
				PARA_SQL_SINGLE, limit));


	g_assert(limit->limit_para == -1);
	g_assert(limit->limit_switch);

	g_assert(NETWORK_SOCKET_ERROR == process_sql_para_rule(con));

	modify_sql_para_rule_limit_switch(con->srv->para_limit_rules, "user", "db_name",
			"select * from help", PARA_EXEC_INDIVIDUAL, PARA_SQL_SINGLE, FALSE);

	g_assert(get_sql_para_rule(con->srv->para_limit_rules, "user",
			"db_name", "select * from help", NULL,
			con->normalized_sql[PARA_SQL_SINGLE], PARA_EXEC_INDIVIDUAL,
			PARA_SQL_SINGLE, limit));


	g_assert(limit->limit_para == -1);
	g_assert(!limit->limit_switch);

	g_assert(NETWORK_SOCKET_SUCCESS == process_sql_para_rule(con));

	delete_sql_para_rule_limit_rule(con->srv->para_limit_rules,
			"user", "db_name", "select * from help",
			PARA_EXEC_INDIVIDUAL, PARA_SQL_SINGLE);

	delete_sql_para_rule_limit_rule(con->srv->para_limit_rules,
			"user", "db_name", "select * from help",
			PARA_EXEC_INDIVIDUAL, PARA_SQL_TEMPLATE);

	g_assert(NETWORK_SOCKET_ERROR == process_sql_para_rule(con));
}



int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/test_para_limit_mange_Add",test_para_limit_mange_Add);
	g_test_add_func("/core/test_para_limit_mange_EXEC",test_para_limit_mange_EXEC);
	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}




