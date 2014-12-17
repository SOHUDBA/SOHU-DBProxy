/*
 * mytest_admin_command_test_sqlrule_manage.c
 *
 *  Created on: 2013-8-1
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
#include "network-security-sqlmode.h"

typedef enum command_process_result_t {
	COMMAND_PROCESS_SUCCESS,
	COMMAND_PROCESS_ERROR,
	COMMAND_NOT_SUPPORT,
	COMMAND_NO_QUERY_SPECIFIED
} command_process_result_t; /** < admin 命令处理的结果包括执行 */

typedef struct admin_command admin_command; /**< 保存解析后的用户命令 */
struct admin_command{
	gchar *backend; /**< backend的ip：port */
	gchar *bktype; /**< backend的类型：rw或ro */
	gchar *username; /**< proxy 用户的用户名 */
	gchar *passwd; /**< proxy 用户的密码 */
	gchar *hostip; /**< 允许访问的ip段 */
	gint conn_limit; /**< 要设置的user@ip 连接限制数 */
	gchar *port_type; /**< 要设置的端口类型：rw或ro */
	proxy_rw port_rw_type; /**< 与port_type 对应：rw对应PROXY_TYPE_WRITE; ro对应PROXY_TYPE_READ */
	gint max_conn; /**< 设置连接池的最大连接 */
	gint min_conn; /**< 设置连接池的最小连接 */
	gint max_interval; /**< 设置连接池连接的最大空闲时间 */
	gchar *dbname; /**< 设置数据库相关的属性时的数据库名 */
	gchar *filter_sql; /**< 设置sql限制时的sql语句(可以是非标准化的)*/
	gchar *filter_type_str; /**< 设置sql限制的类别 */
	security_model_type filter_type; /**< filter_type_str对应的security_model_type变量 */
	gchar *filter_action_str; /**< 设置sql限制时的动作，可取值为safe,log,warning,block */
	security_action filter_action; /**< filter_action_str 对应的security_action变量 */
	gchar *filter_is_disabled_str; /**< 设置sql限制时的开关，可取值为true,false */
	gboolean filter_is_disabled; /**< filter_is_disabled_str 对应的gboolean变量 */
	gchar *flag; /** 连接复用的开关参数 */
	gchar *save_option; /**< 保存的选项，mem:保存在内存;disk:保存在磁盘;all:两者 */
	gchar *help_option; /**< 帮助选项，取值是支持的命令 */
	gint rw_weight; /**< 设置backend的写权重 */
	gint ro_weight; /**< 设置backend的读权重 */
	gint rise; /**< 设置backend的连续检测成功次数 */
	gint fall; /**< 设置backend的连续检测失败次数 */
	gint inter; /**< 设置backend的检测间隔 */
	gint fastdowninter; /**< 设置down状态的backend的检测间隔 */
	gint para_limit; /**< 并行限制数 */
	/**
	 * @todo 所有的开关设置使用一个参数
	 */
	gboolean rule_switch; /** 用于标示规则是否启用 */
	gchar *rule_switch_str; /** 设置规则时的开关，可取值为on、off */
	gint limit_type; /** 对应sql限制的类别 ,对应于global和individual */
	gchar *limit_type_str; /** 并发限制或执行时间限制的类型，可取值global、individual */
}; /**< 保存解析后的用户命令 */

extern void admin_command_free(admin_command *command);
extern admin_command * admin_command_new();
extern gboolean process_filter_sql(admin_command *, const char*);
extern command_process_result_t admin_command_process(network_mysqld_con *con, gchar *query);

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)
#define END_TEST

/** 测试自己的--filter-sql='' 处理函数是否正确 */
START_TEST(test_filter_sql_process) {
	char *command_str = NULL;

	/** 测试简单的情况没有包括转义字符的， 用'''定位边界*/
	admin_command *command = admin_command_new();
	command_str = g_strdup("setfilterswitch --username=XXXX --database=mysql --filter-sql='select * from user' "
			"--filter-type=single|template --filter-disabled=true|false");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command->filter_sql, ==, "select * from user");
	g_assert_cmpstr(command_str, ==,
			"setfilterswitch --username=XXXX --database=mysql  --filter-type=single|template --filter-disabled=true|false");

	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;

	/** 测试简单的情况没有包括转义字符的，用'"'定位边界 */
	command = admin_command_new();
	command_str = g_strdup("setfilterswitch --username=XXXX --database=mysql --filter-sql=\"select * from user\" "
				"--filter-type=single|template --filter-disabled=true|false");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command->filter_sql, ==, "select * from user");
	g_assert_cmpstr(command_str, ==,
			"setfilterswitch --username=XXXX --database=mysql  --filter-type=single|template --filter-disabled=true|false");

	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;

	/** 测试复杂的情况包括转义字符的， 用'''定位边界*/
	command = admin_command_new();
	command_str = g_strdup("setfilterswitch --username=XXXX --database=mysql --filter-sql='select\\' * from user' "
			"--filter-type=single|template --filter-disabled=true|false");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command->filter_sql, ==, "select' * from user");
	g_assert_cmpstr(command_str, ==,
			"setfilterswitch --username=XXXX --database=mysql  --filter-type=single|template --filter-disabled=true|false");

	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;

	/** 测试复杂的情况包括转义字符的，用'"'定位边界 */
	command = admin_command_new();
	command_str = g_strdup("setfilterswitch --username=XXXX --database=mysql --filter-sql=\"select \\\"* from user\" "
			"--filter-type=single|template --filter-disabled=true|false");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command->filter_sql, ==, "select \"* from user");
	g_assert_cmpstr(command_str, ==,
			"setfilterswitch --username=XXXX --database=mysql  --filter-type=single|template --filter-disabled=true|false");

	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;

	/** 不包含--filter-sql的情况 */
	command = admin_command_new();
	command_str = g_strdup("setfilterswitch --username=XXXX --database=mysql "
			"--filter-type=single|template --filter-disabled=true|false");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command_str, ==,
			"setfilterswitch --username=XXXX --database=mysql --filter-type=single|template --filter-disabled=true|false");

	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;

	command = admin_command_new();
	command_str = g_strdup("just a test --sql=askdjfkshdf");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command_str, ==,
			"just a test --sql=askdjfkshdf");

	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;


	command = admin_command_new();
	command_str = g_strdup("addsqlfilter --username=test --filter-sql='SElect * #sjdfjasdjfldsf \n from a -- sdfd \n where id in (1)' --database=test --filter-type=template --filter-action=block;");
	g_assert(process_filter_sql(command, command_str));

	g_assert_cmpstr(command_str, ==,
			"addsqlfilter --username=test  --database=test --filter-type=template --filter-action=block;");

	g_assert_cmpstr(command->filter_sql, ==, "SElect * #sjdfjasdjfldsf \n from a -- sdfd \n where id in (1)");
	g_free(command_str);
	command_str = NULL;
	admin_command_free(command);
	command = NULL;
}

START_TEST(test_admin_sqlrule_mange_Add) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->rule_table = user_db_sql_rule_table_new();
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();
	srv1->xml_filename = "test_config.xml";
	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;
	

	gchar *cmd = NULL;

	/** 各种错误的sql过滤规则添加命令 */

	/** 选项不全 */
	cmd = g_strdup("addsqlfilter");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --filter-sql='select * from help' --filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-sql='select * from help' --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-sql='select * from help' --filter-type=single ");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("addsqlfilters --username=root --database=test --filter-sql='select * from help' --filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("addsqlfilter --userame=root --database=test --filter-sql='select * from help' --filadsfter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --databaase=test --filer-sql='select * from help' --filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 取值错误 */
	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-sql=select * from help --filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-sql='select * from help' --filter-type=111 --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-sql='select * from help' --filter-type=single --filter-action=gggg");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	sql_security_rule* rule = NULL;
	/** 添加sql过滤规则 */
	cmd = g_strdup("addsqlfilter --username=root --database=test --filter-sql='select * from help' --filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
	// 查询添加的过滤规则是否正确
	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"root",
			"test",
			"select * from help",
			SQL_SINGLE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from help");
	g_assert_cmpint(rule->action, ==, ACTION_BLOCK);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select #### abdjfsahfksafdlk\n * from help",
			"test",
			"root"));

	/** 设置规则的动作 */
	cmd = g_strdup("setfilteraction --username=root --database=test --filter-sql='select # jhsjdhfahsjfh \n * from help' --filter-type=single --filter-action=warning");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select -- abdjfsahfksafdlk\n * from help",
			"test",
			"root"));
	
	/** 设置规则的开关  */
	cmd = g_strdup("setfilterswitch --username=root --database=test --filter-sql='select # jhsjdhfahsjfh \n * from help' --filter-type=single --filter-disabled=true");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select /* abdjfsahfksafdlk  */ * from help",
			"test",
			"root"));

	/** 添加规则类规则 */
	cmd = g_strdup("addsqlfilter --username=root --database=test "
			"--filter-sql='select a, b, c from help where id in (\\'a\\',\\'b\\')' "
			"--filter-type=template --filter-action=block");

	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"root",
			"test",
			"select a, b, c from help where id in (N)",
			SQL_TEMPLATE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select a, b, c from help where id in (N)");
	g_assert_cmpint(rule->action, ==, ACTION_BLOCK);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select a, #sdkfhsadhf \n b, \t \n     c FROM help where ID in (1)",
			"test",
			"root"));

	/** 设置规则的动作 */
	cmd = g_strdup("setfilteraction --username=root "
			"--database=test "
			"--filter-sql='select a, #sdkfhsadhf \n b, \t \n     c FROM help where ID in (\\'b\\')' "
			"--filter-type=template --filter-action=warning");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select a, #sdkfhsadhf \n b, \t \n     c FROM help where ID in (1)",
			"test",
			"root"));

	/** 设置规则的开关  */
	cmd = g_strdup("setfilterswitch --username=root --database=test "
			"--filter-sql=\"select a, #sdkfhsadhf \n b, \t \n     c FROM help where ID in (\\\"b\\\")\" "
			"--filter-type=template --filter-disabled=true");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select a, #sdkfhsadhf \n b, \t \n     c FROM help where ID in (1)",
			"test",
			"root"));

	cmd = g_strdup("delsqlfilter --username=root --database=test "
			"--filter-sql=\"select a, #sdkfhsadhf \n b, \t \n     c FROM help where ID in ('b')\" "
			"--filter-type=template");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("delsqlfilter --username=root --database=test "
			"--filter-sql=\"select * from help\" "
			"--filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;
}

START_TEST(test_admin_sqlrule_mange_Del) {
	chassis *srv1 = g_new0(chassis, 1);
	srv1->rule_table = user_db_sql_rule_table_new();
	srv1->priv = g_new0(chassis_private, 1);
	srv1->priv->backends  = network_backends_new();
	srv1->xml_filename = "test_config.xml";
	network_mysqld_con *con = network_mysqld_con_new();
	con->client = network_socket_new();
	con->srv = srv1;

	gchar *cmd = NULL;

	/** 各种错误的sql过滤规则删除命令 */

	/** 选项不全 */
	cmd = g_strdup("delsqlfilter");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("delsqlfilter --filter-sql='select * from help' --filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("delsqlfilter --username=root --filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("delsqlfilter --username=root --filter-sql='select * from help'");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 命令错误 */
	cmd = g_strdup("delsqslfilters --username=root --filter-sql='select * from help' --filter-type=single");
	//g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 选项错误 */
	cmd = g_strdup("addsqlfilter --userame=root --database=test --filter-sql='select * from help' --filadsfter-type=single --filter-action=block");
	//g_assert_cmpint(COMMAND_NOT_SUPPORT, ==, admin_command_process(con, cmd));
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	cmd = g_strdup("delsqlfilter --usersdfname=root --filters-sql='select * from help' --filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 取值错误 */
	cmd = g_strdup("delsqlfilter --username=root --filter-sql='select * from help' --filter-type=asjdhf");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 删除不存在的规则 */
	cmd = g_strdup("delsqlfilter --username=root --filter-sql='select * from help' --filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_ERROR, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;


	sql_security_rule* rule = NULL;
	/** 添加sql过滤规则 为后续删除 做准备*/
	/** User   		DB    	SQL      							Type   		Action 		*/
	/**	root   		test   	'select * from help '				single		block  		*/
	/**	test   	test   	'select * from help '				single		warning		*/
	/**	test   	test   	'select * from a where id in (N)'	template	block  		*/
	/**	test   	test   	'select * from a where id in (1)'	single		warning  	*/
	/**	test	   	test   	'select * from a where id in ('A')'	single		log		  	*/

	/** 添加规则 1  */
	cmd = g_strdup("addsqlfilter --username=root "
			"--database=test --filter-sql='select * from help' "
			"--filter-type=single --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"root",
			"test",
			"select * from help",
			SQL_SINGLE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from help");
	g_assert_cmpint(rule->action, ==, ACTION_BLOCK);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	/** 添加规则2  */
	cmd = g_strdup("addsqlfilter --username=test "
			"--database=test --filter-sql='select * from help' "
			"--filter-type=single --filter-action=warning");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"test",
			"test",
			"select * from help",
			SQL_SINGLE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from help");
	g_assert_cmpint(rule->action, ==, ACTION_WARNING);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	/** 添加规则 3  */
	cmd = g_strdup("addsqlfilter --username=test "
			"--database=test --filter-sql='select * from a where id in (1, \\'A\\')' "
			"--filter-type=template --filter-action=block");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"test",
			"test",
			"select * from a where id in (N)",
			SQL_TEMPLATE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from a where id in (N)");
	g_assert_cmpint(rule->action, ==, ACTION_BLOCK);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	/** 添加规则 4  */
	cmd = g_strdup("addsqlfilter --username=test --database=test "
			"--filter-sql='select * from a where id in (1)' "
			"--filter-type=single --filter-action=warning");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"test",
			"test",
			"select * from a where id in (1)",
			SQL_SINGLE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from a where id in (1)");
	g_assert_cmpint(rule->action, ==, ACTION_WARNING);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	/** 添加规则 5  */
	cmd = g_strdup("addsqlfilter --username=test --database=test "
			"--filter-sql='select * from a where id in (\\'A\\')' "
			"--filter-type=single --filter-action=log");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	rule = get_rule_from_user_db_sql_rule(
			con->srv->rule_table,
			"test",
			"test",
			"select * from a where id in ('A')",
			SQL_SINGLE
			);

	g_assert(rule);
	g_assert_cmpstr(rule->sql_content->str, ==, "select * from a where id in ('A')");
	g_assert_cmpint(rule->action, ==, ACTION_LOG);
	g_assert_cmpint(rule->is_disabled, ==, FALSE);

	/** 规则列表查询  */
	/** 对应规则1 */
	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select #### abdjfsahfksafdlk\n * from help",
			"test",
			"root"));
	/** 对应规则2 */
	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM HElp",
			"test",
			"test"));
	/** 对应规则3 */
	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in (1, 2, 3) ",
			"test",
			"test"));

	/** 对应规则4 */
	g_assert(ACTION_WARNING == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in (1) ",
			"test",
			"test"));
	/** 对应规则5 */
	g_assert(ACTION_LOG == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in ('A') ",
			"test",
			"test"));

	/** 设置规则4的动作 */
	cmd = g_strdup("setfilteraction --username=test "
			"--database=test "
			"--filter-sql='select \n * FROM a where id in (1)' "
			"--filter-type=single --filter-action=log");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 对应规则4 */
	g_assert(ACTION_LOG == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in (1) ",
			"test",
			"test"));

	/** 设置规则4的开关 */
	cmd = g_strdup("setfilterswitch --username=test "
			"--database=test "
			"--filter-sql='select \n * FROM a where id in (1)' "
			"--filter-type=single --filter-disabled=true");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 原来规则4的语句对应规则3 */
	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in (1) ",
			"test",
			"test"));

	/** 删除规则 5 */
	cmd = g_strdup("delsqlfilter --username=test --database=test "
			"--filter-sql=\"select \n * FROM a where id in ('A')\" "
			"--filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;


	/** 原来规则5 的语句对应规则3 */
	g_assert(ACTION_BLOCK == sql_security_rule_match_process(
				con->srv->rule_table,
				NULL,
				"select \n * FROM a where id in ('A') ",
				"test",
				"test"));


	/** 删除规则3 */
	cmd = g_strdup("delsqlfilter --username=test --database=test "
			"--filter-sql=\"select \n * FROM a where id in ('A')\" "
			"--filter-type=template");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 原来对应规则3 的语句为safe */
	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in ('A') ",
			"test",
			"test"));

	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM a where id in (1) ",
			"test",
			"test"));

	/** 删除规则1*/
	cmd = g_strdup("delsqlfilter --username=root --database=test "
			"--filter-sql=\"select \n * FROM HELP\" "
			"--filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 原来对应规则1的语句safe */
	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select #### abdjfsahfksafdlk\n * from help",
			"test",
			"root"));

	/** 删除规则2 */
	cmd = g_strdup("delsqlfilter --username=test --database=test "
			"--filter-sql=\"select \n * FROM HELP\" "
			"--filter-type=single");
	g_assert_cmpint(COMMAND_PROCESS_SUCCESS, ==, admin_command_process(con, cmd));
	g_free(cmd);
	cmd = NULL;

	/** 对应规则2 */
	g_assert(ACTION_SAFE == sql_security_rule_match_process(
			con->srv->rule_table,
			NULL,
			"select \n * FROM HElp",
			"test",
			"test"));

}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	chassis_log *log = NULL;
	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/test_filter_sql_process",test_filter_sql_process);
	g_test_add_func("/core/test_admin_sqlrule_mange_Add",test_admin_sqlrule_mange_Add);
	g_test_add_func("/core/test_admin_sqlrule_mange_Del",test_admin_sqlrule_mange_Del);

	gint ret = g_test_run();
	chassis_log_free(log);
	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */




