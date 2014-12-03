/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2012, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */

/**
 * @page page-plugin-admin Administration plugin
 *
 * The admin plugin exposes the internals of the MySQL Proxy on a SQL interface 
 * to the outside world. 
 *
 * @section plugin-admin-options Configuration
 *
 * @li @c --admin-address    defaults to @c :4041
 * @li @c --admin-lua-script specifies the lua script to load that exposes handles the SQL statements
 * @li @c --admin-username   username
 * @li @c --admin-password   password
 *
 * @section plugin-admin-implementation Implementation
 *
 * The admin plugin handles two SQL queries by default that are used by the mysql commandline client when
 * it logins to expose the version string and username. All other queries are returned with an error if they 
 * are not handled by the Lua script (@c --admin-lua-script). 
 *
 * The script provides a @c read_query() function which returns a result-set in the same way as the proxy
 * module does:
 *
 * @include lib/admin.lua
 *
 * @section plugin-admin-missing To fix before 1.0
 *
 * Before MySQL Proxy 1.0 we have to cleanup the admin plugin to:
 *
 * @li replace the hard-coded username, password by a real credential store @see network_mysqld_admin_plugin_apply_config()
 * @li provide a full fleged admin script that exposes all the internal stats @see lib/admin.lua
 *
 * @section plugin-admin-backends Backends 
 *
 * @b TODO The admin plugin should also be able to change and add the information about the backends
 * while the MySQL Proxy is running. It is stored in the @c proxy.global.backends table can be mapped to SQL commands.
 *
 * @li support for @c SHOW @c CREATE @c TABLE should return @code
 *   CREATE TABLE backends {
 *     id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
 *     address VARCHAR(...) NOT NULL,
 *     port INT,
 *     is_enabled INT NOT NULL, -- 0 or 1, a bool
 *   }
 * @endcode
 * @li getting all backends @code
 *   SELECT * FROM backends;
 *   SELECT * FROM backends WHERE id = 1;
 * @endcode
 * @li disable backends (a flag needs to be added to the backend code) @code
 *   UPDATE backends SET is_enabled = 0;
 * @endcode
 * @li adding and removing backends like @code
 *   INSERT INTO backends ( address, port ) VALUES ( "X.X.X.X", 3306 );
 *   DELETE backends WHERE id = 1;
 * @endcode
 *
 * In a similar way the @c config section of @c proxy.global should be exposed allowing the admin plugin to change the
 * configuration at runtime. @see lib/proxy/auto-config.lua
 */

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#include <errno.h>

#include "chassis-mainloop.h"
#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "network-mysqld-t.h"
#include "network-backend-status-updater.h"
#include "network-detection-event-thread.h"

#include "sys-pedantic.h"
#include "glib-ext.h"
//#include "lua-env.h"
#include "network-security-sqlmode.h"
#include "chassis-config-xml-admin.h"
#include "chassis-event-thread.h"
#include "network-para-exec-process.h"
#include "network-sql-statistics.h"
#include "network-query-rate.h"
#include "network-inbytes-statistic.h"
#include "network-outbytes-statistic.h"
#include "network-dml-statistic.h"

#include "chassis-path.h"

#include <gmodule.h>

typedef enum command_process_result_t command_process_result_t;
typedef struct admin_command admin_command;

#define C(x) x, sizeof(x) -1
#define S(x) x->str, x->len
#define COMMAND_MAX_TOKENS 10
#define THREAD_ID_MAX_LENGTH 32

//static void test_proxy_connection_init(chassis *chas);

static const char *proxyhelp_fields[] = {
		"Command","comment",
		NULL
};

static const char *backend_status_fields[] = {
		"backend_ndx", "address",
		"status", "type",
		"connected_clients", "rw_weight",
		"ro_weight", "rise", 
		"fall", "interval", 
		"fastdowninter", "health", NULL
};

static const char * user_status_fields[] = {
		"user", "ip_range",
		"rw_login_limit", "rw_login_count",
		"ro_login_limit","ro_login_count",
		NULL
};

static const char *pool_config_fields[] = {
		"user", "rw_max_connection",
		"rw_min_connection", "rw_idle_interval",
		"ro_max_connection", "ro_min_connection",
		"ro_idle_interval", NULL
};

static const char *pool_status_fields[] = {
		"user","backend",
		"rw_conn_idle", "rw_conn_using",
		"rw_conn_pending", "ro_conn_idle",
		"ro_conn_using", "ro_conn_pending",
		NULL
};

static const char *showsqlfilter_fields[] = {
		"user","database","normalized_sql",
		"rule_action","rule_type",
		"rule_enabled",NULL
};

static const char *showmultiplexswitch_fields[] = {
		"multiplex switch",
		NULL
};

static const char *showprocesslist_fields[] = {
		"Thread Id", "User",
		"Client Host", "Backend Host",
		"Database", "State",
		"Time", "Sql",
		NULL
};

static const char *showlimit_fields[] = {
		"User", "Database", "Normalized_sql", "Limit_type",
		"Sql_normalie_type", "Limit", "Limit_switch", NULL
};

static const char *showparalimitflag_fields[] = {
		"ParaLimit_flag", NULL
};

static const char *showduralimitflag_fields[] = {
		"DuraLimit_flag", NULL
};

static const char *showqueryresponsetime_fields[] = {
		"Time", "User",
		"Db", "Sql",
		"Count", "Total",
		NULL
};

static const char *showtotalresponsetime_fields[] = {
		"Time", "Count",
		"Total",
		NULL
};

static const char *showstatisticsswitch_fields[] = {
		"statistics switch",
		NULL
};



static const char *showconnectionstate_fields[] = {
		"connection_id"
		, "state"
		, "cpu_count", "cpu_time"
		, "iowait_count", "iowait_time"
		,NULL
};

static const char *showthreadconnectionstate_fields[] = {
		"thread_name", "state",
		"cpu_count", "cpu_time",
		"iowait_count", "iowait_time",
		NULL
};

static const char *showglobalconnectionstate_fields[] = {
		"state",
		"cpu_count", "cpu_time",
		"iowait_count", "iowait_time",
		NULL
};

static const char *showlbalgo_fields[] = {
		"port_type", "lbalgo",
		NULL
};

static const char *showloglevel_fields[] = {
		"loglevel",
		NULL
};

static const char *showlistenaddr_fields[] = {
		"port_type", "listenAddr_list",
		NULL
};

static const char *showslowlogconf_fields[] = {
		"enabled", "execute_time", "file",
		NULL
};

static const char *showsqlaccnum_fields[] = {
		"user", "total_sql_num",
		"rw_sql_num","ro_sql_num",
		"droped_sql_num","is_banned","banned_time",
		NULL
};

static const char *showsqlaccswitch_fields[] = {
	"sqlaccswitch", NULL
};

static const char *showthroughputacc_fields[] = {
	"user", "inbytes","is_in_banned","in_banned_time",
	"outbytes","is_out_banned","out_banned_time",
	NULL
};

static const char *showthroughoutswitch_fields[] = {
	"in_through_switch", "out_through_switch",NULL
};

static const char *showblacklistflag_fields[] = {
		"blacklist switch",
		NULL
};

////// DML 相关
static const char *showsqldmlswitch_fields[] = {
	"sqldmlswitch", NULL
};

static const char *showusersqldml_fields[] = {
	"user", "is_banned","banned_time",
	NULL
};

static const char *showsqldmlkind_fields[] = {
	"H_ALTER", "H_CREATE", "H_DELETE",
	"H_DROP", "H_INSERT", "H_REPLACE",
	"H_RENAME", "H_TRUNCATE", "H_UPDATE",
	NULL
};


/** 结果构造函数 */
#define CONSTRUCT_FIELDS_FUNC(x)  GPtrArray * (x)()
#define CONSTRUCT_ROWS_FUNC(x)  GPtrArray * (x)(chassis *chas)

/** 命令处理函数 */
#define ADMIN_COMMAND_PROCESS_FUNC(x) static command_process_result_t (x)(network_mysqld_con *con, admin_command *command)

/** 由命令直接定位到处理函数 */
#define PROCESS_COMMAND(CON, COMMAND, NAME) #NAME##_command_process(CON, COMMAND)

static gboolean sql_space(unsigned char a) {
	return (a == 0x20 || a == 0xA0 || (a > 0x08 && a < 0x0E));
}

struct chassis_plugin_config {
	gchar *address;                   /**< listening address of the admin interface */

	#if 0
	gchar *lua_script;                /**< script to load at the start the connection */
	#endif

	gchar *admin_username;            /**< login username */
	gchar *admin_password;            /**< login password */

	network_mysqld_con *listen_con;
};

enum command_process_result_t {
	COMMAND_PROCESS_SUCCESS,
	COMMAND_PROCESS_ERROR,
	COMMAND_NOT_SUPPORT,
	COMMAND_NO_QUERY_SPECIFIED
}; /** < admin 命令处理的结果包括执行 */

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

	/** 大于等于0 的限制值 */
	guint64 limit;
	gint base; /**< 设置statistics的base */

	gchar *connectionstatefull_str;
	gboolean connectionstatefull;
	gint connection_id; /*< 连接标识 */
	gchar *thread_name; /*< 线程名 */

	gchar *lbalgo_str;

	gchar *loglevel_str;

	gchar *slowlogswitch;
	gchar *slowlogtime;
	gchar *slowlogfile;

	gchar *is_banned; /** 标识是否被封禁 */
	gboolean is_banned_bool;

	/*是否显示不带IP的用户(异常)*/
	gchar *showusernoip_str;
	gboolean showusernoip;

}; /**< 保存解析后的用户命令 */


static gboolean add_conn_limit_helper(chassis *chas, const gchar *port_type_str,
		const gchar *username, const gchar *ip_str, const gint num);
static gboolean del_conn_limit_helper(chassis *chas, const gchar *port_type_str,
		const gchar *username, const gchar *ip_str);
static gboolean set_pool_config_for_user_helper(chassis *chas,
		const gchar *username,
		const gchar *port_type_str,
		const gint max_conn,
		const gint min_conn,
		const gint max_interval);
static gboolean config_setpoolconfig_helper(const gchar* filename,
		const gchar *username, const gchar *port_type_str, const gint max_conn,
		const gint min_conn, const gint max_interval);
static gboolean del_pool_config_for_user_helper(chassis *chas,
		const gchar *username, const gchar *port_type_str);
static gboolean config_delpoolconfig_helper(const gchar* filename,
		const gchar *username, const gchar *port_type_str);


admin_command * admin_command_new(void) {
	admin_command * command = g_new0(admin_command, 1);// 各成员变量的初始值为NULL
	command->conn_limit = -2;
	command->max_conn = -1;
	command->min_conn = -1;
	command->max_interval = -1;
	command->filter_is_disabled = FALSE; // 默认添加的规则是启用的
	command->rw_weight = -1;
	command->ro_weight = -1;
	command->rise = -1;
	command->fall = -1;
	command->inter = -1;
	command->fastdowninter = -1;
	command->para_limit = -2;
	command->rule_switch = TRUE;
	command->limit = 0;

	command->base = -1;
	command->connection_id = -1;
	command->connectionstatefull = FALSE;

	command->is_banned_bool = FALSE;
	command->showusernoip = FALSE;
	return command;
}

void admin_command_free(admin_command *command) {
	if (!command)
		return;

	if (command->backend != NULL) {
		g_free(command->backend);
		command->backend = NULL;
	}

	if (command->bktype != NULL) {
		g_free(command->bktype);
		command->bktype = NULL;
	}

	if (command->username != NULL) {
		g_free(command->username);
		command->username = NULL;
	}

	if (command->passwd != NULL) {
		g_free(command->passwd);
		command->passwd = NULL;
	}

	if (command->hostip != NULL) {
		g_free(command->hostip);
		command->hostip = NULL;
	}

	if (command->port_type != NULL) {
		g_free(command->port_type);
		command->port_type = NULL;
	}

	if (command->dbname != NULL) {
		g_free(command->dbname);
		command->dbname = NULL;
	}

	if (command->filter_sql != NULL) {
		g_free(command->filter_sql);
		command->filter_sql = NULL;
	}

	if (command->filter_type_str != NULL) {
		g_free(command->filter_type_str);
		command->filter_type_str = NULL;
	}

	if (command->filter_action_str != NULL) {
		g_free(command->filter_action_str);
		command->filter_action_str = NULL;
	}

	if (command->filter_is_disabled_str != NULL) {
		g_free(command->filter_is_disabled_str);
		command->filter_is_disabled_str = NULL;
	}

	if (command->flag != NULL) {
		g_free(command->flag);
		command->flag = NULL;
	}

	if (command->save_option != NULL) {
		g_free(command->save_option);
		command->save_option = NULL;
	}

	if (command->help_option != NULL) {
		g_free(command->help_option);
		command->help_option = NULL;
	}

	if (command->rule_switch_str) {
		g_free(command->rule_switch_str);
		command->rule_switch_str = NULL;
	}

	if (command->limit_type_str) {
		g_free(command->limit_type_str);
		command->limit_type_str = NULL;
	}

	if (command->thread_name != NULL) {
		g_free(command->thread_name);
		command->thread_name = NULL;
	}

	if (command->connectionstatefull_str != NULL) {
		g_free(command->connectionstatefull_str);
		command->connectionstatefull_str = NULL;
	}

	if (command->lbalgo_str != NULL) {
		g_free(command->lbalgo_str);
		command->lbalgo_str = NULL;
	}

	if (command->loglevel_str != NULL) {
		g_free(command->loglevel_str);
		command->loglevel_str = NULL;
	}

	if (command->slowlogswitch != NULL) {
		g_free(command->slowlogswitch);
		command->slowlogswitch = NULL;
	}
	if (command->slowlogtime != NULL) {
		g_free(command->slowlogtime);
		command->slowlogtime = NULL;
	}
	if (command->slowlogfile != NULL) {
		g_free(command->slowlogfile);
		command->slowlogfile = NULL;
	}

	if (command->is_banned != NULL) {
		g_free(command->is_banned);
		command->is_banned = NULL;
	}

	if (command->showusernoip_str != NULL) {
		g_free(command->showusernoip_str);
		command->showusernoip_str = NULL;
	}

	g_free(command);
}

int network_mysqld_con_handle_stmt(chassis G_GNUC_UNUSED *chas, network_mysqld_con *con, GString *s) {
	gsize i, j;
	GPtrArray *fields;
	GPtrArray *rows;
	GPtrArray *row;

	
	switch(s->str[NET_HEADER_SIZE]) {
	case COM_QUERY:
		fields = NULL;
		rows = NULL;
		row = NULL;

		if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("select @@version_comment limit 1"))) {
			MYSQL_FIELD *field;

			fields = network_mysqld_proto_fielddefs_new();

			field = network_mysqld_proto_fielddef_new();
			field->name = g_strdup("@@version_comment");
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields, field);

			rows = g_ptr_array_new();
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup("MySQL Enterprise Agent"));
			g_ptr_array_add(rows, row);

			network_mysqld_con_send_resultset(con->client, fields, rows);
			
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("select USER()"))) {
			MYSQL_FIELD *field;

			fields = network_mysqld_proto_fielddefs_new();
			field = network_mysqld_proto_fielddef_new();
			field->name = g_strdup("USER()");
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields, field);

			rows = g_ptr_array_new();
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup("root"));
			g_ptr_array_add(rows, row);

			network_mysqld_con_send_resultset(con->client, fields, rows);
		} else {
//			network_mysqld_con_send_error(con->client, C("(admin-server) query not known"));
			mpe_send_error(con->client, MPE_ADM_HSTMT_UNKNOWN_QUERY);
		}

		/* clean up */
		if (fields) {
			network_mysqld_proto_fielddefs_free(fields);
			fields = NULL;
		}

		if (rows) {
			for (i = 0; i < rows->len; i++) {
				row = rows->pdata[i];

				for (j = 0; j < row->len; j++) {
					g_free(row->pdata[j]);
				}

				g_ptr_array_free(row, TRUE);
			}
			g_ptr_array_free(rows, TRUE);
			rows = NULL;
		}

		break;
	case COM_QUIT:
		break;
	case COM_INIT_DB:
		network_mysqld_con_send_ok(con->client);
		break;
	default:
//		network_mysqld_con_send_error(con->client, C("unknown COM_*"));
		mpe_send_error(con->client, MPE_ADM_HSTMT_UNKNOWN_COMMAND);
		break;
	}

	return 0;
}

NETWORK_MYSQLD_PLUGIN_PROTO(server_con_init) {
	network_mysqld_auth_challenge *challenge;
	GString *packet;

	challenge = network_mysqld_auth_challenge_new();
	challenge->server_version_str = g_strdup("5.1.00-dbproxy-admin-port");
	challenge->server_version     = 50099;
	challenge->charset            = 0x08; /* latin1 */
	challenge->capabilities       = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD;
	challenge->server_status      = SERVER_STATUS_AUTOCOMMIT;
	challenge->thread_id          = 1;

	network_mysqld_auth_challenge_set_challenge(challenge); /* generate a random challenge */

	packet = g_string_new(NULL);
	network_mysqld_proto_append_auth_challenge(packet, challenge);
	con->client->challenge = challenge;

	network_mysqld_queue_append(con->client, con->client->send_queue, S(packet));

	g_string_free(packet, TRUE);
	
	con->state = CON_STATE_SEND_HANDSHAKE;

	g_assert(con->plugin_con_state == NULL);

	con->plugin_con_state = network_mysqld_con_t_new();

	return NETWORK_SOCKET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(server_read_auth) {
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_auth_response *auth;
	GString *excepted_response;
	GString *hashed_password;
	
	recv_sock = con->client;
	send_sock = con->client;

	packet.data = g_queue_peek_head(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	/* decode the packet */
	network_mysqld_proto_skip_network_header(&packet);

	auth = network_mysqld_auth_response_new(con->client->challenge->capabilities);
	if (network_mysqld_proto_get_auth_response(&packet, auth)) {
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}
	if (!(auth->client_capabilities & CLIENT_PROTOCOL_41)) {
		/* should use packet-id 0 */
		network_mysqld_queue_append(con->client, con->client->send_queue, C("\xff\xd7\x07" "4.0 protocol is not supported"));
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}
	
	con->client->response = auth;
	
	/* check if the password matches */
	excepted_response = g_string_new(NULL);
	hashed_password = g_string_new(NULL);

	if (!strleq(S(con->client->response->username), con->config->admin_username, strlen(con->config->admin_username))) {
		//network_mysqld_con_send_error_full(send_sock, C("unknown user"), 1045, "28000");
		mpe_send_error(send_sock, MPE_ADM_RAUTH_UNKNOWN_USER);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else if (network_mysqld_proto_password_hash(hashed_password, con->config->admin_password, strlen(con->config->admin_password))) {
	} else if (network_mysqld_proto_password_scramble(excepted_response,
				S(recv_sock->challenge->auth_plugin_data),
				S(hashed_password))) {
		//network_mysqld_con_send_error_full(send_sock, C("scrambling failed"), 1045, "28000");
		mpe_send_error(send_sock, MPE_ADM_RAUTH_PWD_SCRAMBLE_FAILED);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else if (!g_string_equal(excepted_response, auth->auth_plugin_data)) {
		//network_mysqld_con_send_error_full(send_sock, C("password doesn't match"), 1045, "28000");
		mpe_send_error(send_sock, MPE_ADM_RAUTH_PWD_NOT_MATCHED);
		con->state = CON_STATE_SEND_ERROR; /* close the connection after we have sent this packet */
	} else {
		network_mysqld_con_send_ok(send_sock);
	
		con->state = CON_STATE_SEND_AUTH_RESULT;
	}

	g_string_free(hashed_password, TRUE);	
	g_string_free(excepted_response, TRUE);

	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
	

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * 将返回过程中构造的结果集rows释放
 * @param rows
 */
static void destroy_rows(GPtrArray *rows) {
	if (!rows)
		return;

	guint i = 0;
	guint j = 0;
	GPtrArray *row = NULL;
	if (rows) {
		for (i = 0; i < rows->len; i++) {
			row = rows->pdata[i];

			for (j = 0; j < row->len; j++) {
				g_free(row->pdata[j]);
			}

			g_ptr_array_free(row, TRUE);
		}
		g_ptr_array_free(rows, TRUE);
		rows = NULL;
	}
}

/**
 * 释放放回构造的结果集
 * @param fields
 * @param rows
 */
static void clean_up(GPtrArray *fields, GPtrArray *rows) {
	if (fields != NULL) {
		network_mysqld_proto_fielddefs_free(fields);
		fields = NULL;
	}
	if (rows != NULL) {
		destroy_rows(rows);
		rows = NULL;
	}
}

static GPtrArray * construct_fields(const char **titles) {
	if (NULL == titles) {
		return NULL;
	}

	GPtrArray *fields;
	fields = network_mysqld_proto_fielddefs_new();

	MYSQL_FIELD *field;

	int index = 0;
	for (index = 0; ;index++) {
		if (NULL == titles[index])
			break;
		field = network_mysqld_proto_fielddef_new();
		field->name = g_strdup(titles[index]);
		field->type = FIELD_TYPE_VAR_STRING;
		g_ptr_array_add(fields, field);
	}

	return fields;
}

/**
 * @author sohu-inc.com
 * 获取admin 命令解析的GOptionEntry 变量
 * @param command 需要通过命令行解析要初始化的command
 * @return
 */
static GOptionEntry * network_mysqld_admin_command_get_options(admin_command *command) {
	guint i;

	static GOptionEntry command_entries[] =
	{
		{ "backend",            0, 0, G_OPTION_ARG_STRING, NULL, "backend will be processed", "<ip:port>" },
		{ "bktype",            0, 0, G_OPTION_ARG_STRING, NULL, "backend type will be processed", "<rw/ro>" },
		{ "username",            0, 0, G_OPTION_ARG_STRING, NULL, "username will be processed", "<string>" },
		{ "passwd",            0, 0, G_OPTION_ARG_STRING, NULL, "the password of the processed user", "<string>" },
		{ "hostip",            0, 0, G_OPTION_ARG_STRING, NULL, "client ip allowed to access", "<ip>" },
		{ "conn-limit",            0, 0, G_OPTION_ARG_INT, NULL, "counts allowed to log in", "int" },
		{ "port-type",            0, 0, G_OPTION_ARG_STRING, NULL, "port type you want to set some thing on", "<rw/ro>" },
		{ "max-conn",            0, 0, G_OPTION_ARG_INT, NULL, "max connection of a pool", "int" },
		{ "min-conn",            0, 0, G_OPTION_ARG_INT, NULL, "min connection of a pool", "int" },
		{ "max-interval",            0, 0, G_OPTION_ARG_INT, NULL, "max idle interval of connections in pool", "int" },
		{ "database",            0, 0, G_OPTION_ARG_STRING, NULL, "the database related to this admin command", "<string>" },
		{ "filter-sql",            0, 0, G_OPTION_ARG_STRING, NULL, "sql that want to filter", "<string>" },
		{ "filter-type",            0, 0, G_OPTION_ARG_STRING, NULL, "sql filter type that you want to process", "<string>" },
		{ "filter-action",            0, 0, G_OPTION_ARG_STRING, NULL, "sql filter related action", "<string>" },
		{ "filter-disabled",            0, 0, G_OPTION_ARG_STRING, NULL, "whether sql filter should be disabled", "<string>" },
		{ "flag", 				0, 0, G_OPTION_ARG_STRING, NULL, "whether connection multiplex is on or not", "<string>" },
		{ "save-option",           0, 0, G_OPTION_ARG_STRING, NULL, "save option of config support:mem/disk/all ", "<string:mem/disk/all>" },
		{ "help-option",           0, 0, G_OPTION_ARG_STRING, NULL, "suboption of help,such addbackend", "<string>" },
		{ "rw-weight",            0, 0, G_OPTION_ARG_INT, NULL, "rw weight of backend", "int" },
		{ "ro-weight",            0, 0, G_OPTION_ARG_INT, NULL, "ro weight of backend", "int" },
		{ "rise",                 0, 0, G_OPTION_ARG_INT, NULL, "detect rise of backend", "int" },
		{ "fall",                 0, 0, G_OPTION_ARG_INT, NULL, "detect fall of backend", "int" },
		{ "inter",                0, 0, G_OPTION_ARG_INT, NULL, "interval of detecting of backend", "int" },
		{ "fasedowninter",        0, 0, G_OPTION_ARG_INT, NULL, "interval of detecting of down backend", "int" },
		{ "para-limit",        0, 0, G_OPTION_ARG_INT, NULL, "MaxLimit of parallel execution", "int" },
		{ "posi-limit",        0, 0, G_OPTION_ARG_INT64, NULL, "MaxLimit of parallel execution", "int64" },
		{ "rule-switch",    0, 0, G_OPTION_ARG_STRING, NULL, "whether this rule will be in use", "string"},
		{ "limit-type",     0, 0, G_OPTION_ARG_STRING, NULL, "the type of the limit rule:individual or global", "string"},
		{ "base",                 0, 0, G_OPTION_ARG_INT, NULL, "base of response time statistics info", "int" },

		{ "connectionstatefull",  0, 0, G_OPTION_ARG_STRING, NULL, "whether connection state should be fully displayed", "true|<false>" },
		{ "connection_id"      ,  0, 0, G_OPTION_ARG_INT   , NULL, "Connection Id"                                     , "<int>"      },
		{ "thread_name"        ,  0, 0, G_OPTION_ARG_STRING, NULL, "Thread Name"                                       , "<string>"   },

		{ "lbalgo"             ,  0, 0, G_OPTION_ARG_STRING, NULL, "Load balance algorithm"                            , "lc|<wrr>"   },

		{ "loglevel", 0, 0, G_OPTION_ARG_STRING, NULL, "Log Level", "debug|info|message|warning|critical|error"},

		{ "slowlogswitch", 0, 0, G_OPTION_ARG_STRING, NULL, "Slow Log Switch", "on|off"    },
		{ "slowlogtime"  , 0, 0, G_OPTION_ARG_STRING, NULL, "Slow Log Time"  , "<seconds>" },
		{ "slowlogfile"  , 0, 0, G_OPTION_ARG_STRING, NULL, "Slow Log File"  , "<filename>"},

		{ "is-banned"  , 0, 0, G_OPTION_ARG_STRING, NULL, "Whether is banned or not"  , "on|off"},

		{ "showusernoip"  , 0, 0, G_OPTION_ARG_STRING, NULL, "Whether show user without ip"  , "true|<false>"},

		{ NULL,                   0, 0, G_OPTION_ARG_NONE,   NULL, NULL, NULL }
	};

	i = 0;
	command_entries[i++].arg_data = &(command->backend);
	command_entries[i++].arg_data = &(command->bktype);
	command_entries[i++].arg_data = &(command->username);
	command_entries[i++].arg_data = &(command->passwd);
	command_entries[i++].arg_data = &(command->hostip);
	command_entries[i++].arg_data = &(command->conn_limit);
	command_entries[i++].arg_data = &(command->port_type);
	command_entries[i++].arg_data = &(command->max_conn);
	command_entries[i++].arg_data = &(command->min_conn);
	command_entries[i++].arg_data = &(command->max_interval);
	command_entries[i++].arg_data = &(command->dbname);
	command_entries[i++].arg_data = &(command->filter_sql);
	command_entries[i++].arg_data = &(command->filter_type_str);
	command_entries[i++].arg_data = &(command->filter_action_str);
	command_entries[i++].arg_data = &(command->filter_is_disabled_str);
	command_entries[i++].arg_data = &(command->flag);
	command_entries[i++].arg_data = &(command->save_option);
	command_entries[i++].arg_data = &(command->help_option);
	command_entries[i++].arg_data = &(command->rw_weight);
	command_entries[i++].arg_data = &(command->ro_weight);
	command_entries[i++].arg_data = &(command->rise);
	command_entries[i++].arg_data = &(command->fall);
	command_entries[i++].arg_data = &(command->inter);
	command_entries[i++].arg_data = &(command->fastdowninter);
	command_entries[i++].arg_data = &(command->para_limit);
	command_entries[i++].arg_data = &(command->limit);
	command_entries[i++].arg_data = &(command->rule_switch_str);
	command_entries[i++].arg_data = &(command->limit_type_str);
	command_entries[i++].arg_data = &(command->base);

	command_entries[i++].arg_data = &(command->connectionstatefull_str);
	command_entries[i++].arg_data = &(command->connection_id);
	command_entries[i++].arg_data = &(command->thread_name);

	command_entries[i++].arg_data = &(command->lbalgo_str);

	command_entries[i++].arg_data = &(command->loglevel_str);

	command_entries[i++].arg_data = &(command->slowlogswitch);
	command_entries[i++].arg_data = &(command->slowlogtime);
	command_entries[i++].arg_data = &(command->slowlogfile);

	command_entries[i++].arg_data = &(command->is_banned);

	command_entries[i++].arg_data = &(command->showusernoip_str);

	return command_entries;
}

/**
 * 获取字符创中空格的数目
 * @param query
 * @return
 */
static gint get_space_count(const gchar *query) {
	if (!query)
		return 0;

	gint count = 0;
	const gchar *tmp = query;

	while ('\0' != *tmp) {
		if (' ' == *tmp) {
			count++;
		}
		tmp++;
	}
	return count;
}

/**
 * 字符串标准化，主要是想将开头的空白字符去掉
 * @param query
 */
void remove_spaces(char *query) {
	if (!query)
		return;
	int cur = -1;
	int tail = 0;

	while('\0' != query[tail]) {
		if (cur != tail) {
			if ((-1 == cur) || sql_space(query[cur])) {
				if (sql_space(query[tail])) {
					tail++;
				} else {
					query[++cur] = query[tail++];
				}
			} else {
				query[++cur] = query[tail++];
			}
		} else {
			tail++;
		}
	}
	query[cur + 1] = '\0';
}

/**
 * 检测ip:port格式是否正确,port >= 1025 &&  port <= 65535
 * @param ptr
 * @return
 */
gboolean check_ipandport(const gchar *ptr){

	if(NULL == ptr)
		return FALSE;

	const gchar *temp;
	gsize total_len = 0;
	temp = ptr;

	while ('\0' != *temp && '#' != *temp) {
		total_len++;
		temp++;
	}

	/** process ip **/
	gchar *ip_pattern = "((2(([0-4]\\d)|(5[0-5])))|(1(\\d{2}))|([1-9]\\d)|([1-9]))(\\.((2(([0-4]\\d)|(5[0-5])))|(1(\\d{2}))|([1-9]\\d)|(\\d))){3}";
	GRegex *ip_reg = g_regex_new(ip_pattern, 0, 0, NULL);
	GMatchInfo *ip_match_info;
	g_regex_match(ip_reg, ptr, 0, &ip_match_info);

	gsize ip_len = 0;

	if(g_match_info_matches(ip_match_info)){
		gchar * ip = g_match_info_fetch(ip_match_info, 0);

		temp = ip;
		while('\0' != *temp){
			ip_len++;
			temp++;
		}

		g_free(ip);
		g_match_info_next(ip_match_info, NULL);
	}

	g_match_info_free(ip_match_info);
	g_regex_unref(ip_reg);

    /** process port **/

	if(':' != ptr[ip_len]){
		return FALSE;
	}

	gchar *port_pattern = "\\d{1,}";
	GRegex *port_reg = g_regex_new(port_pattern, 0, 0, NULL);
	GMatchInfo *port_match_info;
	g_regex_match(port_reg, ptr + ip_len + 1, 0, &port_match_info);

	gsize port_num = 0;
	gsize port_len = 0;
	if(g_match_info_matches(port_match_info)){
		gchar * port = g_match_info_fetch(port_match_info, 0);
		temp = port;

		while('\0' != *temp){
			port_len++;
			port_num  = port_num * 10 + *temp -'0';
			temp++;
		}
		g_free(port);
		g_match_info_next(port_match_info, NULL);
	}


	g_match_info_free(port_match_info);
	g_regex_unref(port_reg);

	if((port_len + ip_len + 1) == total_len){

		if(port_num <= 65535 && port_num >= 1025){
			return TRUE;
		}
		else{
			return FALSE;
		}
	}
	else{
		return FALSE;
	}
}

/**
 * 检查backend 类型是否正确,可能的却只为ro/rw
 * @param bktype
 * @return
 */
static gboolean check_bktype(const gchar *bktype) {
	if (0 == g_ascii_strcasecmp(bktype, "RO") || 0 == g_ascii_strcasecmp(bktype, "RW")) {
		return TRUE;
	}

	return FALSE;
}

/**
 * 检查port 类型是否正确,可能的却只为ro/rw
 * @param bktype
 * @return
 */
static gboolean check_port_type(const gchar *port_type) {
	if (0 == g_ascii_strcasecmp(port_type, "RO") || 0 == g_ascii_strcasecmp(port_type, "RW")) {
		return TRUE;
	}
	return FALSE;
}

//static void set_port_type(const gchar *port_type, proxy_rw *port_rw_type) {
//	if (0 == g_ascii_strcasecmp(port_type, "RO")) {
//		*port_rw_type = PROXY_TYPE_READ;
//	} else {
//		*port_rw_type = PROXY_TYPE_WRITE;
//	}
//}

/** 检查command 对应的sql限制的type是否正确 */
static gboolean check_filter_type(admin_command *command) {
	if (0 == g_ascii_strcasecmp(command->filter_type_str, "SINGLE")) {
		command->filter_type = SQL_SINGLE;
		return TRUE;
	}
	if (0 == g_ascii_strcasecmp(command->filter_type_str, "TEMPLATE")) {
		command->filter_type = SQL_TEMPLATE;
		return TRUE;
	}
	return FALSE;
}

/** 检查用户动作设置正确与否 */
static gboolean check_filter_action(admin_command *command) {
	gboolean ret = FALSE;
	switch(command->filter_action_str[0]) {
	case 's':
	case 'S':
		if (0 == g_ascii_strcasecmp(command->filter_action_str, "safe")) {
			command->filter_action = ACTION_SAFE;
			ret = TRUE;
		}
		break;
	case 'l':
	case 'L':
		if (0 == g_ascii_strcasecmp(command->filter_action_str, "log")) {
			command->filter_action = ACTION_LOG;
			ret = TRUE;
		}
		break;
	case 'w':
	case 'W':
		if (0 == g_ascii_strcasecmp(command->filter_action_str, "warning")) {
			command->filter_action = ACTION_WARNING;
			ret = TRUE;
		}
		break;
	case 'b':
	case 'B':
		if (0 == g_ascii_strcasecmp(command->filter_action_str, "block")) {
			command->filter_action = ACTION_BLOCK;
			ret = TRUE;
		}
		break;
	}

	return ret;
}

/** 检查开关设置是否正确 */
static gboolean check_boolean(const gchar *str, gboolean *bool) {
	if (0 == g_ascii_strcasecmp(str, "TRUE") || 0 == g_ascii_strcasecmp(str, "ON") || 0 == g_ascii_strcasecmp(str, "1")) {
		*bool = TRUE;
		return TRUE;
	}
	if (0 == g_ascii_strcasecmp(str, "FALSE") || 0 == g_ascii_strcasecmp(str, "OFF") || 0 == g_ascii_strcasecmp(str, "0")) {
		*bool = FALSE;
		return TRUE;
	}
	return FALSE;
}

static gboolean check_filter_is_disabled(admin_command *command) {
	if (0 == g_ascii_strcasecmp(command->filter_is_disabled_str, "TRUE")) {
		command->filter_is_disabled = TRUE;
		return TRUE;
	}
	if (0 == g_ascii_strcasecmp(command->filter_is_disabled_str, "FALSE")) {
		command->filter_is_disabled = FALSE;
		return TRUE;
	}
	return FALSE;
}

/** 检查规则开关设置是否正确 */
static gboolean check_rule_switch(admin_command *command) {
	if (0 == g_ascii_strcasecmp(command->rule_switch_str, "on")) {
		command->rule_switch = TRUE;
		return TRUE;
	}
	if (0 == g_ascii_strcasecmp(command->rule_switch_str, "off")) {
		command->rule_switch = FALSE;
		return TRUE;
	}
	return FALSE;
}

/** 检查限制规则的类别 */
static gboolean check_rule_type(admin_command *command) {
	if (0 == g_ascii_strcasecmp(command->limit_type_str, "individual")) {
		command->limit_type = 0;
		return TRUE;
	}
	if (0 == g_ascii_strcasecmp(command->limit_type_str, "global")) {
		command->limit_type = 1;
		return TRUE;
	}
	return FALSE;
}

/**
 * 判定ip段的格式是否正确
 * @param hostip
 * @return
 */
static gboolean check_ip_range(const gchar *hostip) {

	guint tmp[2];
	int ret = inet_pton4(hostip, tmp);
	if (ret == 0) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * 检查save option 取值是否正确，可能的取值为mem/disk/all
 * @param save_option
 * @return
 */
static gboolean check_save_option(const gchar* save_option) {
	if (0 == g_ascii_strcasecmp(save_option, "mem") ||
			0 == g_ascii_strcasecmp(save_option, "disk") ||
			0 == g_ascii_strcasecmp(save_option, "all")) {
		return TRUE;
	}

	return FALSE;
}

/**
 * 检查help option的取值
 * @param command
 * @return
 */
static gboolean check_help_option (const gchar *help_option) {
	//  现在只打算支持showbackends、addbackend、delbackend、setbkonline、setbkoffline
	// 后续支持的命令越来越多逐渐添加。 不过是不是提供更细功能的help也有待商榷
	return (0 == g_ascii_strcasecmp(help_option, "addbackend"))?TRUE:\
			(0 == g_ascii_strcasecmp(help_option, "delbackend"))?TRUE:\
					(0 == g_ascii_strcasecmp(help_option, "setbkonline"))?TRUE:\
							(0 == g_ascii_strcasecmp(help_option, "setbkoffline"))?TRUE:\
									(0 == g_ascii_strcasecmp(help_option, "showbackends"))?TRUE:FALSE;
}

/**
 * 只是检查参数的合理性（取值是否正确），不做参数的完整性检查（是否该有某些参数）
 * @param command
 * @return
 */
static command_process_result_t check_command_rationality(admin_command *command) {
	if (!command)
		return COMMAND_PROCESS_SUCCESS;

	// 检查backend->ip:port
	if (command->backend) {
		g_debug("[%s]:going to check whether ip:port is correct",G_STRLOC);
		if (!check_ipandport(command->backend)) {
			g_message("[%s]: ip:port->%s is not correct.",G_STRLOC, command->backend);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查backend的类型
	if (command->bktype) {
		g_debug("[%s]:going to check whether backend type is correct",G_STRLOC);
		if (!check_bktype(command->bktype)) {
			g_message("[%s]: backend type->%s is not correct", G_STRLOC, command->bktype);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查ip段地址是否合乎规范
	if (command->hostip) {
		g_debug("[%s]:going to check whether hostip is in correct pattern", G_STRLOC);
		if (!check_ip_range(command->hostip)) {
			g_message("[%s]:client ip address->%s is not correct", G_STRLOC, command->hostip);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查要访问的设置的port类型
	if (command->port_type) {
		g_debug("[%s]:going to check whether port type is correct", G_STRLOC);
		if (!check_port_type(command->port_type)) {
			g_message("[%s]:port_type->%s is not correct", G_STRLOC, command->port_type);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查sql限制的type是否正确
	if (command->filter_type_str) { // 可能的取值为：single或template
		g_debug("[%s]:going to check whether filter type is right", G_STRLOC);
		if (!check_filter_type(command)) {
			g_message("[%s]:filter_type->%s is not correct", G_STRLOC, command->filter_type_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查sql限制的action 设置是否正确
	if (command->filter_action_str) { // 可能的取值为safe/log/warning/block
		g_debug("[%s]:going to check whether filter action is right", G_STRLOC);
		if (!check_filter_action(command)) {
			g_message("[%s]:filter_action->%s is not correct", G_STRLOC, command->filter_action_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查sql限制的开关设置是否正确
	if (command->filter_is_disabled_str) { // 可能的取值有true/false
		g_debug("[%s]:going to check whether filter switch is right", G_STRLOC);
		if (!check_filter_is_disabled(command)) {
			g_message("[%s]:filter_is_disabled->%s is not correct", G_STRLOC, command->filter_is_disabled_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查规则开关参数是否正确
	if (command->rule_switch_str) {
		g_debug("[%s]:going to check whether help option is correct", G_STRLOC);
		if (!check_rule_switch(command)) {
			g_message("[%s]:filter_is_disabled->%s is not correct", G_STRLOC, command->rule_switch_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查规则类别是否正确
	if (command->limit_type_str) {
		g_debug("[%s]:going to check whether help option is correct", G_STRLOC);
		if (!check_rule_type(command)) {
			g_message("[%s]:limit-type->%s is not correct", G_STRLOC, command->rule_switch_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 检查存储地点的类型
	if (command->save_option) {
		g_debug("[%s]:going to check whether save option is correct", G_STRLOC);
		if (!check_save_option(command->save_option)) {
			g_message("[%s]: save option->%s is not correct", G_STRLOC, command->save_option);
			return COMMAND_PROCESS_ERROR;
		}
	}

	// 后面还需要检查help_option
	if (command->help_option) {
		g_debug("[%s]:going to check whether help option is correct", G_STRLOC);
		if (!check_help_option(command->help_option)) {
			g_message("[%s]: save option->%s is not correct", G_STRLOC, command->help_option);
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (command->connectionstatefull_str) { // 可能的取值有true/false
		g_debug("[%s]:going to check connectionstatefull", G_STRLOC);
		if (!check_boolean(command->connectionstatefull_str, &(command->connectionstatefull))) {
			g_message("[%s]:connectionstatefull->%s is not correct", G_STRLOC, command->connectionstatefull_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (command->showusernoip_str) { // 可能的取值有true/false
		g_debug("[%s]:going to check showusernoip", G_STRLOC);
		if (!check_boolean(command->showusernoip_str, &(command->showusernoip))) {
			g_message("[%s]:showusernoip->%s is not correct", G_STRLOC, command->showusernoip_str);
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (command->is_banned) { // 可能的取值有on/off
		g_debug("[%s]:going to check is_banned", G_STRLOC);
		if (!check_boolean(command->is_banned, &(command->is_banned_bool))) {
			g_message("[%s]:is_banned->%s is not correct", G_STRLOC, command->is_banned);
			return COMMAND_PROCESS_ERROR;
		}
	}

	return COMMAND_PROCESS_SUCCESS;
}

/**
 * 遍历backend列表检查对应的backend是否存在
 * @return
 */
static gboolean backend_exist(const network_backends_t *bs,const gchar *ip_port) {
	if (!ip_port)
		return FALSE;

	network_backend_t *bk_tmp = NULL;
	bk_tmp = network_backends_get_by_name(bs, ip_port);

	if (bk_tmp != NULL) {
		return TRUE;
	}

	return FALSE;
}

/**
 * 检查集群中是否已经有活跃的rw节点，
 * 若有是不允许再添加rw节点的
 * @param bs backend列表
 * @return
 */
static gboolean rw_backend_exist(const network_backends_t *bs) {
	gboolean ret = FALSE;
	guint index= 0;
	network_backend_t *tmp_backend = NULL;
	g_mutex_lock(bs->backends_mutex);
	for (index = 0; index < bs->backends->len; index++) {
		tmp_backend = bs->backends->pdata[index];
		if (tmp_backend &&
				(tmp_backend->type == BACKEND_TYPE_RW) &&
				(tmp_backend->state == BACKEND_STATE_UP)) {
			ret = TRUE;
			break;
		}
	}
	g_mutex_unlock(bs->backends_mutex);
	return ret;
}

gchar** my_g_strsplit (const gchar *string,
		const gchar *delimiter,
		gint         max_tokens) {
	GSList *string_list = NULL, *slist;
	gchar **str_array, *s;
	guint n = 0;
	const gchar *remainder;

	g_return_val_if_fail (string != NULL, NULL);
	g_return_val_if_fail (delimiter != NULL, NULL);
	g_return_val_if_fail (delimiter[0] != '\0', NULL);

	if (max_tokens < 1)
		max_tokens = G_MAXINT;

	remainder = string;
	s = strstr (remainder, delimiter);
	if (s) {
		gsize delimiter_len = strlen (delimiter);

		while (--max_tokens && s) {
			gsize len;

			len = s - remainder;
			string_list = g_slist_prepend (string_list,
					g_strndup (remainder, len));
			n++;
			remainder = s + delimiter_len;
			s = strstr (remainder, delimiter);
		}
	}
	if (*string) {
		n++;
		gsize len = strlen (remainder);
		string_list = g_slist_prepend (string_list, g_strndup (remainder, len));
	}

	str_array = g_new (gchar*, n + 1);

	str_array[n--] = NULL;
	for (slist = string_list; slist; slist = slist->next)
		str_array[n--] = slist->data;

	g_slist_free (string_list);

	return str_array;
}

void my_g_strfreev (gchar **str_array){
	if (str_array) {
		int i;

		for (i = 0; str_array[i] != NULL; i++)
			g_free (str_array[i]);

		g_free (str_array);
	}
}

/** 由于--filter-sql="sql 语句" socket 语句会比较复杂需要自己做转义处理*/
gboolean process_filter_sql(admin_command *command, gchar *query) {
	if (NULL == command || NULL == query)
		return TRUE;

	gchar *filter_sql_pos = strstr(query, "--filter-sql=");
	if (NULL != filter_sql_pos) {
		/** 接下来定位sql的具体值 约定sql需要是以 '\'' 或 '"' 开头和结尾*/
		gchar *sql_pos = strstr(filter_sql_pos, "=");
		if (NULL == sql_pos || ('\'' != *(sql_pos + 1) && '"' != *(sql_pos + 1))){
			return FALSE;
		}
		gchar transfer =  *(sql_pos + 1);
		gchar *index = sql_pos + 2;
		gint transfer_no = -1;
		gboolean pre_is_dash = FALSE;
		GString *buffer = g_string_new(NULL);
		while('\0' != *index && transfer_no < 0) {
			if ('\\' == *index) {
				if (pre_is_dash) {
					pre_is_dash = FALSE;
					g_string_append_c(buffer, *index);
				} else {
					if (transfer == *(index + 1)) {
						index ++;
						g_string_append_c(buffer, *index);
						pre_is_dash = FALSE;
					} else {
						pre_is_dash = TRUE;
					}
				}
			} else if (transfer == *index) {
				transfer_no++;
				pre_is_dash = FALSE;
			} else {
				g_string_append_c(buffer, *index);
				pre_is_dash= FALSE;
			}
			index++;
		}
		/** 接下来将query中的sql语句去掉 */
		while ('\0' != *index) {
			*filter_sql_pos = *index;
			filter_sql_pos++;
			index++;
		}
		*filter_sql_pos = '\0';
		command->filter_sql = g_strdup(buffer->str);
		g_string_free(buffer, TRUE);
	}
	return TRUE;
}

/**==============================
 * 下面是每个命令处理的函数
 ===============================*/

/**
 * 构造help的命令的fields字段
 * @return
 */
static GPtrArray * construct_help_fields() {
	return construct_fields(proxyhelp_fields);
}

/**
 * 构造help 的内容字段
 * @return
 */
static GPtrArray *construct_help_rows() {
	GPtrArray *rows;
	GPtrArray *row;

	rows = g_ptr_array_new();
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("AddBackend"));
	g_ptr_array_add(row,
			g_strdup("add a new backend to backend list,example: Addbackend --backend=127.0.0.1:3306"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetBackendParam"));
	g_ptr_array_add(row,
			g_strdup("set the param of a backend,example: SetBackendParam --backend=127.0.0.1:3306 --rw-weight= --ro-weight= --rise= --fall= --inter --fastdowninter="));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("DelBackend"));
	g_ptr_array_add(row,
			g_strdup("delete a backend from backend list(same as setbkoffline),"
					"example: DelBackend --backend=127.0.0.1:3306"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetBKOffline"));
	g_ptr_array_add(row,
			g_strdup("set the status of a backend to pending,example: SetBKOffline --backend=127.0.0.1:3306"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetBKOnline"));
	g_ptr_array_add(row,
			g_strdup("set the status of a backend to up,example: SetBKOnline --backend=127.0.0.1:3306"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowBackends"));
	g_ptr_array_add(row,
			g_strdup("list the status of backends, example: ShowBackends"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("AddUser"));
	g_ptr_array_add(row,
			g_strdup("add a user of proxy, example: AddUser --username=root --passwd=XXX --hostip=%"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("DelUser"));
	g_ptr_array_add(row,
			g_strdup("delete a user of proxy username@ip, example: deluser --username=root [--hostip=%]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("UpdatePwd"));
	g_ptr_array_add(row,
			g_strdup("update the password of user, example: updatepwd --username=root --passwd=XXXX"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowUsers"));
	g_ptr_array_add(row,
			g_strdup("list the status of users, example: ShowUsers --username=xxx --hostip=a.b.c.d --showusernoip=true|false"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetConnLimit"));
	g_ptr_array_add(row,
			g_strdup("set the connection limit of a user@hostip, "
					"example: SetConnLimit --username=root [--port-type=rw/ro] [--hostip=x.x.%] --conn-limit=n"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("DelConnLimit"));
	g_ptr_array_add(row,
			g_strdup("del the connection limit of a user@hostip, "
					"example: DelConnLimit --username=root [--port-type=rw/ro] [--hostip=x.x.%]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetPoolConfig"));
	g_ptr_array_add(row,
			g_strdup("set the pool configuration of a user, "
					"example: SetPoolConfig --username=root [--port-type=rw/ro] --max-conn= --min-conn= --max-interval="));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("DelPoolConfig"));
	g_ptr_array_add(row,
			g_strdup("delete the pool configuration of a user, "
					"example: SetPoolConfig --username=root [--port-type=rw/ro]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowPoolConfig"));
	g_ptr_array_add(row,
			g_strdup("list the pool configuration of users, example: ShowPoolConfig"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowPoolStatus"));
	g_ptr_array_add(row,
			g_strdup("list the pool status of users, example: ShowPoolStatus"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("AddSQLFilter"));
	g_ptr_array_add(row,
			g_strdup("add a sql filter to proxy, "
					"example: AddSQLFilter --username=XXXX --database=mysql --filter-sql='XXX' --filter-type=single|template --filter-action=safe|log|warning|block [--filter-disabled=true|false]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("DelSQLFilter"));
	g_ptr_array_add(row,
			g_strdup("delete a sql filter from proxy, "
					"example: DelSQLFilter --username=XXXX --database=mysql --filter-sql='XXXX' --filter-type=single|template"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetFilterSwitch"));
	g_ptr_array_add(row,
			g_strdup("[en|dis]able a sql filter in proxy, "
					"example: SetFilterSwitch --username=XXXX --database=mysql --filter-sql='XXXX' --filter-type=single|template --filter-disabled=true|false"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetFilterAction"));
	g_ptr_array_add(row,
			g_strdup("set actionof sql filter in proxy, "
					"example: SetFilterAction --username=XXXX --database=mysql --filter-sql='XXXX' --filter-type=single|template --filter-action=safe|log|warning|block"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowSQLFilter"));
	g_ptr_array_add(row,
			g_strdup("list sql filter in proxy, "
					"ShowSQLFilter"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetMultiplexSwitch"));
	g_ptr_array_add(row,
			g_strdup("set multiplex function on/off, "
					"example: SetMultiplexSwitch --flag=on/off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowMultiplexSwitch"));
	g_ptr_array_add(row,
			g_strdup("list multiplex flag, "
					"example: ShowMultiplexSwitch"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowProxyProcesslist"));
	g_ptr_array_add(row,
			g_strdup("list current connections status, "
					"example: ShowProxyProcesslist"));
	g_ptr_array_add(rows, row);
	
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowQueryResponseTime"));
	g_ptr_array_add(row,
			g_strdup("list sql response time by histogram, username and/or db can be selected, "
					"example: ShowQueryResponseTime [--username=XXX], [--database=XXX]"));
	g_ptr_array_add(rows, row);
	
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowTotalResponseTime"));
	g_ptr_array_add(row,
			g_strdup("list total response time by histogram, "
					"example: ShowTotalResponseTime"));
	g_ptr_array_add(rows, row);
	
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ClearStatistics"));
	g_ptr_array_add(row,
			g_strdup("clear response time statistics info, "
					"example: ClearStatistics"));
	g_ptr_array_add(rows, row);
	
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetStatisticsBase"));
	g_ptr_array_add(row,
			g_strdup("set the base of response time statistics info, "
					"example: SetStatisticsBase --base=2|10"));
	g_ptr_array_add(rows, row);
	
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetStatisticsSwitch"));
	g_ptr_array_add(row,
			g_strdup("set statistics function on/off, "
					"example: SetStatisticsSwitch --flag=on/off"));
	g_ptr_array_add(rows, row);
	
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowStatisticsSwitch"));
	g_ptr_array_add(row,
			g_strdup("list statistics flag, "
					"example: ShowStatisticsSwitch"));
	g_ptr_array_add(rows, row);

	/** 并发限制相关 */
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("Addparalimit"));
	g_ptr_array_add(row,
			g_strdup("add a sql para, "
					"example: AddParaLimit --limit-type= --filter-type= "
					"--username= --database= --filter-sql= --para-limit= --rule-switch=;"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("ModifyParaLimit"));
	g_ptr_array_add(row, g_strdup("modify the limitation of sql para execution"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("ModifyLimitSwitch"));
	g_ptr_array_add(row, g_strdup("modify the limit switch of sql para execution"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("DelParaLimit"));
	g_ptr_array_add(row, g_strdup("delete given para limit"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("ShowParaLimit"));
	g_ptr_array_add(row, g_strdup("display all the para limit"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("SetParaLimit"));
	g_ptr_array_add(row, g_strdup("set Para limit function on/off "));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("Showparalimitflag"));
	g_ptr_array_add(row, g_strdup("list para limit flag"));
	g_ptr_array_add(rows, row);

	/** 超时限制相关 */
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("Addduralimit"));
	g_ptr_array_add(row,
			g_strdup("add a sql dura limit, "
					"example: AddduraLimit --limit-type= --filter-type= "
					"--username= --database= --filter-sql= --posi-limit= --rule-switch=;"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("ModifyDuraLimit"));
	g_ptr_array_add(row, g_strdup("modify the limitation of sql para execution"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("ModifyDuraLimitSwitch"));
	g_ptr_array_add(row, g_strdup("modify the limit switch of sql para execution"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("DelDuraLimit"));
	g_ptr_array_add(row, g_strdup("delete given para limit"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("ShowDuraLimit"));
	g_ptr_array_add(row, g_strdup("display all the para limit"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("SetDuraLimit"));
	g_ptr_array_add(row, g_strdup("set Para limit function on/off "));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("Showduralimitflag"));
	g_ptr_array_add(row, g_strdup("list para limit flag"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowConnectionState"));
	g_ptr_array_add(row,
			g_strdup("list current connections state, "
					"example: ShowConnectionState [--connection_id=?] [--connectionstatefull=true|false]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("FlushConnectionState"));
	g_ptr_array_add(row,
			g_strdup("clean up current connections state, "
					"example: FlushConnectionState [--connection_id=?]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowThreadConnectionState"));
	g_ptr_array_add(row,
			g_strdup("list connection state of current threads, "
					"example: ShowThreadConnectionState [--thread_name=?] [--connectionstatefull=true|false]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("FlushThreadConnectionState"));
	g_ptr_array_add(row,
			g_strdup("clean up connection state of current threads, "
					"example: FlushThreadConnectionState [--thread_name=?] [--connectionstatefull=true|false]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowGlobalConnectionState"));
	g_ptr_array_add(row,
			g_strdup("list global connections state, "
					"example: ShowGlobalConnectionState [--connectionstatefull=true|false]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("FlushGlobalConnectionState"));
	g_ptr_array_add(row,
			g_strdup("flush global connections state, "
					"example: FlushGlobalConnectionState"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowLBAlgo"));
	g_ptr_array_add(row,
			g_strdup("list load balance algorithm, "
					"example: ShowLBAlgo [--port-type=rw|ro]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetLBAlgo"));
	g_ptr_array_add(row,
			g_strdup("set load balance algorithm, "
					"example: SetLBAlgo --lbalgo=wrr|lc [--port-type=rw|ro]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowLogLevel"));
	g_ptr_array_add(row,
			g_strdup("list log level, "
					"example: ShowLogLevel"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetLogLevel"));
	g_ptr_array_add(row,
			g_strdup("set log level, "
					"example: SetLogLevel --loglevel=debug|info|message|warning|critical|error"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("AddListenAddr"));
	g_ptr_array_add(row,
			g_strdup("AddListenAddr, "
					"example: AddListenAddr --backend=ip:port --bktype=rw/ro"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("ShowSlowLogConf"));
	g_ptr_array_add(row,
			g_strdup("list slow query log config, "
					"example: ShowSlowLogConf"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("SetSlowLogConf"));
	g_ptr_array_add(row,
			g_strdup("set slow query log config, "
					"example: SetSlowLogSwitch --slowlogswitch=on|off  --slowlogtime=<seconds> --slowlogfile=<filename>"));
	g_ptr_array_add(rows, row);

	/*SCE statistics begin*/
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showsqlaccnum"));
	g_ptr_array_add(row,
			g_strdup("show user sql accumulate number, "
					"example: showsqlaccnum --username=<username> | --is-banned=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setusersqlaccswitch"));
	g_ptr_array_add(row,
			g_strdup("ban/unban user if/not exceed sql accumulate number limit, "
					"example: setusersqlaccswitch --username=<username> --is-banned=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showsqlaccswitch"));
	g_ptr_array_add(row,
			g_strdup("show sql accumulate switch, "
					"example: showsqlaccswitch"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setsqlaccswitch"));
	g_ptr_array_add(row,
			g_strdup("set sql accumulate switch, "
					"example: setsqlaccswitch --flag=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showthroughoutacc"));
	g_ptr_array_add(row,
			g_strdup("show user throughtout accumulate, "
					"example: showthroughoutacc --username=<username> | --is-banned=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setinbytesbanned"));
	g_ptr_array_add(row,
			g_strdup("ban/unban user if/not exceed in bytes limit, "
					"example: setinbytesbanned --username=<username> --is-banned=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setoutbytesbanned"));
	g_ptr_array_add(row,
			g_strdup("ban/unban user if/not exceed out bytes limit, "
					"example: setoutbytesbanned --username=<username> --is-banned=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showthroughoutswitch"));
	g_ptr_array_add(row,
			g_strdup("show user throughtout accumulate number, "
					"example: showthroughoutswitch"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setinbytesaccswitch"));
	g_ptr_array_add(row,
			g_strdup("set in bytes accumulate switch, "
					"example: setinbytesbanned --flag=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setoutbytesaccswitch"));
	g_ptr_array_add(row,
			g_strdup("set out bytes accumulate switch, "
					"example: setoutbytesaccswitch --flag=on|off"));
	g_ptr_array_add(rows, row);

	/*black list*/
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showblacklistflag"));
	g_ptr_array_add(row,
			g_strdup("show black list flag, "
					"example: showblacklistflag"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setblacklistflag"));
	g_ptr_array_add(row,
			g_strdup("set black list flag, "
					"example: setblacklistflag --flag=on|off"));
	g_ptr_array_add(rows, row);

	/// dml 操作相关
	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showsqldmlswitch "));
	g_ptr_array_add(row,
			g_strdup("show whether dml is on or not, "
					"example: showsqldmlswitch"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setsqldmlswitch"));
	g_ptr_array_add(row,
			g_strdup("set dml mgr switch, "
					"example: setsqldmlswitch --flag=on|off"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showsqldmlkind "));
	g_ptr_array_add(row,
			g_strdup("show whihh kinds of dml will be banned, "
					"example: showsqldmlkind"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("showusersqldml"));
	g_ptr_array_add(row,
			g_strdup("show whether dml isbanned for users, "
					"example: showusersqldml [--username=] [--is-banned=on|off]"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("setusersqldmlswitch"));
	g_ptr_array_add(row,
			g_strdup("set the dml switch for user, "
					"example: setusersqldmlswitch --username= --is-banned=on|off"));
	g_ptr_array_add(rows, row);

	/*SCE statistics end*/


	row = g_ptr_array_new();
	g_ptr_array_add(row,
			g_strdup("proxyhelp"));
	g_ptr_array_add(row,
			g_strdup("list all commands and corresponding comments"));
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(proxyhelp_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	/** 构造结果集 */
	fields = construct_help_fields();
	rows = construct_help_rows();

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
	
}
/**
 * 构造backend status的表头
 * @return
 */
static GPtrArray *construct_backend_status_fields() {
	return construct_fields(backend_status_fields);
}

/**
 * 构造backend的status状态信息
 * @return
 */
static GPtrArray *construct_backend_status_rows(network_backends_t *bs) {
	GPtrArray *rows;
	GPtrArray *row;
	gint index = 0;
	network_backend_t *tmp;
	gchar buffer[32];
	rows = g_ptr_array_new();
	// so big a lock
	g_mutex_lock(bs->backends_mutex);
	gint len = bs->backends->len;
	for (index = 0; index < len; index++) {
		tmp = bs->backends->pdata[index];
		if (tmp) {
			row = g_ptr_array_new();

			// 添加ndx 列
			sprintf(buffer, "%d", index);
			g_ptr_array_add(row, g_strdup(buffer));

			// 添加address 列
			g_ptr_array_add(row, g_strdup(tmp->addr->name->str));

			// 添加status 列
			g_ptr_array_add(row, g_strdup(get_backend_state_name(tmp->state)));

			// 添加type 列
			g_ptr_array_add(row, g_strdup(get_backend_type_name(tmp->type)));

			// 添加连接的client的数目
			sprintf(buffer, "%d", tmp->connected_clients[0] + tmp->connected_clients[1]);
			g_ptr_array_add(row, g_strdup(buffer));

			// 添加rw_weight 值
			sprintf(buffer, "%d", tmp->connect_w[PROXY_TYPE_WRITE]);
			g_ptr_array_add(row, g_strdup(buffer));

			// 添加ro_weight 值
			sprintf(buffer, "%d", tmp->connect_w[PROXY_TYPE_READ]);
			g_ptr_array_add(row, g_strdup(buffer));
			
			// 添加rise值
			sprintf(buffer, "%d", tmp->health_check.rise);
			g_ptr_array_add(row, g_strdup(buffer));
			
			// 添加fall值
			sprintf(buffer, "%d", tmp->health_check.fall);
			g_ptr_array_add(row, g_strdup(buffer));
			
			// 添加interval值
			sprintf(buffer, "%d", tmp->health_check.inter);
			g_ptr_array_add(row, g_strdup(buffer));
			
			// 添加fastdowninterval值
			sprintf(buffer, "%d", tmp->health_check.fastdowninter);
			g_ptr_array_add(row, g_strdup(buffer));
			
			// 添加health值
			sprintf(buffer, "%d", tmp->health_check.health);
			g_ptr_array_add(row, g_strdup(buffer));

			g_ptr_array_add(rows, row);
			
			row = NULL;
		}
	}
	g_mutex_unlock(bs->backends_mutex);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showbackends_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	/** 构造结果集 */
	fields = construct_backend_status_fields();
	rows = construct_backend_status_rows(con->srv->priv->backends);

	/** 返回结果*/
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
	
}

ADMIN_COMMAND_PROCESS_FUNC(addbackend_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	backend_type_t new_added_type;

	/** 检查参数的有效性 */
	if (!command->backend) {
		/** 1. backend 不为空 */
//		network_mysqld_con_send_error(con->client,
//				C("addbackend should specify a backend use --backend=ip:port, please see \"help addbackend\" for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->bktype) {
		/** 2. backend 的类型不为空 */
//		network_mysqld_con_send_error(con->client,
//				C("addbackend should specify the backend type use --bktype=ro/rw, please see \"help addbackend\" for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "bktype", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (backend_exist(con->srv->priv->backends, command->backend)) {
		/** 3. 新添加的backend不许与已经存在与backend列表中 */
//		network_mysqld_con_send_error(con->client,
//				C("backend you want to add already in backends list"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_ALREADY_EXISTS, "backend");
		return COMMAND_PROCESS_ERROR;
	} 
	/** 若添加的是RW节点，rw节点需要唯一*/
	if (0 == g_ascii_strcasecmp("RW", command->bktype)) {
		if (rw_backend_exist(con->srv->priv->backends)) {
//			network_mysqld_con_send_error(con->client,
//					C("there is already a rw backend in backends list, it is forbiden to add two RW backend"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_ALREADY_EXISTS, "RW backend");
			return COMMAND_PROCESS_ERROR;
		}
		new_added_type = BACKEND_TYPE_RW;
	} else {
		new_added_type = BACKEND_TYPE_RO;
	}
	/**
	 * added by zhenfan, 2013/09/03
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_addbackend(con->srv->xml_filename, command->backend, command->bktype, BACKEND_STATE_UNKNOWN, &(con->srv->priv->backends->backend_config_default))) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when save addbackend in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "addbackend");
			return COMMAND_PROCESS_ERROR;
		}
	}
				
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		/** 开始添加节点 */
		g_debug("[%s]: check over, we will add the backend to backends list", G_STRLOC);
		gint backend_index = -1;
		backend_index = network_backends_add2(con->srv->priv->backends, command->backend, new_added_type, BACKEND_STATE_UNKNOWN, &(con->srv->priv->backends->backend_config_default));
		if (backend_index == -1) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when adding backend"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_ADD_BACKEND);
			return COMMAND_PROCESS_ERROR;
		} else {
			/** 接下来为新增加的backend，启动一个检测线程 */
			network_backend_t *backend = network_backends_get(con->srv->priv->backends, (guint)backend_index);
			backend_detect_thread_t *thread = NULL;
			if (backend) {
				thread = backend_detect_thread_new(con->srv->detect_threads->len);
				backend_detect_thread_init(thread, con->srv, backend);
				g_ptr_array_add (con->srv->detect_threads, thread);
			}
			if (thread) {
				g_message("[%s]: start detect thread for backend->%s", G_STRLOC, thread->backend->addr->name->str);
				backend_detect_thread_start(thread); // thread的内存的释放是在proxy plugin free时释放
			}
		}
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setbackendparam_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 检查参数的有效性 */
	if (!command->backend) {
		/** 1. backend 不为空 */
//		network_mysqld_con_send_error(con->client,
//				C("setbackendparam should specify a backend use --backend=ip:port, please see \"help setbackendparam\" for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!backend_exist(con->srv->priv->backends, command->backend)) {
		/** 2. 设置的backend不在backends列表中 */
//		network_mysqld_con_send_error(con->client,
//				C("backend you want to setparam does not exist in backends list"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "backend");
		return COMMAND_PROCESS_ERROR;
	}
	if (command->rw_weight >= 0 || command->ro_weight >= 0 || command->rise > 0 || command->fall > 0 || command->inter > 0 || command->fastdowninter > 0) {
		if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
			if (!config_setbackendparam(con->srv->xml_filename, command->backend, command->rw_weight, command->ro_weight, 
					command->rise, command->fall, command->inter, command->fastdowninter)) {
//				network_mysqld_con_send_error(con->client,
//						C("encounter error when setbackendparam in xml"));
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setbackendparam");
				return COMMAND_PROCESS_ERROR;
			}
		}
		if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
//			if (!set_backend_param(con->srv->priv->backends, command->backend, command->rw_weight, command->ro_weight,
//					command->rise, command->fall, command->inter, command->fastdowninter)) {
//				mpe_send_error(con->client, MPE_ADM_CMDPRC_ADD_BACKEND);
////				network_mysqld_con_send_error(con->client,
////						C("encounter error when setbackendparam"));
//				return COMMAND_PROCESS_ERROR;
//			}
			set_backend_param(con->srv->priv->backends, command->backend,
					command->rw_weight, command->ro_weight, command->rise,
					command->fall, command->inter, command->fastdowninter);
		}
	} else {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID,
				"at least one of --rw-weight/--ro-weight/--rise/--fall/--inter/--fastdown-inter ",
				"greater than 0", "proxyhelp");
//		network_mysqld_con_send_error(con->client,
//				C("at least one of --rw-weight/--ro-weight/--rise/--fall/--inter/--fastdown-inter should not be NULL when you want to set the backend param"));
		return COMMAND_PROCESS_ERROR;
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}
ADMIN_COMMAND_PROCESS_FUNC(delbackend_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 检查参数的有效性 */
	if (!command->backend) {
		/** 1. backend 不能为空 */
//		network_mysqld_con_send_error(con->client,
//				C("addbackend should specify a backend use --backend=ip:port, please see \"help addbackend\" for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!backend_exist(con->srv->priv->backends, command->backend)) {
		/** 2.backend 需要存在于backend列表中 */
//		network_mysqld_con_send_error(con->client,
//				C("backend you want to del does no exist in backends list"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "backend");
		return COMMAND_PROCESS_ERROR;
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setbackend_state(con->srv->xml_filename, command->backend, BACKEND_STATE_PENDING)) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when deltbackend in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deltbackend");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		set_backend_status(con->srv, con->srv->priv->backends, command->backend, BACKEND_STATE_PENDING);
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setbkoffline_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 检查参数的有效性 */
	if (!command->backend) {
		/** 1. backend 不能为空 */
//		network_mysqld_con_send_error(con->client,
//				C("setbkoffline should specify a backend use --backend=ip:port, please see \"help addbackend\" for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!backend_exist(con->srv->priv->backends, command->backend)) {
		/** 2. backend 需要存在于backend列表中*/
//		network_mysqld_con_send_error(con->client,
//				C("backend you want to set offline does no exist in backends list"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "backend");
		return COMMAND_PROCESS_ERROR;
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setbackend_state(con->srv->xml_filename, command->backend, BACKEND_STATE_PENDING)) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when setbkoffline in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setbkoffline");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		set_backend_status(con->srv, con->srv->priv->backends, command->backend, BACKEND_STATE_PENDING);
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setbkonline_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 检查参数的有效性 */
	if (!command->backend) {
		/** 1. backend 不能为空 */
//		network_mysqld_con_send_error(con->client,
//				C("setbkonline should specify a backend use --backend=ip:port, please see \"help addbackend\" for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!backend_exist(con->srv->priv->backends, command->backend)) {
		/** 2. backend 需要存在于backend列表中 */
//		network_mysqld_con_send_error(con->client,
//				C("backend you want to set online does no exist in backends list"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "backend");
		return COMMAND_PROCESS_ERROR;
	} 
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setbackend_state(con->srv->xml_filename, command->backend, BACKEND_STATE_UNKNOWN)) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when setbkonline xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setbkonline");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		set_backend_status(con->srv, con->srv->priv->backends, command->backend, BACKEND_STATE_UNKNOWN);
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/**
 * 构造用户信息的表头
 * @return
 */
static GPtrArray *construct_user_status_fields() {
	return construct_fields(user_status_fields);
}

/**
 * 构造用户状态信息
 * @return
 */
static GPtrArray *construct_user_status_rows(chassis *chas, const gchar *username, const gchar *hostip, const gboolean showusernoip) {
	if ((chas == NULL) || (chas->user_infos == NULL)) {
		return NULL;
	}

	GPtrArray *rows;
	GPtrArray *row;
	gchar buffer[32];
	rows = g_ptr_array_new();
	/** 获取所有的用户信息列表 */
	GList *users = g_hash_table_get_values(chas->user_infos);
	GList *tmp_user_list = users;
	user_info *tmp_user = NULL;
	GList *tmp_ip_list = NULL;
	GString *tmp_ip = NULL;
	gboolean has_ip = FALSE;

	for (tmp_user_list = users; tmp_user_list != NULL; tmp_user_list = tmp_user_list->next) {
		tmp_user = (user_info *)(tmp_user_list->data);
		if (tmp_user == NULL) {
			continue;
		}

		if (username != NULL && g_ascii_strcasecmp(tmp_user->username->str, username) != 0) {
			continue;
		}

		if (tmp_user->cli_ips == NULL) {
			has_ip = FALSE;
		} else if (0 == tmp_user->cli_ips->length) {
			has_ip = FALSE;
		} else {
			has_ip = TRUE;
		}

		if (has_ip == TRUE) {
			/** 遍历ip端列表，将对应的连接限制信息、连接数信息添加到返回列表中（分读写端口） */
			for (tmp_ip_list = tmp_user->cli_ips->head; tmp_ip_list != NULL; tmp_ip_list = tmp_ip_list->next) {
				tmp_ip = ((ip_range*)(tmp_ip_list->data))->ip;

				if (hostip != NULL && g_ascii_strcasecmp(tmp_ip->str, hostip) != 0) {
					continue;
				}

				row = g_ptr_array_new();
				/** 添加username 字段 */
				g_ptr_array_add(row, g_strdup(tmp_user->username->str));

				/** 添加ip字段 */
				g_ptr_array_add(row, g_strdup(tmp_ip->str));

				/** 添加rw连接限制数 */
				int *limit = NULL;
				if ( NULL == (limit = get_conn_limit(chas, PROXY_TYPE_WRITE, tmp_user->username->str, tmp_ip->str))) {
					// 默认连接限制
					sprintf(buffer, "%d(default)", chas->default_conn_limit[PROXY_TYPE_WRITE]);
				} else {
					sprintf(buffer, "%d", *limit);
				}
				g_ptr_array_add(row, g_strdup(buffer));

				/**　添加rw实际连接数 */
				gint *login = NULL;
				if (NULL == (login = get_login_users(chas,
						PROXY_TYPE_WRITE,
						tmp_user->username->str,
						tmp_ip->str))) {
					sprintf(buffer, "%d", 0);
				} else {
					sprintf(buffer, "%d", *login);
				}
				g_ptr_array_add(row, g_strdup(buffer));


				/** 添加rw连接限制数 */
				limit = NULL;
				if ( NULL == (limit = get_conn_limit(chas,
						PROXY_TYPE_READ,
						tmp_user->username->str,
						tmp_ip->str))) {
					// 默认连接限制
					sprintf(buffer, "%d(default)", chas->default_conn_limit[PROXY_TYPE_READ]);
				} else {
					sprintf(buffer, "%d", *limit);
				}
				g_ptr_array_add(row, g_strdup(buffer));

				/**　添加rw实际连接数 */
				login = NULL;
				if (NULL == (login = get_login_users(chas,
						PROXY_TYPE_READ,
						tmp_user->username->str,
						tmp_ip->str))) {
					sprintf(buffer, "%d", 0);
				} else {
					sprintf(buffer, "%d", *login);
				}
				g_ptr_array_add(row, g_strdup(buffer));

				g_ptr_array_add(rows, row);
				row = NULL;
			}
		} else if (showusernoip == TRUE) {
			row = g_ptr_array_new();
			/** 添加username 字段 */
			g_ptr_array_add(row, g_strdup(tmp_user->username->str));

			/** 添加ip字段 */
			g_ptr_array_add(row, g_strdup("NULL"));

			/** 添加rw连接限制数 */
			// 默认连接限制
			sprintf(buffer, "%d(default)", chas->default_conn_limit[PROXY_TYPE_WRITE]);
			g_ptr_array_add(row, g_strdup(buffer));

			/**　添加rw实际连接数 */
			sprintf(buffer, "%d", 0);
			g_ptr_array_add(row, g_strdup(buffer));

			/** 添加rw连接限制数 */
			sprintf(buffer, "%d(default)", chas->default_conn_limit[PROXY_TYPE_READ]);
			g_ptr_array_add(row, g_strdup(buffer));

			/**　添加rw实际连接数 */
			sprintf(buffer, "%d", 0);
			g_ptr_array_add(row, g_strdup(buffer));

			g_ptr_array_add(rows, row);
			row = NULL;
		}
	}
	g_list_free(users);
	users = NULL;
	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showUsers_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_user_status_fields();
	rows = construct_user_status_rows(con->srv, command->username, command->hostip, command->showusernoip);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
	
}

ADMIN_COMMAND_PROCESS_FUNC(adduser_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->username) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to add user, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->passwd) {
//		network_mysqld_con_send_error(con->client,
//				C("--passwd should not be NULL when you want to add user, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "passwd", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->hostip) {
//		network_mysqld_con_send_error(con->client,
//				C("--hostip should not be NULL when you want to add user, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "hostip", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}	
	
	/** 参数完整性判断结束，接下来看是否符合逻辑要求 */
	/**
	 * 1. 相同用户名时，需要密码相同
	 * 2. ip 段可以重合，会加两个ip段
	 */
	/**
	 * added by zhenfan, 2013/09/03
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_adduser(con->srv->xml_filename, command->username, command->passwd, command->hostip)) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when adduser in xml; maybe the password of the user you want to add does not identify with password in proxy"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "adduser");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		GString *key = g_string_new(command->username);
		g_rw_lock_writer_lock(&con->srv->user_lock);
		user_info *tmp = g_hash_table_lookup(con->srv->user_infos, key);
		if (tmp == NULL) {
			user_info *user = user_info_new();
			user->username = g_string_new(command->username);
			user->passwd = g_string_new(command->passwd);
			add_ip_range_to_user_info(command->hostip, user);
			g_hash_table_insert(con->srv->user_infos, key, user);
		} else {
			if (0 == g_strcmp0(tmp->passwd->str, command->passwd)) {
				add_ip_range_to_user_info(command->hostip, tmp);
			} else {
//				network_mysqld_con_send_error(con->client,
//						C("the password of the user you want to add does not identify with password in proxy"));
				mpe_send_error(con->client, MPE_ADM_CMDPRC_PWD_NOT_MATCH);
				g_rw_lock_writer_unlock(&con->srv->user_lock);
				g_string_free(key, TRUE);
				return COMMAND_PROCESS_ERROR;
			}
			g_string_free(key, TRUE);
		}	
		g_rw_lock_writer_unlock(&con->srv->user_lock);
	}	
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(deluser_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	
	/**
	 * added by zhenfan, 2013/09/03
	 * 
	 */
	/*删文件*/
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		/*全删*/
		if (command->hostip == NULL) {
			/*1.删连接限制*/
			user_info *user =  get_user_info_for_user(con->srv, command->username);
			if (user != NULL) {
				GList *tmp_ip_list = user->cli_ips->head;
				if (!config_delconnlimit_user_allip(con->srv->xml_filename, NULL, command->username, tmp_ip_list)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deluser(allip)+delconnlimit. allip?");
					return COMMAND_PROCESS_ERROR;
				}
			}
			/*2.删用户*/
			if (!config_deluser(con->srv->xml_filename, command->username)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deluser(allip). no such user?");
				return COMMAND_PROCESS_ERROR;
			}
			/*3.删连接池配置*/
			if (!config_delpoolconfig_helper(con->srv->xml_filename, command->username, NULL)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deluser(allip)+setpoolconfig");
				return COMMAND_PROCESS_ERROR;
			}
		}
		/*只删一个IP。若是最后一个IP，则全删*/
		else {
			gboolean del_user_noip = FALSE;
			/*1.删连接限制*/
			if (!config_delconnlimit_user_ip(con->srv->xml_filename, NULL, command->username, command->hostip)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deluser+delconnlimit");
				return COMMAND_PROCESS_ERROR;
			}
			/*2.删用户*/
			if (!config_deluser_ip(con->srv->xml_filename, command->username, command->hostip, &del_user_noip)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deluser. no such ip?");
				return COMMAND_PROCESS_ERROR;
			}
			/*3.删连接池配置*/
			/*如果是最后一个IP，才删连接池配置*/
			if (del_user_noip == TRUE) {
				if (!config_delpoolconfig_helper(con->srv->xml_filename, command->username, NULL)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "deluser+setpoolconfig");
					return COMMAND_PROCESS_ERROR;
				}
			}
		}	
	}

	/*删内存*/
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		GString *key = g_string_new(command->username);
		g_rw_lock_writer_lock(&con->srv->user_lock);
		/*全删*/
		if (command->hostip == NULL) {
			/*1.删连接限制*/
			// 没有指定ip地址段会将所有的地址段的限制数删除
			user_info *user =  g_hash_table_lookup(con->srv->user_infos, key);
			if (user != NULL) {
				GList *tmp_ip_list = NULL;
				ip_range *ip_r = NULL;
				g_rw_lock_reader_lock(&user->ip_queue_lock);
				for (tmp_ip_list = user->cli_ips->head; tmp_ip_list != NULL; tmp_ip_list = tmp_ip_list->next) {
					ip_r = (ip_range*)tmp_ip_list->data;
					if(ip_r) {
						del_conn_limit_helper(con->srv,
								NULL,
								command->username,
								ip_r->ip->str);
					}
				}
				g_rw_lock_reader_unlock(&user->ip_queue_lock);
			}
			/*2.删连接池配置*/
			del_pool_config_for_user_helper(con->srv, command->username, NULL);
			/*3.删用户*/
			if (g_hash_table_remove(con->srv->user_infos, key)) {
				network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
			} else {
				network_mysqld_con_send_ok_full(con->client, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0);
			}
		}
		/*只删一个IP。若是最后一个IP，则全删*/
		else {
			gboolean del_user_noip = FALSE;
			/*1.删连接限制*/
			del_conn_limit_helper(con->srv,
					NULL,
					command->username,
					command->hostip);
			/*2.删用户*/
			user_info *user = g_hash_table_lookup(con->srv->user_infos, key);
			if (user) {
				del_ip_range_from_user_info(command->hostip, user);
				/*删除无IP用户*/
				del_user_info_without_ip_nolock(con->srv->user_infos, user, key, &del_user_noip);
				/*3.删连接池配置*/
				/*如果是最后一个IP，才删连接池配置*/
				if (del_user_noip == TRUE) {
					del_pool_config_for_user_helper(con->srv, command->username, NULL);
				}
				network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
			} else {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
				g_rw_lock_writer_unlock(&con->srv->user_lock);
				g_string_free(key, TRUE);
				key = NULL;
				return COMMAND_PROCESS_ERROR;
			}
		}
		g_rw_lock_writer_unlock(&con->srv->user_lock);
		g_string_free(key, TRUE);
		key = NULL;
	}
	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(updatepwd_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 下面检查参数的完整性 */
	if (!command->username) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to modify the password of a user, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->passwd) {
//		network_mysqld_con_send_error(con->client,
//				C("--passwd should not be NULL when you want to modify the password of a user, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "passwd", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	/**
	 * added by zhenfan, 2013/09/03
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setuserpasswd(con->srv->xml_filename, command->username, command->passwd)) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when set user passwd in xml; The user you want to modify password does not exist in user list"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "updatepwd");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		GString *key = g_string_new(command->username);
		g_rw_lock_writer_lock(&con->srv->user_lock);

		user_info *user = g_hash_table_lookup(con->srv->user_infos, key);
		if (user) {
			g_message("[%s]:going to modify passwd of %s, current pwd is %s",
					G_STRLOC,
					command->username,
					user->passwd->str);
			g_string_truncate(user->passwd, 0);
			g_string_append(user->passwd, command->passwd);
		} else {
//			network_mysqld_con_send_error(con->client,
//					C("the user you want to modify password does not exist in user list"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
			g_rw_lock_writer_unlock(&con->srv->user_lock);
			g_string_free(key, TRUE);
			return COMMAND_PROCESS_ERROR;
		}
		g_rw_lock_writer_unlock(&con->srv->user_lock);
		g_string_free(key, TRUE);
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}


static gboolean add_conn_limit_helper(chassis *chas, const gchar *port_type_str,
		const gchar *username, const gchar *ip_str, const gint num) {
	proxy_rw port_type;
	if (port_type_str != NULL ) {
		if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
			port_type = PROXY_TYPE_READ;
		} else {
			port_type = PROXY_TYPE_WRITE;
		}
		add_conn_limit(chas, port_type, username, ip_str, num);
	} else {
		add_conn_limit(chas, PROXY_TYPE_READ, username, ip_str, num);
		add_conn_limit(chas, PROXY_TYPE_WRITE, username, ip_str, num);
	}
	return TRUE;
}
ADMIN_COMMAND_PROCESS_FUNC(setconnlimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 检查参数完整性 */
	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
//	if (!command->port_type) {
//		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "port-type", "proxyhelp");
//		return COMMAND_PROCESS_ERROR;
//	}
	if (command->port_type != NULL) {
		if (0 != g_ascii_strcasecmp(command->port_type, "RO")
			&& 0 != g_ascii_strcasecmp(command->port_type, "RW")) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "port-type", "rw or ro" ,"proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (command->conn_limit <= -2) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "conn-limit", ">=-1" ,"proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	user_info *user =  get_user_info_for_user(con->srv, command->username);
	if (user == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * added by zhenfan, 2013/09/03
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (command->hostip) {
			if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
				if (!config_setconnlimit_user_ip(con->srv->xml_filename, command->port_type, command->username, command->hostip, command->conn_limit)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setconnlimit");
					return COMMAND_PROCESS_ERROR;
				}
			}
		} else {
			// 找到user的ip集合
			GList *tmp_ip_list = user->cli_ips->head;
			if (!config_setconnlimit_user_allip(con->srv->xml_filename, command->port_type, command->username, tmp_ip_list, command->conn_limit)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setconnlimit. allip?");
				return COMMAND_PROCESS_ERROR;							
			}
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		if (command->hostip) {
			/**
			 * 设置相应的username@hostip
			 * 的连接限制数为command->conn_limit
			 */
			if (!is_ip_range_allowed_for_user(command->hostip, user)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "hostip");
				return COMMAND_PROCESS_ERROR;
			} 
			add_conn_limit_helper(con->srv,
					command->port_type,
					command->username,
					command->hostip,
					command->conn_limit);
		} else {
			// 没有指定ip地址段会将所有的地址段的限制数更新
			GList *tmp_ip_list = user->cli_ips->head;
			ip_range *ip_r = NULL;
			g_rw_lock_reader_lock(&user->ip_queue_lock);
			while (tmp_ip_list) {
				ip_r = (ip_range*)tmp_ip_list->data;
				if(ip_r) {
					add_conn_limit_helper(con->srv,
							command->port_type,
							command->username,
							ip_r->ip->str,
							command->conn_limit);
				}
				tmp_ip_list = tmp_ip_list->next;
			}
			g_rw_lock_reader_unlock(&user->ip_queue_lock);
		}
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

static gboolean del_conn_limit_helper(chassis *chas, const gchar *port_type_str,
		const gchar *username, const gchar *ip_str) {
	proxy_rw port_type;
	if (port_type_str != NULL ) {
		if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
			port_type = PROXY_TYPE_READ;
		} else {
			port_type = PROXY_TYPE_WRITE;
		}
		del_conn_limit(chas, port_type, username, ip_str);
	} else {
		del_conn_limit(chas, PROXY_TYPE_READ, username, ip_str);
		del_conn_limit(chas, PROXY_TYPE_WRITE, username, ip_str);
	}
	return TRUE;
}
ADMIN_COMMAND_PROCESS_FUNC(delconnlimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 检查参数完整性 */
	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	//if (!command->port_type) {
	//	mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "port-type", "proxyhelp");
	//	return COMMAND_PROCESS_ERROR;
	//}
	if (command->port_type != NULL) {
		if (0 != g_ascii_strcasecmp(command->port_type, "RO")
			&& 0 != g_ascii_strcasecmp(command->port_type, "RW")) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "port-type", "rw or ro" ,"proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}
	user_info *user =  get_user_info_for_user(con->srv, command->username);
	if (user == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
		return COMMAND_PROCESS_ERROR;
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (command->hostip) {
			if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
				if (!config_delconnlimit_user_ip(con->srv->xml_filename, command->port_type, command->username, command->hostip)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "delconnlimit");
					return COMMAND_PROCESS_ERROR;
				}
			}
		} else {
			// 找到user的ip集合
			GList *tmp_ip_list = user->cli_ips->head;
			if (!config_delconnlimit_user_allip(con->srv->xml_filename, command->port_type, command->username, tmp_ip_list)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "delconnlimit. allip?");
				return COMMAND_PROCESS_ERROR;
			}
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		if (command->hostip) {
			/**
			 * 设置相应的username@hostip
			 * 的连接限制数为command->conn_limit
			 */
			if (!is_ip_range_allowed_for_user(command->hostip, user)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "hostip");
				return COMMAND_PROCESS_ERROR;
			}
			del_conn_limit_helper(con->srv,
					command->port_type,
					command->username,
					command->hostip);
		} else {
			// 没有指定ip地址段会将所有的地址段的限制数更新
			GList *tmp_ip_list = user->cli_ips->head;
			ip_range *ip_r = NULL;
			g_rw_lock_reader_lock(&user->ip_queue_lock);
			while (tmp_ip_list) {
				ip_r = (ip_range*)tmp_ip_list->data;
				if(ip_r) {
					del_conn_limit_helper(con->srv,
							command->port_type,
							command->username,
							ip_r->ip->str);
				}
				tmp_ip_list = tmp_ip_list->next;
			}
			g_rw_lock_reader_unlock(&user->ip_queue_lock);
		}
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

static GPtrArray *construct_pool_config_fields() {
	return construct_fields(pool_config_fields);
}

static GPtrArray *construct_pool_config_rows(chassis *chas) {
	if ((chas == NULL) || (chas->user_infos == NULL)) {
		return NULL;
	}

	if ((chas->priv == NULL) || (chas->priv->backends == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();
	char buffer[64];
	g_rw_lock_reader_lock(&chas->user_lock);
	GList *users = g_hash_table_get_keys (chas->user_infos);
	user_pool_config *pool_conf = NULL;
	GList *user = users;
	GString *user_str;
	proxy_rw  index_type = PROXY_TYPE_WRITE;
	char *format;
	while (user) {
		user_str = (GString *)user->data;
		if (user_str) {
			row = g_ptr_array_new();

			// 添加username 列
			g_ptr_array_add(row, g_strdup(user_str->str));

			// 开始添加rw相关的配置信息
			for (index_type = PROXY_TYPE_WRITE; index_type <= PROXY_TYPE_READ; index_type++) {
				pool_conf = get_pool_config_for_user(chas, user_str->str, index_type);
				if (pool_conf == NULL) {
					format = "%d(default)";
					pool_conf = chas->default_pool_config[index_type];
				} else {
					format = "%d";
				}

				// 最大连接数
				sprintf(buffer, format, pool_conf->max_connections);
				g_ptr_array_add(row, g_strdup(buffer));

				// 最小连接数
				sprintf(buffer, format, pool_conf->min_connections);
				g_ptr_array_add(row, g_strdup(buffer));

				// 最大空闲间隙
				sprintf(buffer, format, pool_conf->max_idle_interval);
				g_ptr_array_add(row, g_strdup(buffer));
			}
		}
		g_ptr_array_add(rows, row);
		user = user->next;
	}
	g_rw_lock_reader_unlock(&chas->user_lock);
	g_list_free(users);
	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showPoolConfig_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	/** 展现每个用户的连接池的使用情况（对每个backend的） */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	
	/** 展现每个用户的连接池的使用情况（对每个backend的） */
	fields = construct_pool_config_fields();
	rows = construct_pool_config_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
	
}

static gboolean set_pool_config_for_user_helper(chassis *chas,
		const gchar *username,
		const gchar *port_type_str,
		const gint max_conn,
		const gint min_conn,
		const gint max_interval)
{
	proxy_rw port_type;
	if (port_type_str != NULL ) {
		if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
			port_type = PROXY_TYPE_READ;
		} else {
			port_type = PROXY_TYPE_WRITE;
		}
		set_pool_config_for_user(chas, username, port_type, max_conn, min_conn, max_interval);
	} else {
		set_pool_config_for_user(chas, username, PROXY_TYPE_READ, max_conn, min_conn, max_interval);
		set_pool_config_for_user(chas, username, PROXY_TYPE_WRITE, max_conn, min_conn, max_interval);
	}
	return TRUE;
}
static gboolean config_setpoolconfig_helper(const gchar* filename,
		const gchar *username, const gchar *port_type_str, const gint max_conn,
		const gint min_conn, const gint max_interval) {
	proxy_rw port_type;
	gboolean ret = FALSE;
	if (port_type_str != NULL ) {
		if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
			port_type = PROXY_TYPE_READ;
		} else {
			port_type = PROXY_TYPE_WRITE;
		}
		ret = config_setpoolconfig(filename, username, port_type, max_conn,
				min_conn, max_interval);
	} else {
		/*必须都成功*/
		ret = config_setpoolconfig(filename, username, PROXY_TYPE_READ,
				max_conn, min_conn, max_interval)
				&& config_setpoolconfig(filename, username, PROXY_TYPE_WRITE,
						max_conn, min_conn, max_interval);
	}
	return ret;
}
ADMIN_COMMAND_PROCESS_FUNC(setPoolConfig_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 检查参数的完整性 */
	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (command->port_type != NULL) {
		if (0 != g_ascii_strcasecmp(command->port_type, "RO")
			&& 0 != g_ascii_strcasecmp(command->port_type, "RW")) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "port-type", "rw or ro" ,"proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}
	// 2014/01/08 jira-bug-DBPROXY-1: command->max_conn > 0 ------ command->max_conn >= 0
	if (command->max_conn >= 0 || command->min_conn >= 0 || command->max_interval > 0) {
		if (NULL == get_user_info_for_user(con->srv,command->username)) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "userinfo");
			return COMMAND_PROCESS_ERROR;
		} 
		/**
		 * added by zhenfan, 2013/09/03
		 */
		if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
			if (!config_setpoolconfig_helper(con->srv->xml_filename, command->username, command->port_type, command->max_conn, command->min_conn, command->max_interval)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setpoolconfig");
				return COMMAND_PROCESS_ERROR;						
			}
		}
		if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
			set_pool_config_for_user_helper(con->srv,
				command->username,
				command->port_type,
				command->max_conn,
				command->min_conn,
				command->max_interval);	
		}		
	} else {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "max-conn >=0 or min-conn >= 0 or max-interval > 0", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

static gboolean del_pool_config_for_user_helper(chassis *chas,
		const gchar *username, const gchar *port_type_str) {
	proxy_rw port_type;
	if (port_type_str != NULL ) {
		if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
			port_type = PROXY_TYPE_READ;
		} else {
			port_type = PROXY_TYPE_WRITE;
		}
		/*删除时不管是否成功?*/
		del_pool_config_for_user(chas, username, port_type);
	} else {
		/*删除时不管是否成功?*/
		del_pool_config_for_user(chas, username, PROXY_TYPE_READ);
		del_pool_config_for_user(chas, username, PROXY_TYPE_WRITE);
	}
	return TRUE;
}
static gboolean config_delpoolconfig_helper(const gchar* filename,
		const gchar *username, const gchar *port_type_str) {
	proxy_rw port_type;
	if (port_type_str != NULL ) {
		if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
			port_type = PROXY_TYPE_READ;
		} else {
			port_type = PROXY_TYPE_WRITE;
		}
		/*删除时不管是否成功?*/
		config_delpoolconfig(filename, username, port_type);
	} else {
		/*删除时不管是否成功?*/
		config_delpoolconfig(filename, username, PROXY_TYPE_READ);
		config_delpoolconfig(filename, username, PROXY_TYPE_WRITE);
	}
	return TRUE;
}
ADMIN_COMMAND_PROCESS_FUNC(delPoolConfig_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	/** 检查参数的完整性 */
	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (command->port_type != NULL) {
		if (0 != g_ascii_strcasecmp(command->port_type, "RO")
			&& 0 != g_ascii_strcasecmp(command->port_type, "RW")) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "port-type", "rw or ro" ,"proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}
	// 2014/01/08 jira-bug-DBPROXY-1: command->max_conn > 0 ------ command->max_conn >= 0
	if (command->max_conn >= 0 || command->min_conn >= 0 || command->max_interval > 0) {
		if (NULL == get_user_info_for_user(con->srv,command->username)) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "userinfo");
			return COMMAND_PROCESS_ERROR;
		}
		if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
			if (!config_delpoolconfig_helper(con->srv->xml_filename, command->username, command->port_type)) {
				mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "delpoolconfig");
				return COMMAND_PROCESS_ERROR;
			}
		}
		if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
			del_pool_config_for_user_helper(con->srv,
				command->username,
				command->port_type);
		}
	} else {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "max-conn >=0 or min-conn >= 0 or max-interval > 0", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/**
 * 构造查询连接池状态的表头
 * @return
 */
static GPtrArray* construct_pool_status_fields() {
	return construct_fields(pool_status_fields);
}

/**
 * 构造查询连接池状态的表项
 * @return
 */
static GPtrArray* construct_pool_status_rows(chassis *chas) {
	if ((chas == NULL) || (chas->user_infos == NULL)) {
		return NULL;
	}

	if ((chas->priv == NULL) || (chas->priv->backends == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();
	g_rw_lock_reader_lock(&chas->user_lock);
	GList *users = g_hash_table_get_keys (chas->user_infos);
	GList *user = users;
	GString *user_str = NULL;
	network_backends_t *bs = chas->priv->backends;
	network_backend_t *bk = NULL;
	char buffer[64];
 	guint index = 0;
	while(user) {
		// 遍历所有用户
		user_str = (GString *)user->data;
		if (user_str) {
			// 接下来遍历所有的backend，找到pool的状态
			g_mutex_lock(bs->backends_mutex);
			for (index = 0; index < bs->backends->len; index++) {
				row = g_ptr_array_new();
				/** 添加用户名列*/
				g_ptr_array_add(row, g_strdup(user_str->str));
				bk = bs->backends->pdata[index];
				/** 添加backend列 */
				g_ptr_array_add(row, g_strdup(bk->addr->name->str));

				/** 添加空闲连接数 */
				sprintf(buffer, "%d",
						get_count_of_idle_conns(bk, user_str->str, PROXY_TYPE_WRITE));
				g_ptr_array_add(row, g_strdup(buffer));

				/** 添加在用连接数 */
				sprintf(buffer, "%d",
						get_count_of_using_conns(bk, user_str->str, PROXY_TYPE_WRITE));
				g_ptr_array_add(row, g_strdup(buffer));

				/** 添加在建连接数 */
				sprintf(buffer, "%d",
						get_count_of_pending_conns(bk, user_str->str, PROXY_TYPE_WRITE));
				g_ptr_array_add(row, g_strdup(buffer));

				/** 添加空闲连接数 */
				sprintf(buffer, "%d",
						get_count_of_idle_conns(bk, user_str->str, PROXY_TYPE_READ));
				g_ptr_array_add(row, g_strdup(buffer));

				/** 添加在用连接数 */
				sprintf(buffer, "%d",
						get_count_of_using_conns(bk, user_str->str, PROXY_TYPE_READ));
				g_ptr_array_add(row, g_strdup(buffer));

				/** 添加在建连接数 */
				sprintf(buffer, "%d",
						get_count_of_pending_conns(bk, user_str->str, PROXY_TYPE_READ));
				g_ptr_array_add(row, g_strdup(buffer));
				g_ptr_array_add(rows, row);
			}
			g_mutex_unlock(bs->backends_mutex);
		}
		user = user->next;
	}
	g_rw_lock_reader_unlock(&chas->user_lock);
	g_list_free(users);
	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showPoolStatus_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	/** 展现每个用户的连接池的使用情况（对每个backend的） */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	
	fields = construct_pool_status_fields();
	rows = construct_pool_status_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

/** 构造showsqlfilter 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showsqlfilter_fields) {
	return construct_fields(showsqlfilter_fields);
}

/** 构造showsqlfilter 命令的rows变量 */
CONSTRUCT_ROWS_FUNC(construct_showsqlfilter_rows) {
	g_assert(chas);

	if ((NULL == chas) || (NULL == chas->rule_table)) {
		return NULL;
	}

	/** 添加具体的规则列表，遍历SQL_SINGLE及SQL_TEMPLATE两个列表 */
	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();
	security_model_type index;

	GList *user_list = NULL;
	GList *user_list_tmp = NULL;
	GString *user_key = NULL;

	GList *db_list = NULL;
	GList *db_list_tmp = NULL;
	GString *db_key = NULL;

	GList *sql_list = NULL;
	GList *sql_list_tmp = NULL;

	db_sql_rule_table *db_sql_rule;
	sql_rule_table *sql_rule;
	sql_security_rule *rule;

	for (index = SQL_SINGLE; index <= SQL_TEMPLATE; index++) {
		g_rw_lock_reader_lock(&chas->rule_table->table_lock[index]);
		user_list = g_hash_table_get_keys(chas->rule_table->user_db_sql_rule[index]);
		user_list_tmp= user_list;
		while (user_list_tmp) {
			user_key = (GString *)(user_list_tmp->data);
			if (user_key) {
				db_sql_rule = g_hash_table_lookup(chas->rule_table->user_db_sql_rule[index], user_key);
				g_rw_lock_reader_lock(&db_sql_rule->table_lock);
				db_list = g_hash_table_get_keys(db_sql_rule->db_sql_rule);
				db_list_tmp = db_list;
				while(db_list_tmp) {
					db_key = (GString *)(db_list_tmp->data);
					if (db_key) {
						sql_rule = g_hash_table_lookup(db_sql_rule->db_sql_rule, db_key);
						g_rw_lock_reader_lock(&sql_rule->table_lock);
						sql_list = g_hash_table_get_values(sql_rule->sql_rule);
						sql_list_tmp = sql_list;
						while(sql_list_tmp) {
							rule = (sql_security_rule*)(sql_list_tmp->data);
							if (rule) {
								/** 构造一行新的数据单元 */
								row = g_ptr_array_new();

								/** 添加用户列 */
								g_ptr_array_add(row,
										g_strdup(user_key->str));

								/** 添加db列 */
								g_ptr_array_add(row,
										g_strdup(db_key->str));

								/** 添加sql列*/
								g_ptr_array_add(row,
										g_strdup(rule->sql_content->str));

								/** 添加规则的动作列*/
								g_ptr_array_add(row,
										g_strdup(get_security_action_name(rule->action)));

								/** 添加规则的类别列*/
								g_ptr_array_add(row,
										g_strdup(index==SQL_SINGLE?"single":"template"));

								/** 添加规则的状态（是否启用）*/
								g_ptr_array_add(row,
										g_strdup((!rule->is_disabled)?"true":"false"));

								//添加到结果集中
								g_ptr_array_add(rows, row);
							}
							sql_list_tmp = sql_list_tmp->next;
						}
						g_list_free(sql_list);
						g_rw_lock_reader_unlock(&sql_rule->table_lock);
					}
					db_list_tmp = db_list_tmp->next;
				}
				g_list_free(db_list);
				g_rw_lock_reader_unlock(&db_sql_rule->table_lock);
			}
			user_list_tmp = user_list_tmp->next;
		}
		g_list_free(user_list);
		g_rw_lock_reader_unlock(&chas->rule_table->table_lock[index]);
	}
	return rows;
}

/** showsqlfilter 的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(showsqlfilter_command_process) {
	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 检查参数完整性 */

	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showsqlfilter_fields();
	rows = construct_showsqlfilter_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** sql限制规则添加相关的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(addsqlfilter_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->username) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to add sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_sql) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-sql should not be NULL when you want to add sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->dbname) {
//		network_mysqld_con_send_error(con->client,
//				C("--database should not be NULL when you want to add sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->filter_type_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-type should not be NULL when you want to add sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_action_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-action should not be NULL when you want to add sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-action", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		/**
		 * added by zhenfan, 2013/09/03
		 * sql需要先进行标准化
		 */
		gchar * normalized_sql = sql_normalize_with_token(command->filter_sql, command->filter_type);
		if (!config_addsqlfilter(
				con->srv->xml_filename,
				normalized_sql, 
				command->dbname, 
				command->username, 
				command->filter_type, 
				command->filter_action, 
				command->filter_is_disabled)) {
//			network_mysqld_con_send_error(con->client,
//				C("encounter error when addsqlfilter in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "addsqlfilter");
			g_free(normalized_sql);		
			return COMMAND_PROCESS_ERROR;
		}
		g_free(normalized_sql);	
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		if (!add_sql_security_rule(
				con->srv->rule_table,
				command->filter_sql,
				command->dbname,
				command->username,
				command->filter_type,
				command->filter_action,
				command->filter_is_disabled)) {
//			network_mysqld_con_send_error(
//					con->client,
//					C("encounter error when adding sql filter, please contact with OPS"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "add_sql_security_rule");
			return COMMAND_PROCESS_ERROR;
		}
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/** 删除sql的filter */
ADMIN_COMMAND_PROCESS_FUNC(delsqlfilter_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->username) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to del sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_sql) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-sql should not be NULL when you want to del sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->dbname) {
//		network_mysqld_con_send_error(con->client,
//				C("--database should not be NULL when you want to del sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_type_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-type should not be NULL when you want to del sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	/**
	 * added by zhenfan, 2013/09/03
	 */	
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		gchar * normalized_sql = sql_normalize_with_token(command->filter_sql, command->filter_type);
		if (!config_delsqlfilter(
			con->srv->xml_filename,
			normalized_sql, 
			command->dbname, 
			command->username, 
			command->filter_type)) {
//			network_mysqld_con_send_error(con->client,
//					C("encounter error when delsqlfilter in xml. Maybe the filter you want to delete not exist!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "delsqlfilter");
			g_free(normalized_sql);
			return COMMAND_PROCESS_ERROR;
		}
		g_free(normalized_sql);
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		if (!del_sql_security_rule(
			con->srv->rule_table,
			command->filter_sql,
			command->dbname,
			command->username,
			command->filter_type)) {
//			network_mysqld_con_send_error(
//				con->client,
//				C("encounter error when deleting sql filter, Maybe the filter you want to delete not exist!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "del_sql_security_rule");
			return COMMAND_PROCESS_ERROR;
		}
	}

	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}


/** 设置filter的开关 */
ADMIN_COMMAND_PROCESS_FUNC(setfilterswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->username) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to set switch of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->filter_sql) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-sql should not be NULL when you want to set switch of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->dbname) {
//		network_mysqld_con_send_error(con->client,
//				C("--database should not be NULL when you want to set switch of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->filter_type_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-type should not be NULL when you want to set switch of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->filter_is_disabled_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-disabled should not be NULL when you want to set switch of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-disabled", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	/**
	 * added by zhenfan, 2013/09/03
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		gchar * normalized_sql = sql_normalize_with_token(command->filter_sql, command->filter_type);
		if (!config_setfilterswitch(
			con->srv->xml_filename,
			normalized_sql, 
			command->dbname, 
			command->username, 
			command->filter_type,
			command->filter_is_disabled)) {
//			network_mysqld_con_send_error(con->client,
//				C("encounter error when [en|dis]able sql filter in xml. Maybe the filter you want to [en|dis]able not exist!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setfilterswitch");
			g_free(normalized_sql);
			return COMMAND_PROCESS_ERROR;
		}
		g_free(normalized_sql);
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		if (!set_switch_sql_security_rule(
			con->srv->rule_table,
			command->filter_sql,
			command->dbname,
			command->username,
			command->filter_type,
			command->filter_is_disabled)) {
//			network_mysqld_con_send_error(
//					con->client,
//					C("encounter error when [en|dis]able sql filter, Maybe the filter you want to [en|dis]able not exist!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "set_switch_sql_security_rule");
			return COMMAND_PROCESS_ERROR;
		}
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setfilteraction_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->username) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to set action of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_sql) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-sql should not be NULL when you want to set action of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (!command->dbname) {
//		network_mysqld_con_send_error(con->client,
//				C("--database should not be NULL when you want to set action of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_type_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-type should not be NULL when you want to set action of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (!command->filter_action_str) {
//		network_mysqld_con_send_error(con->client,
//				C("--filter-action should not be NULL when you want to set action of sql filter, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-action", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	/**
	 * added by zhenfan, 2013/09/03
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		char * normalized_sql = sql_normalize_with_token(command->filter_sql, command->filter_type);
		if (!config_setfilteraction(
			con->srv->xml_filename,
			normalized_sql, 
			command->dbname, 
			command->username, 
			command->filter_type,
			command->filter_action)) {
//			network_mysqld_con_send_error(
//					con->client,
//					C("encounter error when setfilteraction in xml. Maybe the filter you want to process not exist!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setfilteraction");
			g_free(normalized_sql);
			return COMMAND_PROCESS_ERROR;
		}
		g_free(normalized_sql);
	}	
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		if (!set_action_sql_security_rule(
			con->srv->rule_table,
			command->filter_sql,
			command->dbname,
			command->username,
			command->filter_type,
			command->filter_action)) {			
//			network_mysqld_con_send_error(
//					con->client,
//					C("encounter error when set action of sql filter, Maybe the filter you want to process not exist!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "set_action_sql_security_rule");
			return COMMAND_PROCESS_ERROR;
		}
	}
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/** 构造showsmultiplex 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showmultiplexswitch_fields) {
	return construct_fields(showmultiplexswitch_fields);
}


/** 构造showsmultiplex 命令的rows变量*/
CONSTRUCT_ROWS_FUNC(construct_showmultiplexswitch_rows) {
	if ((chas == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	/** multiplex flag列*/
	row = g_ptr_array_new();
	g_ptr_array_add(row, (chas->multiplex == TRUE)? g_strdup("on"): g_strdup("off"));
	g_ptr_array_add(rows, row);

	return rows;
}

/** showmultiplexswitch 命令*/
ADMIN_COMMAND_PROCESS_FUNC(showmultiplexswitch_command_process) {
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 首先检查参数的完整性 */
	g_assert(command);
	
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现是否设置连接复用标志*/
	fields = construct_showmultiplexswitch_fields();
	rows = construct_showmultiplexswitch_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** setmultiplexswitch 命令*/
ADMIN_COMMAND_PROCESS_FUNC(setmultiplexswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	if (!command->flag || (g_ascii_strcasecmp("on", command->flag) != 0 && g_ascii_strcasecmp("off", command->flag) != 0)) {
//		network_mysqld_con_send_error(con->client,
//			C("--flag should not be NULL, and should be on/off"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	/**
	 * added by zhenfan, 2013/08/29
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setmultiplex(con->srv->xml_filename, command->flag)) {
//			network_mysqld_con_send_error(con->client,
//				C("encounter error when setmultiplex in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setmultiplex");
			return COMMAND_PROCESS_ERROR;
		}	
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		con->srv->multiplex = ((0 == g_ascii_strcasecmp("on", command->flag)) ?TRUE : FALSE);	
	}
	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/** 构造show proxy processlist 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showproxyprocesslist_fields) {
	return construct_fields(showprocesslist_fields);
}

/** 构造show proxy processlist 命令的rows变量*/
CONSTRUCT_ROWS_FUNC(construct_showproxyprocesslist_rows) {
	g_assert(chas);

	if ((NULL == chas) || (NULL == chas->priv)) {
		return NULL;
	}
	
	GPtrArray *rows = NULL;
	// NEW rows
	rows = g_ptr_array_new();
	chassis_private *priv = chas->priv;
	GPtrArray *cons = priv->cons;
	network_mysqld_con *con_temp;
	network_socket *tmp_server = NULL;
	network_socket *tmp_client = NULL;
	guint index;
	/** 对cons数组加锁，并遍历 */
	g_mutex_lock(&priv->cons_mutex);
	for (index = 0; index < cons->len; index++) {
		con_temp = NULL;

		GPtrArray *row = g_ptr_array_new();
		con_temp = g_ptr_array_index(cons, index);
		if (NULL == con_temp) {
			break;
		}
		g_mutex_lock(&con_temp->client_mutex);
		g_mutex_unlock(&con_temp->client_mutex);
		network_socket *client = con_temp->client;
		network_socket *server = con_temp->server;
		network_socket *cache_server = con_temp->cache_server;
		
		/** 其他线程可以访问到con_temp，从而将client、server、cache_server的结构变化，所以先要memcpy出来一份*/
		g_mutex_lock(&con_temp->server_mutex);
		if (NULL != server) {
			tmp_server = g_new0(network_socket, 1);
			memcpy(tmp_server, server, sizeof(network_socket));
		} 
		g_mutex_unlock(&con_temp->server_mutex);
		
		if (NULL == tmp_server) {
			g_mutex_lock(&con_temp->cache_server_mutex);
			if (NULL != cache_server) {
				tmp_server = g_new0(network_socket, 1);
				memcpy(tmp_server, cache_server, sizeof(network_socket));
			}	
			g_mutex_unlock(&con_temp->cache_server_mutex);
		}
		if (NULL == tmp_server) {
			g_ptr_array_free(row, TRUE);
			row = NULL;
			continue;
		}
		
		g_mutex_lock(&con_temp->client_mutex);
		if (NULL != client) {
			tmp_client = g_new0(network_socket, 1);
			memcpy(tmp_client, client, sizeof(network_socket));
		}
		g_mutex_unlock(&con_temp->client_mutex);
		if (NULL == tmp_client) {
			g_free(tmp_server);
			tmp_server = NULL;
			g_ptr_array_free(row, TRUE);
			row = NULL;
			continue;
		}
		
		// 所有和proxy相关的数据结构: Thread_Id,User,Client_Host,Backend_Host,Db
		network_address *server_address = tmp_server->dst;
		network_address *client_address = tmp_client->src;
		network_mysqld_auth_challenge *challenge = tmp_server->challenge;
		network_mysqld_auth_response *response = tmp_server->response;
		
		// Thread_Id: challenge->thread_id
		if (NULL == challenge) {
			g_ptr_array_add(row, NULL);
		} else {
			gsize thread_id = challenge->thread_id;
			if (thread_id <= 0) {
				g_ptr_array_add(row, NULL);
			} else {
				gchar *buffer = g_new0(gchar, THREAD_ID_MAX_LENGTH);
				sprintf(buffer, "%ld", thread_id);
				g_ptr_array_add(row, g_strdup(buffer));
				g_free(buffer);
				buffer = NULL;
			}
		}
		
		// User: response->username->str
		if (NULL != response && NULL != response->username) {
			g_ptr_array_add(row, g_strdup(response->username->str));
		} else {
			g_ptr_array_add(row, NULL);
		}
		
		// Client_Host: client_address->name->str
		if ( NULL != client_address && NULL != client_address->name) {
			g_ptr_array_add(row, g_strdup(client_address->name->str));
		} else {
			g_ptr_array_add(row, NULL);
		}
		
		// Backend_Host: server_address->name->str
		if ( NULL != server_address && NULL != server_address->name) {
			g_ptr_array_add(row, g_strdup(server_address->name->str));
		} else {
			g_ptr_array_add(row, NULL);
		}
		
		// Db: response->database->str
		if (NULL != tmp_client->response && NULL != tmp_client->response->database) {
			g_ptr_array_add(row, g_strdup(tmp_client->response->database->str));
		} else if (NULL != response && NULL != response->database) {
			g_ptr_array_add(row, g_strdup(response->database->str));
		} else {
			g_ptr_array_add(row, NULL);
		}
		
		/** State: con_temp->is_sql_running 
		 *  Time: con_temp->start_timestamp or con_temp->end_timestamp 
		 */
		if (NULL != con_temp) {
			guint64 duration = 0;
			if (con_temp->is_sql_running) {
				g_ptr_array_add(row, g_strdup("Running"));
				guint64 now_microsecond = chassis_get_rel_microseconds();
				duration = chassis_calc_rel_microseconds(con_temp->start_timestamp, now_microsecond);
			} else {
				g_ptr_array_add(row, g_strdup("Sleep"));
				duration = chassis_calc_rel_microseconds(con_temp->start_timestamp, con_temp->end_timestamp);
			}
			duration /= 1000000L;
			gchar * time_buffer = g_new0(gchar, 32);
			sprintf(time_buffer, "%ld", duration);
			g_ptr_array_add(row, g_strdup(time_buffer));
			g_free(time_buffer);
			time_buffer = NULL;
		} else {
			g_ptr_array_add(row, NULL);
			g_ptr_array_add(row, NULL);
		}
		
		// Sql: con_temp->sql_sentence->str
		if (NULL != con_temp && NULL != con_temp->sql_sentence) {
			g_ptr_array_add(row, g_strdup(con_temp->sql_sentence->str));
		} else {
			g_ptr_array_add(row, NULL);
		}
		
		// 向rows中添加一行row
		g_ptr_array_add(rows, row);
		g_free(tmp_server);
		tmp_server = NULL;
		g_free(tmp_client);
		tmp_client = NULL;
	}
	g_mutex_unlock(&priv->cons_mutex);

	return rows;

}

/** show proxy processlist 命令*/
ADMIN_COMMAND_PROCESS_FUNC(showproxyprocesslist_command_process) {
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 首先检查参数的完整性 */
	g_assert(command);

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现是否设置连接复用标志*/
	fields = construct_showproxyprocesslist_fields();
	rows = construct_showproxyprocesslist_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** sql并发限制规则 */
/** 并发限制规则添加 */
ADMIN_COMMAND_PROCESS_FUNC(addparalimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (command->para_limit <= -2) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "para-limit", ">=-1" ,"proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着添加并发限制规则
	 * @todo 暂时还没有持久化
	 */
	if (NULL == add_sql_para_rule(
			con->srv->para_limit_rules, command->username,
			command->dbname, command->filter_sql, command->limit_type,
			command->filter_type, command->para_limit, command->rule_switch)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "add_para_limit_rule");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 删除并发限制规则 */
ADMIN_COMMAND_PROCESS_FUNC(delparalimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着删除并发限制规则
	 * @todo 暂时还没有持久化
	 */
	if (!delete_sql_para_rule_limit_rule(con->srv->para_limit_rules,
			command->username, command->dbname, command->filter_sql,
			command->limit_type, command->filter_type)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "del_para_limit_rule");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 更新并发限制规则包括限制数*/
ADMIN_COMMAND_PROCESS_FUNC(modifyparalimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (command->para_limit <= -2) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "para-limit", ">=-1" ,"proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着修改并发限制规则值
	 * @todo 暂时还没有持久化
	 */
	if (!modify_sql_para_rule_limit_para(
			con->srv->para_limit_rules, command->username,
			command->dbname, command->filter_sql, command->limit_type,
			command->filter_type, command->para_limit)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "modify_sql_para_rule_limit_para");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 更新并发限制规则包括限制数*/
ADMIN_COMMAND_PROCESS_FUNC(modifylimitswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着修改并发限制规则的启用开关,默认是启用
	 * @todo 暂时还没有持久化
	 */
	if (!modify_sql_para_rule_limit_switch(
			con->srv->para_limit_rules, command->username,
			command->dbname, command->filter_sql, command->limit_type,
			command->filter_type, command->rule_switch)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "modify_sql_para_rule_limit_para");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 查看并发限制规则 */
// 构造头文件
CONSTRUCT_FIELDS_FUNC(construct_showparalimit_fields) {
	return construct_fields(showlimit_fields);
}

/** 构造showparalimit 命令的rows变量 */
/**
 * 先不显示对应规则具体对应的sql的执行条数
 * 主要是规则和执行条数无法对应起来
 * @todo 将数据结构分开？？
 * 现用的是否有对应的限制规则的标志分开成4个，统计分开成4个；
 * （这样做不好的地方是限制数不能立刻更新？但是如果是想显示对应规则的sql执行条数比现在的结构方便，也不好弄！！）
 */
CONSTRUCT_ROWS_FUNC(construct_showparalimit_rows) {
	g_assert(chas);

	if ((NULL == chas) || (NULL == chas->rule_table)) {
		return NULL ;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	GList *user_list = NULL;
	GList *user_list_tmp = NULL;
	GString *user_key = NULL;

	GList *db_list = NULL;
	GList *db_list_tmp = NULL;
	GString *db_key = NULL;

	GList *sql_list = NULL;
	GList *sql_list_tmp = NULL;
	GString *sql_key = NULL;

	db_sql_limit_list *db_sql_limit;
	sql_limit_list *sql_limit;
	para_exec_limit *limit;

	char buffer[256];
	//GString *user_db_key = g_string_new(NULL);

	gint sql_type;

	/** 构造individual 限制列表 */
	for (sql_type = PARA_SQL_SINGLE; sql_type <= PARA_SQL_TEMPLATE;
			sql_type++) {
		g_rw_lock_writer_lock(
				&(chas->para_limit_rules->para_exec_individ_rules[sql_type]->list_lock));
		user_list =
				g_hash_table_get_keys(
						chas->para_limit_rules->para_exec_individ_rules[sql_type]->user_db_sql_list);
		user_list_tmp = user_list;
		while (user_list_tmp) {
			user_key = (GString *) (user_list_tmp->data);
			if (user_key) {
				db_sql_limit =
						g_hash_table_lookup(
								chas->para_limit_rules->para_exec_individ_rules[sql_type]->user_db_sql_list,
								user_key);
				g_rw_lock_writer_lock(&(db_sql_limit->list_lock));
				db_list = g_hash_table_get_keys(db_sql_limit->db_sql_list);
				db_list_tmp = db_list;
				while (db_list_tmp) {
					db_key = (GString *) (db_list_tmp->data);
					if (db_key) {
						sql_limit = g_hash_table_lookup(
								db_sql_limit->db_sql_list, db_key);
						g_rw_lock_writer_lock(&(sql_limit->list_lock));
						sql_list = g_hash_table_get_keys(sql_limit->sql_list);
						sql_list_tmp = sql_list;
						while (sql_list_tmp) {
							limit = g_hash_table_lookup(sql_limit->sql_list,
									(GString *) (sql_list_tmp->data));
							if (limit) {
								// 开始构造结果集
								row = g_ptr_array_new();

								/** username 列 */
								g_ptr_array_add(row, g_strdup(user_key->str));

								/** dbname 列 */
								g_ptr_array_add(row, g_strdup(db_key->str));

								/** sql 列 */
								g_ptr_array_add(row,
										g_strdup(
												((GString *) (sql_list_tmp->data))->str));

								/** 限制类别列：individual 或者 global */
								g_ptr_array_add(row, g_strdup("Individual"));

								/** 类别：template 或者是  single*/
								g_ptr_array_add(row,
										g_strdup(
												(PARA_SQL_SINGLE == sql_type) ?
														"Single" : "Template"));

								/** 连接限制数 */
								snprintf(buffer, 255, "%d", limit->limit_para);
								g_ptr_array_add(row, g_strdup(buffer));

								/** 限制开关 */
								g_ptr_array_add(row,
										g_strdup(
												limit->limit_switch ?
														"On" : "Off"));

								g_ptr_array_add(rows, row);
								row = NULL;
								limit = NULL;
							}
							sql_list_tmp = sql_list_tmp->next;
						}
						g_list_free(sql_list);
						g_rw_lock_writer_unlock(&(sql_limit->list_lock));
					}
					db_list_tmp = db_list_tmp->next;
				}
				g_list_free(db_list);
				g_rw_lock_writer_unlock(&(db_sql_limit->list_lock));
			}
			user_list_tmp = user_list_tmp->next;
		}
		g_list_free(user_list);
		g_rw_lock_writer_unlock(
				&(chas->para_limit_rules->para_exec_individ_rules[sql_type]->list_lock));
	}

	/** 构造global 限制列表 */
	for (sql_type = PARA_SQL_SINGLE; sql_type <= PARA_SQL_TEMPLATE;
			sql_type++) {
		g_rw_lock_writer_lock(
				&(chas->para_limit_rules->para_exec_global_rules[sql_type]->list_lock));
		sql_list =
				g_hash_table_get_keys(
						chas->para_limit_rules->para_exec_global_rules[sql_type]->sql_list);
		sql_list_tmp = sql_list;
		while (sql_list_tmp) {
			sql_key = (GString *) (sql_list_tmp->data);
			if (sql_key) {
				limit =
						g_hash_table_lookup(
								chas->para_limit_rules->para_exec_global_rules[sql_type]->sql_list,
								sql_key);

				if (limit) {
					// 开始构造结果集
					row = g_ptr_array_new();

					/** username 列 */
					g_ptr_array_add(row, g_strdup("NULL"));

					/** dbname 列 */
					g_ptr_array_add(row, g_strdup("NULL"));

					/** sql 列 */
					g_ptr_array_add(row, g_strdup(sql_key->str));

					/** 限制类别列：individual 或者 global */
					g_ptr_array_add(row, g_strdup("Global"));

					/** 类别：template 或者是  single*/
					g_ptr_array_add(row,
							g_strdup(
									(PARA_SQL_SINGLE == sql_type) ?
											"Single" : "Template"));

					/** 连接限制数 */
					snprintf(buffer, 255, "%d", limit->limit_para);
					g_ptr_array_add(row, g_strdup(buffer));

					/** 限制开关 */
					g_ptr_array_add(row,
							g_strdup(limit->limit_switch ? "On" : "Off"));

					g_ptr_array_add(rows, row);
					row = NULL;
					limit = NULL;
				}
			}
			sql_list_tmp = sql_list_tmp->next;
		}
		g_list_free(user_list);
		g_rw_lock_writer_unlock(
				&(chas->para_limit_rules->para_exec_global_rules[sql_type]->list_lock));
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showparalimit_command_process) {

	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 检查参数完整性 */

	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showparalimit_fields();
	rows = construct_showparalimit_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** 设置并发限制的启用标志 */
ADMIN_COMMAND_PROCESS_FUNC(setparalimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->flag ||
			(g_ascii_strcasecmp("on", command->flag) != 0 && g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}


	/**
	 * 下面设置并发控制的标志
	 * @todo 没有持久化
	 */
	con->srv->para_limit_on = ((0 == g_ascii_strcasecmp("on", command->flag)) ?TRUE : FALSE);
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

CONSTRUCT_FIELDS_FUNC(construct_showparalimitflag_fields) {
	return construct_fields(showparalimitflag_fields);
}

CONSTRUCT_ROWS_FUNC(construct_showparalimitflag_rows) {
	if ((chas == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	/** ParaLimit flag列*/
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup((chas->para_limit_on == TRUE)? "on": "off"));
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showparalimitflag_command_process) {
	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 检查参数完整性 */

	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showparalimitflag_fields();
	rows = construct_showparalimitflag_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** 超时时间限制相关 */
/** 添加超时连接限制 */
ADMIN_COMMAND_PROCESS_FUNC(addduralimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (command->limit <= 0) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "posi-limit", "> 0" ,"proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着添加并发限制规则
	 * @todo 暂时还没有持久化
	 */
	if (NULL == add_sql_dura_rule(
			con->srv->dura_limit_rules, command->username,
			command->dbname, command->filter_sql, command->limit_type,
			command->filter_type, command->limit, command->rule_switch)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "add_dura_limit_rule");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 删除超时连接限制 */
ADMIN_COMMAND_PROCESS_FUNC(delduralimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着删除并发限制规则
	 * @todo 暂时还没有持久化
	 */
	if (!delete_sql_dura_rule_limit_rule(con->srv->dura_limit_rules,
			command->username, command->dbname, command->filter_sql,
			command->limit_type, command->filter_type)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "del_dura_limit_rule");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 更新超时限制规则时长*/
ADMIN_COMMAND_PROCESS_FUNC(modifyduralimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (command->limit <= 0) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "posi-limit", "> 0" ,"proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着修改并发限制规则值
	 * @todo 暂时还没有持久化
	 */
	if (!modify_sql_dura_rule_limit_para(
			con->srv->dura_limit_rules, command->username,
			command->dbname, command->filter_sql, command->limit_type,
			command->filter_type, command->limit)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "modify_sql_para_rule_limit_para");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

ADMIN_COMMAND_PROCESS_FUNC(modifyduralimitswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->limit_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "limit-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (0 == command->limit_type) {
		// individual 规则
		if (!command->username) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}

		if (!command->dbname) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "database", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (!command->filter_type_str) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-type", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->filter_sql) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "filter-sql", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/**
	 * 接着修改并发限制规则的启用开关,默认是启用
	 * @todo 暂时还没有持久化
	 */
	if (!modify_sql_dura_rule_limit_switch(
			con->srv->dura_limit_rules, command->username,
			command->dbname, command->filter_sql, command->limit_type,
			command->filter_type, command->rule_switch)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_PROCESS_IN_MEM, "modify_sql_dura_rule_limit_switch");
		return COMMAND_PROCESS_ERROR;
	} else {
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

// 构造头文件
CONSTRUCT_FIELDS_FUNC(construct_showduralimit_fields) {
	return construct_fields(showlimit_fields);
}

/** 构造showparalimit 命令的rows变量 */
/**
 * 先不显示对应规则具体对应的sql的执行条数
 * 主要是规则和执行条数无法对应起来
 * @todo 将数据结构分开？？
 * 现用的是否有对应的限制规则的标志分开成4个，统计分开成4个；
 * （这样做不好的地方是限制数不能立刻更新？但是如果是想显示对应规则的sql执行条数比现在的结构方便，也不好弄！！）
 */
CONSTRUCT_ROWS_FUNC(construct_showduralimit_rows) {
	g_assert(chas);

	if ((NULL == chas) || (NULL == chas->rule_table)) {
		return NULL ;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	GList *user_list = NULL;
	GList *user_list_tmp = NULL;
	GString *user_key = NULL;

	GList *db_list = NULL;
	GList *db_list_tmp = NULL;
	GString *db_key = NULL;

	GList *sql_list = NULL;
	GList *sql_list_tmp = NULL;
	GString *sql_key = NULL;

	db_sql_dura_list *db_sql_limit;
	sql_dura_list *sql_limit;
	dura_exec_limit *limit;

	char buffer[256];
	//GString *user_db_key = g_string_new(NULL);

	gint sql_type;

	/** 构造individual 限制列表 */
	for (sql_type = DURA_SQL_SINGLE; sql_type <= DURA_SQL_TEMPLATE;
			sql_type++) {
		g_rw_lock_writer_lock(
				&(chas->dura_limit_rules->dura_exec_individ_rules[sql_type]->list_lock));
		user_list =
				g_hash_table_get_keys(
						chas->dura_limit_rules->dura_exec_individ_rules[sql_type]->user_db_sql_list);
		user_list_tmp = user_list;
		while (user_list_tmp) {
			user_key = (GString *) (user_list_tmp->data);
			if (user_key) {
				db_sql_limit =
						g_hash_table_lookup(
								chas->dura_limit_rules->dura_exec_individ_rules[sql_type]->user_db_sql_list,
								user_key);
				g_rw_lock_writer_lock(&(db_sql_limit->list_lock));
				db_list = g_hash_table_get_keys(db_sql_limit->db_sql_list);
				db_list_tmp = db_list;
				while (db_list_tmp) {
					db_key = (GString *) (db_list_tmp->data);
					if (db_key) {
						sql_limit = g_hash_table_lookup(
								db_sql_limit->db_sql_list, db_key);
						g_rw_lock_writer_lock(&(sql_limit->list_lock));
						sql_list = g_hash_table_get_keys(sql_limit->sql_list);
						sql_list_tmp = sql_list;
						while (sql_list_tmp) {
							limit = g_hash_table_lookup(sql_limit->sql_list,
									(GString *) (sql_list_tmp->data));
							if (limit) {
								// 开始构造结果集
								row = g_ptr_array_new();

								/** username 列 */
								g_ptr_array_add(row, g_strdup(user_key->str));

								/** dbname 列 */
								g_ptr_array_add(row, g_strdup(db_key->str));

								/** sql 列 */
								g_ptr_array_add(row,
										g_strdup(
												((GString *) (sql_list_tmp->data))->str));

								/** 限制类别列：individual 或者 global */
								g_ptr_array_add(row, g_strdup("Individual"));

								/** 类别：template 或者是  single*/
								g_ptr_array_add(row,
										g_strdup(
												(DURA_SQL_SINGLE == sql_type) ?
														"Single" : "Template"));

								/** 连接限制数 */
								snprintf(buffer, 255, "%ld", limit->limit_dura);
								g_ptr_array_add(row, g_strdup(buffer));

								/** 限制开关 */
								g_ptr_array_add(row,
										g_strdup(
												limit->limit_switch ?
														"On" : "Off"));

								g_ptr_array_add(rows, row);
								row = NULL;
								limit = NULL;
							}
							sql_list_tmp = sql_list_tmp->next;
						}
						g_list_free(sql_list);
						g_rw_lock_writer_unlock(&(sql_limit->list_lock));
					}
					db_list_tmp = db_list_tmp->next;
				}
				g_list_free(db_list);
				g_rw_lock_writer_unlock(&(db_sql_limit->list_lock));
			}
			user_list_tmp = user_list_tmp->next;
		}
		g_list_free(user_list);
		g_rw_lock_writer_unlock(
				&(chas->dura_limit_rules->dura_exec_individ_rules[sql_type]->list_lock));
	}

	/** 构造global 限制列表 */
	for (sql_type = DURA_SQL_SINGLE; sql_type <= DURA_SQL_TEMPLATE;
			sql_type++) {
		g_rw_lock_writer_lock(
				&(chas->dura_limit_rules->dura_exec_global_rules[sql_type]->list_lock));
		sql_list =
				g_hash_table_get_keys(
						chas->dura_limit_rules->dura_exec_global_rules[sql_type]->sql_list);
		sql_list_tmp = sql_list;
		while (sql_list_tmp) {
			sql_key = (GString *) (sql_list_tmp->data);
			if (sql_key) {
				limit =
						g_hash_table_lookup(
								chas->dura_limit_rules->dura_exec_global_rules[sql_type]->sql_list,
								sql_key);

				if (limit) {
					// 开始构造结果集
					row = g_ptr_array_new();

					/** username 列 */
					g_ptr_array_add(row, g_strdup("NULL"));

					/** dbname 列 */
					g_ptr_array_add(row, g_strdup("NULL"));

					/** sql 列 */
					g_ptr_array_add(row, g_strdup(sql_key->str));

					/** 限制类别列：individual 或者 global */
					g_ptr_array_add(row, g_strdup("Global"));

					/** 类别：template 或者是  single*/
					g_ptr_array_add(row,
							g_strdup(
									(DURA_SQL_SINGLE == sql_type) ?
											"Single" : "Template"));

					/** 连接限制数 */
					snprintf(buffer, 255, "%ld", limit->limit_dura);
					g_ptr_array_add(row, g_strdup(buffer));

					/** 限制开关 */
					g_ptr_array_add(row,
							g_strdup(limit->limit_switch ? "On" : "Off"));

					g_ptr_array_add(rows, row);
					row = NULL;
					limit = NULL;
				}
			}
			sql_list_tmp = sql_list_tmp->next;
		}
		g_list_free(user_list);
		g_rw_lock_writer_unlock(
				&(chas->dura_limit_rules->dura_exec_global_rules[sql_type]->list_lock));
	}

	return rows;
}


ADMIN_COMMAND_PROCESS_FUNC(showduralimit_command_process) {

	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 检查参数完整性 */

	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showduralimit_fields();
	rows = construct_showduralimit_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

ADMIN_COMMAND_PROCESS_FUNC(setduralimit_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 下面检查参数的完整性 */
	if (!command->flag ||
			(g_ascii_strcasecmp("on", command->flag) != 0 && g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}


	/**
	 * 下面设置超时控制的标志
	 * @todo 没有持久化
	 */
	con->srv->dura_limit_on = ((0 == g_ascii_strcasecmp("on", command->flag)) ?TRUE : FALSE);
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

CONSTRUCT_FIELDS_FUNC(construct_showduralimitflag_fields) {
	return construct_fields(showduralimitflag_fields);
}

CONSTRUCT_ROWS_FUNC(construct_showduralimitflag_rows) {
	if ((chas == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	/** ParaLimit flag列*/
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup((chas->dura_limit_on == TRUE)? "on": "off"));
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showduralimitflag_command_process) {
	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 检查参数完整性 */

	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showduralimitflag_fields();
	rows = construct_showduralimitflag_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}


/** 构造showqueryresponsetime 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showqueryresponsetime_fields) {
	return construct_fields(showqueryresponsetime_fields);
}

/** 构造showqueryresponsetime 命令的rows变量 */
GPtrArray *construct_showqueryresponsetime_rows(chassis *chas, const gchar *username, const gchar *dbname) {
	g_assert(chas);

	if ((NULL == chas) || (NULL == chas->tmi)) {
		return NULL;
	}
	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();
	guint index;
	
	time_section_statistics *time_section_stat = NULL;
	
	GList *user_db_list = NULL;
	GList *user_db_list_tmp = NULL;
	GString *user_db_key = NULL;
	
	GList *sql_list = NULL;
	GList *sql_list_tmp = NULL;
	GString *sql_key = NULL;
	
	sql_info_table *sql_info_v = NULL;
	statistics_info *info = NULL;
	
	gchar *tmp_buffer = g_new0(gchar, 32);
	gchar **user_db_split_array = NULL;
	
	// 在执行统计管理命令时，现将sql直方图统计关掉，执行后再回复
	gboolean old = chas->is_sql_statistics;
	chas->is_sql_statistics = FALSE;
	for (index = 0; index < chas->tmi->time_section_statistics_array->len; index++) {
		// 找到对应section的hash_table
		time_section_stat = chas->tmi->time_section_statistics_array->pdata[index];
		g_rw_lock_reader_lock(&time_section_stat->table_lock);
		// 取出key链表并进行遍历
		user_db_list = g_hash_table_get_keys(time_section_stat->user_db_sql_info_table);
		user_db_list_tmp = user_db_list;
		// 对于每一个user_db的组合字符串进行遍历
		while (user_db_list_tmp) {
			user_db_key = (GString *)(user_db_list_tmp->data);
			if (user_db_key) {
				sql_info_v = g_hash_table_lookup(time_section_stat->user_db_sql_info_table, user_db_key);
				user_db_split_array = g_strsplit(user_db_key->str, "&dprxy;", 2);
				// 判断username是否符合
				if (NULL != username) {
					if (0 != strcmp(user_db_split_array[0], username)) {
						my_g_strfreev(user_db_split_array);
						user_db_list_tmp = user_db_list_tmp->next;
						continue;
					}
				}
				if (NULL != dbname) {
					if (0 != strcmp(user_db_split_array[1], dbname)) {
						my_g_strfreev(user_db_split_array);
						user_db_list_tmp = user_db_list_tmp->next;
						continue;
					}
				}
				g_rw_lock_reader_lock(&sql_info_v->table_lock);
				sql_list = g_hash_table_get_keys(sql_info_v->sql_info_table);
				sql_list_tmp = sql_list;
				while (sql_list_tmp) {
					sql_key = (GString *)(sql_list_tmp->data);
					if (sql_key) {
						info = g_hash_table_lookup(sql_info_v->sql_info_table, sql_key);
						if (info) {
							/** 构造一行新的数据单元 */
							row = g_ptr_array_new();
							
							/** 添加time列 */
							sprintf(tmp_buffer, "%lf~%lf", time_section_stat->section.lower_bound, time_section_stat->section.upper_bound);
							g_ptr_array_add(row, g_strdup(tmp_buffer));
							
							/** 添加user列 */
							g_ptr_array_add(row,
									g_strdup(user_db_split_array[0]));
							
							/** 添加db列 */
							g_ptr_array_add(row,
									g_strdup(user_db_split_array[1]));
							
							/** 添加sql列*/
							g_ptr_array_add(row,
									g_strdup(sql_key->str));
							
							/** 添加count列*/
							sprintf(tmp_buffer, "%d", info->execute_count);
							g_ptr_array_add(row, g_strdup(tmp_buffer));
							
							/** 添加total列*/
							sprintf(tmp_buffer, "%lf", info->accumulate_time);
							g_ptr_array_add(row, g_strdup(tmp_buffer));
							
							//添加到结果集中
							g_ptr_array_add(rows, row);
						}
					}
					sql_list_tmp = sql_list_tmp->next;
				}
				g_list_free(sql_list);			
				g_rw_lock_reader_unlock(&sql_info_v->table_lock);
				my_g_strfreev(user_db_split_array);
			}
			user_db_list_tmp = user_db_list_tmp->next;	
		}
		g_list_free(user_db_list);
		g_rw_lock_reader_unlock(&time_section_stat->table_lock);
	}
	g_free(tmp_buffer);
	tmp_buffer = NULL;
	chas->is_sql_statistics = old;
	return rows;
}


/** showqueryresponsetime 的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(showqueryresponsetime_command_process) {
	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	const gchar *username = NULL;
	const gchar *dbname = NULL;
	/** 检查参数完整性 */
	if (NULL != command->username) {
		username = command->username;
	}
	if (NULL != command->dbname) {
		dbname = command->dbname;
	}
	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showqueryresponsetime_fields();
	rows = construct_showqueryresponsetime_rows(con->srv, username, dbname);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** 构造showtotalresponsetime 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showtotalresponsetime_fields) {
	return construct_fields(showtotalresponsetime_fields);
}

/** 构造showtotalresponsetime 命令的rows变量 */
CONSTRUCT_ROWS_FUNC(construct_showtotalresponsetime_rows) {
	g_assert(chas);

	if ((NULL == chas) || (NULL == chas->rule_table)) {
		return NULL;
	}
	 
	/** 添加具体的规则列表，遍历SQL_SINGLE及SQL_TEMPLATE两个列表 */
	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();
	guint index;
	
	time_section_statistics *time_section_stat = NULL;

	gchar * tmp_buffer = g_new0(gchar, 32);
	
	// 在执行统计管理命令时，现将sql直方图统计关掉，执行后再回复
	gboolean old = chas->is_sql_statistics;
	chas->is_sql_statistics = FALSE;
	for (index = 0; index < chas->tmi->time_section_statistics_array->len; index++) {
		// 找到对应section对象
		time_section_stat = chas->tmi->time_section_statistics_array->pdata[index];
		
		row = g_ptr_array_new();
		
		/** 添加time列 */
		sprintf(tmp_buffer, "%lf", time_section_stat->section.upper_bound);
		g_ptr_array_add(row, g_strdup(tmp_buffer));
		
		/** 添加count列*/
		sprintf(tmp_buffer, "%d", time_section_stat->total_count);
		g_ptr_array_add(row, g_strdup(tmp_buffer));
		
		/** 添加total列*/
		sprintf(tmp_buffer, "%lf", time_section_stat->total_time);
		g_ptr_array_add(row, g_strdup(tmp_buffer));
		
		//添加到结果集中
		g_ptr_array_add(rows, row);
	}			
	g_free(tmp_buffer);
	tmp_buffer = NULL;
	chas->is_sql_statistics = old;
	return rows;
}

/** showqtotalresponsetime 的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(showtotalresponsetime_command_process) {
	g_assert(command);
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 检查参数完整性 */

	/** 检查业务逻辑正确性*/

	/** 构造结果集，返回结果*/

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现系统中设置的sql限制的列表*/
	fields = construct_showtotalresponsetime_fields();
	rows = construct_showtotalresponsetime_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** clearstatistics 的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(clearstatistics_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	// 在执行统计管理命令时，现将sql直方图统计关掉，执行后再回复
	gboolean old = con->srv->is_sql_statistics;
	con->srv->is_sql_statistics = FALSE;
	guint old_base = con->srv->tmi->base;
	time_section_index_free(con->srv->tmi);
	con->srv->tmi = time_section_index_new(old_base);
	con->srv->is_sql_statistics = old;
	
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/** 构造showstatistics 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showstatisticsswitch_fields) {
	return construct_fields(showstatisticsswitch_fields);
}

/** 构造showstatistics 命令的rows变量*/
CONSTRUCT_ROWS_FUNC(construct_showstatisticsswitch_rows) {
	if ((chas == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	/** statistics flag列*/
	row = g_ptr_array_new();
	g_ptr_array_add(row, (chas->is_sql_statistics == TRUE)? g_strdup("on"): g_strdup("off"));
	g_ptr_array_add(rows, row);

	return rows;
}

/** showstatisticsswitch 命令*/
ADMIN_COMMAND_PROCESS_FUNC(showstatisticsswitch_command_process) {
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 首先检查参数的完整性 */
	g_assert(command);
	
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现是否设置连接复用标志*/
	fields = construct_showstatisticsswitch_fields();
	rows = construct_showstatisticsswitch_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);
	
	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}

/** setstatisticsswitch 的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(setstatisticsswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	if (!command->flag || (g_ascii_strcasecmp("on", command->flag) != 0 && g_ascii_strcasecmp("off", command->flag) != 0)) {
//		network_mysqld_con_send_error(con->client,
//			C("--flag should not be NULL, and should be on/off"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	/**
	 * added by zhenfan, 2013/08/29
	 */
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setsqlstatisticsswitch(con->srv->xml_filename, command->flag)) {
//			network_mysqld_con_send_error(con->client,
//				C("encounter error when setmultiplex in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setsqlstatisticsswitch");
			return COMMAND_PROCESS_ERROR;
		}	
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		con->srv->is_sql_statistics = ((0 == g_ascii_strcasecmp("on", command->flag)) ?TRUE : FALSE);	
	}
	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/** setstatisticsbase 的处理函数 */
ADMIN_COMMAND_PROCESS_FUNC(setstatisticsbase_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	
	/** 检查参数完整性 */
	if (command->base != 2 && command->base != 10) {
//		network_mysqld_con_send_error(con->client,
//				C("--username should not be NULL when you want to set the connection limitation of a user, please see proxyhelp for more info"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "base", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	} 
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setsqlstatisticsbase(con->srv->xml_filename, command->base)) {
//			network_mysqld_con_send_error(con->client,
//				C("encounter error when setmultiplex in xml"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setsqlstatisticsbase");
			return COMMAND_PROCESS_ERROR;
		}	
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		// 在执行统计管理命令时，现将sql直方图统计关掉，执行后再回复
		gboolean old = con->srv->is_sql_statistics;
		con->srv->is_sql_statistics = FALSE;
		con->srv->sql_statistics_base = (guint)command->base;
		time_section_index_free(con->srv->tmi);
		con->srv->tmi = time_section_index_new((guint)command->base);
		con->srv->is_sql_statistics = old;		
	}
	
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

///**
// * @author sohu-inc.com
// * 命令端口输入--help 会导致core dump
// * @param query
// */
//gboolean _help_exists(char *query) {
//
//}








/**
 * 构造连接状态统计信息的表头
 * @return
 */
static GPtrArray *construct_showconnectionstate_fields() {
	return construct_fields(showconnectionstate_fields);
}

/**
 * 构造连接状态统计信息
 * @return
 */
static GPtrArray *construct_showconnectionstate_rows(chassis *chas, const gint connection_id, const gboolean full) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	gchar buffer[32] = {0};
	guint i = 0;
	guint j = 0;
	network_mysqld_con *con = NULL;
	connection_state_statistics *stats = NULL;
	connection_state_statistic *css = NULL;
	size_t len = 0;

	if (chas == NULL || chas->priv == NULL || chas->priv->cons == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();
	g_mutex_lock(&(chas->priv->cons_mutex));
	for (i =0; i < chas->priv->cons->len; i++) {
		con = chas->priv->cons->pdata[i];
		if (con == NULL || con->connection_state == NULL || con->connection_state->statistics == NULL) {
			continue;
		}
		stats = con->connection_state->statistics;
		if (connection_id == -1 || con->connection_id == (guint)connection_id) {
			for (j = 0; j < CONNECTION_STATE_LAST_ID; j++) {
				css = &(stats->statistics[j]);

				if (full == TRUE || css->cpu_count != 0 || css->cpu_time != 0
						|| css->iowait_count != 0 || css->iowait_time != 0) {
					row = g_ptr_array_new();

					snprintf(buffer, sizeof(buffer)-1, "%d", con->connection_id);
					g_ptr_array_add(row, g_strdup(buffer));

					g_ptr_array_add(row, g_strdup(connection_state_get_name(css->state_id, &len)));

					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->cpu_count);
					g_ptr_array_add(row, g_strdup(buffer));
					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->cpu_time);
					g_ptr_array_add(row, g_strdup(buffer));
					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->iowait_count);
					g_ptr_array_add(row, g_strdup(buffer));
					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->iowait_time);
					g_ptr_array_add(row, g_strdup(buffer));

					g_ptr_array_add(rows, row);
				}
			}
		}
	}
	g_mutex_unlock(&(chas->priv->cons_mutex));

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showconnectionstate_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showconnectionstate_fields();
	rows = construct_showconnectionstate_rows(con->srv, command->connection_id, command->connectionstatefull);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

static gboolean flushconnectionstate_do(chassis *chas, const gint connection_id) {
	guint i = 0;
	network_mysqld_con *con = NULL;
	connection_state_statistics *stats = NULL;

	if (chas == NULL || chas->priv == NULL || chas->priv->cons == NULL) {
		return FALSE;
	}

	g_mutex_lock(&(chas->priv->cons_mutex));
	for (i =0; i < chas->priv->cons->len; i++) {
		con = chas->priv->cons->pdata[i];
		if (con == NULL || con->connection_state == NULL || con->connection_state->statistics == NULL) {
			continue;
		}
		stats = con->connection_state->statistics;
		if (connection_id == -1 || con->connection_id == (guint)connection_id) {
			connection_state_statistics_clear(stats);
		}
	}
	g_mutex_unlock(&(chas->priv->cons_mutex));
	return TRUE;
}

ADMIN_COMMAND_PROCESS_FUNC(flushconnectionstate_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	flushconnectionstate_do(con->srv, command->connection_id);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}


/**
 * 构造线程连接状态统计信息的表头
 * @return
 */
static GPtrArray *construct_showthreadconnectionstate_fields() {
	return construct_fields(showthreadconnectionstate_fields);
}

/**
 * 构造线程连接状态统计信息
 * @return
 */
static GPtrArray *construct_showthreadconnectionstate_rows(chassis *chas, const gchar *thread_name, const gboolean full) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	gchar buffer[32] = {0};
	guint i = 0;
	guint j = 0;
	chassis_event_thread_t *thr = NULL;
	connection_state_statistics *stats = NULL;
	connection_state_statistic *css = NULL;
	size_t len = 0;

	if (chas == NULL || chas->threads == NULL || chas->threads->event_threads == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();
	for (i =0; i < chas->threads->event_threads->len; i++) {
		thr = chas->threads->event_threads->pdata[i];
		if (thr == NULL || thr->connection_state == NULL || thr->connection_state->statistics == NULL) {
			continue;
		}
		stats = thr->connection_state->statistics;
		if (thread_name == NULL || g_strcmp0(thread_name, thr->name->str) == 0) {
			for (j = 0; j < CONNECTION_STATE_LAST_ID; j++) {
				css = &(stats->statistics[j]);

				if (full == TRUE || css->cpu_count != 0 || css->cpu_time != 0
						|| css->iowait_count != 0 || css->iowait_time != 0) {
					row = g_ptr_array_new();

					g_ptr_array_add(row, g_strdup(thr->name->str));

					g_ptr_array_add(row, g_strdup(connection_state_get_name(css->state_id, &len)));

					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->cpu_count);
					g_ptr_array_add(row, g_strdup(buffer));
					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->cpu_time);
					g_ptr_array_add(row, g_strdup(buffer));
					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->iowait_count);
					g_ptr_array_add(row, g_strdup(buffer));
					snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->iowait_time);
					g_ptr_array_add(row, g_strdup(buffer));

					g_ptr_array_add(rows, row);
				}
			}
		}
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showthreadconnectionstate_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showthreadconnectionstate_fields();
	rows = construct_showthreadconnectionstate_rows(con->srv, command->thread_name, command->connectionstatefull);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

static gboolean flushthreadconnectionstate_do(chassis *chas, const gchar *thread_name) {
	guint i = 0;
	chassis_event_thread_t *thr = NULL;
	connection_state_statistics *stats = NULL;

	if (chas == NULL || chas->threads == NULL || chas->threads->event_threads == NULL) {
		return FALSE;
	}

	for (i =0; i < chas->threads->event_threads->len; i++) {
		thr = chas->threads->event_threads->pdata[i];
		if (thr == NULL || thr->connection_state == NULL || thr->connection_state->statistics == NULL) {
			continue;
		}
		stats = thr->connection_state->statistics;
		if (thread_name == NULL || g_strcmp0(thread_name, thr->name->str) == 0) {
			connection_state_statistics_clear(stats);
		}
	}
	return TRUE;
}

ADMIN_COMMAND_PROCESS_FUNC(flushthreadconnectionstate_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	flushthreadconnectionstate_do(con->srv, command->thread_name);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}


/**
 * 构造全局连接状态统计信息的表头
 * @return
 */
static GPtrArray *construct_showglobalconnectionstate_fields() {
	return construct_fields(showglobalconnectionstate_fields);
}

/**
 * 构造全局连接状态统计信息
 * @return
 */
static GPtrArray *construct_showglobalconnectionstate_rows(chassis *chas, const gboolean full) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	gchar buffer[32] = {0};
	guint j = 0;
	connection_state_statistics *stats = NULL;
	connection_state_statistic *css = NULL;
	size_t len = 0;

	if (chas == NULL || chas->connection_state == NULL ||chas->connection_state->statistics == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();

	stats = chas->connection_state->statistics;
	for (j = 0; j < CONNECTION_STATE_LAST_ID; j++) {
		css = &(stats->statistics[j]);

		if (full == TRUE || css->cpu_count != 0 || css->cpu_time != 0
				|| css->iowait_count != 0 || css->iowait_time != 0) {
			row = g_ptr_array_new();

			g_ptr_array_add(row, g_strdup(connection_state_get_name(css->state_id, &len)));

			snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->cpu_count);
			g_ptr_array_add(row, g_strdup(buffer));
			snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->cpu_time);
			g_ptr_array_add(row, g_strdup(buffer));
			snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->iowait_count);
			g_ptr_array_add(row, g_strdup(buffer));
			snprintf(buffer, sizeof(buffer)-1, "%"G_GUINT64_FORMAT"", css->iowait_time);
			g_ptr_array_add(row, g_strdup(buffer));

			g_ptr_array_add(rows, row);
		}
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showglobalconnectionstate_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showglobalconnectionstate_fields();
	rows = construct_showglobalconnectionstate_rows(con->srv, command->connectionstatefull);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

static gboolean flushglobalconnectionstate_do(chassis *chas) {
	connection_state_statistics *stats = NULL;

	if (chas == NULL || chas->connection_state == NULL ||chas->connection_state->statistics == NULL) {
		return FALSE;
	}

	stats = chas->connection_state->statistics;
	connection_state_statistics_clear(stats);

	return TRUE;
}

ADMIN_COMMAND_PROCESS_FUNC(flushglobalconnectionstate_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	flushglobalconnectionstate_do(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}



/*///// 负载均衡 /////*/

/**
 * 构造负载均衡算法的显示内容的表头
 * @return
 */
static GPtrArray *construct_showlbalgo_fields() {
	return construct_fields(showlbalgo_fields);
}

/**
 * 构造负载均衡算法显示内容
 * @return
 */
static GPtrArray *construct_showlbalgo_rows(chassis *chas, const gchar *port_type) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();

	if (port_type == NULL || 0 == g_ascii_strcasecmp(port_type, "rw")) {
		row = g_ptr_array_new();
		g_ptr_array_add(row, g_strdup("rw"));
		if (chas->lb_algo[PROXY_TYPE_WRITE] == NULL) {
			g_ptr_array_add(row, g_strdup("lc(default)"));
		} else {
			g_ptr_array_add(row, g_strdup(chas->lb_algo[PROXY_TYPE_WRITE]));
		}
		g_ptr_array_add(rows, row);
	}

	if (port_type == NULL || 0 == g_ascii_strcasecmp(port_type, "ro")) {
		row = g_ptr_array_new();
		g_ptr_array_add(row, g_strdup("ro"));
		if (chas->lb_algo[PROXY_TYPE_READ] == NULL) {
			g_ptr_array_add(row, g_strdup("lc(default)"));
		} else {
			g_ptr_array_add(row, g_strdup(chas->lb_algo[PROXY_TYPE_READ]));
		}
		g_ptr_array_add(rows, row);
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showlbalgo_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

//	if (command->port_type != NULL) {
//		if (check_port_type(command->port_type)) {
//			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "--port_type", "ro or rw", "proxyhelp");
//			return COMMAND_PROCESS_ERROR;
//		}
//	}

	fields = construct_showlbalgo_fields();
	rows = construct_showlbalgo_rows(con->srv, command->port_type);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

static void setlbalgo_command_process_do(chassis *chas, const proxy_rw conn_type, const gchar *lb_str) {
	if ( g_ascii_strcasecmp(lb_str, "lc") == 0 ) {
		chas->lb_algo[conn_type] = "lc";
		chas->lb_algo_func[conn_type] = loadbalance_lc_select;
	} else if ( g_ascii_strcasecmp(lb_str, "wrr") == 0 ) {
		chas->lb_algo[conn_type] = "wrr";
		chas->lb_algo_func[conn_type] = loadbalance_wrr_select;
	}
}

ADMIN_COMMAND_PROCESS_FUNC(setlbalgo_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (command->lbalgo_str == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "lbalgo", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (g_ascii_strcasecmp("lc", command->lbalgo_str) != 0 && g_ascii_strcasecmp("wrr", command->lbalgo_str) != 0) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "lbalgo", "lc or wrr", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}
	if (command->port_type != NULL) {
		if (check_port_type(command->port_type) != TRUE) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "--port_type", "ro or rw", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (command->port_type == NULL || 0 == g_ascii_strcasecmp(command->port_type, "rw")) {
		setlbalgo_command_process_do(con->srv, PROXY_TYPE_WRITE, command->lbalgo_str);
	}
	if (command->port_type == NULL || 0 == g_ascii_strcasecmp(command->port_type, "ro")) {
		setlbalgo_command_process_do(con->srv, PROXY_TYPE_READ, command->lbalgo_str);
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}




/*///// 日志级别 /////*/

/**
 * 构造日志级别的显示内容的表头
 * @return
 */
static GPtrArray *construct_showloglevel_fields() {
	return construct_fields(showloglevel_fields);
}

/**
 * 构造日志级别显示内容
 * @return
 */
static GPtrArray *construct_showloglevel_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}
	if (chas->log == NULL) {
		return NULL;
	}

	const char *loglevel = chassis_log_get_level_name(chas->log->min_lvl);
	if (loglevel == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(loglevel));

	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showloglevel_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showloglevel_fields();
	rows = construct_showloglevel_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setloglevel_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->log);

	if (command->loglevel_str == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "loglevel", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (chassis_log_set_level(con->srv->log, command->loglevel_str) != 0) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "loglevel", "debug or info or message or warning or critical or error", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}

//static gboolean is_hostip_contained_BF(const gchar *addresses, const gchar *hostip, int pos) {
//	//brutal force算法实现字符串匹配
//	if (hostip == NULL) {
//		return TRUE;
//	}
//
//	if (addresses == NULL) {
//		return FALSE;
//	}
//
//	gboolean ret = FALSE;
//	g_assert(pos >= 0);
//
//	int index = pos, j = 0;
//
//	while (addresses[index + j] != '\0' && hostip[j] != '\0') {
//		if (addresses[index + j] == hostip[j]) {
//			j++;
//		} else {
//			index++;
//			j = 0;
//		}
//	}
//
//	if (hostip[j] == '\0') {
//		ret = TRUE;
//	}
//
//	return ret;
//}

//static gboolean is_hostip_contained(const gchar * addresses, const gchar * hostip) {
//	// 使用kmp算法查看addresses 中是否包含 hostip 串
//	gboolean ret = FALSE;
//
//	return ret;
//}

static gboolean init_listen_socket(chassis *chas,
		const gchar *ip_port,
		proxy_rw type) {
	g_assert(chas);
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);

	g_assert(ip_port);

	network_mysqld_con *con = NULL;

	con = network_mysqld_con_new();
	g_assert(con);
	network_mysqld_add_connection(chas, con);

	// 设置连接的读写属性
	con->type = type;
	con->config = NULL;

	// 创建写的socket监听
	con->server = network_socket_new();

	if (chas->proxy_connection_init_ptr) {
		chas->proxy_connection_init_ptr(con);
	}
	// 设置后端的监听地址
	if (0 != network_address_set_address(con->server->dst,
					ip_port)) {
		return FALSE ;
	}

	if (0 != network_socket_bind(con->server)) {
		return FALSE ;
	}
	g_message("[%s]: have add %s proxy listen on port %s", G_STRLOC,
			(type == PROXY_TYPE_WRITE) ? "rw" : "ro", ip_port);

	/**
	 * call network_mysqld_con_accept() with this connection when we are done
	 */
	event_assign(&(con->server->event), chas->event_base, con->server->fd,
			EV_READ | EV_PERSIST, network_mysqld_con_accept, con);
	event_add(&(con->server->event), NULL );

	/** 将监听的连接放入监听端口索引列表 */
	GString *listen_key = g_string_new(ip_port);
	g_hash_table_insert(chas->listen_cons[type], listen_key, con);

	return TRUE;
}

//// 动态绑定多虚ip相关 ////

/** 监听地址的动态增减 */
ADMIN_COMMAND_PROCESS_FUNC(addlistenaddr_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->listen_addresses[0]);
	g_assert(con->srv->listen_addresses[1]);

	if (command->backend == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (command->bktype == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "bktype", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (strstr(con->srv->listen_addresses[0]->str, command->backend) ||
			strstr(con->srv->listen_addresses[1]->str, command->backend)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_ALREADY_EXISTS, "listen address");
		return COMMAND_PROCESS_ERROR;
	}

	// 添加监听socket，并注册事件若失败，返回明确的错误信息
	proxy_rw type_add = PROXY_TYPE_WRITE;
	if (0 == g_ascii_strcasecmp(command->bktype, "ro")) {
		type_add = PROXY_TYPE_READ;
	}

	// 先更新xml里面的文件
	if (!config_addlistenaddr(con->srv->xml_filename, command->backend, type_add)) {
		g_critical("[%s]:listen socket added error when processing xml file", G_STRLOC);
		mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "addlistenaddr");
		return COMMAND_PROCESS_ERROR;
	}

	// 开始在内存中添加监听端口
	if (!init_listen_socket(con->srv, command->backend, type_add)) {
		g_critical("[%s]:listen socket added error, will send error to client", G_STRLOC);
		config_dellistenaddr(con->srv->xml_filename, command->backend, type_add);
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ADD_LISTEN_SOCKET);
		return COMMAND_PROCESS_ERROR;
	} else {
		if (con->srv->listen_addresses[type_add]->len > 0) {
			if (0 != strcmp(con->srv->listen_addresses[type_add]->str, " ")) {
				g_string_append(con->srv->listen_addresses[type_add], ",");
			} else {
				g_string_truncate(con->srv->listen_addresses[type_add], 0);
			}
		}
		g_string_append(con->srv->listen_addresses[type_add], command->backend);
		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/**
 * 通过设置标志位来close监听端口
 * @param chas
 * @param listen_addr
 * @param listen_type
 * @return
 */
static gboolean del_listen_socket(chassis *chas, const gchar *listen_addr, proxy_rw listen_type) {
	g_assert(chas);
	g_assert(listen_addr);
	g_assert(listen_type == PROXY_TYPE_WRITE || listen_type == PROXY_TYPE_READ);

	GString *listen_key = g_string_new(listen_addr);
	network_mysqld_con * listen_con = (network_mysqld_con *)g_hash_table_lookup(chas->listen_cons[listen_type], listen_key);

	if (listen_con) {
		g_message("[%s]:going to set listening socket on %s closed...",
				G_STRLOC,
				listen_addr);
		mysqld_con_set_killed_location(listen_con, G_STRLOC);

		g_hash_table_remove(chas->listen_cons[listen_type], listen_key);
	}

	g_string_free(listen_key, TRUE);

	return TRUE;
}

/** 监听地址的动态删除 */
//// 希望通过设置标志位的方式来实现对监听端口的关闭删除
//// 考虑一下方面：
//// 1. 尽快找到需要删除的监听对象变量；
//// 2. 尽量在一个线程中实现对监听端口的注册事件的处理，
////      方式a:因而admin线程通过设置标志位的方式来告知主线程某监听端口被关闭？在下一次连接到来时关闭？有可能一直关闭不了
////      方式b:通过外线程中直接，删除监听端口的事件，后端关闭连接，但是内存变量不会删除，避免出现之前使用libevent遇到的多线程操作的问题
ADMIN_COMMAND_PROCESS_FUNC(dellistenaddr_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->listen_addresses[0]);
	g_assert(con->srv->listen_addresses[1]);

	if (command->backend == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "backend", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (command->bktype == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "bktype", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	// 添加监听socket，并注册事件若失败，返回明确的错误信息
	proxy_rw type_add = PROXY_TYPE_WRITE;
	if (0 == g_ascii_strcasecmp(command->bktype, "ro")) {
		type_add = PROXY_TYPE_READ;
	}

	gchar * s_pos = NULL;
	if (NULL == (s_pos = strstr(con->srv->listen_addresses[type_add]->str, command->backend))) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "listen address");
		return COMMAND_PROCESS_ERROR;
	}

	// 先更新xml里面的文件
	if (!config_dellistenaddr(con->srv->xml_filename, command->backend, type_add)) {
		g_critical("[%s]:listen socket deleteded error when processing xml file", G_STRLOC);
		mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "dellistenaddr");
		return COMMAND_PROCESS_ERROR;
	}

	// 开始在内存中删除监听端口
	if (!del_listen_socket(con->srv, command->backend, type_add)) {
		g_critical("[%s]:listen socket added error, will send error to client", G_STRLOC);
		mpe_send_error(con->client, MPE_ADM_CMDPRC_DEL_LISTEN_SOCKET);
		return COMMAND_PROCESS_ERROR;
	} else {
		guint len = strlen(command->backend);
		guint post_index = s_pos - con->srv->listen_addresses[type_add]->str + len;
		guint remove_len = len;
		if ((con->srv->listen_addresses[type_add]->len > (guint)(s_pos - con->srv->listen_addresses[type_add]->str + len)) && (',' == con->srv->listen_addresses[type_add]->str[post_index])) {
			remove_len++;
		}

		g_string_erase(con->srv->listen_addresses[type_add],
				s_pos - con->srv->listen_addresses[type_add]->str,
				remove_len);
		if (con->srv->listen_addresses[type_add]->len > 0 && ',' == con->srv->listen_addresses[type_add]->str[con->srv->listen_addresses[type_add]->len - 1]) {
			g_string_truncate(con->srv->listen_addresses[type_add], con->srv->listen_addresses[type_add]->len - 1);
		}

		network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
		return COMMAND_PROCESS_SUCCESS;
	}
}

/** 查看监听的端口，读写端口（不包括管理端口） */

/**
 * 构造监听地址列表的显示内容的表头
 * @return
 */
static GPtrArray *construct_showlistenaddr_fields() {
	return construct_fields(showlistenaddr_fields);
}

/**
 * 构造日志级别显示内容
 * @return
 */
static GPtrArray *construct_showlistenaddr_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}

	if ((NULL == chas->listen_addresses[0] || 0 == chas->listen_addresses[0]->len) &&
			(NULL == chas->listen_addresses[1] || 0 == chas->listen_addresses[1]->len)) {
		return NULL;
	}


	rows = g_ptr_array_new();

	proxy_rw type = 0;

	for (type = 0; type <= PROXY_TYPE_READ; type++) {
		if (chas->listen_addresses[type] && (chas->listen_addresses[type]->len > 0 && 0 != strcmp(chas->listen_addresses[type]->str, " "))) {
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup((PROXY_TYPE_WRITE == type)?"rw":"ro"));


			g_ptr_array_add(row, g_strdup(chas->listen_addresses[type]->str));

			g_ptr_array_add(rows, row);

			row = NULL;
		}
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showlistenaddr_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showlistenaddr_fields();
	rows = construct_showlistenaddr_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}






/**
 * 构造慢查询日志配置的显示内容的表头
 * @return
 */
static GPtrArray *construct_showslowlogconf_fields() {
	return construct_fields(showslowlogconf_fields);
}

/**
 * 构造慢查询日志配置显示内容
 * @return
 */
static GPtrArray *construct_showslowlogconf_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	gchar s[1024];

	if (chas == NULL) {
		return NULL;
	}
	if (chas->slow_query_log_config == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();

	row = g_ptr_array_new();

	g_ptr_array_add(row, g_strdup( chas->slow_query_log_config->is_enabled==TRUE?"on":"off" ));

	if (chas->slow_query_log_config->filter != NULL) {
		g_snprintf(s, sizeof(s)-1, "%f", chas->slow_query_log_config->filter->time_threshold_s);
		g_ptr_array_add(row, g_strdup( s ));
	} else {
		g_ptr_array_add(row, g_strdup( "" ));
	}

	g_ptr_array_add(row,
			g_strdup(
					chas->slow_query_log_config->log_file != NULL ?
							(chas->slow_query_log_config->log_file->log_filename
									!= NULL ?
									chas->slow_query_log_config->log_file->log_filename :
									"") :
							""));

	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showslowlogconf_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showslowlogconf_fields();
	rows = construct_showslowlogconf_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setslowlogconf_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->log);

	if (command->slowlogswitch != NULL) {
		if (g_ascii_strcasecmp(command->slowlogswitch, "on") == 0
				|| g_ascii_strcasecmp(command->slowlogswitch, "true")
				|| g_ascii_strcasecmp(command->slowlogswitch, "1")) {
			slow_query_log_enable(con->srv->slow_query_log_config);
		} else if (g_ascii_strcasecmp(command->slowlogswitch, "off") == 0
				|| g_ascii_strcasecmp(command->slowlogswitch, "false")
				|| g_ascii_strcasecmp(command->slowlogswitch, "0")) {
			slow_query_log_disable(con->srv->slow_query_log_config);
		} else {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID,
					"slowlogswitch", "on or off", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
	}

	if (command->slowlogtime != NULL) {
		gchar *err;
		con->srv->slow_query_log_config->filter->time_threshold_s = g_strtod(command->slowlogtime, &err);
		if (*err!=0 && g_ascii_isspace(*err)!=TRUE) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "slowlogtime", "<seconds>", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
		con->srv->slow_query_log_config->filter->time_threshold_us = (guint64) (con->srv->slow_query_log_config->filter->time_threshold_s * 1000000);
	}

	if (command->slowlogfile != NULL) {
		gchar *saved = NULL;
		saved = g_strdup(con->srv->slow_query_log_config->log_file->log_filename);
		con->srv->slow_query_log_config->log_file->log_filename = g_strdup(command->slowlogfile);
		if (con->srv->slow_query_log_config->log_file->log_filename == NULL) {
			g_free(saved);
			saved = NULL;
			mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "slowlogfile", "<filename>", "proxyhelp");
			return COMMAND_PROCESS_ERROR;
		}
		chassis_resolve_path(con->srv->base_dir, &(con->srv->slow_query_log_config->log_file->log_filename));
		if (g_strcmp0(saved, con->srv->slow_query_log_config->log_file->log_filename)!=0) {
			if (con->srv->slow_query_log_config->is_enabled == TRUE) {
				g_debug("new slow log reopen: %s", con->srv->slow_query_log_config->log_file->log_filename);
				slow_query_log_disable(con->srv->slow_query_log_config);
				slow_query_log_enable(con->srv->slow_query_log_config);
			}
		} else {
			g_debug("same slow log: %s", saved);
		}
		g_free(saved);
		saved = NULL;
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}




/**
 * 构造慢查询日志配置的显示内容的表头
 * @return
 */
static GPtrArray *construct_showsqlaccnum_fields() {
	return construct_fields(showsqlaccnum_fields);
}
static GPtrArray *construct_showsqlaccnum_row(GHashTable *query_list,
		const char *username, const char *is_banned, const gboolean is_banned_bool) {
	GPtrArray *row = NULL;
	GString *key = NULL;
	query_rate_statistic *stat = NULL;
	gchar s[1024] = {0};
	int index = 0;
	gint64 total_num = 0;
	GDateTime *dtime = NULL;
	gchar *time_str = NULL;

	key = g_string_new(username);
	stat = g_hash_table_lookup(query_list, key);
	g_string_free(key, TRUE);
	key = NULL;
	if (stat == NULL) {
		return NULL;
	}

	if (is_banned != NULL && stat->is_banned != is_banned_bool) {
		return NULL;
	}

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(username));

	total_num = 0;
	for (index = 0; index < PROXY_TYPE_NO; index++) {
		total_num += stat->query_accumulated_num[index];
	}
	g_sprintf(s, "%ld", total_num);
	g_ptr_array_add(row, g_strdup(s));

	g_sprintf(s, "%ld", stat->query_accumulated_num[PROXY_TYPE_WRITE]);
	g_ptr_array_add(row, g_strdup(s));

	g_sprintf(s, "%ld", stat->query_accumulated_num[PROXY_TYPE_READ]);
	g_ptr_array_add(row, g_strdup(s));

	total_num = 0;
	for (index = 0; index < PROXY_TYPE_NO; index++) {
		total_num += stat->query_accumulated_error_num[index];
	}
	g_sprintf(s, "%ld", total_num);
	g_ptr_array_add(row, g_strdup(s));

	g_ptr_array_add(row, g_strdup(stat->is_banned?"On":"Off"));

	dtime = g_date_time_new_from_timeval_local(&stat->update_time);
	time_str = g_date_time_format(dtime, "%F %T");
	g_ptr_array_add(row, g_strdup(time_str));
	g_free(time_str);
	time_str = NULL;
	g_date_time_unref(dtime);
	dtime = NULL;

	return row;
}
/**
 * 构造慢查询日志配置显示内容
 * @return
 */
static GPtrArray *construct_showsqlaccnum_rows(chassis *chas,
		const char *username, const char *is_banned, const gboolean is_banned_bool) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	GList *users = NULL;
	GList *tmp_user_list = NULL;
	user_info *tmp_user = NULL;
	const gchar *tmp_username = NULL;

	if (chas == NULL) {
		return NULL;
	}

	if (chas->query_rate_list == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();

	/** 获取所有的用户信息列表 */
	users = g_hash_table_get_values(chas->user_infos);
	g_mutex_lock(chas->query_rate_list->list_lock);

	for (tmp_user_list = users; tmp_user_list != NULL; tmp_user_list = tmp_user_list->next) {
		tmp_user = (user_info *)(tmp_user_list->data);
		if (tmp_user == NULL) {
			continue;
		}

		if (username != NULL && g_ascii_strcasecmp(tmp_user->username->str, username) != 0) {
			continue;
		}

		if (username == NULL) {
			tmp_username = tmp_user->username->str;
		} else {
			tmp_username = username;
		}
		row = construct_showsqlaccnum_row(chas->query_rate_list->query_list,
				tmp_username, is_banned, is_banned_bool);
		if (row != NULL) {
			g_ptr_array_add(rows, row);
		}
	}

	g_mutex_unlock(chas->query_rate_list->list_lock);
	if (users != NULL) {
		g_list_free(users);
		users = NULL;
	}

	return rows;
}
ADMIN_COMMAND_PROCESS_FUNC(showsqlaccnum_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showsqlaccnum_fields();
	rows = construct_showsqlaccnum_rows(con->srv, command->username,
			command->is_banned, command->is_banned_bool);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}


ADMIN_COMMAND_PROCESS_FUNC(setusersqlaccswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->is_banned ||
			(g_ascii_strcasecmp("on", command->is_banned) != 0 &&
					g_ascii_strcasecmp("off", command->is_banned) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "is-banned", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to %s the query of %s",
			G_STRLOC,
			(g_ascii_strcasecmp("on", command->is_banned) == 0?"ban":"unban"),
			command->username);

	user_info *user =  get_user_info_for_user(con->srv, command->username);
	if (user == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
		return COMMAND_PROCESS_ERROR;
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_limit_flag_set(con->srv->xml_filename, command->username, SQL_ACC_FLAG,
				command->is_banned_bool)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setusersqlaccswitch");
					return COMMAND_PROCESS_ERROR;
				}
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		modify_query_rate_switch(con->srv->query_rate_list,
				command->username,
				command->is_banned_bool);
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}



ADMIN_COMMAND_PROCESS_FUNC(setsqlaccswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->flag ||
			(g_ascii_strcasecmp("on", command->flag) != 0 &&
					g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to set accumulate statistic of query sql %s",
			G_STRLOC,
			g_ascii_strcasecmp("on", command->flag) == 0?"On":"Off");
	con->srv->is_query_r_enabled = (g_ascii_strcasecmp("on", command->flag) == 0?TRUE:FALSE);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}

static GPtrArray *construct_showsqlaccswitch_fields() {
	return construct_fields(showsqlaccswitch_fields);
}

static GPtrArray *construct_showsqlaccswitch_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(chas->is_query_r_enabled?"On":"Off"));
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showsqlaccswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showsqlaccswitch_fields();
	rows = construct_showsqlaccswitch_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

//////
/// DML 封禁相关的管理命令处理函数
///////////////
static GPtrArray *construct_showsqldmlswitch_fields() {
	return construct_fields(showsqldmlswitch_fields);
}

static GPtrArray *construct_showsqldmlswitch_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(chas->is_dml_check_enable?"On":"Off"));
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showsqldmlswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showsqldmlswitch_fields();
	rows = construct_showsqldmlswitch_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

static GPtrArray *construct_showusersqldml_fields() {
	return construct_fields(showusersqldml_fields);
}

static GPtrArray *construct_showusersqldml_row(GHashTable *query_list,
		const char *username, const char *is_banned, const gboolean is_banned_bool) {
	GPtrArray *row = NULL;
	GString *key = NULL;
	query_dml_statistic *stat = NULL;
	GDateTime *dtime = NULL;
	gchar *time_str = NULL;

	key = g_string_new(username);
	stat = g_hash_table_lookup(query_list, key);
	g_string_free(key, TRUE);
	key = NULL;
	if (stat == NULL) {
		return NULL;
	}

	if (is_banned != NULL && stat->is_banned != is_banned_bool) {
		return NULL;
	}

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(username));

	g_ptr_array_add(row, g_strdup(stat->is_banned?"On":"Off"));

	dtime = g_date_time_new_from_timeval_local(&stat->update_time);
	time_str = g_date_time_format(dtime, "%F %T");
	g_ptr_array_add(row, g_strdup(time_str));
	g_free(time_str);
	time_str = NULL;
	g_date_time_unref(dtime);
	dtime = NULL;

	return row;
}

static GPtrArray *construct_showusersqldml_rows(chassis *chas,
		const char *username, const char *is_banned, const gboolean is_banned_bool) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	GList *users = NULL;
	GList *tmp_user_list = NULL;
	user_info *tmp_user = NULL;
	const gchar *tmp_username = NULL;

	if (chas == NULL) {
		return NULL;
	}

	if (chas->query_rate_list == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();

	/** 获取所有的用户信息列表 */
	users = g_hash_table_get_values(chas->user_infos);
	g_mutex_lock(chas->query_dml_list->list_lock);

	for (tmp_user_list = users; tmp_user_list != NULL; tmp_user_list = tmp_user_list->next) {
		tmp_user = (user_info *)(tmp_user_list->data);
		if (tmp_user == NULL) {
			continue;
		}

		if (username != NULL && g_ascii_strcasecmp(tmp_user->username->str, username) != 0) {
			continue;
		}

		if (username == NULL) {
			tmp_username = tmp_user->username->str;
		} else {
			tmp_username = username;
		}
		row = construct_showusersqldml_row(chas->query_dml_list->query_list,
				tmp_username, is_banned, is_banned_bool);
		if (row != NULL) {
			g_ptr_array_add(rows, row);
		}
	}

	g_mutex_unlock(chas->query_dml_list->list_lock);
	if (users != NULL) {
		g_list_free(users);
		users = NULL;
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showusersqldml_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showusersqldml_fields();
	rows = construct_showusersqldml_rows(con->srv, command->username,
			command->is_banned, command->is_banned_bool);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

static GPtrArray *construct_showsqldmlkind_fields() {
	return construct_fields(showsqldmlkind_fields);
}

static GPtrArray *construct_showsqldmlkind_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();
	row = g_ptr_array_new();
	int index = 0;
	for (index = DML_ALTER; index <= DML_UPDATE; index++) {
		g_ptr_array_add(row, g_strdup(chas->dml_ops[index]?"On":"Off"));
	}
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showsqldmlkind_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showsqldmlkind_fields();
	rows = construct_showsqldmlkind_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setusersqldmlswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->is_banned ||
			(g_ascii_strcasecmp("on", command->is_banned) != 0 &&
					g_ascii_strcasecmp("off", command->is_banned) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "is-banned", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to %s the query of %s",
			G_STRLOC,
			(g_ascii_strcasecmp("on", command->is_banned) == 0?"ban":"unban"),
			command->username);

	user_info *user =  get_user_info_for_user(con->srv, command->username);
	if (user == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
		return COMMAND_PROCESS_ERROR;
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_limit_flag_set(con->srv->xml_filename, command->username, SIZE_ACC_FLAG,
				command->is_banned_bool)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setusersqlaccswitch");
					return COMMAND_PROCESS_ERROR;
				}
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		modify_query_dml_switch(con->srv->query_dml_list,
				command->username,
				command->is_banned_bool);
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setsqldmlswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->flag ||
			(g_ascii_strcasecmp("on", command->flag) != 0 &&
					g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to set accumulate statistic of query sql %s",
			G_STRLOC,
			g_ascii_strcasecmp("on", command->flag) == 0?"On":"Off");
	con->srv->is_dml_check_enable = (g_ascii_strcasecmp("on", command->flag) == 0?TRUE:FALSE);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}


/////
/// 流入流出流量相关的函数
////////////////

static GPtrArray *construct_showthroughoutacc_fields() {
	return construct_fields(showthroughputacc_fields);
}
static GPtrArray *construct_showthroughoutacc_row(
		GHashTable *in_query_list, GHashTable *out_query_list,
		const char *username, const char *is_banned,
		const gboolean is_banned_bool) {
	GPtrArray *row = NULL;
	GString *key = NULL;
	query_inbytes_statistic *in_stat = NULL;
	query_outbytes_statistic *out_stat = NULL;
	gchar s[1024] = {0};
	int index = 0;
	gint64 total_num = 0;
	GDateTime *dtime = NULL;
	gchar *time_str = NULL;

	key = g_string_new(username);
	in_stat = g_hash_table_lookup(in_query_list, key);
	out_stat = g_hash_table_lookup(out_query_list, key);
	g_string_free(key, TRUE);
	key = NULL;
	if (in_stat == NULL && out_stat == NULL) {
		return NULL;
	}

	if (is_banned != NULL && in_stat->is_banned != is_banned_bool
			&& out_stat->is_banned != is_banned_bool) {
		return NULL ;
	}

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(username));

	if (in_stat != NULL) {
		total_num = 0;
		for (index = 0; index < PROXY_TYPE_NO; index++) {
			total_num += in_stat->query_accumulated_inbytes[index];
		}
		g_sprintf(s, "%ld", total_num);
		g_ptr_array_add(row, g_strdup(s));

		g_ptr_array_add(row, g_strdup(in_stat->is_banned ? "On" : "Off"));

		dtime = g_date_time_new_from_timeval_local(&in_stat->update_time);
		time_str = g_date_time_format(dtime, "%F %T");
		g_ptr_array_add(row, g_strdup(time_str));
		g_free(time_str);
		time_str = NULL;
		g_date_time_unref(dtime);
		dtime = NULL;
	} else {
		for (index = 0; index < 3; index++) {
			g_ptr_array_add(row, g_strdup(""));
		}
	}

	if (out_stat != NULL) {
		total_num = 0;
		for (index = 0; index < PROXY_TYPE_NO; index++) {
			total_num += out_stat->query_accumulated_outbytes[index];
		}
		g_sprintf(s, "%ld", total_num);
		g_ptr_array_add(row, g_strdup(s));

		g_ptr_array_add(row, g_strdup(out_stat->is_banned ? "On" : "Off"));

		dtime = g_date_time_new_from_timeval_local(&out_stat->update_time);
		time_str = g_date_time_format(dtime, "%F %T");
		g_ptr_array_add(row, g_strdup(time_str));
		g_free(time_str);
		time_str = NULL;
		g_date_time_unref(dtime);
		dtime = NULL;
	} else {
		for (index = 0; index < 3; index++) {
			g_ptr_array_add(row, g_strdup(""));
		}
	}

	return row;
}
static GPtrArray *construct_showthroughoutacc_rows(chassis *chas,
		const char *username, const char *is_banned, const gboolean is_banned_bool) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;
	GList *users = NULL;
	GList *tmp_user_list = NULL;
	user_info *tmp_user = NULL;
	const gchar *tmp_username = NULL;

	if (chas == NULL ) {
		return NULL ;
	}

	if (chas->inbytes_list == NULL || chas->outbytes_list == NULL) {
		return NULL ;
	}

	rows = g_ptr_array_new();

	/** 获取所有的用户信息列表 */
	users = g_hash_table_get_values(chas->user_infos);
	g_mutex_lock(chas->inbytes_list->list_lock);
	g_mutex_lock(chas->outbytes_list->list_lock);

	for (tmp_user_list = users; tmp_user_list != NULL; tmp_user_list = tmp_user_list->next) {
		tmp_user = (user_info *)(tmp_user_list->data);
		if (tmp_user == NULL) {
			continue;
		}

		if (username != NULL && g_ascii_strcasecmp(tmp_user->username->str, username) != 0) {
			continue;
		}

		if (username == NULL) {
			tmp_username = tmp_user->username->str;
		} else {
			tmp_username = username;
		}
		row = construct_showthroughoutacc_row(chas->inbytes_list->query_list,
				chas->outbytes_list->query_list, tmp_username, is_banned,
				is_banned_bool);
		if (row != NULL) {
			g_ptr_array_add(rows, row);
		}
	}

	g_mutex_unlock(chas->inbytes_list->list_lock);
	g_mutex_unlock(chas->outbytes_list->list_lock);
	if (users != NULL) {
		g_list_free(users);
		users = NULL;
	}

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showthroughoutacc_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showthroughoutacc_fields();
	rows = construct_showthroughoutacc_rows(con->srv,
			command->username,
			command->is_banned, command->is_banned_bool);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setinbytesbanned_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->is_banned ||
			(g_ascii_strcasecmp("on", command->is_banned) != 0 &&
					g_ascii_strcasecmp("off", command->is_banned) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "is-banned", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to %s the query of %s because of in throughout",
			G_STRLOC,
			(g_ascii_strcasecmp("on", command->is_banned) == 0?"ban":"unban"),
			command->username);

	user_info *user =  get_user_info_for_user(con->srv, command->username);
	if (user == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
		return COMMAND_PROCESS_ERROR;
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_limit_flag_set(con->srv->xml_filename, command->username, INB_ACC_FLAG,
				command->is_banned_bool)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setusersqlaccswitch");
					return COMMAND_PROCESS_ERROR;
				}
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		modify_query_inbytes_switch(con->srv->inbytes_list,
				command->username,
				command->is_banned_bool);
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}


ADMIN_COMMAND_PROCESS_FUNC(setoutbytesbanned_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->username) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "username", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (!command->is_banned ||
			(g_ascii_strcasecmp("on", command->is_banned) != 0 &&
					g_ascii_strcasecmp("off", command->is_banned) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "is-banned", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to %s the query of %s because of in throughout",
			G_STRLOC,
			(g_ascii_strcasecmp("on", command->is_banned) == 0?"ban":"unban"),
			command->username);

	user_info *user =  get_user_info_for_user(con->srv, command->username);
	if (user == NULL) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_ELEMENT_NOT_EXIST, "user");
		return COMMAND_PROCESS_ERROR;
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_limit_flag_set(con->srv->xml_filename, command->username, OUTB_ACC_FLAG,
				command->is_banned_bool)) {
					mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setusersqlaccswitch");
					return COMMAND_PROCESS_ERROR;
				}
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		modify_query_outbytes_switch(con->srv->outbytes_list,
				command->username,
				command->is_banned_bool);
	}

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setinbytesaccswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->flag ||
			(g_ascii_strcasecmp("on", command->flag) != 0 &&
					g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to set in throughout accumulate statistic of query %s",
			G_STRLOC,
			g_ascii_strcasecmp("on", command->flag) == 0?"On":"Off");
	con->srv->is_inbytes_r_enabled = (g_ascii_strcasecmp("on", command->flag) == 0?TRUE:FALSE);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}

ADMIN_COMMAND_PROCESS_FUNC(setoutbytesaccswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->flag ||
			(g_ascii_strcasecmp("on", command->flag) != 0 &&
					g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	g_message("[%s]:going to set out throughout accumulate statistic of query %s",
			G_STRLOC,
			g_ascii_strcasecmp("on", command->flag) == 0?"On":"Off");
	con->srv->is_outbytes_r_enabled = (g_ascii_strcasecmp("on", command->flag) == 0?TRUE:FALSE);

	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);

	return COMMAND_PROCESS_SUCCESS;
}

static GPtrArray *construct_showthroughoutswitch_fields() {
	return construct_fields(showthroughoutswitch_fields);
}

static GPtrArray *construct_showthroughoutswitch_rows(chassis *chas) {
	GPtrArray *rows = NULL;
	GPtrArray *row = NULL;

	if (chas == NULL) {
		return NULL;
	}

	rows = g_ptr_array_new();
	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup(chas->is_inbytes_r_enabled?"On":"Off"));
	g_ptr_array_add(row, g_strdup(chas->is_outbytes_r_enabled?"On":"Off"));
	g_ptr_array_add(rows, row);

	return rows;
}

ADMIN_COMMAND_PROCESS_FUNC(showthroughoutswitch_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	/** 构造结果集 */
	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;

	fields = construct_showthroughoutswitch_fields();
	rows = construct_showthroughoutswitch_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;

	return COMMAND_PROCESS_SUCCESS;
}


//////////////
/** 下面是与黑名单相关的管理命令的处理 */
/** setmultiplexswitch 命令*/
//////////////////////

ADMIN_COMMAND_PROCESS_FUNC(setblacklistflag_command_process) {
	/** 首先检查参数的完整性 */
	g_assert(command);
	g_assert(con);
	g_assert(con->srv);

	if (!command->flag || (g_ascii_strcasecmp("on", command->flag) != 0 && g_ascii_strcasecmp("off", command->flag) != 0)) {
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_NOT_SPECIFIED, "flag", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("mem", command->save_option)) {
		if (!config_setblacklistflag(con->srv->xml_filename, command->flag)) {
			mpe_send_error(con->client, MPE_ADM_CMDPRC_SAVE_IN_XML_FAILED, "setblacklistflag");
			return COMMAND_PROCESS_ERROR;
		}
	}
	if (NULL == command->save_option || 0 != g_ascii_strcasecmp("disk", command->save_option)) {
		con->srv->is_black_list_enable = ((0 == g_ascii_strcasecmp("on", command->flag)) ?TRUE : FALSE);
	}
	/** 返回结果 */
	network_mysqld_con_send_ok_full(con->client, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0);
	return COMMAND_PROCESS_SUCCESS;
}

/** 构造showblacklistflag 命令的fields变量*/
CONSTRUCT_FIELDS_FUNC(construct_showblacklistflag_fields) {
	return construct_fields(showblacklistflag_fields);
}

/** 构造showblacklistflag 命令的rows变量*/
CONSTRUCT_ROWS_FUNC(construct_showblacklistflag_rows) {
	if ((chas == NULL)) {
		return NULL;
	}

	GPtrArray *rows = NULL;
	GPtrArray *row;
	rows = g_ptr_array_new();

	/** black list flag列*/
	row = g_ptr_array_new();
	g_ptr_array_add(row, (chas->is_black_list_enable == TRUE)? g_strdup("on"): g_strdup("off"));
	g_ptr_array_add(rows, row);

	return rows;
}

/** showblacklistflag 命令*/
ADMIN_COMMAND_PROCESS_FUNC(showblacklistflag_command_process) {
	command_process_result_t ret = COMMAND_PROCESS_SUCCESS;
	/** 首先检查参数的完整性 */
	g_assert(command);

	GPtrArray *fields = NULL;
	GPtrArray *rows = NULL;
	/** 展现是否设置连接复用标志*/
	fields = construct_showblacklistflag_fields();
	rows = construct_showblacklistflag_rows(con->srv);

	/** 返回结果 */
	network_mysqld_con_send_resultset(con->client, fields, rows);

	/** 释放结果集 */
	clean_up(fields, rows);
	fields = NULL;
	rows = NULL;
	return ret;
}


/** 对密码转义*/
gboolean process_passwd(gchar *pwd) {
	if (!pwd || strlen(pwd) == 0) {
		return TRUE;
	}

	/**
	 * 接下来处理backend的数据：
	 * 1.将开头及结尾的分割符号去掉
	 * 2.去掉转义\'=>',\"=>",\\=>\
	 */

	gchar transfer = pwd[0];

	if ('\'' != transfer && '"' != transfer) {
		return FALSE; //密码格式不正确
	}

	gchar* tmp_pre = pwd;
	gchar* tmp_post = pwd + 1;
	gboolean pre_is_dash = FALSE;
	while (tmp_post && '\0' != *tmp_post) {
		if(pre_is_dash) {
			if (transfer == *tmp_post) {
				*tmp_pre = *tmp_post;
			} else {
				*tmp_pre = *tmp_post;
			}
			pre_is_dash = FALSE;
			tmp_pre++;
		} else {
			if ('\\' == *tmp_post) {
				pre_is_dash = TRUE;
			} else {
				*tmp_pre = *tmp_post;
				tmp_pre++;
			}
		}
		tmp_post++;
	}

	if (tmp_pre > pwd ) {
		tmp_pre--;
		if (*tmp_pre != transfer) {
			return FALSE;
		}
	}

	*tmp_pre = '\0';

	return TRUE;
}

/**
 * @author sohu-inc.com
 * 对admin 命令进行解析，并执行
 * @param con
 * @param query 要处理的管理命令
 * @return
 */
command_process_result_t admin_command_process(network_mysqld_con *con, gchar *query) {
	g_assert(con);
	g_assert(con->srv);
	g_assert(con->srv->priv);
	g_assert(con->srv->priv->backends);

	command_process_result_t ret;
	gchar **argv = NULL; // 存放解析后的命令
	gint argc = 0;
	gint space_count = 0;

	gchar *temp_query = query;
	g_message("[%s]:got admin command \"%s\"", G_STRLOC, query);

	if (!temp_query) {
		return COMMAND_NO_QUERY_SPECIFIED;
	}

	admin_command *command = admin_command_new(); /** 存放格式化的命令 */
	if (!process_filter_sql(command, query)) {
		admin_command_free(command);
//		network_mysqld_con_send_error(con->client, C("--filter-sql related command syntax error, please see help for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_OPT_INVALID, "filter-sql", "single-quoted or double-quoted", "proxyhelp");
		return COMMAND_PROCESS_ERROR;
	}

	GString * action = g_string_new(NULL); /** 存放具体命令：动作　*/

	GError *error = NULL;
	GOptionContext *context = NULL;

	/** 字符串标准化 */
	/**
	 * @fixme 密码和用户名里面是可以有密码的，
	 */
	remove_spaces(temp_query);

	/** remove --help for bug fix */


	/**
	 * 查询query语句中空格的个数
	 */
	space_count = get_space_count(temp_query);
	argv = g_strsplit(temp_query, " ", (COMMAND_MAX_TOKENS >= space_count)?COMMAND_MAX_TOKENS:space_count);

	while (NULL != argv[argc]) {
		argc++;
	}

	/** 开始处理admin命令串 */
	context = g_option_context_new ("--");
	g_option_context_set_help_enabled (context, FALSE);
	g_option_context_add_main_entries (context, network_mysqld_admin_command_get_options(command), NULL);
	g_message("[%s]: there are %d tokens splited", G_STRLOC, argc);

	if (!my_g_option_context_parse (context, &argc, &argv, &error)) {
		g_message ("[%s]:command option parsing failed: %s", G_STRLOC, error->message);

		my_g_strfreev(argv);
		argv = NULL;

		if (context != NULL) {
			g_option_context_free(context);
			context = NULL;
		}

		if (action != NULL) {
			g_string_free(action, TRUE);
			action = NULL;
		}

		if (command != NULL) {
			admin_command_free(command);
			command = NULL;
		}

		if (error) {
			g_error_free(error);
			error = NULL;
		}

//		network_mysqld_con_send_error(con->client, C("command syntax error, please see help for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_SYNTAX_ERROR);
		return COMMAND_PROCESS_ERROR;
	}

	if (error) {
		g_error_free(error);
		error = NULL;
	}
	g_string_append(action, argv[0]);
	/** 释放option项相关的变量 */
	argc = 0;
	while (NULL != argv[argc]) {
		g_debug("the %dth option is %s", argc, argv[argc]);
		argc++;
	}
	my_g_strfreev(argv);
	argv = NULL;

	if (context != NULL) {
		g_option_context_free(context);
		context = NULL;
	}
	/**
	 * @todo 下面的大篇幅的能否用switch替换？采用hash,现在比较少可以先用if else
	 */

	if (!process_passwd(command->passwd)) {
		if (action != NULL) {
			g_string_free(action, TRUE);
			action = NULL;
		}
		if (command != NULL) {
			admin_command_free(command);
			command = NULL;
		}

		g_message("[%s]:command option check error", G_STRLOC);
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_OPT_IRRATIONAL);
		return COMMAND_PROCESS_ERROR;
	}

	/** 先检测命令参数的合理性（格式、取值的正确性） */
	switch (check_command_rationality(command)) {
	case COMMAND_PROCESS_SUCCESS:
		break;
	case COMMAND_PROCESS_ERROR:
	default:
		if (action != NULL) {
			g_string_free(action, TRUE);
			action = NULL;
		}
		if (command != NULL) {
			admin_command_free(command);
			command = NULL;
		}
		g_message("[%s]:command option check error", G_STRLOC);
//		network_mysqld_con_send_error(con->client, C("command syntax error, please see help for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_CMD_OPT_IRRATIONAL);
		return COMMAND_PROCESS_ERROR;
	}

	/** 下面分具体的命令进行参数完整性检查和处理 */
	if (0 == g_ascii_strcasecmp("addbackend", action->str)) {
		ret = addbackend_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setbackendparam", action->str)) {
		ret = setbackendparam_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("delbackend", action->str)) {
		ret = delbackend_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setbkoffline", action->str)) {
		ret = setbkoffline_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setbkonline", action->str)) {
		ret = setbkonline_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showbackends", action->str)){
		ret = showbackends_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("adduser", action->str)) {
		ret = adduser_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("deluser", action->str)){
		ret = deluser_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("updatepwd", action->str)){
		ret = updatepwd_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showUsers", action->str)){
		ret = showUsers_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("setconnlimit", action->str) || 0 == g_ascii_strcasecmp("updateconnlimit", action->str)){
		ret = setconnlimit_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("delconnlimit", action->str)){
		ret = delconnlimit_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("setPoolConfig", action->str)) {
		ret = setPoolConfig_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("delPoolConfig", action->str)) {
		ret = delPoolConfig_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showPoolConfig", action->str)) {
		ret = showPoolConfig_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showPoolStatus", action->str)) {
		ret = showPoolStatus_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("addsqlfilter", action->str)) {
		ret = addsqlfilter_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("delsqlfilter", action->str)) {
		ret = delsqlfilter_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setfilteraction", action->str)) {
		ret = setfilteraction_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setfilterswitch", action->str)) {
		ret = setfilterswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showsqlfilter", action->str)) {
		ret = showsqlfilter_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("setmultiplexswitch", action->str)) {
		ret = setmultiplexswitch_command_process(con, command);		
	} else if (0 == g_ascii_strcasecmp("showmultiplexswitch", action->str)) {
		ret = showmultiplexswitch_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showproxyprocesslist", action->str)) {
		ret = showproxyprocesslist_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("addparalimit", action->str)) {
        ret = addparalimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("delparalimit", action->str)) {
        ret = delparalimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("modifyparalimit", action->str)) {
        ret = modifyparalimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("modifylimitswitch", action->str)) {
        ret = modifylimitswitch_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("showparalimit", action->str)) {
        ret = showparalimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("setparalimit", action->str)) {
        ret = setparalimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("showparalimitflag", action->str)) {
        ret = showparalimitflag_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("setduralimit", action->str)) {
        ret = setduralimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("addduralimit", action->str)) {
        ret = addduralimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("delduralimit", action->str)) {
        ret = delduralimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("modifyduralimit", action->str)) {
        ret = modifyduralimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("modifyduralimitswitch", action->str)) {
        ret = modifyduralimitswitch_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("showduralimit", action->str)) {
        ret = showduralimit_command_process(con, command);
    } else if (0 == g_ascii_strcasecmp("showduralimitflag", action->str)) {
        ret = showduralimitflag_command_process(con, command);

    } else if (0 == g_ascii_strcasecmp("showqueryresponsetime", action->str)) {
		ret = showqueryresponsetime_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showtotalresponsetime", action->str)) {
		ret = showtotalresponsetime_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("clearstatistics", action->str)) {
		ret = clearstatistics_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setstatisticsbase", action->str)) {
		ret = setstatisticsbase_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setstatisticsswitch", action->str)) {
		ret = setstatisticsswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showstatisticsswitch", action->str)) {
		ret = showstatisticsswitch_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showconnectionstate", action->str)) {
		ret = showconnectionstate_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("flushconnectionstate", action->str)) {
		ret = flushconnectionstate_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showthreadconnectionstate", action->str)) {
		ret = showthreadconnectionstate_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("flushthreadconnectionstate", action->str)) {
		ret = flushthreadconnectionstate_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showglobalconnectionstate", action->str)) {
		ret = showglobalconnectionstate_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("flushglobalconnectionstate", action->str)) {
		ret = flushglobalconnectionstate_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showlbalgo", action->str)) {
		ret = showlbalgo_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setlbalgo", action->str)) {
		ret = setlbalgo_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showloglevel", action->str)) {
		ret = showloglevel_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setloglevel", action->str)) {
		ret = setloglevel_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("addlistenaddr", action->str)) {
		ret = addlistenaddr_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("dellistenaddr", action->str)) {
		ret = dellistenaddr_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showlistenaddr", action->str)) {
		ret = showlistenaddr_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showslowlogconf", action->str)) {
		ret = showslowlogconf_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setslowlogconf", action->str)) {
		ret = setslowlogconf_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showsqlaccnum", action->str)) {
		ret = showsqlaccnum_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setusersqlaccswitch", action->str)) {
		ret = setusersqlaccswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setsqlaccswitch", action->str)) {
		ret = setsqlaccswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showsqlaccswitch", action->str)) {
		ret = showsqlaccswitch_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showthroughoutacc", action->str)) {
		ret = showthroughoutacc_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setinbytesbanned", action->str)) {
		ret = setinbytesbanned_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setoutbytesbanned", action->str)) {
		ret = setoutbytesbanned_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setinbytesaccswitch", action->str)) {
		ret = setinbytesaccswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setoutbytesaccswitch", action->str)) {
		ret = setoutbytesaccswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showthroughoutswitch", action->str)) {
		ret = showthroughoutswitch_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showblacklistflag", action->str)) {
		ret = showblacklistflag_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setblacklistflag", action->str)) {
		ret = setblacklistflag_command_process(con, command);

	} else if (0 == g_ascii_strcasecmp("showsqldmlswitch", action->str)) {
		ret = showsqldmlswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setsqldmlswitch", action->str)) {
		ret = setsqldmlswitch_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showsqldmlkind", action->str)) {
		ret = showsqldmlkind_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("showusersqldml", action->str)) {
		ret = showusersqldml_command_process(con, command);
	} else if (0 == g_ascii_strcasecmp("setusersqldmlswitch", action->str)) {
		ret = setusersqldmlswitch_command_process(con, command);

	}else if (0 == g_ascii_strcasecmp("proxyhelp", action->str)){
		ret = proxyhelp_command_process(con, command);
	} else {
		ret = COMMAND_NOT_SUPPORT;
	}

	// 释放函数临时变量
	if (argv != NULL) {
		my_g_strfreev(argv);
		argv = NULL;
	}

	if (context != NULL) {
		g_option_context_free(context);
		context = NULL;
	}
	if (action != NULL) {
		g_string_free(action, TRUE);
		action = NULL;
	}

	if (command != NULL) {
		admin_command_free(command);
		command = NULL;
	}

	return ret;
}

static network_mysqld_stmt_ret admin_read_query(network_mysqld_con *con) {
	network_mysqld_con_t *st = con->plugin_con_state;
	char command = -1;
	network_socket *recv_sock = con->client;
	GList   *chunk  = recv_sock->recv_queue->chunks->head;
	GString *packet = chunk->data;

	if (packet->len < NET_HEADER_SIZE) return PROXY_SEND_QUERY; /* packet too short */

	command = packet->str[NET_HEADER_SIZE + 0];

	if (COM_QUERY == command) {
		/* we need some more data after the COM_QUERY */
		if (packet->len < NET_HEADER_SIZE + 2) return PROXY_SEND_QUERY;

		/* LOAD DATA INFILE is nasty */
		if (packet->len - NET_HEADER_SIZE - 1 >= sizeof("LOAD ") - 1 &&
		    0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("LOAD "))) return PROXY_SEND_QUERY;

		/**
		 * 接下来处理admin管理命令,接下来不希望在通过lua提供admin命令扩展
		 */
		gchar *tmp_query = g_strndup(packet->str + NET_HEADER_SIZE + 1, packet->len - NET_HEADER_SIZE - 1);
		command_process_result_t ret = admin_command_process(con, tmp_query);
		switch (ret) {
		case COMMAND_PROCESS_SUCCESS:
			break;
		case COMMAND_PROCESS_ERROR:
			break;
		case COMMAND_NOT_SUPPORT:
//			network_mysqld_con_send_error(con->client, C("command not supported, please see help for more infomation!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_COMMAND_NOT_SUPPORT);
			break;
		case COMMAND_NO_QUERY_SPECIFIED:
//			network_mysqld_con_send_error(con->client, C("command should not be null, please see help for more infomation!"));
			mpe_send_error(con->client, MPE_ADM_CMDPRC_COMMAND_NOT_SUPPORT);
			break;
		default:
			g_assert_not_reached();
		}

		g_free(tmp_query);
		return PROXY_SEND_RESULT;
	} else {
//		network_mysqld_con_send_error(con->client, C("command not supported, please see help for more infomation!"));
		mpe_send_error(con->client, MPE_ADM_CMDPRC_COMMAND_NOT_SUPPORT);
		return PROXY_SEND_RESULT;
	}

}

/**
 * gets called after a query has been read
 *
 * - calls the lua script via network_mysqld_con_handle_proxy_stmt()
 *
 * @see network_mysqld_con_handle_proxy_stmt
 */
NETWORK_MYSQLD_PLUGIN_PROTO(server_read_query) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	network_mysqld_con_t *st = con->plugin_con_state;
	network_mysqld_stmt_ret ret;

	send_sock = NULL;
	recv_sock = con->client;
	st->injected.sent_resultset = 0;

	chunk = recv_sock->recv_queue->chunks->head;

	if (recv_sock->recv_queue->chunks->length != 1) {
		g_message("%s.%d: client-recv-queue-len = %d", __FILE__, __LINE__, recv_sock->recv_queue->chunks->length);
	}
	
	packet = chunk->data;
#ifdef TEST_ADMIN_USE_INDEPENDENDT_THREAD
	GString *thread_name = chassis_thread_get_local_name(con->srv);
	g_message("[%s]: read admin query using thread %s",G_STRLOC, thread_name->str);
#endif
	ret = admin_read_query(con);

	switch (ret) {
	case PROXY_NO_DECISION:
//		network_mysqld_con_send_error(con->client, C("need a resultset + proxy.PROXY_SEND_RESULT"));
		mpe_send_error(con->client, MPE_ADM_RQ_NEED_RESULTSET);
		con->state = CON_STATE_SEND_ERROR;
		break;
	case PROXY_SEND_RESULT: 
		con->state = CON_STATE_SEND_QUERY_RESULT;
		break; 
	default:
//		network_mysqld_con_send_error(con->client, C("need a resultset + proxy.PROXY_SEND_RESULT ... got something else"));
		mpe_send_error(con->client, MPE_ADM_RQ_NEED_RESULTSET_SOMETHING);
		con->state = CON_STATE_SEND_ERROR;
		break;
	}

	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE); // 将本次接受的用户连接请求清空

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup the admin specific data on the current connection 
 *
 * @return NETWORK_SOCKET_SUCCESS
 */
NETWORK_MYSQLD_PLUGIN_PROTO(admin_disconnect_client) {
	network_mysqld_con_t *st = con->plugin_con_state;

	if (st == NULL) return NETWORK_SOCKET_SUCCESS;

	#if 0
	lua_scope  *sc = con->srv->priv->sc;

#ifdef HAVE_LUA_H
	/* remove this cached script from registry */
	if (st->L_ref > 0) {
		luaL_unref(sc->L, LUA_REGISTRYINDEX, st->L_ref);
	}
#endif
	#endif

	network_mysqld_con_t_free(st);

	con->plugin_con_state = NULL;

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * @author 将函数前的static去掉，统一各个plugin的函数类别
 * @param con
 * @return
 */
//static int network_mysqld_server_connection_init(network_mysqld_con *con) {
int network_mysqld_server_connection_init(network_mysqld_con *con) {
	con->plugins.con_init             = server_con_init;

	con->plugins.con_read_auth        = server_read_auth;

	con->plugins.con_read_query       = server_read_query;
	
	con->plugins.con_cleanup          = admin_disconnect_client;

	return 0;
}

static chassis_plugin_config *network_mysqld_admin_plugin_new(void) {
	chassis_plugin_config *config;

	config = g_new0(chassis_plugin_config, 1);

	return config;
}

static void network_mysqld_admin_plugin_free(chassis_plugin_config *config) {
	if (config->listen_con) {
		/* the socket will be freed by network_mysqld_free() */
	}

	if (config->address) {
		g_free(config->address);
	}

	if (config->admin_username) g_free(config->admin_username);
	if (config->admin_password) g_free(config->admin_password);
	#if 0
	if (config->lua_script) g_free(config->lua_script);
	#endif

	g_free(config);
}

/**
 * add the proxy specific options to the cmdline interface 
 */
static GOptionEntry * network_mysqld_admin_plugin_get_options(chassis_plugin_config *config) {
	guint i;

	static GOptionEntry config_entries[] = 
	{
		{ "admin-address",            0, 0, G_OPTION_ARG_STRING, NULL, "listening address:port of the admin-server (default: :4041)", "<host:port>" },
		{ "admin-username",           0, 0, G_OPTION_ARG_STRING, NULL, "username to allow to log in", "<string>" },
		{ "admin-password",           0, 0, G_OPTION_ARG_STRING, NULL, "password to allow to log in", "<string>" },
		#if 0
		{ "admin-lua-script",         0, 0, G_OPTION_ARG_FILENAME, NULL, "script to execute by the admin plugin", "<filename>" },
		#endif
		
		{ NULL,                       0, 0, G_OPTION_ARG_NONE,   NULL, NULL, NULL }
	};

	i = 0;
	config_entries[i++].arg_data = &(config->address);
	config_entries[i++].arg_data = &(config->admin_username);
	config_entries[i++].arg_data = &(config->admin_password);
	#if 0
	config_entries[i++].arg_data = &(config->lua_script);
	#endif

	return config_entries;
}

/**
 * init the plugin with the parsed config
 */
static int network_mysqld_admin_plugin_apply_config(chassis *chas, chassis_plugin_config *config) {
	network_mysqld_con *con;
	network_socket *listen_sock;

	if (!config->address) config->address = g_strdup(":4041");
	if (!config->admin_username) {
		g_critical("%s: --admin-username needs to be set",
				G_STRLOC);
		return -1;
	}
	if (!config->admin_password) {
		g_critical("%s: --admin-password needs to be set",
				G_STRLOC);
		return -1;
	}
//	if (!config->lua_script) {
//		g_critical("%s: --admin-lua-script needs to be set, <install-dir>/lib/mysql-proxy/lua/admin.lua may be a good value",
//				G_STRLOC);
//		return -1;
//	}


	/** 
	 * create a connection handle for the listen socket 
	 */
	con = network_mysqld_con_new();
	network_mysqld_add_connection(chas, con);
	con->config = config;

	config->listen_con = con;
	
	listen_sock = network_socket_new();
	con->server = listen_sock;

	/* set the plugin hooks as we want to apply them to the new connections too later */
	network_mysqld_server_connection_init(con);

	/* FIXME: network_socket_set_address() */
	if (0 != network_address_set_address(listen_sock->dst, config->address)) {
		return -1;
	}

	/* FIXME: network_socket_bind() */
	if (0 != network_socket_bind(listen_sock)) {
		return -1;
	}

	/**
	 * added by zhenfan, 2013/09/10
	 * 起一个admin线程，单独处理所有的admin请求
	 * @note: 
	 * 1.为了兼容已有结构,使代码改动量最少,admin线程参数变量沿用chassis_event_thread_t结构
	 * 2.将admin端口的监听请求加入到该线程的event_base上
	 * 3.为了调用network_mysqld_con_handle,需要增加network_mysqld_admin_con_accept函数
	 */
	/*event_set(&(listen_sock->event), listen_sock->fd, EV_READ|EV_PERSIST, network_mysqld_con_accept, con);
	event_base_set(chas->event_base, &(listen_sock->event));
	event_add(&(listen_sock->event), NULL);*/
	
	chassis_event_thread_t *event_thread;
	GString *thr_name = NULL;
	guint admin_thread_id = chas->event_thread_count;
	thr_name = g_string_new("foo");
	g_string_printf(thr_name, "admin_%d", admin_thread_id);
	event_thread = chassis_event_thread_new(thr_name, admin_thread_id);
	g_string_free(thr_name, TRUE);
	/**
	 * @note:
	 * 1.chassis_event_threads_init_thread中event_base中注册了local_notify_fds和global_notify_fd_event事件,纯粹是为了代码的改动最少,后续用不到这些事件
	 * 2.admin线程号是event_thread_count,加入到chas->threads线程组中,这个线程不会被业务请求轮询,而且兼容con_handle中的WAIT_FOR_EVENT
	 */
	chassis_event_threads_init_thread(chas->threads, event_thread, chas);
	/**
	 * 将listen_sock注册到该线程的event_base上
	 */
	event_assign(&(listen_sock->event), event_thread->event_base, listen_sock->fd, EV_READ|EV_PERSIST, network_mysqld_admin_con_accept, con);
	event_add(&(listen_sock->event), NULL);
	
	chas->event_admin_thread = event_thread;

	return 0;
}
typedef int(*CONNECTION_INIT_PTR)(network_mysqld_con *con);

/*static CONNECTION_INIT_PTR get_proxy_connection_init_func(chassis *chas) {
	if (NULL == chas || NULL == chas->modules) {
		return NULL;
	}

	int index = 0;
	for (index = 0; index < chas->modules->len; index++) {

	}
}
*/

G_MODULE_EXPORT int plugin_init(chassis_plugin *p) {
	p->magic        = CHASSIS_PLUGIN_MAGIC;
	p->name         = g_strdup("admin");
	p->version		= g_strdup(PACKAGE_VERSION);

	p->init         = network_mysqld_admin_plugin_new;
	p->get_options  = network_mysqld_admin_plugin_get_options;
	p->apply_config = network_mysqld_admin_plugin_apply_config;
	p->destroy      = network_mysqld_admin_plugin_free;

	//p->connection_init_ptr = network_mysqld_server_connection_init;

	return 0;
}


