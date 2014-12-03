/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.

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
 

#ifndef _CHASSIS_MAINLOOP_H_
#define _CHASSIS_MAINLOOP_H_

#include <glib.h>    /* GPtrArray */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>  /* event.h needs struct tm */
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif
#include <event.h>     /* struct event_base */
#include <event2/thread.h>
#include <libxml/tree.h>

#include "chassis-exports.h"
#include "chassis-log.h"
//#include "chassis-stats.h"
#include "chassis-shutdown-hooks.h"
#include "chassis-regex.h"
#include "network-connection-state.h"
#include "slow-query-log.h"


/**@todo 以后改成可配置的?*/
/**前端连接限制的默认配置*/
#define RW_FRONT_END_CONN_LIMIT 5000
#define RO_FRONT_END_CONN_LIMIT 10000

/**连接池限制的默认配置*/
#define RW_CONNECTION_POOL_MAX_CONNECTIONS 4000
#define RW_CONNECTION_POOL_MIN_CONNECTIONS 2
#define RW_CONNECTION_POOL_MAX_IDEL_INTERVAL 3600
#define RO_CONNECTION_POOL_MAX_CONNECTIONS 4001
#define RO_CONNECTION_POOL_MIN_CONNECTIONS 3
#define RO_CONNECTION_POOL_MAX_IDEL_INTERVAL 3601

#define DEFAULT_SECTION_BASE 10u
#define DEFAULT_STATISTICS_RECORD_LIMIT 100000ul

typedef struct connection_scaler_thread_t connection_scaler_thread_t;
typedef struct user_db_sql_rule_table user_db_sql_rule_table;
typedef struct para_exec_limit_rules para_exec_limit_rules;
typedef struct statistic_dic statistic_dic;
typedef struct dura_exec_limit_rules dura_exec_limit_rules;
typedef struct time_section_index time_section_index;
typedef struct sql_statistics_thread_t sql_statistics_thread_t;
typedef struct network_mysqld_con network_mysqld_con;
typedef struct query_inbytes_list query_inbytes_list;
typedef struct query_outbytes_list query_outbytes_list;
typedef struct query_rate_list query_rate_list;
typedef struct query_dml_list query_dml_list;

//#include "network-socket.h"
/** @defgroup chassis Chassis
 * 
 * the chassis contains the set of functions that are used by all programs
 *
 * */
/*@{*/

#define PROXY_TYPE_NO 2

//代表读写端口的类型
typedef enum {
	PROXY_TYPE_WRITE = 0,
	PROXY_TYPE_READ = 1
} proxy_rw;


typedef struct chassis_private chassis_private;
typedef struct chassis chassis;
typedef struct chassis_event_threads_t chassis_event_threads_t;
typedef struct chassis_event_thread_t chassis_event_thread_t;
typedef struct user_pool_config user_pool_config;

#define DML_SQL_NUM 9

struct chassis {
	struct event_base *event_base;
	gchar *event_hdr_version;

	GPtrArray *modules;                       /**< array(chassis_plugin) */

	gchar *base_dir;				/**< base directory for all relative paths referenced */
	gchar *user;					/**< user to run as */

	chassis_private *priv;
	void (*priv_shutdown)(chassis *chas, chassis_private *priv);
	void (*priv_free)(chassis *chas, chassis_private *priv);

	chassis_log *log;
	
	#if 0
	chassis_stats_t *stats;			/**< the overall chassis stats, includes lua and glib allocation stats */
	#endif

	/* network-io threads */
	gint event_thread_count;

	chassis_event_threads_t *threads;

	/**
	 * added by zhenfan, 2013/09/11
	 * admin独立线程
	 */
	chassis_event_thread_t *event_admin_thread;

	chassis_shutdown_hooks_t *shutdown_hooks;


	/** added by jinxuan hou, 2013/04/08 */
	/**
	 * 用户最大连接数限制
	 * key = 用户名:地址
	 * value = 连接数
	 * 2是因为读写服务分离，各有一个
	 */
    GHashTable *conn_limit[2]; //connection limitation for every user -> GHashTable<GString<username:ip>, gint>
	GRWLock limit_lock[2]; /**< 用于实现对连接配置信息的同步访问*/
	/* 默认值 20，参考 chassis-mainloop.c: chassis *chassis_new() */
	gint default_conn_limit[2];/**< 默认的连接限制数 */

	/**
	 * 用户已使用连接数
	 */
    GHashTable *conn_used[2]; //connection used for every user -> GHashTable<GString<username:ip>, gint>
	GRWLock login_lock[2]; /**< 用于实现对登陆统计信息的同步访问*/

	/**
	 * @todo 需要增加两个默认配置参数
	 * 1. 默认的连接池配置信息
	 * 2. 默认的连接控制信息
	 */

    GHashTable *user_infos; //users for proxy -> GHashTable<GString<username>, struct user_info >
	GRWLock user_lock; /**< 用于实现对 */

    GHashTable *pool_config_per_user[2]; //对应后端用户的配置列表，GHashTable<GString<username>, user_pool_config *config>
    GRWLock pool_conf_lock[2];

	// 默认的用户连接池分读写
	struct user_pool_config *default_pool_config[2];

	charset_regex *regs;

	// 强需求需要能够开启或关闭连接的复用
	gboolean multiplex;
	
	// 强需求需要能够开启或关闭直方图统计
	gboolean is_sql_statistics;

	/* 连接池管理线程 */
	connection_scaler_thread_t *connection_scaler_thread;
	GPtrArray *detect_threads;

	gboolean is_running_on_valgrind;

	user_db_sql_rule_table *rule_table; /** sql 限制规则列表 */

	time_section_index *tmi;
	
	guint sql_statistics_base;
	
	guint sql_staitistics_record_limit;
	
	sql_statistics_thread_t *sql_statistics_thread;
	
	xmlDocPtr xml_docptr;
	// config.xml的filename
	gchar *xml_filename;

	gulong base_wait_time; /** 连接获取重试等待的基准时间,单位是us, */

	guint max_allowed_packet_size; /** 默认的dbproxy的 */

	gboolean para_limit_on; /** sql并行限制是否启用的标志 */
	para_exec_limit_rules *para_limit_rules; /** sql并行执行限制规则列表 */
	statistic_dic *para_running_statistic_dic; /** 在执行sql统计列表 */

	gboolean dura_limit_on; /** sql超时限制是否启用的标志 */
	dura_exec_limit_rules *dura_limit_rules; /** 超时执行限制规则列表 */


	global_connection_state_set *connection_state;

	/*负载均衡算法*/
	gchar *lb_algo[2];
	GString * (* lb_algo_func[2])( chassis *chas, proxy_rw conn_type);

	/** 字符集及代码校验相关 */
	gchar *dbproxy_collation;
	guint8 collation_index;

	/** 支持动态绑定多虚ip */
	GString *listen_addresses[2];

	GHashTable * listen_cons[2]; /**< 用户存放所有监听的端口，便于删除的时候定位监听socket */

	/** 支持动态绑定多虚ip的附加条件 */
	int (*proxy_connection_init_ptr) (network_mysqld_con *con);

	slow_query_log_config_t *slow_query_log_config;

	query_inbytes_list * inbytes_list;
	gboolean is_inbytes_r_enabled;

	query_outbytes_list * outbytes_list;
	gboolean is_outbytes_r_enabled;

	query_rate_list * query_rate_list;
	gboolean is_query_r_enabled;

	/** 是否开启table 引擎替换功能 */
	gboolean table_engine_replaceable;

	/** 是否开启黑名单过滤功能 */
	gboolean is_black_list_enable;

	/** 是否开启封禁DML 的功能 */
	query_dml_list * query_dml_list;
	gboolean is_dml_check_enable;

	gboolean dml_ops[DML_SQL_NUM];
};

CHASSIS_API chassis *chassis_init(void) G_GNUC_DEPRECATED;
CHASSIS_API chassis *chassis_new(void);
CHASSIS_API void chassis_free(chassis *chas);
CHASSIS_API int chassis_check_version(const char *lib_version, const char *hdr_version);

/**
 * the mainloop for all chassis apps 
 *
 * can be called directly or as gthread_* functions 
 */
CHASSIS_API int chassis_mainloop(void *user_data);
CHASSIS_API void chassis_set_shutdown_location(const gchar* location);
CHASSIS_API void chassis_set_startup_location(const gchar* location);
CHASSIS_API gboolean chassis_is_shutdown(void);

#define chassis_set_shutdown() chassis_set_shutdown_location(G_STRLOC)




/**
 * the following codes are added by jinxuan hou, 2013/04/08
 * ip struct, connection limitation struct, user info struct
 * and related create and destroy functions
 */
/**
 * added by jinxuan hou
 * A struct containing ip infomation
 * To avoid string comparison, we convert an IP address or a range of ips 
 * to two uint32.
 */
typedef struct ip_range{
        guint minip; //the lowwer num of an ip_range ip
        guint maxip; //the upper num of an ip_range ip
        GString *ip; //the string format of an ip range. such as X.X.%.%
} ip_range;

/**
 * added by jinxuan hou
 * A struct containing user related information
 * like username/ip/password
 * will be used in phases of audit/connect limitation and so on.
 * @@ jinxuanhou
 */
typedef struct user_info{
        GString *username;
        GString *passwd;
        GQueue *cli_ips;// ip_ranges for username 
        GRWLock ip_queue_lock; /**< 需要实现对ip列表的同步访问 */
} user_info;

/**
 * 用户对应的连接池配置信息结构体
 * 包括：连接的最大连接数、最小连接数、最大空闲时间
 */
struct user_pool_config{
	guint min_connections; //<最小连接数
	guint max_connections; //<最大连接数
	gint max_idle_interval; //<最大空闲时间
};

/** sohu-inc.com */
CHASSIS_API user_pool_config *get_pool_config_for_user(chassis *chas,
		const gchar *username,
		proxy_rw type); /** 获取一个用户对应的连接池配置信息 */
CHASSIS_API user_pool_config *get_pool_config_for_user_copy(chassis *chas,
		const GString *username, proxy_rw type, user_pool_config *config_new);
CHASSIS_API guint get_pool_config_min_connections_for_user(chassis *chas,
		const GString *username, proxy_rw type);
CHASSIS_API guint get_pool_config_max_connections_for_user(chassis *chas,
		const GString *username, proxy_rw type);
CHASSIS_API gint get_pool_config_max_idle_interval_for_user(chassis *chas,
		const GString *username, proxy_rw type);
CHASSIS_API void set_pool_config_for_user(chassis *chas,
		const gchar* user,
		const proxy_rw type,
		const gint max_conn,
		const gint min_conn,
		const gint max_interval); /**< 设置一个用户的连接池配置信息 */
CHASSIS_API gboolean del_pool_config_for_user(chassis *chas,
		const gchar* user,
		const proxy_rw type);



/** added by jinxuan hou, 2013/04/08 */
CHASSIS_API gboolean init_conn_limit(chassis *chas); //In the initialization phase, this function will init limitation according to config file
CHASSIS_API void print_conn_limit(gpointer key, gpointer value, gpointer user_data);
CHASSIS_API void display_conn_limit(GHashTable *table);
CHASSIS_API gint* get_conn_limit(chassis *chas, proxy_rw type, const gchar *username,
		const gchar *ip_str);
CHASSIS_API void add_conn_limit(chassis *chas, const proxy_rw type, const gchar *username,
		const gchar *ip_str, const gint num);
CHASSIS_API void del_conn_limit(chassis *chas, const proxy_rw type, const gchar *username,
		const gchar *ip_str);

CHASSIS_API gboolean init_user_infos(GHashTable *users, chassis *chas);
CHASSIS_API void print_user_infos(gpointer key, gpointer value, gpointer user_data);
CHASSIS_API void display_user_infos(GHashTable *table);
CHASSIS_API user_info * user_info_new(void); /**< 创建user_info 变量 */
CHASSIS_API void user_info_free(user_info *data); /**< user_info 变量释放 */
CHASSIS_API user_info * get_user_info_for_user(chassis *chas,
		const gchar *username); /**< 从用户库中查找对应用户的信息 */
CHASSIS_API gboolean check_user_existence(chassis *chas, const GString *username);

CHASSIS_API GQueue *user_infos_name_queue_new(chassis *chas);

CHASSIS_API gboolean add_user_info(chassis *chas,
		user_info *user); /**< 将用户加入到全局用户数组中 */
CHASSIS_API void g_user_info_free(gpointer data);
CHASSIS_API gboolean add_ip_range_to_user_info(const gchar *ip,
		user_info *user);/**< 添加新的可访问ip段至用户列表中 */
CHASSIS_API gboolean del_ip_range_from_user_info(const gchar *ip,
		user_info *user); /**< 从用户的允许访问列表中将对应的ip段去掉 */
CHASSIS_API gboolean del_user_info_without_ip_nolock(GHashTable *user_infos, user_info *user, const GString *username, gboolean *del_user_noip);
CHASSIS_API gboolean is_ip_range_allowed_for_user(const gchar *ip,
		user_info *user); /**< 查询某个ip端是否在用户的允许访问列表中 */
CHASSIS_API int inet_pton4(const char *src, guint *dst); /**< 将ip段转换成一对整数 */
CHASSIS_API ip_range *create_ip_range_from_str(const gchar * ip_str);
CHASSIS_API ip_range *ip_range_new(void);
CHASSIS_API void ip_range_free(ip_range *data);
CHASSIS_API gchar *get_ip_range(guint ipInint, user_info *user);
CHASSIS_API GString *get_all_ips_in_string(user_info *user); /** 获取某个用户允许访问的ip列表，用';'分割 */
CHASSIS_API GString *get_passwd_for_user(GString *username, chassis *chas);

CHASSIS_API gint * get_login_users(chassis *chas, proxy_rw type, const gchar *username, const gchar *ip_str);





/*@}*/

#endif
