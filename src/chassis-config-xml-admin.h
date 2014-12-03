/*
 * chassis-config-xml-admin.h
 *
 *  Created on: 2013年8月22日
 *      Author: zhenfan
 */

#ifndef CHASSIS_CONFIG_XML_ADMIN_H_
#define CHASSIS_CONFIG_XML_ADMIN_H_
#include <glib/gstdio.h>
#include "chassis-mainloop.h"
#include "libxml-ext.h"
#include "network-backend.h"
#include "network-security-sqlmode.h"

#define MASKS {0x0000000001,0x0000000002,0x0000000004,0x0000000008}

typedef enum {
	SQL_ACC_FLAG,
	INB_ACC_FLAG,
	OUTB_ACC_FLAG,
	SIZE_ACC_FLAG
} flag_type;

gboolean config_conn_limit_load(chassis *chas, proxy_rw rw_type);

gboolean config_user_info_load(chassis *chas);

gboolean config_listen_addresses_load(chassis *chas, proxy_rw rw_type);

gboolean config_addlistenaddr(const gchar* filename, const gchar *backend, proxy_rw listen_type);

gboolean config_listen_addresses_load(chassis *chas, proxy_rw rw_type);

gboolean config_dellistenaddr(const gchar* filename, const gchar *backend, proxy_rw listen_type);

gboolean config_multiplex_load(chassis *chas);

gchar *config_lb_algorithm_load(chassis *chas, proxy_rw rw_type);

gboolean config_sql_statistics_switch_load(chassis *chas);

gboolean config_sql_statistics_base_load(chassis *chas); 

gboolean config_default_backends_load(chassis *chas);

gboolean config_backends_load(chassis *chas, proxy_rw rw_type);

gboolean config_pool_config_load(chassis *chas, proxy_rw rw_type);

gboolean config_sqlrules_load(chassis *chas, security_model_type model_type);

gboolean config_addbackend(const gchar* filename, const gchar *backend, const gchar *bktype, backend_state_t backend_state, const backend_config_t *backend_config);

gboolean config_setbackendparam(const gchar* filename, const gchar *ip_port, gint rw_weight, gint ro_weight, gint rise, gint fall, gint inter, gint fastdowninter);

gboolean config_setbackend_state(const gchar* filename, const gchar *backend, backend_state_t backend_state);

gboolean config_adduser(const gchar* filename, const gchar *user, const gchar *password, const gchar *hostip);

gboolean config_deluser(const gchar* filename, const gchar *user);
gboolean config_deluser_ip(const gchar* filename, const gchar *user, const gchar *hostip, gboolean *del_user_noip);

gboolean config_setuserpasswd(const gchar* filename, const gchar *user, const gchar *passwd);

gboolean config_setconnlimit_user_ip(const gchar* filename, const gchar *port_type_str, const gchar *username, const gchar *hostip, const guint conn_limit);
gboolean config_setconnlimit_user_allip(const gchar* filename, const gchar *port_type_str, const gchar *username, const GList *head, const guint conn_limit);
gboolean config_delconnlimit_user_ip(const gchar* filename, const gchar *port_type_str, const gchar *username, const gchar *hostip);
gboolean config_delconnlimit_user_allip(const gchar* filename, const gchar *port_type_str, const gchar *username, const GList *head);

gboolean config_setpoolconfig(const gchar* filename, const gchar *username, const proxy_rw rw_type, const gint max_conn, const gint min_conn, const gint max_interval);
gboolean config_delpoolconfig(const gchar* filename, const gchar *username, const proxy_rw rw_type);

gboolean config_setmultiplex(const gchar* filename, const gchar *flag);

gboolean config_setsqlstatisticsswitch(const gchar* filename, const gchar *flag);

gboolean config_setsqlstatisticsbase(const gchar* filename, const gint base);

gboolean config_addsqlfilter(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type, security_action action, gboolean is_disabled);

gboolean config_delsqlfilter(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type);

gboolean config_setfilterswitch(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type, gboolean is_disabled);

gboolean config_setfilteraction(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type, security_action action);

gboolean config_slow_query_log_load(chassis *chas);

gboolean config_table_engine_replaceable_flag_load(chassis *chas);// 加载引擎替换的配置

gboolean config_balck_list_flag_load(chassis *chas);// 加载黑名单标志的配置

gboolean config_setblacklistflag(const gchar* filename, const gchar *flag);

gboolean config_limit_flag_load(chassis *chas); //  加载用户的封禁状态标志

gboolean config_limit_flag_update(const gchar* filename, const gchar *name, int flag); // 更新某个用户对应的限制标志

gboolean config_limit_flag_set(const gchar* filename, const gchar *name, flag_type type, gboolean is_set); // 设置对应的标志

gboolean config_dml_kind_load(chassis *chas);// 加载用户配置的dml 启用情况
#endif /* CHASSIS_CONFIG_XML_ADMIN_H_ */
