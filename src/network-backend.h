/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.

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
 

#ifndef _BACKEND_H_
#define _BACKEND_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "chassis-mainloop.h"

#include "network-exports.h"

#include "lb_wrr.h"

typedef struct network_backend_t network_backend_t;
#include "network-conn-pool.h"

////代表读写端口的类型
//typedef enum {
//	PROXY_TYPE_WRITE = 0,
//	PROXY_TYPE_READ = 1
//} proxy_rw;

typedef enum { 
	BACKEND_STATE_UNKNOWN, 
	BACKEND_STATE_PENDING,
	BACKEND_STATE_UP, 
	BACKEND_STATE_DOWN
} backend_state_t;
NETWORK_API const gchar *get_backend_state_name(backend_state_t state);

typedef enum { 
	BACKEND_TYPE_UNKNOWN, 
	BACKEND_TYPE_RW, 
	BACKEND_TYPE_RO
} backend_type_t;
NETWORK_API const gchar *get_backend_type_name(backend_type_t type);

#define DEFAULT_BACKEND_WEIGHT 1
#define DEFAULT_BACKEND_RISE 2
#define DEFAULT_BACKEND_FALL 3
#define DEFAULT_BACKEND_INTER 10

/**
 * 用于健康检查的数据结构
 */
typedef struct health_check_t {
	/**连续成功次数*/
	guint rise;
	/**连续失败次数*/
	guint fall;
	/**检查时间间隔。单位秒*/
	guint inter;
	/**处于DOWN状态时的检查时间间隔。单位秒*/
	guint fastdowninter;
	/**当前健康值*/
	guint health;
} health_check_t;

typedef struct backend_config_t {
	gchar *ip_port;
	guint rw_weight;
	guint ro_weight;
	backend_state_t state;
	health_check_t health_check;
} backend_config_t;

struct network_backend_t {
	network_address *addr;
   
	backend_state_t state;   /**< UP or DOWN */
	backend_type_t type;     /**< ReadWrite or ReadOnly */

	GTimeVal state_since;    /**< timestamp of the last state-change */
	
	/**
	 * @author sohu-inc.com
	 */

	//原来的结构，现在需要两套连接池分读写
	//network_connection_pool *pool; /**< the pool of open connections */
	network_connection_pool *pool[2]; /**< the pool of open connections */

	//原来的结构，现在需要统计两套分读写请求
	//guint connected_clients; /**< number of open connections to this backend for SQF */
	guint connected_clients[2]; /**</ 与该backend交互的活动连接数*/
	
	GMutex mutex[2]; //用于实现对相应的connected_clients[]的同步访问
	guint connect_w[2]; //主要是用于负载均衡，现在的做法是读写各自维护一套权重

	GString *uuid;           /**< the UUID of the backend */
	guint port;
	GString *ip;

	/**健康检查配置*/
	health_check_t health_check;
};

typedef network_backend_t backend_t G_GNUC_DEPRECATED;

NETWORK_API network_backend_t *backend_init() G_GNUC_DEPRECATED;
NETWORK_API void backend_free(network_backend_t *b) G_GNUC_DEPRECATED;

NETWORK_API network_backend_t *network_backend_new();
NETWORK_API void network_backend_free(network_backend_t *b);

typedef struct {
	GPtrArray *backends;
	GMutex    _backends_mutex;
	GMutex    *backends_mutex;
	
	GTimeVal backend_last_check;

	/**
	 * @author DBA
	 * wrr_backends.wrr_s是经过加权轮询算法计算后的后端数据库序列
	 * + 负载均衡按照此序列以RR方式分配后端
	 */
	LB_WRR wrr_backends[2];

	GMutex master_mutex;
	gboolean has_master;

	/**健康检查全局默认配置*/
	backend_config_t backend_config_default;
} network_backends_t;

backend_config_t *backend_config_new();
void backend_config_free(backend_config_t *bc);

NETWORK_API network_backends_t *network_backends_new();
NETWORK_API void network_backends_free(network_backends_t *);
NETWORK_API int network_backends_add(network_backends_t *bs, /* const */ gchar *address, backend_type_t type);
NETWORK_API int network_backends_add2(network_backends_t *bs, const gchar *address, backend_type_t type, backend_state_t state, const backend_config_t *backend_config);
NETWORK_API gboolean set_backend_param(network_backends_t *bs, const gchar *ip_port, gint rw_weight, gint ro_weight, gint rise, gint fall, gint inter, gint fastdowninter);
NETWORK_API int network_backends_check(network_backends_t *backends);
NETWORK_API network_backend_t * network_backends_get(network_backends_t *backends, guint ndx);
NETWORK_API network_backend_t * network_backends_get_by_name(const network_backends_t *backends, const gchar *ip_addr);
NETWORK_API guint network_backends_count(network_backends_t *backends);
// 为了创建后端数据库的需要，增加了统计查询函数。主要用于连接建立时
NETWORK_API gint get_count_of_idle_conns(network_backend_t *backend, const gchar* username, proxy_rw type);
NETWORK_API gint get_count_of_pending_conns(network_backend_t *backend, const gchar* username, proxy_rw type);
NETWORK_API gint get_count_of_using_conns(network_backend_t *backend, const gchar* username, proxy_rw type);

NETWORK_API struct pool_status* get_count_of_conn_status(network_backend_t *backend, const gchar* username, proxy_rw type);

// added by sohu-inc.com, 2013/05/15
NETWORK_API void client_inc(network_backend_t * bk, proxy_rw type);
NETWORK_API void client_desc(network_backend_t * bk, proxy_rw type);

/*
void network_connection_pool_create_conn(const gchar *username, const gchar *backend, chassis *srv);// 在指定的backend上面创建对应于指定用户的连接池
void network_connection_pool_create_conns(const gchar *username, const gchar *backend, chassis *srv, gint count);// 在指定的backend上面创建对应于指定的用户的连接count个
*/

/**
 * @note
 * 负载均衡增加的函数
 * 1. proxy plugin的proxy_get_server_list 调用 loadbalance_lc_select
 * + 或 loadbalance_wrr_select(目前写死了loadbalance_lc_select，以后可配置)
 * + 获得后端服务器名
 * 2. loadbalance_wrr_calc 放在plugin apply config中计算权重
 * + 当权重等发生变更时也要调用此重新计算(现在还没有调用)
 * 3. loadbalance_wrr_new 放在plugin apply config中初始化
 * 4. loadbalance_wrr_free 放在 cli exit退出时执行
 */
GString * loadbalance_lc_select(chassis *chas, proxy_rw conn_type);
GString * loadbalance_wrr_select(chassis *chas, proxy_rw conn_type);
void loadbalance_wrr_calc(network_backends_t *bs, proxy_rw conn_type);
void loadbalance_wrr_new(network_backends_t *bs, proxy_rw conn_type);
void loadbalance_wrr_free(network_backends_t *bs, proxy_rw conn_type);

int full_address_split(const gchar *address, gchar **addr_ip_port, gchar **addr_weight, gchar **addr_state);
int full_address_split_new(const gchar *address, gchar **ip_port, guint *weight, backend_state_t *state);
int full_address_split_new2(const gchar *address, backend_config_t *bc, const backend_config_t *bc_def);
gchar **full_address_strsplit_new(const gchar *address);
void full_address_strsplit_free(gchar **str_array);



#endif /* _BACKEND_H_ */

