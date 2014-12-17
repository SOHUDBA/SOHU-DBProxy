/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2012, Oracle and/or its affiliates. All rights reserved.

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
 
#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include "network-backend.h"
#include "chassis-plugin.h"
#include "chassis-mainloop.h"
#include "network-mysqld.h"
#include "glib-ext.h"
#include "network-backend-status-updater.h"

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

const gchar *get_backend_state_name(backend_state_t state) {
	switch(state) {
	case BACKEND_STATE_UNKNOWN:
		return "unknown";
	case BACKEND_STATE_PENDING:
		return "pending";
	case BACKEND_STATE_UP:
		return "up";
	case BACKEND_STATE_DOWN:
		return "down";
	default:
		return "error";
	}
}

const gchar *get_backend_type_name(backend_type_t type) {
	switch(type) {
	case BACKEND_TYPE_UNKNOWN:
		return "unknown";
	case BACKEND_TYPE_RW:
		return "rw";
	case BACKEND_TYPE_RO:
		return "ro";
	default:
		return "error";
	}
}

backend_config_t *backend_config_new() {
	backend_config_t *bc;
	bc = g_new0(backend_config_t, 1);
	bc->ip_port = NULL;
	return bc;
}

void backend_config_free(backend_config_t *bc) {
	if (bc != NULL) {
		if (bc->ip_port != NULL) {
			g_free(bc->ip_port);
			bc->ip_port = NULL;
		}
		g_free(bc);
	}
}

/**
 * @deprecated: will be removed in 1.0
 * @see network_backend_new()
 */
network_backend_t *backend_init() {
	return network_backend_new();
}

network_backend_t *network_backend_new() {
	network_backend_t *b;

	b = g_new0(network_backend_t, 1);
	
	// 开始支持读写连接池的分离
	//b->pool = network_connection_pool_new();
	b->uuid = g_string_new(NULL);
	b->addr = network_address_new();

	/**
	 * @author sohu-inc.com
	 * 支持分离的读写连接池
	 */
	b->pool[PROXY_TYPE_WRITE] = network_connection_pool_new();
	b->pool[PROXY_TYPE_READ] = network_connection_pool_new();

	memset(b->connected_clients, 0, sizeof(guint)*2);

	// 初始化同步锁
	g_mutex_init(&(b->mutex[PROXY_TYPE_WRITE]));
	g_mutex_init(&(b->mutex[PROXY_TYPE_READ]));

	// 权重可以在创建完成以后再设置

	b->state = BACKEND_STATE_UNKNOWN;


	b->connect_w[PROXY_TYPE_WRITE] = 0;
	b->connect_w[PROXY_TYPE_READ] = 0;
	b->ip = g_string_new(NULL);

	b->health_check.rise = 0;
	b->health_check.fall = 0;
	b->health_check.inter = 0;
	b->health_check.fastdowninter = 0;
	b->health_check.health = 0;

	return b;
}

/**
 * @deprecated: will be removed in 1.0
 * @see network_backend_free()
 */
void backend_free(network_backend_t *b) {
	network_backend_free(b);
}

void network_backend_free(network_backend_t *b) {
	if (!b) return;

	// added by sohu-inc.com, 2013/05/15
	network_connection_pool_free(b->pool[PROXY_TYPE_WRITE]);
	network_connection_pool_free(b->pool[PROXY_TYPE_READ]);
	
	g_mutex_clear(&(b->mutex[PROXY_TYPE_WRITE]));
	g_mutex_clear(&(b->mutex[PROXY_TYPE_READ]));
	
	if (b->addr)     network_address_free(b->addr);
	if (b->uuid)     g_string_free(b->uuid, TRUE);
	if (b->ip) g_string_free(b->ip, TRUE);
	g_free(b);
}

network_backends_t *network_backends_new() {
	network_backends_t *bs;

	bs = g_new0(network_backends_t, 1);

	bs->backends = g_ptr_array_new();
	//bs->backends_mutex = g_mutex_new();
	bs->backends_mutex = &(bs->_backends_mutex);
	g_mutex_init (bs->backends_mutex);
	g_mutex_init (&bs->master_mutex);
	bs->has_master = FALSE;

	bs->backend_config_default.ip_port = NULL;
	bs->backend_config_default.rw_weight = DEFAULT_BACKEND_WEIGHT;
	bs->backend_config_default.ro_weight = DEFAULT_BACKEND_WEIGHT;
	bs->backend_config_default.state = BACKEND_STATE_UNKNOWN;
	bs->backend_config_default.health_check.rise = DEFAULT_BACKEND_RISE;
	bs->backend_config_default.health_check.fall = DEFAULT_BACKEND_FALL;
	bs->backend_config_default.health_check.inter = DEFAULT_BACKEND_INTER;
	bs->backend_config_default.health_check.fastdowninter = DEFAULT_BACKEND_INTER;
	bs->backend_config_default.health_check.health = DEFAULT_BACKEND_RISE;

	return bs;
}

void network_backends_free(network_backends_t *bs) {
	gsize i;

	if (!bs) return;

	g_mutex_lock(bs->backends_mutex);
	for (i = 0; i < bs->backends->len; i++) {
		network_backend_t *backend = bs->backends->pdata[i];
		
		network_backend_free(backend);
	}
	g_mutex_unlock(bs->backends_mutex);

	g_ptr_array_free(bs->backends, TRUE);
	//g_mutex_free(bs->backends_mutex);
	g_mutex_clear (bs->backends_mutex);
	g_mutex_clear(&bs->master_mutex);
	bs->backends_mutex = NULL;

	if (bs->backend_config_default.ip_port != NULL) {
		g_free(bs->backend_config_default.ip_port);
		bs->backend_config_default.ip_port = NULL;
	}
	g_free(bs);
}


/**
 * 分析地址格式，取出地址、权重和状态
 * 地址的格式=ip:port#weight#status
 * @param[out] gchar **addr_ip_port 新分配的，注意free
 * @return 字段个数
 */
int full_address_split(const gchar *address, gchar **addr_ip_port, gchar **addr_weight, gchar **addr_state)
{
	int numbers = 0;
	gchar *the_pound = NULL;
	gchar *s = NULL;
	gchar *t = NULL;

	*addr_ip_port = NULL;
	*addr_weight = NULL;
	*addr_state = NULL;

	if (address == NULL) {
		return 0;
	}

	*addr_ip_port = g_strdup(address);
	if (*addr_ip_port == NULL) {
		g_critical("address dup failed. %s", address);
		return -1;
	}

	numbers = 1;

	s = *addr_ip_port;
	t = NULL;
	if (s != NULL) {
		the_pound = strchr(s, '#');
		if (the_pound != NULL) {
			numbers++;
			*the_pound = '\0';
			t = the_pound + 1;
		}
	}
	*addr_weight = t;

	s = *addr_weight;
	t = NULL;
	if (s != NULL) {
		the_pound = strchr(s, '#');
		if (the_pound != NULL) {
			numbers++;
			*the_pound = '\0';
			t = the_pound + 1;
		}
	}
	*addr_state = t;

	//g_debug("n=%d addr_ip_port=%s addr_weight=%s addr_state=%s", numbers, *addr_ip_port, *addr_weight, *addr_state);
	return numbers;
}

/**
 * 分析地址格式，取出地址、权重和状态
 * 地址的格式=ip:port#weight#status
 * @note 该函数不再使用
 */
int full_address_split_new(const gchar *address, gchar **ip_port, guint *weight, backend_state_t *state)
{
	int n = 0;
	gchar *addr_ip_port = NULL;
	gchar *addr_weight = NULL;
	gchar *addr_state = NULL;
#define DEFAULT_BACKEND_WEIGHT 1
	*weight = DEFAULT_BACKEND_WEIGHT;
	*state = BACKEND_STATE_UNKNOWN; /*默认UNKNOWN*/

	n = full_address_split(address, &addr_ip_port, &addr_weight, &addr_state);
	//g_debug("n=%d address=%s weight=%s state=%s", n, addr_ip_port, addr_weight, addr_state);
	if (n >= 3)	{
		if (addr_state != NULL) {
			if (g_ascii_strncasecmp(addr_state, "up", strlen("up")) == 0) {
				*state = BACKEND_STATE_UP;
			} else if (g_ascii_strncasecmp(addr_state, "do", strlen("do")) == 0) {
				*state = BACKEND_STATE_DOWN;
			} else if (g_ascii_strncasecmp(addr_state, "pe", strlen("pe")) == 0) {
				*state = BACKEND_STATE_PENDING;
			}
		}
	}
	if (n >= 2)	{
		if (addr_weight != NULL) {
			if (*addr_weight != '\0') {
				*weight = atoi(addr_weight);
			}
		}
	}
	if (n >= 1) {
		*ip_port = addr_ip_port;
	}
	//g_debug("address=%s weight=%s(%d) state=%s(%d)", addr_ip_port, addr_weight, *weight, addr_state, *state);

	return n;
}

/**
 * 分析地址格式，取出地址、权重和状态
 * @note 该函数不再使用
 * 地址的格式=ip:port#weight#status#rise#fall#inter#fastdowninter
 * @param[IN] const gchar *address 地址字符串
 * @param[OUT] backend_config_t *bc 解析后的
 * @param[IN] const network_backends_t *bs bs结构用于取缺省值
 */
int full_address_split_new2(const gchar *address, backend_config_t *bc, const backend_config_t *bc_def)
{
	gchar **addr_tokens = NULL;
	guint n = 0;
	guint i = 0;

	addr_tokens = full_address_strsplit_new(address);
	if (addr_tokens == NULL) {
		return 0;
	} else {
		n = g_strv_length(addr_tokens);
	}

	//g_debug("n=%d address=%s weight=%s state=%s", n, addr_ip_port, addr_weight, addr_state);
	for (i = 1; i <= 7; i++) {
		switch (i) {
		/*ip_port*/
		case 1:
			if (n >= i && addr_tokens[i-1] != NULL && addr_tokens[i-1][0] != '\0') {
				bc->ip_port = strdup(addr_tokens[i-1]);
			} else {
				if (bc_def->ip_port == NULL) {
					bc->ip_port = NULL;
				} else {
					bc->ip_port = strdup(bc_def->ip_port);
				}
			}
			break;
		/*weight*/
		case 2:
			if (n >= i && addr_tokens[i-1] != NULL && addr_tokens[i-1][0] != '\0' ) {
				bc->rw_weight = atoi(addr_tokens[i-1]);
			} else {
				bc->rw_weight = bc_def->rw_weight;
			}
			break;
		/*state*/
		case 3:
			if (n >= i && addr_tokens[i-1] != NULL) {
				if (g_ascii_strncasecmp(addr_tokens[i-1], "up", strlen("up")) == 0) {
					bc->state = BACKEND_STATE_UP;
				} else if (g_ascii_strncasecmp(addr_tokens[i-1], "do", strlen("do")) == 0) {
					bc->state = BACKEND_STATE_DOWN;
				} else if (g_ascii_strncasecmp(addr_tokens[i-1], "pe", strlen("pe")) == 0) {
					bc->state = BACKEND_STATE_PENDING;
				} else {
					bc->state = bc_def->state;
				}
			} else {
				bc->state = bc_def->state;
			}
			break;
		/*rise & health*/
		case 4:
			if (n >= i && addr_tokens[i-1] != NULL && addr_tokens[i-1][0] != '\0') {
				bc->health_check.rise = atoi(addr_tokens[i-1]);
			} else {
				bc->health_check.rise = bc_def->health_check.rise;
			}
			if (bc->health_check.rise < 1) {
				bc->health_check.rise = 1;
			}
			bc->health_check.health = bc->health_check.rise;
			break;
		/*fall*/
		case 5:
			if (n >= i && addr_tokens[i-1] != NULL && addr_tokens[i-1][0] != '\0') {
				bc->health_check.fall = atoi(addr_tokens[i-1]);
			} else {
				bc->health_check.fall = bc_def->health_check.fall;
			}
			if (bc->health_check.fall < 1) {
				bc->health_check.fall = 1;
			}
			break;
		/*inter*/
		case 6:
			if (n >= i && addr_tokens[i-1] != NULL && addr_tokens[i-1][0] != '\0') {
				bc->health_check.inter = atoi(addr_tokens[i-1]);
			} else {
				bc->health_check.inter = bc_def->health_check.inter;
			}
			if (bc->health_check.inter < 1) {
				bc->health_check.inter = 1;
			}
			break;
		/*fastdowninter*/
		case 7:
			if (n >= i && addr_tokens[i-1] != NULL && addr_tokens[i-1][0] != '\0') {
				bc->health_check.fastdowninter = atoi(addr_tokens[i-1]);
			} else {
				bc->health_check.fastdowninter = bc->health_check.inter;
			}
			if (bc->health_check.fastdowninter < 1) {
				bc->health_check.fastdowninter = 1;
			}
			break;
		default:
			break;
		}
	}

	//g_debug("address=%s weight=%s(%d) state=%s(%d)", addr_ip_port, addr_weight, *weight, addr_state, *state);
	if (addr_tokens != NULL) {
		full_address_strsplit_free(addr_tokens);
		addr_tokens = NULL;
	}

	return n;
}

/**
 * address字符串按分隔符"#"切分
 * @note 该函数不再使用
 */
gchar **full_address_strsplit_new(const gchar *address) {
#define MAX_ADDR_TOKEN 8
	return g_strsplit(address, "#", MAX_ADDR_TOKEN);
}

/**
 * 释放string vector
 * 同g_strfreev，但增加了将char **指针数组成员设置为NULL
 */
void full_address_strsplit_free(gchar **str_array) {
	if (str_array) {
		int i;
		for (i = 0; str_array[i] != NULL ; i++) {
			g_free(str_array[i]);
			str_array[i] = NULL;
		}
		g_free(str_array);
	}
}

/**
 * 向数组添加一个后端
 * @return -1 添加失败
 * @return >=0 下标
 * @note:该函数已经废除
 *
 * FIXME: 1) remove _set_address, make this function callable with result of same
 *        2) differentiate between reasons for "we didn't add" (now -1 in all cases)
 * @note 该函数不再使用
 */
int network_backends_add(network_backends_t *bs, /* const */ gchar *address, backend_type_t type) {
	network_backend_t *new_backend = NULL;
	guint i;
	int n = 0;
	int ret = -1;
	/*
	gchar *addr_ip_port = NULL;
	guint weight = DEFAULT_BACKEND_WEIGHT;
	backend_state_t state = BACKEND_STATE_UNKNOWN;
	*/
	backend_config_t *bc = NULL;

	/*
	n = full_address_split_new(address, &addr_ip_port, &weight, &state);
	g_debug("n=%d address=%s weight=%d state=%d", n, addr_ip_port, weight, state);
	new_backend = network_backend_new();
	new_backend->type = type;
	new_backend->connect_w[PROXY_TYPE_WRITE] = weight;
	new_backend->connect_w[PROXY_TYPE_READ] = weight;
	new_backend->state = state;
	*/
	bc = backend_config_new();
	n = full_address_split_new2(address, bc, &(bs->backend_config_default));
	if (n < 1) {
		return -1;
	}
	new_backend = network_backend_new();
	new_backend->type = type;
	new_backend->connect_w[PROXY_TYPE_WRITE] = bc->rw_weight;
	new_backend->connect_w[PROXY_TYPE_READ] = bc->ro_weight;
	new_backend->state = bc->state;
	new_backend->health_check.rise = bc->health_check.rise;
	new_backend->health_check.fall = bc->health_check.fall;
	new_backend->health_check.inter = bc->health_check.inter;
	new_backend->health_check.fastdowninter = bc->health_check.fastdowninter;
	new_backend->health_check.health = bc->health_check.health;

	if (new_backend->state != BACKEND_STATE_UP) {
		/**
		 * @note 若添加的主库不处于up状态，将backend设置为RO节点
		 * 		 对于有多主节点的数据如何处理呢？
		 */
		new_backend->type = BACKEND_TYPE_RO;
	}

	if (0 != network_address_set_address(new_backend->addr, bc->ip_port)) {
		network_backend_free(new_backend);
		backend_config_free(bc);
		bc = NULL;
		return -1;
	}

	gchar * index_c = g_strstr_len (bc->ip_port, strlen(bc->ip_port), ":");
	if (NULL == index_c) {
		g_critical("[%s]: pattern of ip:port is error", G_STRLOC);
	} else {
		new_backend->port = atoi(index_c + 1);
		g_string_truncate(new_backend->ip, 0);
		g_string_append_len(new_backend->ip, bc->ip_port, index_c - bc->ip_port);
	}
	/* check if this backend is already known */
	g_mutex_lock(bs->backends_mutex);
	for (i = 0; i < bs->backends->len; i++) {
		network_backend_t *old_backend = bs->backends->pdata[i];

		if (strleq(S(old_backend->addr->name), S(new_backend->addr->name))) {
			g_critical("backend %s is already known!", address);
			g_mutex_unlock(bs->backends_mutex);
			network_backend_free(new_backend);
			backend_config_free(bc);
			bc = NULL;
			return -1;
		}
	}

	if (type == BACKEND_TYPE_RW && BACKEND_STATE_UP == new_backend->state) {
		// 如果添加的是主库，则需要将主库标志设置为TRUE
		g_mutex_lock(&bs->master_mutex);
		if (!bs->has_master) {
			bs->has_master = TRUE;
		} else {
			g_critical("There is already a master!");
			g_mutex_unlock(&bs->master_mutex);
			g_mutex_unlock(bs->backends_mutex);
			network_backend_free(new_backend);
			backend_config_free(bc);
			bc = NULL;
			return -1;
		}
		g_mutex_unlock(&bs->master_mutex);
	}

	g_ptr_array_add(bs->backends, new_backend);
	ret = (gint)(bs->backends->len) - 1;
	g_mutex_unlock(bs->backends_mutex);

	g_message("added %s backend: %s", (new_backend->type == BACKEND_TYPE_RW) ?
			"read/write" : "read-only", address);

	backend_config_free(bc);
	bc = NULL;

	return ret;
}

/**
 * modified by zhenfan, 2013/08/26
 * 这个函数代替了上边的函数network_backends_add
 * @param bs
 * @param address
 * @param state
 * @param rw_weight
 * @param guint
 * @param ro_weight
 * @param type
 * @return
 */
int network_backends_add2(network_backends_t *bs, const gchar *address, backend_type_t type, backend_state_t state, const backend_config_t *backend_config) {
	network_backend_t *new_backend;
	guint i;
	gint ret = 0;

	g_debug("address=%s state=%d rw_weight=%d ro_weight=%d rise=%d fall=%d inter=%d fastdowninter=%d", address, state, 
			backend_config->rw_weight, backend_config->ro_weight, backend_config->health_check.rise, 
			backend_config->health_check.fall, backend_config->health_check.inter,  backend_config->health_check.fastdowninter);

	new_backend = network_backend_new();
	new_backend->type = type;
	new_backend->connect_w[PROXY_TYPE_WRITE] = backend_config->rw_weight;
	new_backend->connect_w[PROXY_TYPE_READ] = backend_config->ro_weight;
	new_backend->state = state;

	new_backend->health_check.rise = backend_config->health_check.rise;
	new_backend->health_check.fall = backend_config->health_check.fall;
	new_backend->health_check.inter = backend_config->health_check.inter;
	new_backend->health_check.fastdowninter = backend_config->health_check.fastdowninter;
	if (BACKEND_STATE_UP == state) {
		new_backend->health_check.health = backend_config->health_check.rise + backend_config->health_check.fall - 1;
	}
	if (BACKEND_STATE_DOWN == state) {
		new_backend->health_check.health = 0;
	}
	if (BACKEND_STATE_UNKNOWN == state) {
		new_backend->health_check.health = backend_config->health_check.rise;
	}

	if (new_backend->state != BACKEND_STATE_UP) {
		/**
		 * @note 若添加的主库不处于up状态，将backend设置为RO节点
		 * 		 对于有多主节点的数据如何处理呢？
		 */
		new_backend->type = BACKEND_TYPE_RO;
	}

	if (0 != network_address_set_address(new_backend->addr, address)) {
		network_backend_free(new_backend);
		new_backend = NULL;
		return -1;
	}

	gchar * index_c = g_strstr_len (address, strlen(address), ":");
	if (NULL == index_c) {
		g_critical("[%s]: pattern of ip:port is error", G_STRLOC);
	} else {
		new_backend->port = atoi(index_c + 1);
		g_string_truncate(new_backend->ip, 0);
		g_string_append_len(new_backend->ip, address, index_c - address);
	}
	/* check if this backend is already known */
	g_mutex_lock(bs->backends_mutex);
	for (i = 0; i < bs->backends->len; i++) {
		network_backend_t *old_backend = bs->backends->pdata[i];

		if (strleq(S(old_backend->addr->name), S(new_backend->addr->name))) {
			network_backend_free(new_backend);
			new_backend = NULL;
			g_mutex_unlock(bs->backends_mutex);
			g_critical("backend %s is already known!", address);
			return -1;
		}
	}

	if (new_backend->type == BACKEND_TYPE_RW && BACKEND_STATE_UP == new_backend->state) {
		// 如果添加的是主库，则需要将主库标志设置为TRUE
		g_mutex_lock(&bs->master_mutex);
		if (!bs->has_master) {
			bs->has_master = TRUE;
		} else {
			/** added by zhenfan, 这里有个bug，应该需要释放掉内存*/
			network_backend_free(new_backend);
			g_mutex_unlock(&bs->master_mutex);
			g_mutex_unlock(bs->backends_mutex);
			g_critical("There is already a master!");
			return -1;
		}
		g_mutex_unlock(&bs->master_mutex);
	}

	ret = bs->backends->len;
	g_ptr_array_add(bs->backends, new_backend);
	g_mutex_unlock(bs->backends_mutex);

	g_message("added %s backend: %s", (type == BACKEND_TYPE_RW) ?
			"read/write" : "read-only", address);

	return ret;
}

gboolean set_backend_param(network_backends_t *bs, const gchar *ip_port, gint rw_weight, gint ro_weight,
					   gint rise, gint fall, gint inter, gint fastdowninter) {

	network_backend_t *bk_tmp = NULL;
	bk_tmp = network_backends_get_by_name(bs, ip_port);
	network_backend_t *master = NULL;
	gint old_weight = -1;

	if (NULL == bk_tmp) {
		return FALSE;
	}
	if (rw_weight >= 0) {
		g_mutex_lock(&bs->master_mutex);
		old_weight = bk_tmp->connect_w[PROXY_TYPE_WRITE];
		bk_tmp->connect_w[PROXY_TYPE_WRITE] = rw_weight;


		if ( /*自己是主库，要改为0*/
			(bs->has_master == TRUE && bk_tmp->type == BACKEND_TYPE_RW
				&& rw_weight == 0)
			|| /*没主库，要改为不是0*/
			(bs->has_master != TRUE && old_weight == 0 && rw_weight > 0)
			) {
			bk_tmp->type = BACKEND_TYPE_RO; /*类型先改成RO*/
			master = master_elect_with_priority(bs);
			if (master == NULL ) {
				g_critical("[%s]: master elect failed. No master!", G_STRLOC);
				bs->has_master = FALSE;
			} else {
				g_message("[%s]: master elect done. new master is %s", G_STRLOC,
						master->addr->name->str);
				bs->has_master = TRUE;
				master->type = BACKEND_TYPE_RW;
			}
		}

		g_mutex_unlock(&bs->master_mutex);

		loadbalance_wrr_calc(bs, PROXY_TYPE_WRITE);
	}
	if (ro_weight >= 0) {
		bk_tmp->connect_w[PROXY_TYPE_READ] = ro_weight;
		loadbalance_wrr_calc(bs, PROXY_TYPE_READ);
	}
	if (rise > 0)
		bk_tmp->health_check.rise = rise;
	if (fall > 0)
		bk_tmp->health_check.fall = fall;
	if (inter > 0)
		bk_tmp->health_check.inter = inter;
	if (fastdowninter > 0)
		bk_tmp->health_check.fastdowninter = fastdowninter;

	return TRUE;
}

/**
 * updated the _DOWN state to _UNKNOWN if the backends were
 * down for at least 4 seconds
 *
 * we only check once a second to reduce the overhead on connection setup
 *
 * @returns   number of updated backends
 */
int network_backends_check(network_backends_t *bs) {
	GTimeVal now;
	guint i;
	int backends_woken_up = 0;
	gint64	t_diff;

	g_get_current_time(&now);
	ge_gtimeval_diff(&bs->backend_last_check, &now, &t_diff);

	/* check max(once a second) */
	/* this also covers the "time went backards" case */
	if (t_diff < G_USEC_PER_SEC) {
		if (t_diff < 0) {
			g_message("%s: time went backwards (%"G_GINT64_FORMAT" usec)!",
				G_STRLOC, t_diff);
			bs->backend_last_check.tv_usec = 0;
			bs->backend_last_check.tv_sec = 0;
		}
		return 0;
	}
	
	/* check once a second if we have to wakeup a connection */
	g_mutex_lock(bs->backends_mutex);

	bs->backend_last_check = now;

	for (i = 0; i < bs->backends->len; i++) {
		network_backend_t *cur = bs->backends->pdata[i];

		if (cur->state != BACKEND_STATE_DOWN) continue;

		/* check if a backend is marked as down for more than 4 sec */
		if (now.tv_sec - cur->state_since.tv_sec > 4) {
			g_debug("%s.%d: backend %s was down for more than 4 sec, waking it up", 
					__FILE__, __LINE__,
					cur->addr->name->str);

			cur->state = BACKEND_STATE_UNKNOWN;
			cur->state_since = now;
			backends_woken_up++;
		}
	}
	g_mutex_unlock(bs->backends_mutex);

	return backends_woken_up;
}

/**
 *
 * added by jinxuan hou
 *
 * @param bs		backend list
 * @param ip_addr	the ip:port of the backend we want to find	
 * @return		network_backend_t the address of the backend we want to find
 */
network_backend_t *network_backends_get_by_name(const network_backends_t *bs,
		const gchar *ip_addr) {
	g_assert(bs);
	g_assert(ip_addr);

	network_backend_t *res = NULL;
	network_backend_t *tmp;
	gint index = 0;
	//gint len = network_backends_count(bs);

	// so big a lock
	g_mutex_lock(bs->backends_mutex);
	gint len = bs->backends->len;
	for (index = 0; index < len; index++) {
		tmp = bs->backends->pdata[index];
		if (0 == g_strcmp0(tmp->addr->name->str, ip_addr)) {
			res = tmp;
			break;
		}
	}
	g_mutex_unlock(bs->backends_mutex);
	return res;
}

network_backend_t *network_backends_get(network_backends_t *bs, guint ndx) {
	if (ndx >= network_backends_count(bs)) return NULL;

	/* FIXME: shouldn't we copy the backend or add ref-counting ? */	
	return bs->backends->pdata[ndx];
}

guint network_backends_count(network_backends_t *bs) {
	guint len;

	g_mutex_lock(bs->backends_mutex);
	len = bs->backends->len;
	g_mutex_unlock(bs->backends_mutex);

	return len;
}

/**
 * added by sohu-inc 
 */
gint get_count_of_idle_conns(network_backend_t *backend, const gchar*username, proxy_rw type) {
	g_assert(backend);
	return get_conn_idle_count(backend->pool[type], username);
}

gint get_count_of_pending_conns(network_backend_t *backend, const gchar*username, proxy_rw type) {
	g_assert(backend);
	return get_conn_pending_count(backend->pool[type], username);
}

gint get_count_of_using_conns(network_backend_t *backend, const gchar*username, proxy_rw type) {
	g_assert(backend);
	return get_conn_using_count(backend->pool[type], username);
}

struct pool_status* get_count_of_conn_status(network_backend_t *backend, const gchar* username, proxy_rw type) {
	g_assert(backend);
	return get_conn_pool_status(backend->pool[type], username);
}

/**
 * @author sohu-inc.com
 * backend上面连接数的同步访问
 */
void client_inc(network_backend_t * bk, proxy_rw type) {
	g_assert(bk);
	g_mutex_lock(&(bk->mutex[type]));
	bk->connected_clients[type]++;
	g_mutex_unlock(&(bk->mutex[type]));
}

void client_desc(network_backend_t * bk, proxy_rw type) {
	g_assert(bk);
	g_mutex_lock(&(bk->mutex[type]));
	if (bk->connected_clients[type] > 0) {
		bk->connected_clients[type]--;
	}
	g_mutex_unlock(&(bk->mutex[type]));
}



/**
 * 负载均衡-最少连接数
 * @param[inout] bs backends结构
 * @param[in] conn_type 请求的类型
 * 通过最小连接数获取一个可用的连接
 * 根据连接类型，选择不同策略
 * 写请求：发往RW类型的后端。选择一个最少连接数的后端
 * 读请求：发往RO类型的后端，如果没有RO的，才用RW。选择一个最少连接数的后端
 */
static GString * loadbalance_lc_select_do(network_backends_t *bs, proxy_rw conn_type) {
	network_backend_t *cur = NULL;
	network_backend_t *b = NULL;
	guint i = 0;
	guint min_connected_clients_rw = G_MAXUINT;
	guint min_connected_clients_ro = G_MAXUINT;
	network_backend_t *min_connected_backend_rw = NULL;
	network_backend_t *min_connected_backend_ro = NULL;

	/*
	guint min_connected_clients_id_rw = 0;
	guint min_connected_clients_id_ro = 0;
	guint selected = 0;
	*/

	g_assert(bs);
	g_assert(conn_type == PROXY_TYPE_WRITE || conn_type == PROXY_TYPE_READ);

	/**@note 不能对backends加锁，因为network_backends_get里加锁了*/
	//g_mutex_lock(bs->backends_mutex);
	/**
	 * 后端全扫描一遍，分别找出读/写类型的具有最少连接数的后端
	 */
	for (i = 0; i < network_backends_count(bs); i++) {
		cur = network_backends_get(bs, i);
		if (cur->state != BACKEND_STATE_UP)
			continue;
		//g_debug("%d clients connected to backend #%d", cur->connected_clients[conn_type], i);
		if (cur->type == BACKEND_TYPE_RW) {
			if (cur->connected_clients[conn_type] < min_connected_clients_rw) {
				min_connected_clients_rw = cur->connected_clients[conn_type];
				min_connected_backend_rw = cur;
				/*min_connected_clients_id_rw = i;*/
			}
		} else if (cur->type == BACKEND_TYPE_RO) {
			if (cur->connected_clients[conn_type] < min_connected_clients_ro) {
				min_connected_clients_ro = cur->connected_clients[conn_type];
				min_connected_backend_ro = cur;
				/*min_connected_clients_id_ro = i;*/
			}
		}
	}
	//g_mutex_unlock(bs->backends_mutex);

	/**
	 * 写类型直接就用上面找到的写后端
	 * 读类型首先看有没有符合条件的读后端，其次再是写后端
	 */
	if (conn_type == PROXY_TYPE_WRITE) {
		b = min_connected_backend_rw;
		/*selected = min_connected_clients_id_rw;*/
	} else if (conn_type == PROXY_TYPE_READ) {
		b = (min_connected_backend_ro == NULL) ? min_connected_backend_rw : min_connected_backend_ro;
		/*
		if (min_connected_backend_ro == NULL) {
			b = min_connected_backend_rw;
			selected = min_connected_clients_id_rw;
		} else {
			b = min_connected_backend_ro;
			selected = min_connected_clients_id_ro;
		}
		*/
	}

	/**
	 * 这里分配内存给字符串，返回后端地址。在proxy_get_server_list函数里释放的？
	 */
	/*g_debug("select backend: %d/%s", selected, b->addr->name->str);*/
	if (b != NULL) {
		client_inc(b, conn_type);
		return g_string_new_len(b->addr->name->str, b->addr->name->len);
	} else {
		return NULL;
	}
}
GString * loadbalance_lc_select(chassis *chas, proxy_rw conn_type) {
	g_assert(chas);
	g_assert(chas->priv);
	g_assert(chas->priv->backends);
	return loadbalance_lc_select_do(chas->priv->backends, conn_type);
}


/**
 * 负载均衡-加权轮询
 * @param[inout] bs backends结构
 * @param[in] conn_type 请求的类型
 * 通过权重获取一个可用的连接
 * 根据连接类型，选择不同策略
 * 写请求：发往RW类型的后端
 * 读请求：发往RO类型的后端，如果没有RO的，才用RW
 */
static GString * loadbalance_wrr_select_do(network_backends_t *bs, proxy_rw conn_type) {
	LB_WRR *wrr = NULL;
	gint i = 0;
	network_backend_t *cur = NULL;
	network_backend_t *b = NULL;
	guint retry = 0;
	guint max_retry = 0;

	g_assert(bs);
	g_assert(conn_type == PROXY_TYPE_WRITE || conn_type == PROXY_TYPE_READ);

	//g_mutex_lock(bs->backends_mutex);
	//g_debug("conn_type=%d", conn_type);
	wrr = &(bs->wrr_backends[conn_type]);

	/** 取可用后端，最多次数等于wrr_s序列的长度 */
	max_retry = wrr->wrr_s->len;
	for (retry = 0; retry < max_retry; retry++) {
		i = lb_wrr_get_locked(wrr);
		//g_debug("i=%d", i);

		cur = network_backends_get(bs, i);
		if (conn_type == PROXY_TYPE_WRITE) {
			if (cur->state != BACKEND_STATE_UP || cur->type != BACKEND_TYPE_RW) {
				continue;
			} else {
				b = cur;
				break;
			}
		} else if (conn_type == PROXY_TYPE_READ) {
			if (cur->state != BACKEND_STATE_UP || cur->type != BACKEND_TYPE_RO) {
				continue;
			} else {
				b = cur;
				break;
			}
		}
	}

	/** 如果没有可用只读后端，那么取一个可用读写后端 */
	if (b == NULL && conn_type == PROXY_TYPE_READ) {
		//g_debug("no available PROXY_TYPE_READ");
		for (retry = 0; retry < max_retry; retry++) {
			i = lb_wrr_get_locked(wrr);
			//g_debug("i=%d", i);
			cur = network_backends_get(bs, i);
			if (cur->state != BACKEND_STATE_UP || cur->type != BACKEND_TYPE_RW) {
				continue;
			} else {
				b = cur;
				break;
			}
		}
	}
	//g_mutex_unlock(bs->backends_mutex);

	if (b != NULL) {
		client_inc(b, conn_type);
		return g_string_new_len(b->addr->name->str, b->addr->name->len);
	} else {
		return NULL;
	}
}
GString * loadbalance_wrr_select(chassis *chas, proxy_rw conn_type) {
	g_assert(chas);
	g_assert(chas->priv);
	g_assert(chas->priv->backends);
	return loadbalance_wrr_select_do(chas->priv->backends, conn_type);
}


/**
 * 负载均衡-加权轮询 重新计算权重
 * @param[inout] bs backends结构
 * @param[in] conn_type 请求的类型
 * @note 现在放在plugin_apply_config里初始化
 * @todo 后端的权重、数量、角色、(和状态)发生变化时都要重新计算权重
 */
void loadbalance_wrr_calc(network_backends_t *bs, proxy_rw conn_type) {
	LB_WRR *wrr = NULL;
	guint i = 0;
	network_backend_t *cur = NULL;
	gint weight = 0;

	g_assert(bs);
	g_assert(conn_type == PROXY_TYPE_WRITE || conn_type == PROXY_TYPE_READ);

	wrr = &(bs->wrr_backends[conn_type]);

	lb_wrr_init(wrr, TRUE, FALSE);

	for (i = 0; i < network_backends_count(bs); i++) {
		cur = network_backends_get(bs, i);
		weight = 0;
		if (conn_type == PROXY_TYPE_WRITE) {
			if (cur->state == BACKEND_STATE_UP && cur->type == BACKEND_TYPE_RW) /**只取RW类型的*/
				weight = cur->connect_w[PROXY_TYPE_WRITE];
		} else if (conn_type == PROXY_TYPE_READ) {
			if (cur->state == BACKEND_STATE_UP) /**取RW和RO类型的，select函数里再区分*/
				weight = cur->connect_w[PROXY_TYPE_READ];
		}
		lb_wrr_append(wrr, weight);
	}

	lb_wrr_calc(wrr, TRUE);

	return;
}


/**
 * 负载均衡-加权轮询 初始化
 * @param[inout] bs backends结构
 * @param[in] conn_type 请求的类型
 * @note 现在放在plugin_apply_config里初始化
 */
void loadbalance_wrr_new(network_backends_t *bs, proxy_rw conn_type) {
	LB_WRR *wrr = NULL;
	g_assert(bs);
	g_assert(conn_type == PROXY_TYPE_WRITE || conn_type == PROXY_TYPE_READ);
	wrr = &(bs->wrr_backends[conn_type]);
	lb_wrr_init(wrr, TRUE, TRUE);
	return;
}


/**
 * 负载均衡-加权轮询 释放
 * @param[inout] bs backends结构
 * @param[in] conn_type 请求的类型
 * @note 放在mysql-proxy-cli exit_nicely那里执行
 */
void loadbalance_wrr_free(network_backends_t *bs, proxy_rw conn_type) {
	LB_WRR *wrr = NULL;
	g_assert(bs);
	g_assert(conn_type == PROXY_TYPE_WRITE || conn_type == PROXY_TYPE_READ);
	wrr = &(bs->wrr_backends[conn_type]);
	lb_wrr_clear(wrr, TRUE, TRUE);
	return;
}



/*eof*/
