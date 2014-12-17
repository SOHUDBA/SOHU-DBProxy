/*
 * chassis-config-xml.c
 *
 *  Created on: 2013年8月22日
 *      Author: zhenfan
 */
/**
 * @todo 目前都是以boolean形式返回给上层的caller,无法得到相应的错误码
 * @todo 改进：设置enum错误码
 */
#include "chassis-config-xml-admin.h"
#include "network-mysqld.h"
#include "glib-ext.h"
#include "chassis-path.h"
#include "network-query-rate.h"
#include "network-outbytes-statistic.h"
#include "network-inbytes-statistic.h"
#include "network-dml-statistic.h"

static void config_conn_limit_free(xmlChar *username, xmlChar *ip, xmlChar *max_connections);
static void config_user_info_free(xmlChar *name, xmlChar *password);
static void config_backends_free(xmlChar *address, xmlChar *type);
static void config_default_pool_config_free(xmlChar *default_min_connections, xmlChar * default_max_connections, xmlChar * default_max_idle_interval);
static void config_user_pool_config_free(xmlChar *username);
//static void config_sqlrule_free(xmlChar *user, xmlChar *db, xmlChar *text);
static gboolean config_adduser_notexist(xmlDoc *docptr, const gchar *user, const gchar *password, const gchar *hostip);
static gboolean config_adduser_ip(xmlDoc *docptr, const gchar *user, const gchar *hostip);
static gboolean config_setconnlimit_common(xmlDoc *docptr, proxy_rw rw_type, const gchar *username, const gchar *hostip, guint conn_limit);
static gboolean config_delconnlimit_common(xmlDoc *docptr, const proxy_rw rw_type, const gchar *username, const gchar *hostip);
static void config_savebak(const gchar* filename, xmlDoc *docptr);
static void config_user_accflag_free(xmlChar *name, xmlChar *accflag);
static gboolean config_addaccflag_notexist(xmlDoc *docptr, const gchar *name, int flag);

int masks[] = MASKS;
char *zabbixuser = NULL;
char *zabbixuserpassword = NULL;

/**
 * xml中加载所有的conn_limit配置，然后insert到chas->conn_limit[type]中
 * @param chas
 * @param rw_type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_conn_limit_load(chassis *chas, proxy_rw rw_type) {
	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);
	
	xmlChar *xpath = NULL;
	xmlChar *default_conn_limit = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr curNode = NULL;
	xmlChar *username = NULL;
	xmlChar *ip = NULL;
	xmlChar *max_connections; 
	gint max_conn;
	gint i;
	guint ip_tmp[2];
	/**
	 * default conn_limit
	 */
	if (rw_type == PROXY_TYPE_WRITE)
		xpath = BAD_CAST("/dbproxy/conn_limit/conn_limit_rw/default_limit/max_connections");
	else
		xpath = BAD_CAST("/dbproxy/conn_limit/conn_limit_ro/default_limit/max_connections");
	
	default_conn_limit = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	if (NULL == default_conn_limit) {
		return FALSE;
	}
	chas->default_conn_limit[rw_type] = atoi((gchar *)default_conn_limit);
	xmlFree(default_conn_limit);
	/**
	 * user对应的conn_limit
	 */
	if (rw_type == PROXY_TYPE_WRITE)
		xpath = BAD_CAST("/dbproxy/conn_limit/conn_limit_rw/limits/limit");
	else 
		xpath = BAD_CAST("/dbproxy/conn_limit/conn_limit_ro/limits/limit");
	
	// 通过xpath找到所有的nodeset
	result = xml_xpath_get_nodeset(chas->xml_docptr, xpath);
	
	if (result == NULL) {
		return FALSE;
	}
	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		curNode = result->nodesetval->nodeTab[i];
		// username
		if (!xmlHasProp(curNode, BAD_CAST "username") || NULL == (username = xmlGetProp(curNode, BAD_CAST "username"))) {
			config_conn_limit_free(username, ip, max_connections);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		// ip
		if (!xmlHasProp(curNode, BAD_CAST "ip") || NULL == (ip = xmlGetProp(curNode, BAD_CAST "ip")) || 0 == inet_pton4((gchar *)ip, ip_tmp)) {
			config_conn_limit_free(username, ip, max_connections);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		// max_connections
		if (NULL != (max_connections = xmlNodeGetContent(curNode->children->children))) {
			max_conn = atoi((gchar *)max_connections);
		} else {
			config_conn_limit_free(username, ip, max_connections);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		
		// 需要的字段已经准备好，插入conn_limit结构
		add_conn_limit(chas, rw_type, (gchar *)username, (gchar *)ip, max_conn);
		config_conn_limit_free(username, ip, max_connections);
	}
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 对应config_conn_limit_load函数，释放相应内存
 * @param username，ip，max_connections
 * @return None
 */
static void config_conn_limit_free(xmlChar *username, xmlChar *ip, xmlChar *max_connections) {
	if (NULL != username) {
		xmlFree(username);
		username = NULL;
	}
	if (NULL != ip) {
		xmlFree(ip);
		ip = NULL;
	}	
	if (NULL != max_connections) {
		xmlFree(max_connections);
		max_connections = NULL;
	}
}

/**
 * xml中加载所有的user_info配置，然后insert到chas->conn_limit[type]中
 * @param chas
 * @param rw_type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_user_info_load(chassis *chas) {
	xmlChar *xpath = NULL;
	GString *xpath_tmp = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlXPathObjectPtr ip_ranges = NULL;
	xmlNodePtr curNode = NULL;
	xmlChar *name = NULL;
	xmlChar *password = NULL;
	xmlChar *ip = NULL;
	user_info *user = NULL;
	gint i, j;
	guint ip_tmp[2];
	
	xpath = BAD_CAST("/dbproxy/user_info/user");
	
	// 通过xpath找到所有的nodeset
	result = xml_xpath_get_nodeset(chas->xml_docptr, xpath);
	
	if (result == NULL) {
		return FALSE;
	}
	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		curNode = result->nodesetval->nodeTab[i];
		// name
		if (!xmlHasProp(curNode, BAD_CAST "name") || NULL == (name = xmlGetProp(curNode, BAD_CAST "name"))) {
			config_user_info_free(name, password);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		// password
		xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
		g_string_append(xpath_tmp, (gchar *)name);
		g_string_append(xpath_tmp, "']/password");
		password = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, BAD_CAST xpath_tmp->str);
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
		if (NULL == password) {
			config_user_info_free(name, password);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}

		// ip_ranges
		xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
		g_string_append(xpath_tmp, (gchar *)name);
		g_string_append(xpath_tmp, "']/ip_ranges/ip");
		ip_ranges = xml_xpath_get_nodeset(chas->xml_docptr, BAD_CAST xpath_tmp->str);
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
		if (NULL == ip_ranges) {
			config_user_info_free(name, password);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		user = user_info_new();
		user->username = g_string_new((gchar *)name);
		user->passwd = g_string_new((gchar *)password);
		// 将每一个ip添加到user对象中
		for (j = 0; j < ip_ranges->nodesetval->nodeNr; j++) {
			if (NULL == (ip = xmlNodeGetContent(ip_ranges->nodesetval->nodeTab[j]->children)) || 0 == inet_pton4((gchar *)ip, ip_tmp)) { //如果解析错误或者ip格式不正确
				config_user_info_free(name, password);
				xmlXPathFreeObject(result);
				result = NULL;
				xmlXPathFreeObject(ip_ranges);
				ip_ranges = NULL;
				user_info_free(user);
				user = NULL;
				if (NULL != ip)
					xmlFree(ip);
					ip = NULL;
				return FALSE;
			}
			add_ip_range_to_user_info((gchar *)ip, user);
			xmlFree(ip);
		}
		g_rw_lock_writer_lock(&chas->user_lock);
		g_hash_table_insert(chas->user_infos,  g_string_new((gchar *)name), user);
		g_rw_lock_writer_unlock(&chas->user_lock);
		
		if(zabbixuser == NULL && zabbixuserpassword == NULL)
		{
			int zulen = strlen(name) + 1;
			zabbixuser = (char *)malloc(zulen);
			if(zabbixuser != NULL)
			{
				memset(zabbixuser, 0, zulen);
				memcpy(zabbixuser, name, strlen(name));
			}
			
			int zuplen = strlen(password) + 1;
			zabbixuserpassword = (char *)malloc(zuplen);
			if(zabbixuserpassword != NULL)
			{
				memset(zabbixuserpassword, 0, zuplen);
				memcpy(zabbixuserpassword, password, strlen(password));
			}
		}
		
		config_user_info_free(name, password);
		xmlXPathFreeObject(ip_ranges);
		ip_ranges = NULL;
	}
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 对应config_user_info_load函数，释放相应内存
 * @param name，password
 * @return None
 */
static void config_user_info_free(xmlChar *name, xmlChar *password) {
	if (NULL != name) {
		xmlFree(name);
		name = NULL;
	}
	if (NULL != password) {
		xmlFree(password);
		password = NULL;
	}	
}

/**
 * xml中加载rw_address 或 ro_address的配置，然后放到chas->rw_addresses 或者 chas->ro_addresses 中
 * @param chas
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_listen_addresses_load(chassis *chas, proxy_rw rw_type) {
	xmlChar *xpath = NULL;
	xmlChar *flag =  NULL;

	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);

	if (rw_type == PROXY_TYPE_WRITE)
		xpath = BAD_CAST("/dbproxy/mysql_proxy/rw_addresses");
	else
		xpath = BAD_CAST("/dbproxy/mysql_proxy/ro_addresses");

	// 通过xpath找到唯一的node，并取得相应的child textnode内容
	flag = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);

	if (NULL == flag) {
		return FALSE;
	}

	g_string_append(chas->listen_addresses[rw_type], (gchar *)flag);

	xmlFree(flag);
	flag = NULL;
	return TRUE;
}

/**
 * 在配置文件中动态添加监听的地址
 * @param filename
 * @param backend
 * @param listen_type
 * @return
 */
gboolean config_addlistenaddr(const gchar* filename, const gchar *backend, proxy_rw listen_type) {
	g_assert(listen_type == PROXY_TYPE_WRITE || listen_type == PROXY_TYPE_READ);

	xmlDoc *docptr = NULL;
	xmlChar *xpath_tmp;

	GString * new_value = g_string_new(NULL);

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}

	/** 首先判断要添加的ip是否存在于配置文件中 */
	xmlChar *flag =  NULL;

	/** 1. 判定rw 的ip列表 */
	xpath_tmp = BAD_CAST ("/dbproxy/mysql_proxy/rw_addresses");
	flag = xml_xpath_onenodeset_getchild_text(docptr, xpath_tmp);
	if (flag) {
		if (strstr((char *) flag, backend)) {
			g_critical("[%s]: the listen addr already in rw_address list!",
					G_STRLOC);
			xmlFree(flag);
			return TRUE;
		}
		if (listen_type == PROXY_TYPE_WRITE) {
			if (strcmp((char *)flag, " ") != 0) {
				g_string_append(new_value, (char *)flag);
				g_string_append(new_value, ",");
			}
		}
		xmlFree(flag);
		flag = NULL;
	}

	/** 2. 判定ro 的ip列表 */
	xpath_tmp = BAD_CAST ("/dbproxy/mysql_proxy/ro_addresses");
	flag = xml_xpath_onenodeset_getchild_text(docptr, xpath_tmp);
	if (flag) {
		if (strstr((char *) flag, backend)) {
			g_critical("[%s]: the listen addr already in ro_address list!",
					G_STRLOC);
			xmlFree(flag);
			return TRUE;
		}
		if (listen_type == PROXY_TYPE_READ) {
			if (strcmp((char *)flag, " ") != 0) {
				g_string_append(new_value, (char *)flag);
				g_string_append(new_value, ",");
			}
		}
		xmlFree(flag);
		flag = NULL;
	}

	g_string_append(new_value, backend);

	if (listen_type == PROXY_TYPE_WRITE)
		xpath_tmp = BAD_CAST("/dbproxy/mysql_proxy/rw_addresses");
	else
		xpath_tmp = BAD_CAST("/dbproxy/mysql_proxy/ro_addresses");

	/** 接下来更新xml文件的内容 */
	if (!xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp, BAD_CAST new_value->str)) {
		g_string_free(new_value, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(new_value, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 在配置文件中动态删除监听的地址
 * @param filename
 * @param backend
 * @param listen_type
 * @return
 */
gboolean config_dellistenaddr(const gchar* filename, const gchar *backend, proxy_rw listen_type) {
	g_assert(listen_type == PROXY_TYPE_WRITE || listen_type == PROXY_TYPE_READ);

	xmlDoc *docptr = NULL;
	xmlChar *xpath_tmp;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}

	/** 首先判断要删除的ip是否存在与配置文件中 */
	xmlChar *flag =  NULL;

	/** 1. 判定listen_type 的ip列表 */
	if (listen_type == PROXY_TYPE_WRITE)
		xpath_tmp = BAD_CAST("/dbproxy/mysql_proxy/rw_addresses");
	else
		xpath_tmp = BAD_CAST("/dbproxy/mysql_proxy/ro_addresses");

	flag = xml_xpath_onenodeset_getchild_text(docptr, xpath_tmp);

	if (NULL == flag) {
		g_critical(
				"[%s]: the listen addr user want to del is not in %s_address list!",
				G_STRLOC, (listen_type == PROXY_TYPE_WRITE) ? "rw" : "ro");
		xmlFree(flag);
		return FALSE;
	}

	gchar * s_pos = NULL;
	if (NULL == (s_pos = strstr((char *) flag, backend))) {
		g_critical(
				"[%s]: the listen addr user want to del is not in %s_address list!",
				G_STRLOC, (listen_type == PROXY_TYPE_WRITE) ? "rw" : "ro");
		xmlFree(flag);
		return FALSE;
	}

	GString *new_value = g_string_new(NULL);

	g_string_append_len(new_value, (char *)flag, s_pos - (char *)flag);

	if (strlen((char *) flag) > (size_t)(s_pos - (char *) flag)
			&& ',' == *(s_pos + strlen(backend))) {
		g_string_append_len(new_value, s_pos + strlen(backend) + 1,
				strlen((char *) flag)
						- (s_pos + strlen(backend) - (char *) flag));
	} else {
		g_string_append_len(new_value, s_pos + strlen(backend),
				strlen((char *) flag)
						- (s_pos + strlen(backend) - (char *) flag));

	}

	if (new_value->str) {
		if (new_value->len > 0 && new_value->str[new_value->len - 1] == ',') {
			g_string_truncate(new_value, new_value->len - 1);
		}
	}

	if (new_value->len == 0) {
		g_string_append(new_value, " "); //避免对应的字符串为空，出现不必要的问题。
	}

	xmlFree(flag);
	flag = NULL;
	/** 接下来更新xml文件的内容 */
	if (!xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp, BAD_CAST new_value->str)) {
		g_string_free(new_value, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(new_value, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}


/**
 * xml中加载multiplex配置，然后放到chas->multiplex中
 * @param chas
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_multiplex_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *flag =  NULL;

	xpath = BAD_CAST("/dbproxy/mysql_proxy/multiplex");
	
	// 通过xpath找到唯一的node，并取得相应的child textnode内容
	flag = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	
	if (NULL == flag) {
		return FALSE;
	}
	if (!xmlStrcasecmp(flag, BAD_CAST "on")) {
		chas->multiplex = TRUE;
	} else if (!xmlStrcasecmp(flag, BAD_CAST "off")) {
		chas->multiplex = FALSE;
	} else {
		xmlFree(flag);
		flag = NULL;
		return FALSE;
	}
	xmlFree(flag);
	flag = NULL;
	return TRUE;
}

/**
 * xml中加载lb_algorithm配置，然后将lb_algorithm字符串返回中
 * @param chas
 * @param rw_type
 * @return 成功返回lb_algorithm的字符串，失败返回NULL
 */
gchar *config_lb_algorithm_load(chassis *chas, proxy_rw rw_type) {
	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);
	
	gchar *ret;
	xmlChar *xpath = NULL;
	xmlChar *algorithm =  NULL;
	
	if (rw_type == PROXY_TYPE_WRITE)
		xpath = BAD_CAST("/dbproxy/mysql_proxy/rw_load_balance_algorithm");
	else 
		xpath = BAD_CAST("/dbproxy/mysql_proxy/ro_load_balance_algorithm");
	
	// 通过xpath找到唯一的node，并取得相应的child textnode内容
	algorithm = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	
	if (NULL == algorithm) {
		return NULL;
	}
	if (!xmlStrcasecmp(algorithm, BAD_CAST "lc")) {
		ret = g_strdup("lc");
	} else if (!xmlStrcasecmp(algorithm, BAD_CAST "wrr")) {
		ret = g_strdup("wrr");
	} else {
		xmlFree(algorithm);
		algorithm = NULL;
		return NULL;
	}
	xmlFree(algorithm);
	algorithm = NULL;
	return ret;
}

/**
 * xml中加载sql_statistics_switch配置，然后放到chas->is_sql_statistics中
 * @param chas
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_sql_statistics_switch_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *flag =  NULL;

	xpath = BAD_CAST("/dbproxy/mysql_proxy/sql_statistics_switch");
	
	// 通过xpath找到唯一的node，并取得相应的child textnode内容
	flag = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	
	if (NULL == flag) {
		return FALSE;
	}
	if (!xmlStrcasecmp(flag, BAD_CAST "on")) {
		chas->is_sql_statistics = TRUE;
	} else if (!xmlStrcasecmp(flag, BAD_CAST "off")) {
		chas->is_sql_statistics = FALSE;
	} else {
		xmlFree(flag);
		flag = NULL;
		return FALSE;
	}
	xmlFree(flag);
	flag = NULL;
	return TRUE;
}

/**
 * xml中加载sql_statistics_base配置，然后放到chas->sql_statistics_base中
 * @param chas
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_sql_statistics_base_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *base_str =  NULL;
	guint base;

	xpath = BAD_CAST("/dbproxy/mysql_proxy/sql_statistics_base");
	
	// 通过xpath找到唯一的node，并取得相应的child textnode内容
	base_str = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	
	if (NULL == base_str) {
		return FALSE;
	}
	base = atoi((gchar *)base_str);
	xmlFree(base_str);
	base_str = NULL;
	if (base != 2 && base != 10)
		return FALSE;
	chas->sql_statistics_base = base;
	return TRUE;
}

/**
 * xml中加载backends的缺省配置，然后将其放在chas->priv->backends中
 * @param chas
 * @param rw_type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_default_backends_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *tmp = NULL;
	guint rw_weight;
	guint ro_weight;
	guint rise;
	guint fall;
	guint inter;
	guint fastdowninter;
	// rw_weight
	xpath = BAD_CAST("/dbproxy/backends/default/rw_weight");
	if (NULL == (tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath))) {
		return FALSE;
	}
	rw_weight = atoi((gchar *)tmp);
	xmlFree(tmp);
	// ro_weight
	xpath = BAD_CAST("/dbproxy/backends/default/ro_weight");
	if (NULL == (tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath))) {
		return FALSE;
	}
	ro_weight = atoi((gchar *)tmp);
	xmlFree(tmp);
	// rise
	xpath = BAD_CAST("/dbproxy/backends/default/rise");
	if (NULL == (tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath))) {
		return FALSE;
	}
	rise = atoi((gchar *)tmp);
	xmlFree(tmp);
	// fall
	xpath = BAD_CAST("/dbproxy/backends/default/fall");
	if (NULL == (tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath))) {
		return FALSE;
	}
	fall = atoi((gchar *)tmp);
	xmlFree(tmp);
	// inter
	xpath = BAD_CAST("/dbproxy/backends/default/inter");
	if (NULL == (tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath))) {
		return FALSE;
	}
	inter = atoi((gchar *)tmp);
	xmlFree(tmp);
	// fastdowninter
	xpath = BAD_CAST("/dbproxy/backends/default/fastdowninter");
	if (NULL == (tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath))) {
		return FALSE;
	}
	fastdowninter = atoi((gchar *)tmp);
	xmlFree(tmp);
	tmp = NULL;
	
	chas->priv->backends->backend_config_default.rw_weight = rw_weight;
	chas->priv->backends->backend_config_default.ro_weight = ro_weight;
	chas->priv->backends->backend_config_default.health_check.rise = rise;
	chas->priv->backends->backend_config_default.health_check.fall = fall;
	chas->priv->backends->backend_config_default.health_check.inter = inter;
	chas->priv->backends->backend_config_default.health_check.fastdowninter = fastdowninter;	
	return TRUE;
}

/**
 * xml中加载所有backends配置，然后将其放在chas->priv->backends中
 * @param chas
 * @param rw_type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_backends_load(chassis *chas, proxy_rw rw_type) {
	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);
	
	xmlChar *xpath = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr childNode = NULL;
	xmlChar *address = NULL;
	xmlChar *type = NULL;
	xmlChar *child_content = NULL;
	backend_state_t state = BACKEND_STATE_UNKNOWN;
	guint rw_weight;
	guint ro_weight;
	guint rise;
	guint fall;
	guint inter;
	guint fastdowninter;
	backend_type_t backend_type = BACKEND_TYPE_UNKNOWN;
	gint i;
		
	if (rw_type == PROXY_TYPE_WRITE)
		xpath = BAD_CAST("/dbproxy/backends/backend[@type='rw']");
	else 
		xpath = BAD_CAST("/dbproxy/backends/backend[@type='ro']");
	
	// 通过xpath找到所有的nodeset
	result = xml_xpath_get_nodeset(chas->xml_docptr, xpath);
	
	if (NULL == result) {
		return FALSE;
	}
	// 首先赋值为默认值，如果xml中获得不到特定的值，就用默认值
	rw_weight = chas->priv->backends->backend_config_default.rw_weight;
	ro_weight = chas->priv->backends->backend_config_default.ro_weight;
	rise = chas->priv->backends->backend_config_default.health_check.rise;
	fall = chas->priv->backends->backend_config_default.health_check.fall;
	inter = chas->priv->backends->backend_config_default.health_check.inter;
	fastdowninter = chas->priv->backends->backend_config_default.health_check.fastdowninter;
	
	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		curNode = result->nodesetval->nodeTab[i];
		// address 
		if (!xmlHasProp(curNode, BAD_CAST "address") || NULL == (address = xmlGetProp(curNode, BAD_CAST "address"))) {
			config_backends_free(address, type);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		// type
		if (!xmlHasProp(curNode, BAD_CAST "type") || NULL == (type = xmlGetProp(curNode, BAD_CAST "type"))) {
			config_backends_free(address, type);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		if (!xmlStrcasecmp(type, BAD_CAST "rw")) {
			backend_type = BACKEND_TYPE_RW;
		} else if (!xmlStrcasecmp(type, BAD_CAST "ro")) {
			backend_type = BACKEND_TYPE_RO;
		}
		
		// 遍历curNode的children节点state、ro_weight、rw_weight、rise、fall、inter、fastdowninter
		childNode = curNode->xmlChildrenNode;
		if (NULL == childNode) {
			config_backends_free(address, type);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		while (NULL != childNode) {
			child_content = xmlNodeGetContent(childNode->xmlChildrenNode);
			if (!xmlStrcasecmp(childNode->name, BAD_CAST "state")) {
				if (!xmlStrcasecmp(child_content, BAD_CAST "up")) {
					state = BACKEND_STATE_UP;
				} else if (!xmlStrcasecmp(child_content, BAD_CAST "down")) {
					state = BACKEND_STATE_DOWN;
				} else if (!xmlStrcasecmp(child_content, BAD_CAST "pending")) {
					state = BACKEND_STATE_PENDING;
				} else if (!xmlStrcasecmp(child_content, BAD_CAST "unknown")) {
					state = BACKEND_STATE_UNKNOWN;
				}
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "rw_weight")) {
				rw_weight = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "ro_weight")) {
				ro_weight = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "rise")) {
				rise = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "fall")) {
				fall = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "inter")) {
				inter = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "fastdowninter")) {
				fastdowninter = atoi((gchar *)child_content);
			}
			xmlFree(child_content);
			child_content = NULL;
			childNode = childNode->next;
		}
		// 所有参数已经获取齐全，增加到backends列表中, 新申请一个backend_config_t对象, 传递进函数后释放backend_config_t对象
		backend_config_t *backend_config = backend_config_new();
		backend_config->rw_weight = rw_weight;
		backend_config->ro_weight = ro_weight;
		backend_config->health_check.rise = rise;
		backend_config->health_check.fall = fall;
		backend_config->health_check.inter = inter;
		backend_config->health_check.fastdowninter = fastdowninter;
		if (-1 >= (network_backends_add2(chas->priv->backends, (gchar *)address, backend_type, state, backend_config))) {
			g_free(backend_config);
			config_backends_free(address, type);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		backend_config_free(backend_config);
		config_backends_free(address, type);
	}
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 对应config_backends_load函数，释放相应内存
 * @param address，type
 * @return None
 */
static void config_backends_free(xmlChar *address, xmlChar *type) {
	if (NULL != address) {
		xmlFree(address);
		address = NULL;
	}
	if (NULL != type) {
		xmlFree(type);
		type = NULL;
	}	
}

/**
 * xml中加载所有pool_config配置，然后将
 * 1.默认配置放在chas->default_pool_config
 * 2.user自定义配置放在chas->pool_config_per_user中
 * @param chas
 * @param rw_type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_pool_config_load(chassis *chas, proxy_rw rw_type) {
	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);
	
	xmlChar *xpath = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlChar *default_min_connections = NULL;
	xmlChar *default_max_connections = NULL;
	xmlChar *default_max_idle_interval = NULL;
	
	xmlNodePtr curNode = NULL;
	xmlNodePtr childNode = NULL;
	xmlChar *username = NULL;
	xmlChar *child_content = NULL;
	guint min_connections;
	guint max_connections;
	guint max_idle_interval;
	gint i;
	
	/**
	 * default pool_config
	 */
	if (rw_type == PROXY_TYPE_WRITE) {
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_rw/default_pool/min_connections");
		default_min_connections = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_rw/default_pool/max_connections");
		default_max_connections = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_rw/default_pool/max_idle_interval");
		default_max_idle_interval = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	} else {
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_ro/default_pool/min_connections");
		default_min_connections = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_ro/default_pool/max_connections");
		default_max_connections = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_ro/default_pool/max_idle_interval");
		default_max_idle_interval = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	}
	if (NULL == default_min_connections || NULL == default_max_connections || NULL == default_max_idle_interval) {
		config_default_pool_config_free(default_min_connections, default_max_connections, default_max_idle_interval);
		return FALSE;
	}
	chas->default_pool_config[rw_type]->min_connections = atoi((gchar *)default_min_connections);
	chas->default_pool_config[rw_type]->max_connections = atoi((gchar *)default_max_connections);
	chas->default_pool_config[rw_type]->max_idle_interval = atoi((gchar *)default_max_idle_interval);
	
	config_default_pool_config_free(default_min_connections, default_max_connections, default_max_idle_interval);
	
	/**
	 * 对应user的pool_config
	 */
	if (rw_type == PROXY_TYPE_WRITE)
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_rw/pools/pool");
	else 
		xpath = BAD_CAST("/dbproxy/pool_conf/pool_conf_ro/pools/pool");
	
	result = xml_xpath_get_nodeset(chas->xml_docptr, xpath);
	
	if (NULL == result) {
		return FALSE;
	}
	
	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		curNode = result->nodesetval->nodeTab[i];
		// username
		if (!xmlHasProp(curNode, BAD_CAST "username") || NULL == (username = xmlGetProp(curNode, BAD_CAST "username"))) {
			config_user_pool_config_free(username);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		// 遍历curNode的children节点min_connections,max_connections,max_idle_interval
		childNode = curNode->xmlChildrenNode;
		if (NULL == childNode) {
			config_user_pool_config_free(username);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}
		while (NULL != childNode) {
			child_content = xmlNodeGetContent(childNode->xmlChildrenNode);
			if (!xmlStrcasecmp(childNode->name, BAD_CAST "min_connections")) {
				min_connections = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "max_connections")) {
				max_connections = atoi((gchar *)child_content);
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "max_idle_interval")) {
				max_idle_interval = atoi((gchar *)child_content);
			}
			xmlFree(child_content);
			child_content = NULL;
			childNode = childNode->next;
		}
		// 所有参数已经获取齐全，增加到pool_config_per_user中
		set_pool_config_for_user(chas, (gchar *)username, rw_type, max_connections, min_connections, max_idle_interval);
		config_user_pool_config_free(username);
	}
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

/**
 * 对应config_pool_config_load函数，释放相应内存
 * @param username
 * @return None
 */
static void config_default_pool_config_free(xmlChar *default_min_connections, xmlChar * default_max_connections, xmlChar * default_max_idle_interval) {
	if (NULL != default_min_connections) {
		xmlFree(default_min_connections);
		default_min_connections = NULL;
	}
	if (NULL != default_max_connections) {
		xmlFree(default_max_connections);
		default_max_connections = NULL;
	}
	if (NULL != default_max_idle_interval) {
		xmlFree(default_max_idle_interval);
		default_max_idle_interval = NULL;
	}
}

/**
 * 对应config_pool_config_load函数，释放相应内存
 * @param username
 * @return None
 */
static void config_user_pool_config_free(xmlChar *username) {
	if (NULL != username) {
		xmlFree(username);
		username = NULL;
	}
}

/**
 * xml中加载所有sql_rules配置，然后将配置加载到3张hash_table中
 * @param chas
 * @param type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_sqlrules_load(chassis *chas, security_model_type type) {
	g_assert(type == SQL_SINGLE || type == SQL_TEMPLATE);
	
	xmlChar *xpath = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlNodePtr curNode = NULL;
	xmlNodePtr childNode = NULL;
	xmlChar *user = NULL;
	xmlChar *db = NULL;
	xmlChar *text = NULL;
	gboolean is_disabled;
	security_action action;
	xmlChar *child_content = NULL;
	gint i;
	GString *sql_xpath = NULL;
	gboolean failed = FALSE;

	if (type == SQL_SINGLE)
		xpath = BAD_CAST("/dbproxy/sql_rules/sql_single/rule");
	else 
		xpath = BAD_CAST("/dbproxy/sql_rules/sql_template/rule");

	// 通过xpath找到所有的nodeset
	result = xml_xpath_get_nodeset(chas->xml_docptr, xpath);
	if (NULL == result) {
		g_critical("There are no %s sql_rules in %s", (type==SQL_SINGLE)?"single":"template", chas->xml_filename);
		return TRUE;
	}

	sql_xpath = g_string_new(NULL);
	if (sql_xpath == NULL) {
		return FALSE;
	}

	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		curNode = result->nodesetval->nodeTab[i];
		// user 
		if (!xmlHasProp(curNode, BAD_CAST "user") || NULL == (user = xmlGetProp(curNode, BAD_CAST "user"))) {
			failed = TRUE;
			break;
		}
		// db
		if (!xmlHasProp(curNode, BAD_CAST "db") || NULL == (db = xmlGetProp(curNode, BAD_CAST "db"))) {
			failed = TRUE;
			break;
		}
		// text
		if (!xmlHasProp(curNode, BAD_CAST "text") || NULL == (text = xmlGetProp(curNode, BAD_CAST "text"))) {
			failed = TRUE;
			break;
		}			
		// 遍历curNode的children节点action, disabled
		childNode = curNode->xmlChildrenNode;
		if (NULL == childNode) {
			failed = TRUE;
			break;
		}
		while (NULL != childNode) {
			child_content = xmlNodeGetContent(childNode->xmlChildrenNode);
			if (!xmlStrcasecmp(childNode->name, BAD_CAST "action")) {
				if (!xmlStrcasecmp(child_content, BAD_CAST "SAFE")) {
					action = ACTION_SAFE;
				} else if (!xmlStrcasecmp(child_content, BAD_CAST "LOG")) {
					action = ACTION_LOG;
				} else if (!xmlStrcasecmp(child_content, BAD_CAST "WARNING")) {
					action = ACTION_WARNING;
				} else if (!xmlStrcasecmp(child_content, BAD_CAST "BLOCK")) {
					action = ACTION_BLOCK;
				}
			} else if (!xmlStrcasecmp(childNode->name, BAD_CAST "disabled")) {
				is_disabled = xmlStrcasecmp(child_content, BAD_CAST "false")? TRUE:FALSE; 
			}
			xmlFree(child_content);
			child_content = NULL;
			childNode = childNode->next;
		}

		g_string_assign(sql_xpath, (gchar *)text);
		g_string_myreplace(sql_xpath, "&dprxy;", "'");

		// 所有的参数都已经准备完全，增加到user_db_sql_rule中
		if (NULL == add_sql_security_rule(chas->rule_table, sql_xpath->str, (gchar *)db, (gchar *)user, type, action, is_disabled)) {
			failed = TRUE;
			break;
		}

		if (NULL != user) {
			xmlFree(user);
			user = NULL;
		}
		if (NULL != db) {
			xmlFree(db);
			db = NULL;
		}
		if (NULL != text) {
			xmlFree(text);
			text = NULL;
		}
	}

	if (NULL != user) {
		xmlFree(user);
		user = NULL;
	}
	if (NULL != db) {
		xmlFree(db);
		db = NULL;
	}
	if (NULL != text) {
		xmlFree(text);
		text = NULL;
	}
	if (sql_xpath != NULL) {
		g_string_free(sql_xpath, TRUE);
		sql_xpath = NULL;
	}
	if (result != NULL) {
		xmlXPathFreeObject(result);
		result = NULL;
	}

	if (failed == TRUE) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * 对应config_sqlrule_free函数，释放相应内存
 * @param user, db, text
 * @return None
 */
/*
static void config_sqlrule_free(xmlChar *user, xmlChar *db, xmlChar *text) {
	if (NULL != user) {
		xmlFree(user);
		user = NULL;
	}
	if (NULL != db) {
		xmlFree(db);
		db = NULL;
	}
	if (NULL != text) {
		xmlFree(text);
		text = NULL;
	}
}
*/

/**
 * 在xml中增加backend节点
 * @param backend，bktype，backend_state，rw_weight，ro_weight
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_addbackend(const gchar* filename, const gchar *backend, const gchar *bktype, backend_state_t backend_state, const backend_config_t *backend_config) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;
	GString *xpath_tmp = NULL;
	gchar *state_str = NULL;
	gchar *tmp_str = NULL;
	xmlNodePtr backendNode = NULL;
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	
	// 首先判断该backend是否已经存在, 已存在返回TRUE?
	xpath_tmp = g_string_new("/dbproxy/backends/backend[@address='");
	g_string_append(xpath_tmp, backend);
	g_string_append(xpath_tmp, "']");
	if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		return TRUE;
	}
	g_string_free(xpath_tmp, TRUE);
	
	xpath = BAD_CAST("/dbproxy/backends");
	// 创建backend节点
	backendNode = xmlNewNode(NULL, BAD_CAST "backend");
	// 增加address属性
	xmlNewProp(backendNode, BAD_CAST "address", BAD_CAST backend);
	// 增加type属性
	xmlNewProp(backendNode, BAD_CAST "type", BAD_CAST bktype);
	// 增加state节点
	switch (backend_state) {
	case BACKEND_STATE_UP:
		state_str = "up";
		break;
	case BACKEND_STATE_DOWN:
		state_str = "down";
		break;
	case BACKEND_STATE_PENDING:
		state_str = "pending";
		break;
	case BACKEND_STATE_UNKNOWN:
	default:
		state_str = "unknown";
		break;
	}
	xmlNewTextChild(backendNode, NULL, BAD_CAST "state", BAD_CAST state_str);
	// 增加rw_weight节点
	tmp_str = g_new0(char, 10);
	sprintf(tmp_str, "%d", backend_config->rw_weight);
	xmlNewTextChild(backendNode, NULL, BAD_CAST "rw_weight", BAD_CAST tmp_str);
	sprintf(tmp_str, "%d", backend_config->ro_weight);
	xmlNewTextChild(backendNode, NULL, BAD_CAST "ro_weight", BAD_CAST tmp_str);
	sprintf(tmp_str, "%d", backend_config->health_check.rise);
	xmlNewTextChild(backendNode, NULL, BAD_CAST "rise", BAD_CAST tmp_str);
	sprintf(tmp_str, "%d", backend_config->health_check.fall);
	xmlNewTextChild(backendNode, NULL, BAD_CAST "fall", BAD_CAST tmp_str);
	sprintf(tmp_str, "%d", backend_config->health_check.inter);
	xmlNewTextChild(backendNode, NULL, BAD_CAST "inter", BAD_CAST tmp_str);
	sprintf(tmp_str, "%d", backend_config->health_check.fastdowninter);
	xmlNewTextChild(backendNode, NULL, BAD_CAST "fastdowninter", BAD_CAST tmp_str);
	g_free(tmp_str);
	if (!xml_xpath_onenodeset_addchild(docptr, xpath, backendNode)) {
		xmlFreeNode(backendNode);
		backendNode = NULL;
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档，如果失败不用释放backendNode，因为已经挂在了DOM树上，由xmlFreeDoc统一释放
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 设置backend参数
 * @param backend, rw_weight, ro_weight, rise, fall, inter, fastdowninter
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setbackendparam(const gchar* filename, const gchar *ip_port, gint rw_weight, gint ro_weight, gint rise, gint fall, gint inter, gint fastdowninter) {
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;
	gchar *tmp_str = NULL;
	guint xpath_backend_len;
		
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	
	// 拼出xpath路径
	xpath_tmp = g_string_new("/dbproxy/backends/backend");
	g_string_append(xpath_tmp, "[@address='");
	g_string_append(xpath_tmp, ip_port);
	g_string_append(xpath_tmp, "']");
	xpath_backend_len = xpath_tmp->len;
	
	tmp_str = g_new0(char, 10);
	// 如果--rw_weight没有设置则，传进来rw_weight=-1
	if (rw_weight >= 0) {
		sprintf(tmp_str, "%d", rw_weight);
		g_string_append(xpath_tmp, "/rw_weight");
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
	}
	// 如果--ro_weight没有设置则，传进来ro_weight=-1
	if (ro_weight >= 0) {
		sprintf(tmp_str, "%d", ro_weight);
		g_string_truncate(xpath_tmp, xpath_backend_len);
		g_string_append(xpath_tmp, "/ro_weight");
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
	}
	// 如果--rise没有设置则，传进来rise=-1
	if (rise > 0) {
		sprintf(tmp_str, "%d", rise);
		g_string_truncate(xpath_tmp, xpath_backend_len);
		g_string_append(xpath_tmp, "/rise");
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
	}
	// 如果--fall没有设置则，传进来fall=-1
	if (fall > 0) {
		sprintf(tmp_str, "%d", fall);
		g_string_truncate(xpath_tmp, xpath_backend_len);
		g_string_append(xpath_tmp, "/fall");
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
	}
	// 如果--inter没有设置则，传进来inter=-1
	if (inter > 0) {
		sprintf(tmp_str, "%d", inter);
		g_string_truncate(xpath_tmp, xpath_backend_len);
		g_string_append(xpath_tmp, "/inter");
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
	}
	// 如果--fastdowninter没有设置则，传进来fastdowninter=-1
	if (fastdowninter > 0) {
		sprintf(tmp_str, "%d", fastdowninter);
		g_string_truncate(xpath_tmp, xpath_backend_len);
		g_string_append(xpath_tmp, "/fastdowninter");
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
	}
	g_free(tmp_str);
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}
/**
 * 设置backend状态
 * @param backend，bktype，backend_state
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setbackend_state(const gchar* filename, const gchar *backend, backend_state_t backend_state) {
	g_assert(backend_state == BACKEND_STATE_UP || backend_state == BACKEND_STATE_DOWN 
				 || backend_state == BACKEND_STATE_PENDING || backend_state == BACKEND_STATE_UNKNOWN);
	
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	gchar *state_str = NULL;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	switch (backend_state) {
	case BACKEND_STATE_UP:
		state_str = "up";
		break;
	case BACKEND_STATE_DOWN:
		state_str = "down";
		break;
	case BACKEND_STATE_PENDING:
		state_str = "pending";
		break;
	case BACKEND_STATE_UNKNOWN:
		state_str = "unknown";
	}
	// 拼出xpath路径
	xpath_tmp = g_string_new("/dbproxy/backends/backend[@address='");
	g_string_append(xpath_tmp, (gchar *)backend);
	g_string_append(xpath_tmp, "']/state");
	if (!xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST state_str)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

gboolean config_adduser(const gchar* filename, const gchar *user, const gchar *password, const gchar *hostip) {
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 首先判断该用户是否已经存在
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, (gchar *)user);
	g_string_append(xpath_tmp, "']");
	if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于user匹配，还需要看密码是否匹配
		g_string_append(xpath_tmp, "/password");
		if (!xml_xpath_nodeset_ischild_matchtext(docptr, BAD_CAST xpath_tmp->str, BAD_CAST password)) { // 对于user匹配，还需要看密码是否匹配
			g_string_free(xpath_tmp, TRUE);
			xmlFreeDoc(docptr);
			docptr = NULL;
			return FALSE;
		}
		// user、password都匹配则加入hostip
		if (!config_adduser_ip(docptr, user, hostip)) {
			g_string_free(xpath_tmp, TRUE);
			xmlFreeDoc(docptr);
			docptr = NULL;
			return FALSE;
		}
	} else { // 如果user不匹配，需要加一个user
		if (!config_adduser_notexist(docptr, user, password, hostip)) {
			g_string_free(xpath_tmp, TRUE);
			xmlFreeDoc(docptr);
			docptr = NULL;
			return FALSE;
		}
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档，如果失败不用释放userNode，因为已经挂在了DOM树上, 由xmlFreeDoc统一释放
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}
/**
 * 在xml中增加user节点
 * @param user，password，host_ip
 * @return 成功返回TRUE，失败返回FALSE
 */
static gboolean config_adduser_notexist(xmlDoc *docptr, const gchar *user, const gchar *password, const gchar *hostip) {
	xmlChar *xpath = NULL;
	xmlNodePtr userNode = NULL;
	xmlNodePtr ipRangesNode = NULL;

	xpath = BAD_CAST("/dbproxy/user_info");
	// 创建user节点
	userNode = xmlNewNode(NULL, BAD_CAST "user");
	// 增加name属性
	xmlNewProp(userNode, BAD_CAST "name", BAD_CAST user);
	// 增加password节点
	xmlNewTextChild(userNode, NULL, BAD_CAST "password", BAD_CAST password);
	// 增加ip_ranges节点
	ipRangesNode = xmlNewNode(NULL, BAD_CAST "ip_ranges");
	xmlNewTextChild(ipRangesNode, NULL, BAD_CAST "ip", BAD_CAST hostip);
	xmlAddChild(userNode, ipRangesNode);
	if (!xml_xpath_onenodeset_addchild(docptr, xpath, userNode)) {
		xmlFreeNode(userNode);
		userNode = NULL;
		return FALSE;
	}
	return TRUE;
}

/**
 * user已经存在，在其中加入hostip
 * @param user, hostip
 * @return 成功返回TRUE，失败返回FALSE
 */
static gboolean config_adduser_ip(xmlDoc *docptr, const gchar *user, const gchar *hostip) {
	GString *xpath_tmp;
	xmlNodePtr ipnode = NULL;

	// 首先判断是否xml中已经有了该hostip,如果有直接返回TRUE
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, user);
	g_string_append(xpath_tmp, "']/ip_ranges/ip");
	if (xml_xpath_nodeset_ischild_matchtext(docptr, BAD_CAST xpath_tmp->str, BAD_CAST hostip)) {
		g_string_free(xpath_tmp, TRUE);
		return TRUE;
	}
	g_string_free(xpath_tmp, TRUE);
	
	// 拼出xpath路径
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, (gchar *)user);
	g_string_append(xpath_tmp, "']/ip_ranges");
	ipnode = xmlNewNode(NULL, BAD_CAST "ip");
	xmlNodeAddContent(ipnode, BAD_CAST hostip);
	// 如果增加失败，需要释放ipnode内存
	if (!xml_xpath_onenodeset_addchild(docptr, BAD_CAST xpath_tmp->str, ipnode)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeNode(ipnode);
		ipnode = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	return TRUE;
}

/**
 * 在xml中删除user节点
 * @param user
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_deluser(const gchar* filename, const gchar *user) {
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, user);
	g_string_append(xpath_tmp, "']");
	// 调用libxml-ext中的函数
	if (!xml_xpath_onenodeset_delmyself(docptr, BAD_CAST xpath_tmp->str)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;	
}

/**
 * 在xml中，删除指定user的一个ip
 * @param user, hostip
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_deluser_ip(const gchar* filename, const gchar *user, const gchar *hostip, gboolean *del_user_noip) {
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 首先判断该ip是不是该user的最后一个ip
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, user);
	g_string_append(xpath_tmp, "']/ip_ranges/ip");
	
	// 如果是最后一个ip，直接删除user节点 调用config_deluser函数
	if (xml_xpath_onenodeset_ischild_matchtext(docptr, BAD_CAST xpath_tmp->str, BAD_CAST hostip)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		*del_user_noip = TRUE;
		return config_deluser(filename, user);
	} else {
		*del_user_noip = FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 拼出xpath路径
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, user);
	g_string_append(xpath_tmp, "']/ip_ranges/ip");
	// 调用libxml-ext中的函数
	if (!xml_xpath_nodeset_delchild_matchtext(docptr, BAD_CAST xpath_tmp->str, BAD_CAST hostip)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 在xml中，修改指定user的passwd
 * @param user, passwd
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setuserpasswd(const gchar* filename, const gchar *user, const gchar *passwd) { 
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}

	// 拼出xpath路径
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, (gchar *)user);
	g_string_append(xpath_tmp, "']/password");
	// 如果user不存在，返回false，所以不需要先判断user是否存在
	if (!xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST passwd)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 在xml中，修改指定user@ip的connlimit
 * 1.对于user@ip匹配，直接修改
 * 2.如果不匹配，需要加一个limit节点user@ip
 * @param user, passwd
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setconnlimit_user_ip(const gchar* filename, const gchar *port_type_str, const gchar *username, const gchar *hostip, const guint conn_limit) {
	gboolean ret = FALSE;
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;
	proxy_rw port_type;

	do {
		ret = FALSE;

		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			break;
		}

		config_savebak(filename, docptr);

		if (NULL == xml_get_file_node_root(docptr)) {
			break;
		}

		// 首先需要判断hostip是否在user列表中,如果不在直接返回FALSE
		xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
		g_string_append(xpath_tmp, username);
		g_string_append(xpath_tmp, "']/ip_ranges/ip");
		if (!xml_xpath_nodeset_ischild_matchtext(docptr, BAD_CAST xpath_tmp->str, BAD_CAST hostip)) {
			break;
		}
		if (xpath_tmp != NULL) {
			g_string_free(xpath_tmp, TRUE);
			xpath_tmp = NULL;
		}

		if (port_type_str != NULL) {
			if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
				port_type = PROXY_TYPE_READ;
			} else {
				port_type = PROXY_TYPE_WRITE;
			}
			if (!config_setconnlimit_common(docptr, port_type, username, hostip, conn_limit)) {
				break;
			}
		} else {
			/*只要一个失败就算失败*/
			if (config_setconnlimit_common(docptr, PROXY_TYPE_READ, username, hostip, conn_limit) != TRUE
					|| config_setconnlimit_common(docptr, PROXY_TYPE_WRITE, username, hostip, conn_limit) != TRUE) {
				break;
			}
		}

		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			break;
		}

		ret = TRUE;
	} while(FALSE);

	if (xpath_tmp != NULL) {
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
	}
	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}
	return ret;
}
/**
 * 在xml中，修改指定user@ip的connlimit
 * 1.对于user@ip匹配，直接修改
 * 2.如果不匹配，需要加一个limit节点user@ip
 * 3.需要将Glist链表的所有ip遍历
 * @param user, passwd
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setconnlimit_user_allip(const gchar* filename, const gchar *port_type_str, const gchar *username, const GList *head, const guint conn_limit) {
	gboolean ret = FALSE;
	gboolean inner_ret = FALSE;
	xmlDoc *docptr = NULL;
	const GList *list_node = NULL;
	ip_range* ip_r = NULL;
	proxy_rw port_type;

	do {
		ret = FALSE;

		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			break;
		}

		config_savebak(filename, docptr);

		if (NULL == xml_get_file_node_root(docptr)) {
			break;
		}

		for (list_node = head; NULL != list_node; list_node = list_node->next) {
			inner_ret = FALSE;
			ip_r = (ip_range*)list_node->data;
			if (port_type_str != NULL) {
				if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
					port_type = PROXY_TYPE_READ;
				} else {
					port_type = PROXY_TYPE_WRITE;
				}
				if (!config_setconnlimit_common(docptr, port_type, username, ip_r->ip->str, conn_limit)) {
					break;
				}
			} else {
				/*只要一个失败就算失败*/
				if (config_setconnlimit_common(docptr, PROXY_TYPE_READ, username, ip_r->ip->str, conn_limit) != TRUE
						|| config_setconnlimit_common(docptr, PROXY_TYPE_WRITE, username, ip_r->ip->str, conn_limit) != TRUE) {
					break;
				}
			}
			inner_ret = TRUE;
		}
		if (inner_ret != TRUE) {
			break;
		}

		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			break;
		}

		ret = TRUE;
	} while(FALSE);

	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}
	return ret;
}
static gboolean config_setconnlimit_common(xmlDoc *docptr, proxy_rw rw_type, const gchar *username, const gchar *hostip, const guint conn_limit) {
	gboolean ret = FALSE;
	GString *xpath_tmp = NULL;
	gchar *conn_limit_str = NULL;
	xmlNodePtr limitNode = NULL;

	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);

	do {
		// 拼出xpath路径
		if (rw_type == PROXY_TYPE_WRITE)
			xpath_tmp = g_string_new("/dbproxy/conn_limit/conn_limit_rw/limits/limit[@username='");
		else
			xpath_tmp = g_string_new("/dbproxy/conn_limit/conn_limit_ro/limits/limit[@username='");
		g_string_append(xpath_tmp, username);
		g_string_append(xpath_tmp, "' and @ip='");
		g_string_append(xpath_tmp, hostip);
		g_string_append(xpath_tmp, "']");

		conn_limit_str = g_new0(char, 10);
		sprintf(conn_limit_str, "%d", conn_limit);

		ret = FALSE;
		if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于user@ip匹配，直接修改
			g_string_append(xpath_tmp, "/max_connections");
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST conn_limit_str);
		} else { // 如果不匹配，需要加一个limit节点user@ip
			g_string_truncate(xpath_tmp, 0);
			if (rw_type == PROXY_TYPE_WRITE)
				g_string_append(xpath_tmp, "/dbproxy/conn_limit/conn_limit_rw/limits");
			else
				g_string_append(xpath_tmp, "/dbproxy/conn_limit/conn_limit_ro/limits");
			// 增加limitNode节点
			limitNode = xmlNewNode(NULL, BAD_CAST "limit");
			// 增加username属性
			xmlNewProp(limitNode, BAD_CAST "username", BAD_CAST username);
			// 增加ip属性
			xmlNewProp(limitNode, BAD_CAST "ip", BAD_CAST hostip);
			// 增加max_connections textnode
			xmlNewTextChild(limitNode, NULL, BAD_CAST "max_connections", BAD_CAST conn_limit_str);
			// 如果增加失败，需要释放limitNode内存
			if (!xml_xpath_onenodeset_addchild(docptr, BAD_CAST xpath_tmp->str, limitNode)) {
				xmlFreeNode(limitNode);
				limitNode = NULL;
				break;
			}
		}
		ret = TRUE;
	} while (FALSE);

	if (conn_limit_str != NULL) {
		g_free(conn_limit_str);
		conn_limit_str = NULL;
	}
	if (xpath_tmp != NULL) {
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
	}
	return ret;
}


/**
 * 在xml中，删除指定user@ip的connlimit
 * 1.对于user@ip匹配，直接删除
 * 2.如果不匹配，返回失败
 * @param user, passwd
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_delconnlimit_user_ip(const gchar* filename, const gchar *port_type_str, const gchar *username, const gchar *hostip) {
	gboolean ret = FALSE;
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;
	proxy_rw port_type;

	do {
		ret = FALSE;

		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			break;
		}

		config_savebak(filename, docptr);

		if (NULL == xml_get_file_node_root(docptr)) {
			break;
		}

		// 首先需要判断hostip是否在user列表中,如果不在直接返回FALSE
		xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
		g_string_append(xpath_tmp, username);
		g_string_append(xpath_tmp, "']/ip_ranges/ip");
		if (!xml_xpath_nodeset_ischild_matchtext(docptr, BAD_CAST xpath_tmp->str, BAD_CAST hostip)) {
			break;
		}

		if (port_type_str != NULL) {
			if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
				port_type = PROXY_TYPE_READ;
			} else {
				port_type = PROXY_TYPE_WRITE;
			}
			/*删除时不管是否失败?*/
			config_delconnlimit_common(docptr, port_type, username, hostip);
		} else {
			/*删除时不管是否失败?*/
			config_delconnlimit_common(docptr, PROXY_TYPE_READ, username, hostip);
			config_delconnlimit_common(docptr, PROXY_TYPE_WRITE, username, hostip);
		}

		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			break;
		}

		ret = TRUE;
	} while(FALSE);

	if (xpath_tmp != NULL) {
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
	}
	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}
	return ret;
}
gboolean config_delconnlimit_user_allip(const gchar* filename, const gchar *port_type_str, const gchar *username, const GList *head) {
	gboolean ret = FALSE;
	gboolean inner_ret = FALSE;
	xmlDoc *docptr = NULL;
	const GList *list_node = NULL;
	ip_range* ip_r = NULL;
	proxy_rw port_type;

	do {
		ret = FALSE;

		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			break;
		}

		config_savebak(filename, docptr);

		if (NULL == xml_get_file_node_root(docptr)) {
			break;
		}

		for (list_node = head; NULL != list_node; list_node = list_node->next) {
			inner_ret = FALSE;
			ip_r = (ip_range*)list_node->data;
			if (port_type_str != NULL) {
				if (0 == g_ascii_strcasecmp(port_type_str, "RO")) {
					port_type = PROXY_TYPE_READ;
				} else {
					port_type = PROXY_TYPE_WRITE;
				}
				/*删除时不管是否失败?*/
				config_delconnlimit_common(docptr, port_type, username, ip_r->ip->str);
			} else {
				/*删除时不管是否失败?*/
				config_delconnlimit_common(docptr, PROXY_TYPE_READ, username, ip_r->ip->str);
				config_delconnlimit_common(docptr, PROXY_TYPE_WRITE, username, ip_r->ip->str);
			}
			inner_ret = TRUE;
		}
		if (inner_ret != TRUE) {
			break;
		}

		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			break;
		}

		ret = TRUE;
	} while (FALSE);

	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}
	return ret;
}
static gboolean config_delconnlimit_common(xmlDoc *docptr, const proxy_rw rw_type, const gchar *username, const gchar *hostip) {
	GString *xpath_tmp = NULL;

	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);

	// 拼出xpath路径
	if (rw_type == PROXY_TYPE_WRITE)
		xpath_tmp = g_string_new("/dbproxy/conn_limit/conn_limit_rw/limits/limit[@username='");
	else 
		xpath_tmp = g_string_new("/dbproxy/conn_limit/conn_limit_ro/limits/limit[@username='");
	g_string_append(xpath_tmp, username);
	g_string_append(xpath_tmp, "' and @ip='");
	g_string_append(xpath_tmp, hostip);
	g_string_append(xpath_tmp, "']");

	if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于user@ip匹配，直接删除
		xml_xpath_onenodeset_delmyself(docptr, BAD_CAST xpath_tmp->str);
	}

	g_string_free(xpath_tmp, TRUE);
	xpath_tmp = NULL;

	return TRUE;
}


/**
 * 在xml中，修改指定user的configpool
 * 1.如果user匹配，直接修改
 * 2.如果user不匹配，需要增加一个pool节点
 * @param username, rw_type, max_conn, min_conn, max_interval
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setpoolconfig(const gchar* filename, const gchar *username, const proxy_rw rw_type, const gint max_conn, const gint min_conn, const gint max_interval) {
	gboolean ret = FALSE;
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;
	gchar *tmp_str = NULL;
	xmlNodePtr poolNode = NULL;
	xmlChar *default_str = NULL;
	guint xpath_root_len;
	guint xpath_username_len;

	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);

	do {
		ret = FALSE;

		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			break;
		}

		config_savebak(filename, docptr);

		if (NULL == xml_get_file_node_root(docptr)) {
			break;
		}

		// 拼出xpath路径
		if (rw_type == PROXY_TYPE_WRITE)
			xpath_tmp = g_string_new("/dbproxy/pool_conf/pool_conf_rw");
		else
			xpath_tmp = g_string_new("/dbproxy/pool_conf/pool_conf_ro");
		xpath_root_len = xpath_tmp->len;
		g_string_append(xpath_tmp, "/pools/pool[@username='");
		g_string_append(xpath_tmp, username);
		g_string_append(xpath_tmp, "']");

		if (0 == xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于不user匹配，增加pool节点并设置为默认值
			// 增加pool节点
			poolNode = xmlNewNode(NULL, BAD_CAST "pool");
			// 增加username属性
			xmlNewProp(poolNode, BAD_CAST "username", BAD_CAST username);
			// 增加min_connections节点,需要先在default节点中找到相应的值
			g_string_truncate(xpath_tmp, xpath_root_len);
			g_string_append(xpath_tmp, "/default_pool/min_connections");
			default_str = xml_xpath_onenodeset_getchild_text(docptr, BAD_CAST xpath_tmp->str);
			xmlNewTextChild(poolNode, NULL, BAD_CAST "min_connections", BAD_CAST default_str);
			xmlFree(default_str);
			default_str = NULL;

			// 增加max_connections节点,需要先在default节点中找到相应的值
			g_string_truncate(xpath_tmp, xpath_root_len);
			g_string_append(xpath_tmp, "/default_pool/max_connections");
			default_str = xml_xpath_onenodeset_getchild_text(docptr, BAD_CAST xpath_tmp->str);
			xmlNewTextChild(poolNode, NULL, BAD_CAST "max_connections", BAD_CAST default_str);
			xmlFree(default_str);
			default_str = NULL;

			// 增加max_interval节点,需要先在default节点中找到相应的值
			g_string_truncate(xpath_tmp, xpath_root_len);
			g_string_append(xpath_tmp, "/default_pool/max_idle_interval");
			default_str = xml_xpath_onenodeset_getchild_text(docptr, BAD_CAST xpath_tmp->str);
			xmlNewTextChild(poolNode, NULL, BAD_CAST "max_idle_interval", BAD_CAST default_str);
			xmlFree(default_str);
			default_str = NULL;

			// 将poolNode加入DOM
			g_string_truncate(xpath_tmp, xpath_root_len);
			g_string_append(xpath_tmp, "/pools");
			if (!xml_xpath_onenodeset_addchild(docptr, BAD_CAST xpath_tmp->str, poolNode)) {
				xmlFreeNode(poolNode);
				poolNode = NULL;
				break;
			}
		}

		tmp_str = g_new0(char, 10);
		g_string_truncate(xpath_tmp, xpath_root_len);
		g_string_append(xpath_tmp, "/pools/pool[@username='");
		g_string_append(xpath_tmp, username);
		g_string_append(xpath_tmp, "']");
		xpath_username_len = xpath_tmp->len;

		// 如果--max_conn没有设置则，传进来max_conn=-1
		if (max_conn >= 0) {
			sprintf(tmp_str, "%d", max_conn);
			g_string_append(xpath_tmp, "/max_connections");
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
		}
		// 如果--min_conn没有设置则，传进来min_conn=-1
		if (min_conn >= 0) {
			sprintf(tmp_str, "%d", min_conn);
			g_string_truncate(xpath_tmp, xpath_username_len);
			g_string_append(xpath_tmp, "/min_connections");
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
		}
		// 如果--max_interval没有设置则，传进来max_interval=-1
		if (max_interval > 0) {
			sprintf(tmp_str, "%d", max_interval);
			g_string_truncate(xpath_tmp, xpath_username_len);
			g_string_append(xpath_tmp, "/max_idle_interval");
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST tmp_str);
		}

		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			break;
		}

		ret = TRUE;
	} while (FALSE);

	if (tmp_str != NULL) {
		g_free(tmp_str);
		tmp_str = NULL;
	}
	if (xpath_tmp != NULL) {
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
	}
	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}
	return ret;
}
gboolean config_delpoolconfig(const gchar* filename, const gchar *username, const proxy_rw rw_type) {
	gboolean ret = FALSE;
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;

	g_assert(rw_type == PROXY_TYPE_WRITE || rw_type == PROXY_TYPE_READ);

	do {
		ret = FALSE;

		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			break;
		}

		config_savebak(filename, docptr);

		if (NULL == xml_get_file_node_root(docptr)) {
			break;
		}

		// 拼出xpath路径
		if (rw_type == PROXY_TYPE_WRITE)
			xpath_tmp = g_string_new("/dbproxy/pool_conf/pool_conf_rw");
		else
			xpath_tmp = g_string_new("/dbproxy/pool_conf/pool_conf_ro");
		g_string_append(xpath_tmp, "/pools/pool[@username='");
		g_string_append(xpath_tmp, username);
		g_string_append(xpath_tmp, "']");

		if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于user@ip匹配，直接删除
			xml_xpath_onenodeset_delmyself(docptr, BAD_CAST xpath_tmp->str);
		}

		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			break;
		}

		ret = TRUE;
	} while(FALSE);

	if (xpath_tmp != NULL) {
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
	}
	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}

	return ret;
}


/**
 * 在xml中，修改mutiplex 的flag
 * @param flag
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setmultiplex(const gchar* filename, const gchar *flag) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST
			"/dbproxy/mysql_proxy/multiplex";
	if (!xml_xpath_onenodeset_setchild_text(docptr, xpath, BAD_CAST flag)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 在xml中，修改sql_statistics_switch的flag
 * @param flag
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setsqlstatisticsswitch(const gchar* filename, const gchar *flag) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST "/dbproxy/mysql_proxy/sql_statistics_switch";
	if (!xml_xpath_onenodeset_setchild_text(docptr, xpath, BAD_CAST flag)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 在xml中，修改sql_statistics_base的base
 * @param base
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setsqlstatisticsbase(const gchar* filename, const gint base) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;
	gchar *base_str = NULL;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST "/dbproxy/mysql_proxy/sql_statistics_base";
	
	base_str = g_new0(char, 10);
	if (base == 2 || base == 10) {
		sprintf(base_str, "%d", base);
		xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath, BAD_CAST base_str);
	}
	g_free(base_str);
	
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 在xml中，增加sql rules
 * 1.如果user,db,text均匹配，将原来的记录action和disabled覆盖
 * 2.如果不匹配，需要增加一个rule节点
 * @param filter_sql, dbname, username, action, type, action, is_disabled
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_addsqlfilter(const gchar* filename, const gchar *sql,
		const gchar *dbname, const gchar *username, security_model_type type,
		security_action action, gboolean is_disabled) {
	xmlDoc *docptr = NULL;
	GString *sql_xpath = NULL;
	gchar *action_str = NULL;
	gchar *disabled_str = NULL;
	GString *xpath_tmp = NULL;
	guint xpath_root_len = 0;
	guint xpath_rule_len = 0;
	xmlNodePtr ruleNode = NULL;
	gboolean failed = FALSE;
	gboolean add_node_failed = FALSE;

	g_assert(type == SQL_SINGLE || type == SQL_TEMPLATE);

	do {
		if (NULL == (docptr = xml_get_file_ptr(filename))) {
			failed = TRUE;
			break;
		}

		if (NULL == xml_get_file_node_root(docptr)) {
			failed = TRUE;
			break;
		}

		// 将单引号转义，好像xpath支持单引号比较复杂，故转换成&dprxy;罕见组合
		sql_xpath = g_string_new(sql);
		g_string_myreplace(sql_xpath, "'", "&dprxy;");
		// 转换action
		switch (action) {
		case ACTION_WARNING:
			action_str = "warning";
			break;
		case ACTION_BLOCK:
			action_str = "block";
			break;
		case ACTION_LOG:
			action_str = "log";
			break;
		case ACTION_SAFE:
		default:
			action_str = "safe";
			break;
		}
		// 转换disabled
		if (is_disabled) {
			disabled_str = "true";
		} else {
			disabled_str = "false";
		}

		// 拼出xpath路径
		if (type == SQL_SINGLE)
			xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_single");
		else
			xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_template");
		xpath_root_len = xpath_tmp->len;

		g_string_append_printf(xpath_tmp,
				"/rule[@user='%s' and @db='%s' and @text='%s']", username, dbname,
				sql_xpath->str);
		xpath_rule_len = xpath_tmp->len;

		if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 如果匹配，直接修改下面两个节点action disabled值
			// action
			g_string_append(xpath_tmp, "/action");
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST action_str);
			// disabled
			g_string_truncate(xpath_tmp, xpath_rule_len);
			g_string_append(xpath_tmp, "/disabled");
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST disabled_str);
		} else {		// 增加rule节点
			ruleNode = xmlNewNode(NULL, BAD_CAST "rule");
			// 增加user属性
			xmlNewProp(ruleNode, BAD_CAST "user", BAD_CAST username);
			// 增加db属性
			xmlNewProp(ruleNode, BAD_CAST "db", BAD_CAST dbname);
			// 增加text属性
			xmlNewProp(ruleNode, BAD_CAST "text", BAD_CAST sql_xpath->str);
			// 增加action节点
			xmlNewTextChild(ruleNode, NULL, BAD_CAST "action", BAD_CAST action_str);
			// 增加disabled节点
			xmlNewTextChild(ruleNode, NULL, BAD_CAST "disabled", BAD_CAST disabled_str);

			// 将ruleNode加入DOM
			g_string_truncate(xpath_tmp, xpath_root_len);
			if (!xml_xpath_onenodeset_addchild(docptr, BAD_CAST xpath_tmp->str, ruleNode)) {
				add_node_failed = TRUE;
				failed = TRUE;
				break;
			}
		}

		config_savebak(filename, docptr);
		// 存储xml文档
		if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
			failed = TRUE;
			break;
		}

	} while(0);

	if (sql_xpath != NULL) {
		g_string_free(sql_xpath, TRUE);
		sql_xpath = NULL;
	}
	if (xpath_tmp != NULL) {
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;
	}
	if (add_node_failed == TRUE) {
		if (ruleNode != NULL) {
			xmlFreeNode(ruleNode);
			ruleNode = NULL;
		}
	}
	// 释放doc内存
	if (docptr != NULL) {
		xmlFreeDoc(docptr);
		docptr = NULL;
	}

	if (failed == TRUE) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * 在xml中，删除sql rules
 * 1.如果user,db,text均匹配，将原来的记录节点删除
 * 2.如果不匹配，FALSE
 * @param filter_sql, dbname, username, type
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_delsqlfilter(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type) {
	g_assert(type == SQL_SINGLE || type == SQL_TEMPLATE);
	
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	GString *sql_xpath = NULL;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 将单引号转义，好像xpath支持单引号比较复杂，故转换成&dprxy;罕见组合
	sql_xpath = g_string_new(sql);
	g_string_myreplace(sql_xpath, "'", "&dprxy;");
	// 拼出xpath路径
	if (type == SQL_SINGLE)
		xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_single");
	else 
		xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_template");
	g_string_append(xpath_tmp, "/rule[@user='");
	g_string_append(xpath_tmp, username);
	g_string_append(xpath_tmp, "' and @db='");	
	g_string_append(xpath_tmp, dbname);
	g_string_append(xpath_tmp, "' and @text='");
	g_string_append(xpath_tmp, sql_xpath->str);
	g_string_append(xpath_tmp, "']");
	g_string_free(sql_xpath, TRUE);
	// 调用libxml-ext中的函数
	if (!xml_xpath_onenodeset_delmyself(docptr, BAD_CAST xpath_tmp->str)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;	
}

gboolean config_setfilterswitch(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type, gboolean is_disabled) {
	g_assert(type == SQL_SINGLE || type == SQL_TEMPLATE);
	
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;
	gchar *disabled_str = NULL;
	GString *sql_xpath = NULL;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 将单引号转义，好像xpath支持单引号比较复杂，故转换成&dprxy;罕见组合
	sql_xpath = g_string_new(sql);
	g_string_myreplace(sql_xpath, "'", "&dprxy;");
	// 转换disabled
	if (is_disabled)
		disabled_str = "true";
	else 
		disabled_str = "false";	
	// 拼出xpath路径
	if (type == SQL_SINGLE)
		xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_single");
	else 
		xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_template");
	g_string_append(xpath_tmp, "/rule[@user='");
	g_string_append(xpath_tmp, username);
	g_string_append(xpath_tmp, "' and @db='");	
	g_string_append(xpath_tmp, dbname);
	g_string_append(xpath_tmp, "' and @text='");
	g_string_append(xpath_tmp, sql_xpath->str);
	g_string_append(xpath_tmp, "']/disabled");
	g_string_free(sql_xpath, TRUE);

	if (!xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST disabled_str)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

gboolean config_setfilteraction(const gchar* filename, const gchar *sql, const gchar *dbname, const gchar *username, security_model_type type, security_action action) {
	g_assert(type == SQL_SINGLE || type == SQL_TEMPLATE);
	
	xmlDoc *docptr = NULL;
	GString *xpath_tmp = NULL;
	gchar *action_str = NULL;
	GString *sql_xpath = NULL;
	
	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}
	
	config_savebak(filename, docptr);
	
	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 将单引号转义，好像xpath支持单引号比较复杂，故转换成&dprxy;罕见组合
	sql_xpath = g_string_new(sql);
	g_string_myreplace(sql_xpath, "'", "&dprxy;");
	// 转换action
	switch (action) {
	case ACTION_WARNING:
		action_str = "warning";
		break;
	case ACTION_BLOCK:
		action_str = "block";
		break;
	case ACTION_LOG:
		action_str = "log";
		break;
	case ACTION_SAFE:
	default:
		action_str = "safe";
		break;
	}
	// 拼出xpath路径
	if (type == SQL_SINGLE)
		xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_single");
	else 
		xpath_tmp = g_string_new("/dbproxy/sql_rules/sql_template");
	g_string_append(xpath_tmp, "/rule[@user='");
	g_string_append(xpath_tmp, username);
	g_string_append(xpath_tmp, "' and @db='");	
	g_string_append(xpath_tmp, dbname);
	g_string_append(xpath_tmp, "' and @text='");
	g_string_append(xpath_tmp, sql_xpath->str);
	g_string_append(xpath_tmp, "']/action");
	g_string_free(sql_xpath, TRUE);
	
	if (!xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST action_str)) {
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

static void config_savebak(const gchar* filename, xmlDoc *docptr) {
	char buf[32];
	char path_buf[256];
	char filename_buf[256];
	struct timeval tv;
	struct tm *tm;
	
	gchar *dirname = g_path_get_dirname(filename);
	sprintf(path_buf, "%s/confxmlbak", dirname);
	if (-1 == g_access(path_buf, 0755)) {
		g_mkdir(path_buf, 0755);
	}
	g_free(dirname);
	
	if (0 != (gettimeofday(&tv, NULL))) {
		g_critical("config_savebak: cannot gettimeofday.");
	}
	tm = localtime(&tv.tv_sec);
	strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", tm);
	sprintf(filename_buf, "%s/%s_%ld.xml", path_buf, buf, tv.tv_usec);
	xmlSaveFormatFile(filename_buf, docptr, 1);
}

/**
 * 加载慢查询配置
 */
gboolean config_slow_query_log_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *tmp = NULL;

	xpath = BAD_CAST("/dbproxy/slow-query-log/enabled");
	tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	if (NULL == tmp) {
		/*默认关闭*/
		chas->slow_query_log_config->is_enabled = FALSE;
		//if (!xml_xpath_onenodeset_setchild_text(chas->xml_docptr, xpath, BAD_CAST "off")) {
		//	return FALSE;
		//}
	} else {
		if (!xmlStrcasecmp(tmp, BAD_CAST "on")) {
			chas->slow_query_log_config->is_enabled = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "true")) {
			chas->slow_query_log_config->is_enabled = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "1")) {
			chas->slow_query_log_config->is_enabled = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "off")) {
			chas->slow_query_log_config->is_enabled = FALSE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "false")) {
			chas->slow_query_log_config->is_enabled = FALSE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "0")) {
			chas->slow_query_log_config->is_enabled = FALSE;
		} else {
			xmlFree(tmp);
			tmp = NULL;
			return FALSE;
		}
		xmlFree(tmp);
		tmp = NULL;
	}

	xpath = BAD_CAST("/dbproxy/slow-query-log/file");
	tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	if (NULL == tmp) {
		/*默认日志名*/
		chas->slow_query_log_config->log_file->log_filename = g_strdup("var/log/slow.log");
		//if (!xml_xpath_onenodeset_setchild_text(chas->xml_docptr, xpath, BAD_CAST "var/log/slow.log")) {
		//	return FALSE;
		//}
	} else {
		chas->slow_query_log_config->log_file->log_filename = g_strdup((gchar *)tmp);
		xmlFree(tmp);
		tmp = NULL;
	}
	chassis_resolve_path(chas->base_dir, &(chas->slow_query_log_config->log_file->log_filename));

	xpath = BAD_CAST("/dbproxy/slow-query-log/execute-time");
	tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	if (NULL == tmp) {
		/*默认3秒*/
		chas->slow_query_log_config->filter->time_threshold_s = 3.0;
		//if (!xml_xpath_onenodeset_setchild_text(chas->xml_docptr, xpath, BAD_CAST "3.0")) {
		//	return FALSE;
		//}
	} else {
		gchar *err;
		chas->slow_query_log_config->filter->time_threshold_s = g_strtod((gchar *)tmp, &err);
		if (*err!=0 && g_ascii_isspace(*err)!=TRUE) {
			g_warning("read error: /dbproxy/slow-query-log/execute-time");
			xmlFree(tmp);
			tmp = NULL;
			return FALSE;
		}
		xmlFree(tmp);
		tmp = NULL;
	}
	chas->slow_query_log_config->filter->time_threshold_us = (guint64) (chas->slow_query_log_config->filter->time_threshold_s * 1000000);

	return TRUE;
}

gboolean config_set_slow_query_log_enabled(const gchar* filename, const gchar *flag) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST "/dbproxy/slow-query-log/enabled";
	if (!xml_xpath_onenodeset_setchild_text(docptr, xpath, BAD_CAST flag)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

gboolean config_set_slow_query_log_file(const gchar* filename, const gchar *flag) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST "/dbproxy/slow-query-log/file";
	if (!xml_xpath_onenodeset_setchild_text(docptr, xpath, BAD_CAST flag)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

gboolean config_set_slow_query_log_execute_time(const gchar* filename, const gchar *flag) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST "/dbproxy/slow-query-log/execute-time";
	if (!xml_xpath_onenodeset_setchild_text(docptr, xpath, BAD_CAST flag)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

// 加载引擎替换的配置
gboolean config_table_engine_replaceable_flag_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *tmp = NULL;

	xpath = BAD_CAST("/dbproxy/mysql_proxy/table_engine_replace");
	tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	if (NULL == tmp) {
		/*默认关闭*/
		chas->table_engine_replaceable = TRUE;
		//if (!xml_xpath_onenodeset_setchild_text(chas->xml_docptr, xpath, BAD_CAST "off")) {
		//	return FALSE;
		//}
	} else {
		if (!xmlStrcasecmp(tmp, BAD_CAST "on")) {
			chas->table_engine_replaceable = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "true")) {
			chas->table_engine_replaceable = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "1")) {
			chas->table_engine_replaceable = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "off")) {
			chas->table_engine_replaceable = FALSE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "false")) {
			chas->table_engine_replaceable = FALSE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "0")) {
			chas->table_engine_replaceable = FALSE;
		} else {
			xmlFree(tmp);
			tmp = NULL;
			return FALSE;
		}
		xmlFree(tmp);
		tmp = NULL;
	}

	return TRUE;
}


// 加载黑名单标志的配置
gboolean config_balck_list_flag_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *tmp = NULL;

	xpath = BAD_CAST("/dbproxy/mysql_proxy/black_list_flag");
	tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
	if (NULL == tmp) {
		/*默认关闭*/
		chas->is_black_list_enable = TRUE;
		//if (!xml_xpath_onenodeset_setchild_text(chas->xml_docptr, xpath, BAD_CAST "off")) {
		//	return FALSE;
		//}
	} else {
		if (!xmlStrcasecmp(tmp, BAD_CAST "on")) {
			chas->is_black_list_enable = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "true")) {
			chas->is_black_list_enable = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "1")) {
			chas->is_black_list_enable = TRUE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "off")) {
			chas->is_black_list_enable = FALSE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "false")) {
			chas->is_black_list_enable = FALSE;
		} else if (!xmlStrcasecmp(tmp, BAD_CAST "0")) {
			chas->is_black_list_enable = FALSE;
		} else {
			xmlFree(tmp);
			tmp = NULL;
			return FALSE;
		}
		xmlFree(tmp);
		tmp = NULL;
	}

	return TRUE;
}


/**
 * 在xml中，修改black list 的flag
 * @param flag
 * @return 成功返回TRUE，失败返回FALSE
 */
gboolean config_setblacklistflag(const gchar* filename, const gchar *flag) {
	xmlDoc *docptr = NULL;
	xmlChar *xpath = NULL;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}
	// 拼出xpath路径
	xpath = BAD_CAST
			"/dbproxy/mysql_proxy/black_list_flag";
	if (!xml_xpath_onenodeset_setchild_text(docptr, xpath, BAD_CAST flag)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 存储xml文档
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * 对应config_user_accflag_load函数，释放相应内存
 * @param name，accflag
 * @return None
 */
static void config_user_accflag_free(xmlChar *name, xmlChar *accflag) {
	if (NULL != name) {
		xmlFree(name);
		name = NULL;
	}
	if (NULL != accflag) {
		xmlFree(accflag);
		accflag = NULL;
	}
}

//  加载用户的封禁状态标志
gboolean config_limit_flag_load(chassis *chas) {
	xmlChar *xpath = NULL;
	GString *xpath_tmp = NULL;
	xmlXPathObjectPtr result = NULL;

	xmlNodePtr curNode = NULL;
	xmlChar *name = NULL;
	xmlChar *accflag = NULL;
	int iflag = 0;

	int i = 0;


	xpath = BAD_CAST("/dbproxy/user_info/user");

	// 通过xpath找到所有的nodeset
	result = xml_xpath_get_nodeset(chas->xml_docptr, xpath);

	if (result == NULL) {
		return FALSE;
	}

	for (i = 0; i < result->nodesetval->nodeNr; i++) {
		curNode = result->nodesetval->nodeTab[i];
		// name
		if (!xmlHasProp(curNode, BAD_CAST "name") || NULL == (name = xmlGetProp(curNode, BAD_CAST "name"))) {
			config_user_accflag_free(name, accflag);
			xmlXPathFreeObject(result);
			result = NULL;
			return FALSE;
		}

		// accflag
		xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
		g_string_append(xpath_tmp, (gchar *)name);
		g_string_append(xpath_tmp, "']/accflag");
		accflag = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, BAD_CAST xpath_tmp->str);
		g_string_free(xpath_tmp, TRUE);
		xpath_tmp = NULL;

		// 更新用户的访问标志
		if (NULL == accflag) {
			iflag = 0;
		} else {
			iflag = atoi((char *)accflag);
		}

		gboolean flag = (masks[0] & iflag);

		modify_query_rate_switch(
				chas->query_rate_list, (char *)name,
				flag);

		// 更新流入流量的标志
		flag = (masks[1] & iflag);

		modify_query_inbytes_switch(
				chas->inbytes_list, (char *)name,
				flag);

		// 更新流出流量的标志
		flag = (masks[2] & iflag);

		modify_query_outbytes_switch(
				chas->outbytes_list, (char *)name,
				flag);

		// 更新dml 的标志
		flag = (masks[3] & iflag);
		modify_query_dml_switch(
				chas->query_dml_list, (char *)name,
				flag);

		config_user_accflag_free(name, accflag);
	}
	xmlXPathFreeObject(result);
	result = NULL;
	return TRUE;
}

// 更新某个用户对应的限制标志
gboolean config_limit_flag_update(const gchar* filename, const gchar *name, int flag) {
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	char buffer[10];

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}


	// 首先判断该用户是否已经存在
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, name);
	g_string_append(xpath_tmp, "']");
	if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于user匹配，还需要看密码是否匹配
		sprintf(buffer, "%d", flag);
		// 如果有相应的用户，查看是否有标志项
		g_string_append(xpath_tmp, "/accflag");
		xmlXPathObjectPtr  result = NULL;

		result = xml_xpath_get_nodeset(docptr, BAD_CAST xpath_tmp->str);
		if (NULL == result) {
			if (!config_addaccflag_notexist(docptr, name, flag)) {
				g_string_free(xpath_tmp, TRUE);
				xmlFreeDoc(docptr);
				docptr = NULL;
				return FALSE;
			}
		} else {
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST buffer);
			xmlXPathFreeObject(result);
			result = NULL;
		}
	} else {
		// 如果没有对应的用户， 不会设置标志位
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档，如果失败不用释放userNode，因为已经挂在了DOM树上, 由xmlFreeDoc统一释放
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

/**
 * @ 增加一个用户对应的accflag字段
 */
static gboolean config_addaccflag_notexist(xmlDoc *docptr, const gchar *name, int flag) {

	char buffer[32];
	GString *xpath_tmp = NULL;
	xmlNodePtr accflagNode = NULL;


	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, name);
	g_string_append(xpath_tmp, "']");

	sprintf(buffer, "%d", flag);

	xmlXPathObjectPtr  result = NULL;
	result = xml_xpath_get_nodeset(docptr, BAD_CAST xpath_tmp->str);

	if (result->nodesetval->nodeTab[0]) {
		// 增加accflag 节点
		accflagNode = xmlNewTextChild(result->nodesetval->nodeTab[0], NULL, BAD_CAST "accflag", BAD_CAST buffer);
		xmlXPathFreeObject(result);
	}

	g_string_free(xpath_tmp, TRUE);
	return TRUE;
}

// 设置某个
gboolean config_limit_flag_set(const gchar* filename,
		const gchar *name,
		flag_type type,
		gboolean is_set) {
	xmlDoc *docptr = NULL;
	GString *xpath_tmp;
	char buffer[10];
	int flag = 0;

	if (NULL == (docptr = xml_get_file_ptr(filename))) {
		return FALSE;
	}

	config_savebak(filename, docptr);

	if (NULL == xml_get_file_node_root(docptr)) {
		xmlFreeDoc(docptr);
		return FALSE;
	}


	// 首先判断该用户是否已经存在
	xpath_tmp = g_string_new("/dbproxy/user_info/user[@name='");
	g_string_append(xpath_tmp, name);
	g_string_append(xpath_tmp, "']");
	if (0 != xml_xpath_get_nodeset_count(docptr, BAD_CAST xpath_tmp->str)) { // 对于user匹配，还需要看密码是否匹配
		// 如果有相应的用户，查看是否有标志项
		g_string_append(xpath_tmp, "/accflag");
		xmlXPathObjectPtr  result = NULL;

		result = xml_xpath_get_nodeset(docptr, BAD_CAST xpath_tmp->str);
		if (NULL == result) {

			if (is_set) {
				flag = masks[type] | flag;
			} else {
				flag = (~masks[type]) & flag;
			}

			if (!config_addaccflag_notexist(docptr, name, flag)) {
				g_string_free(xpath_tmp, TRUE);
				xmlFreeDoc(docptr);
				docptr = NULL;
				return FALSE;
			}
		} else {
			xmlChar *ret = NULL;
			if (1 == result->nodesetval->nodeNr &&
					NULL != result->nodesetval->nodeTab[0]->xmlChildrenNode) {
				ret = xmlNodeGetContent(result->nodesetval->nodeTab[0]->xmlChildrenNode);
				if (NULL != ret) {
					flag = atoi((char *)ret);
					xmlFree(ret);
				}
			}

			if (is_set) {
				flag = masks[type] | flag;
			} else {
				flag = (~masks[type]) & flag;
			}

			sprintf(buffer, "%d", flag);
			xml_xpath_onenodeset_setchild_text(docptr, BAD_CAST xpath_tmp->str, BAD_CAST buffer);
			xmlXPathFreeObject(result);
			result = NULL;
		}
	} else {
		// 如果没有对应的用户， 不会设置标志位
		g_string_free(xpath_tmp, TRUE);
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	g_string_free(xpath_tmp, TRUE);
	// 存储xml文档，如果失败不用释放userNode，因为已经挂在了DOM树上, 由xmlFreeDoc统一释放
	if (-1 == xmlSaveFormatFile(filename, docptr, 1)) {
		xmlFreeDoc(docptr);
		docptr = NULL;
		return FALSE;
	}
	// 释放doc内存
	xmlFreeDoc(docptr);
	docptr = NULL;
	return TRUE;
}

static char *dml_xpaths[] = {
	"/dbproxy/mysql_proxy/dml_alter",
	"/dbproxy/mysql_proxy/dml_create",
	"/dbproxy/mysql_proxy/dml_delete",
	"/dbproxy/mysql_proxy/dml_drop",
	"/dbproxy/mysql_proxy/dml_insert",
	"/dbproxy/mysql_proxy/dml_replace",
	"/dbproxy/mysql_proxy/dml_rename",
	"/dbproxy/mysql_proxy/dml_truncate",
	"/dbproxy/mysql_proxy/dml_update"
};

static gboolean dml_default[] = {
	TRUE, TRUE, TRUE, FALSE, TRUE,
	TRUE, TRUE, FALSE, TRUE
};

gboolean config_dml_kind_load(chassis *chas) {
	xmlChar *xpath = NULL;
	xmlChar *tmp = NULL;

	int index = 0;
	for (index = DML_ALTER; index <= DML_UPDATE; index ++) {
		xpath = BAD_CAST(dml_xpaths[index]);
		tmp = xml_xpath_onenodeset_getchild_text(chas->xml_docptr, xpath);
		if (NULL == tmp) {
			/*默认关闭*/
			chas->dml_ops[index] = dml_default[index];
		} else {
			if (!xmlStrcasecmp(tmp, BAD_CAST "on")) {
				chas->dml_ops[index] = TRUE;
			} else if (!xmlStrcasecmp(tmp, BAD_CAST "true")) {
				chas->dml_ops[index] = TRUE;
			} else if (!xmlStrcasecmp(tmp, BAD_CAST "1")) {
				chas->dml_ops[index] = TRUE;
			} else if (!xmlStrcasecmp(tmp, BAD_CAST "off")) {
				chas->dml_ops[index] = FALSE;
			} else if (!xmlStrcasecmp(tmp, BAD_CAST "false")) {
				chas->dml_ops[index] = FALSE;
			} else if (!xmlStrcasecmp(tmp, BAD_CAST "0")) {
				chas->dml_ops[index] = FALSE;
			} else {
				xmlFree(tmp);
				tmp = NULL;
				return FALSE;
			}
			xmlFree(tmp);
			tmp = NULL;
		}
	}
	return TRUE;
}

/*eof*/
