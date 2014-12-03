/**
 * added by jinxuan hou ,for user_info test
 * @@jinxuanhou
 * using glib gtester
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

#include "chassis-mainloop.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1

static chassis * chas;
/**
 *	初始化测试用的连接限制配置
 * @param chas
 */
void init_conn_limit_for_test(chassis *chas) {
	g_assert(chas);
	g_assert(chas->conn_limit);

	// 构造test:X.X.X.% 写的连接限制为10
	GString * key = g_string_new("test:X.X.X.%");
	guint *limit = g_new(guint, 1);
	*limit = 10;
	g_hash_table_insert(chas->conn_limit[PROXY_TYPE_WRITE], key, limit);

	// 构造test:X.X.X.% 读的连接限制为50
	key = g_string_new("test:X.X.X.%");
	limit = g_new(guint, 1);
	*limit = 50;
	g_hash_table_insert(chas->conn_limit[PROXY_TYPE_READ], key, limit);

	// 构造test:X.X.%.% 写的连接限制为5
	key = g_string_new("test:X.X.%.%");
	limit = g_new(guint, 1);
	*limit = 5;
	g_hash_table_insert(chas->conn_limit[PROXY_TYPE_WRITE], key, limit);
}

/**
 *	初始化测试的用户信息
 * @param chas
 */
void init_user_infos_for_test(chassis *chas) {
	g_assert(chas);
	g_assert(chas->user_infos);

	GHashTable  *users = chas->user_infos;
	GString *username = g_string_new("test");
	user_info *user = user_info_new();
	user->username = g_string_new("test");
	user->passwd = g_string_new("test");
	add_ip_range_to_user_info("X.X.%.%",user);
	add_ip_range_to_user_info("X.X.X.%",user);

	GHashTable *conn_using = chas->conn_used[PROXY_TYPE_WRITE];
	g_assert(conn_using);
	// 初始化test:X.X.X.% 写端口的连接使用数
	GString *key = g_string_new("test:X.X.X.%");
	guint *used = g_new(guint, 1);
	*used = 0;
	g_hash_table_insert(conn_using, key, used);

	// 初始化xx:x.x.% 写端口的连接使用数
	key = g_string_new("xxx:x.x.%");
	used = g_new(guint, 1);
	*used = 0;
	g_hash_table_insert(conn_using, key, used);

	// 读的连接限制初始值的初始化
	conn_using = chas->conn_used[PROXY_TYPE_READ];

	// 初始化test:X.X.X.%的读端口的连接使用数
	key = g_string_new("test:X.X.X.%");
	used = g_new(guint, 1);
	*used = 0;
	g_hash_table_insert(conn_using, key, used);

	// 初始化xx:x.x.%的度端口的连接使用数
	key = g_string_new("xxx:x.x.%");
	used = g_new(guint, 1);
	*used = 0;
	g_hash_table_insert(conn_using, key, used);

	// 将用户插入用户列表中
	g_hash_table_insert(users, username, user);
}

/**
 * 初始化测试用的连接池配置信息
 * @param chas
 */
void init_pool_config_for_test(chassis *chas) {
	g_assert(chas);
	g_assert(chas->pool_config_per_user);
	GHashTable *pool_config = chas->pool_config_per_user[PROXY_TYPE_WRITE];

	// 设置用户test的写端口的连接池配置信息
	user_pool_config *config = g_new0(user_pool_config, 1);
	config->min_connections = 10;
	config->max_connections = 20;
	config->max_idle_interval = 3600;
	GString  *key = g_string_new("test");
	g_hash_table_insert(pool_config, key, config);

	pool_config = chas->pool_config_per_user[PROXY_TYPE_READ];

	// 设置用户test的度端口的连接池配置信息
	config = g_new0(user_pool_config, 1);
	config->min_connections = 10;
	config->max_connections = 20;
	config->max_idle_interval = 3600;
	key = g_string_new("test");
	g_hash_table_insert(pool_config, key, config);
}

/**
 * 测试初始设置的连接池配置信息
 */
void test_pool_config_init() {
	g_assert(chas);
	g_assert(chas->pool_config_per_user);

	user_pool_config *config = NULL;
	GString *key = NULL;

	// read proxy
	key = g_string_new("test");
	config = g_hash_table_lookup(chas->pool_config_per_user[PROXY_TYPE_READ], key);
	g_assert(config);
	g_assert_cmpint(config->max_connections, ==, 20);
	g_string_free(key, TRUE);
	key = NULL;

	// write proxy2
	key = g_string_new("test2");
	config = g_hash_table_lookup(chas->pool_config_per_user[PROXY_TYPE_WRITE], key);
	g_assert(!config);
	g_string_free(key, TRUE);
	key = NULL;

	// write proxy
	key = g_string_new("test");
	config = g_hash_table_lookup(chas->pool_config_per_user[PROXY_TYPE_WRITE], key);
	g_assert(config);
	g_assert_cmpint(config->min_connections, ==, 10);
	g_string_free(key, TRUE);
	key = NULL;
}

/**
 * 测试用户的默认的连接限制数时
 */
void test_default_conn_limit() {
	g_assert(chas);
	g_assert_cmpint(chas->default_conn_limit[PROXY_TYPE_WRITE], ==, RW_FRONT_END_CONN_LIMIT);
	g_assert_cmpint(chas->default_conn_limit[PROXY_TYPE_READ], ==, RO_FRONT_END_CONN_LIMIT);

	g_assert(chas->default_pool_config[PROXY_TYPE_WRITE]);
	g_assert(chas->default_pool_config[PROXY_TYPE_READ]);

	g_assert_cmpint(chas->default_pool_config[PROXY_TYPE_WRITE]->max_connections, ==, RW_CONNECTION_POOL_MAX_CONNECTIONS);
	g_assert_cmpint(chas->default_pool_config[PROXY_TYPE_READ]->max_idle_interval, ==, RO_CONNECTION_POOL_MAX_IDEL_INTERVAL);
}

/**
 * 测试初始设置的连接限制数
 */
void test_conn_limit_init() {
	g_assert(chas);
	gint *limit = get_conn_limit(chas, PROXY_TYPE_WRITE, "test", "X.X.X.%");
	g_assert_cmpint(*limit, ==, 10);

	limit = NULL;
	limit = get_conn_limit(chas, PROXY_TYPE_READ, "test", "X.X.%.%");
	g_assert(NULL == limit);

	limit = NULL;
	limit = get_conn_limit(chas, PROXY_TYPE_WRITE, "test", "X.X.%.%");
	g_assert_cmpint(*limit, ==, 5);
}

/**
 * 测试初始设置的用户信息
 */
void test_user_info_init() {
	g_assert(chas);

	// proxy@X.X.X.X test
	gchar *ip = "X.X.X.X";
	GString *username = g_string_new("test");
	ip_range *ipr = create_ip_range_from_str(ip);
	user_info *user = g_hash_table_lookup(chas->user_infos, username);

	g_assert(user);
	gchar *ip_region = get_ip_range(ipr->maxip, user);
	g_assert_cmpstr(ip_region, ==, "X.X.X.%");
	gint *con_in_use = get_login_users(chas, PROXY_TYPE_WRITE, "test", ip_region);

	g_assert_cmpint((*con_in_use), ==, 0);

	ip_range_free(ipr);
	ipr = NULL;

	g_free(ip_region);
	ip_region = NULL;

	// proxy@X.X.X.X
	gchar * ip2 = "X.X.X.X"; // a test
	ipr = create_ip_range_from_str(ip2);
	user = g_hash_table_lookup(chas->user_infos, username);

	g_assert(user);
	ip_region = get_ip_range(ipr->maxip, user);
	g_assert(!ip_region);

	ip_range_free(ipr);
	ipr = NULL;
}

/*
void test_log_in_user_found(chassis *chas) {
}

void test_log_in_user_not_found(chassis *chas) {
}

void test_log_in_user_found_but_exceed_limit (chassis *chas) {
}

void test_log_out(chassis *chas) {
}
*/

void test_user_infos_name_queue_new(void) {
	GQueue *q = NULL;
	GString *username = NULL;
	q = user_infos_name_queue_new(chas);
	while ((username = g_queue_pop_head(q)) != NULL ) {
		g_assert_cmpstr(username->str, ==, "test");
		//printf("user: %s\n", username->str);
		g_string_free(username, TRUE);
	}
	g_queue_free(q);
}

int main(int argc, char **argv) {
	chas = chassis_new();
	// init user's info
	init_user_infos_for_test(chas);
	// init conn limit
	init_conn_limit_for_test(chas);
	// init pool config
	init_pool_config_for_test(chas);
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	

	g_test_add_func("/core/test_pool_config_init",test_pool_config_init);
	g_test_add_func("/core/test_default_conn_limit",test_default_conn_limit);
	g_test_add_func("/core/test_conn_limit_init",test_conn_limit_init);
	g_test_add_func("/core/test_user_info_init",test_user_info_init);
	g_test_add_func("/core/test_user_infos_name_queue_new", test_user_infos_name_queue_new);
	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */
