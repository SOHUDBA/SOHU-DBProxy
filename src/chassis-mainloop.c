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
 

#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h> /* event.h need struct timeval */
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>	 /* getpwnam() */
#endif

#include <glib.h>
#include <glib/gprintf.h>
#include "glib-ext.h"
#include "chassis-plugin.h"
#include "chassis-mainloop.h"
#include "chassis-event-thread.h"
#include "chassis-log.h"
//#include "chassis-stats.h"
#include "chassis-timings.h"
//#include "network-mysqld.h"
//#include "network-socket.h"
#include "slow-query-log.h"

#ifdef _WIN32
static volatile int signal_shutdown;
#else
static volatile sig_atomic_t signal_shutdown;
#endif

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

/**
 * @deprecated will be removed in 1.0
 * @see chassis_new()
 */
chassis *chassis_init() {
	return chassis_new();
}

/**
 * check if the libevent headers we built against match the 
 * library we run against
 */
int chassis_check_version(const char *lib_version, const char *hdr_version) {
	int lib_maj, lib_min, lib_pat;
	int hdr_maj, hdr_min, hdr_pat;
	int scanned_fields;

	if (3 != (scanned_fields = sscanf(lib_version, "%d.%d.%d%*s", &lib_maj, &lib_min, &lib_pat))) {
		g_critical("%s: library version %s failed to parse: %d",
				G_STRLOC, lib_version, scanned_fields);
		return -1;
	}
	if (3 != (scanned_fields = sscanf(hdr_version, "%d.%d.%d%*s", &hdr_maj, &hdr_min, &hdr_pat))) {
		g_critical("%s: header version %s failed to parse: %d",
				G_STRLOC, hdr_version, scanned_fields);
		return -1;
	}
	
	if (lib_maj == hdr_maj &&
	    lib_min == hdr_min &&
	    lib_pat >= hdr_pat) {
		return 0;
	}

	return -1;
}

/**
 * create a global context
 */
chassis *chassis_new() {
	chassis *chas;

	if (0 != chassis_check_version(event_get_version(), LIBEVENT_VERSION)) {
		g_critical("%s: chassis is build against libevent %s, but now runs against %s",
				G_STRLOC, LIBEVENT_VERSION, event_get_version());
		return NULL;
	}

	chas = g_new0(chassis, 1);

	chas->modules     = g_ptr_array_new();

	#if 0
	chas->stats = chassis_stats_new();
	#endif

	/* create a new global timer info */
	chassis_timestamps_global_init(NULL);

	chas->threads = chassis_event_threads_new();

	chas->event_hdr_version = g_strdup(LIBEVENT_VERSION);

	chas->shutdown_hooks = chassis_shutdown_hooks_new();

	/**
	 * added by jinxuan hou, 2013/04/08
	 * 前端连接限制的默认配置
	 */
	chas->conn_limit[PROXY_TYPE_WRITE] = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_int_free);
	g_rw_lock_init(&chas->limit_lock[PROXY_TYPE_WRITE]);
	chas->default_conn_limit[PROXY_TYPE_WRITE] = RW_FRONT_END_CONN_LIMIT;

	chas->conn_limit[PROXY_TYPE_READ] = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_int_free);
	g_rw_lock_init(&chas->limit_lock[PROXY_TYPE_READ]);
	chas->default_conn_limit[PROXY_TYPE_READ] = RO_FRONT_END_CONN_LIMIT;

	chas->conn_used[PROXY_TYPE_WRITE] = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_int_free);
	g_rw_lock_init(&chas->login_lock[PROXY_TYPE_WRITE]);

	chas->conn_used[PROXY_TYPE_READ] = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_int_free);
	g_rw_lock_init(&chas->login_lock[PROXY_TYPE_READ]);

	chas->user_infos = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_user_info_free);
	g_rw_lock_init(&chas->user_lock);

	/**
	 * 连接池限制的默认配置
	 */
	chas->pool_config_per_user[PROXY_TYPE_WRITE]= g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_pool_config_free);
	chas->pool_config_per_user[PROXY_TYPE_READ] = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_hash_table_pool_config_free);
	g_rw_lock_init(&chas->pool_conf_lock[PROXY_TYPE_WRITE]);
	g_rw_lock_init(&chas->pool_conf_lock[PROXY_TYPE_READ]);

	chas->default_pool_config[PROXY_TYPE_WRITE] = g_new0(user_pool_config, 1);
	chas->default_pool_config[PROXY_TYPE_WRITE]->max_connections = RW_CONNECTION_POOL_MAX_CONNECTIONS;
	chas->default_pool_config[PROXY_TYPE_WRITE]->min_connections = RW_CONNECTION_POOL_MIN_CONNECTIONS;
	chas->default_pool_config[PROXY_TYPE_WRITE]->max_idle_interval = RW_CONNECTION_POOL_MAX_IDEL_INTERVAL;// 3600 sec

	chas->default_pool_config[PROXY_TYPE_READ] = g_new0(user_pool_config, 1);
	chas->default_pool_config[PROXY_TYPE_READ]->max_connections = RO_CONNECTION_POOL_MAX_CONNECTIONS;
	chas->default_pool_config[PROXY_TYPE_READ]->min_connections = RO_CONNECTION_POOL_MIN_CONNECTIONS;
	chas->default_pool_config[PROXY_TYPE_READ]->max_idle_interval = RO_CONNECTION_POOL_MAX_IDEL_INTERVAL; // 3600 sec

	chas->regs = charset_regex_new();

	// 其配置参数是放在了proxy plugin的config里面
	chas->multiplex = FALSE; //默认是启用连接复用的,因为连接复用功能还不完善改为连接复用是默认不启用的

	chas->is_sql_statistics = TRUE; //默认是启用sql直方图统计的

	chas->sql_statistics_base = DEFAULT_SECTION_BASE;
	
	chas->sql_staitistics_record_limit = DEFAULT_STATISTICS_RECORD_LIMIT;

	chas->base_wait_time = 300; // 默认起始的等待时间为0.3ms
	chas->max_allowed_packet_size = 67108864; // 默认允许的最大的请求数据包是1M
	//chas->xml_filename = g_strdup("../conf/config.xml");
	chas->connection_scaler_thread = NULL;
	chas->xml_filename = NULL;

	// sql并行限制相关
	chas->para_limit_on = FALSE; // 默认不开启？

	// sql 超时执行限制
	chas->dura_limit_on = FALSE;


	chas->connection_state = global_connection_state_set_new();

	/*默认值lc*/
	chas->lb_algo[PROXY_TYPE_WRITE] = "lc";
	chas->lb_algo[PROXY_TYPE_READ] = "lc";
	chas->lb_algo_func[PROXY_TYPE_WRITE] = loadbalance_lc_select;
	chas->lb_algo_func[PROXY_TYPE_READ] = loadbalance_lc_select;

	chas->dbproxy_collation = NULL;

	chas->listen_addresses[0] = g_string_new(NULL);
	chas->listen_addresses[1] = g_string_new(NULL);

	chas->proxy_connection_init_ptr = NULL;

	chas->listen_cons[0] = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			NULL); /**< 这里面保存的监听连接在chas->priv->cons也会保存一份，
					* 所以这里不需要也最好不要释放*value的内存*/

	chas->listen_cons[1] = g_hash_table_new_full(g_hash_table_string_hash,
			g_hash_table_string_equal,
			g_hash_table_string_free,
			NULL); /**< 同上 */

	chas->slow_query_log_config = slow_query_log_config_t_new();

	chas->is_inbytes_r_enabled = TRUE;

	chas->is_outbytes_r_enabled = TRUE;

	chas->is_query_r_enabled = TRUE;

	chas->table_engine_replaceable = TRUE;

	chas->is_black_list_enable = TRUE;

	chas->is_dml_check_enable = TRUE;

	memset(chas->dml_ops, FALSE, sizeof(gboolean) * DML_SQL_NUM);

	return chas;
}


/**
 * free the global scope
 *
 * closes all open connections, cleans up all plugins
 *
 * @param chas      global context
 */
void chassis_free(chassis *chas) {
	guint i;
#ifdef HAVE_EVENT_BASE_FREE
	const char *version;
#endif

	if (!chas) return;

	/* init the shutdown, without freeing share structures */
	if (chas->priv_shutdown) chas->priv_shutdown(chas, chas->priv);


	/* call the destructor for all plugins */
	for (i = 0; i < chas->modules->len; i++) {
		chassis_plugin *p = chas->modules->pdata[i];

		g_assert(p->destroy);
		p->destroy(p->config);
	}

	chassis_shutdown_hooks_call(chas->shutdown_hooks); /* cleanup the global 3rd party stuff before we unload the modules */

	for (i = 0; i < chas->modules->len; i++) {
		chassis_plugin *p = chas->modules->pdata[i];

		chassis_plugin_free(p);
	}

	g_ptr_array_free(chas->modules, TRUE);

	/* free the pointers _AFTER_ the modules are shutdown */
	if (chas->priv_free) chas->priv_free(chas, chas->priv);


	if (chas->base_dir) g_free(chas->base_dir);
	if (chas->user) g_free(chas->user);

	#if 0
	if (chas->stats) chassis_stats_free(chas->stats);
	#endif

	chassis_timestamps_global_free(NULL);

	if (chas->threads) chassis_event_threads_free(chas->threads);

#ifdef HAVE_EVENT_BASE_FREE
	/* only recent versions have this call */

	version = event_get_version();

	/* libevent < 1.3e doesn't cleanup its own fds from the event-queue in signal_init()
	 * calling event_base_free() would cause a assert() on shutdown
	 */
	if (version && (strcmp(version, "1.3e") >= 0)) {
		if (chas->event_base) event_base_free(chas->event_base);
	}
#endif
	g_free(chas->event_hdr_version);

	chassis_shutdown_hooks_free(chas->shutdown_hooks);

	/** added by jinxuan hou, ghashtable resource release. 2013/04/08 */
	g_hash_table_destroy(chas->conn_limit[PROXY_TYPE_WRITE]);
	g_rw_lock_clear(&chas->limit_lock[PROXY_TYPE_WRITE]);

	g_hash_table_destroy(chas->conn_limit[PROXY_TYPE_READ]);
	g_rw_lock_clear(&chas->limit_lock[PROXY_TYPE_READ]);

	g_hash_table_destroy(chas->conn_used[PROXY_TYPE_WRITE]);
	g_rw_lock_clear(&chas->login_lock[PROXY_TYPE_WRITE]);

	g_hash_table_destroy(chas->conn_used[PROXY_TYPE_READ]);
	g_rw_lock_clear(&chas->login_lock[PROXY_TYPE_READ]);

	g_hash_table_destroy(chas->user_infos);
	g_rw_lock_clear(&chas->user_lock);

	g_hash_table_destroy(chas->pool_config_per_user[PROXY_TYPE_WRITE]);
	g_hash_table_destroy(chas->pool_config_per_user[PROXY_TYPE_READ]);
	g_rw_lock_clear(&chas->pool_conf_lock[PROXY_TYPE_WRITE]);
	g_rw_lock_clear(&chas->pool_conf_lock[PROXY_TYPE_READ]);

	g_free(chas->default_pool_config[PROXY_TYPE_WRITE]);
	g_free(chas->default_pool_config[PROXY_TYPE_READ]);

	charset_regex_free(chas->regs);
	
	/** added by zhenfan,  xml_docptr release. 2013/08/26 */
	if (NULL != chas->xml_docptr) {
		xmlFreeDoc(chas->xml_docptr);
		chas->xml_docptr = NULL;
	}
	if (NULL != chas->xml_filename) {
		g_free(chas->xml_filename);
		chas->xml_filename = NULL;
	}

	if (chas->connection_state != NULL) {
		g_debug("global connection state:");
		global_connection_state_set_dump(chas->connection_state);
		global_connection_state_set_free(chas->connection_state);
		chas->connection_state = NULL;
	}

	if (chas->dbproxy_collation) {
		g_free(chas->dbproxy_collation);
		chas->dbproxy_collation = NULL;
	}

	if (chas->listen_addresses[0]) {
		g_string_free(chas->listen_addresses[0], TRUE);
		chas->listen_addresses[0] = NULL;
	}

	if (chas->listen_addresses[1]) {
		g_string_free(chas->listen_addresses[1], TRUE);
		chas->listen_addresses[1] = NULL;
	}

	if (chas->listen_cons[0]) {
		g_hash_table_destroy(chas->listen_cons[0]);
		chas->listen_cons[0] = NULL;
	}

	if (chas->listen_cons[1]) {
		g_hash_table_destroy(chas->listen_cons[1]);
		chas->listen_cons[1] = NULL;
	}

	if (chas->slow_query_log_config != NULL) {
		slow_query_log_config_t_free(chas->slow_query_log_config);
		chas->slow_query_log_config = NULL;
	}

	g_free(chas);
}

void chassis_set_shutdown_location(const gchar* location) {
	if (signal_shutdown == 0) g_message("Initiating shutdown, requested from %s", (location != NULL ? location : "signal handler"));
	signal_shutdown = 1;
}

void chassis_set_startup_location(const gchar* location) {
        if (signal_shutdown == 1) g_message("Initiating startup, requested from %s", (location != NULL ? location : "signal handler"));
        signal_shutdown = 0;
}

gboolean chassis_is_shutdown() {
	return signal_shutdown == 1;
}

static void sigterm_handler(int G_GNUC_UNUSED fd, short G_GNUC_UNUSED event_type, void G_GNUC_UNUSED *_data) {
	chassis_set_shutdown_location(NULL);
}

static void sighup_handler(int G_GNUC_UNUSED fd, short G_GNUC_UNUSED event_type, void *_data) {
	chassis *chas = _data;

	g_message("received a SIGHUP, closing log file"); /* this should go into the old logfile */

	chassis_log_set_logrotate(chas->log);

	g_message("re-opened log file after SIGHUP"); /* ... and this into the new one */
}


/**
 * forward libevent messages to the glib error log
 */
static void event_log_use_glib(int libevent_log_level, const char *msg) {
	/* map libevent to glib log-levels */

	GLogLevelFlags glib_log_level = G_LOG_LEVEL_DEBUG;

	if (libevent_log_level == _EVENT_LOG_DEBUG) glib_log_level = G_LOG_LEVEL_DEBUG;
	else if (libevent_log_level == _EVENT_LOG_MSG) glib_log_level = G_LOG_LEVEL_MESSAGE;
	else if (libevent_log_level == _EVENT_LOG_WARN) glib_log_level = G_LOG_LEVEL_WARNING;
	else if (libevent_log_level == _EVENT_LOG_ERR) glib_log_level = G_LOG_LEVEL_CRITICAL;

	g_log(G_LOG_DOMAIN, glib_log_level, "(libevent) %s", msg);
}

int chassis_mainloop(void *_chas) {
	chassis *chas = _chas;
	guint i;
	struct event ev_sigterm, ev_sigint;
#ifdef SIGHUP
	struct event ev_sighup;
#endif
	chassis_event_thread_t *mainloop_thread;
	GString *thr_name = NULL;

	/* redirect logging from libevent to glib */
	event_set_log_callback(event_log_use_glib);


	/* add a event-handler for the "main" events */
	thr_name = g_string_new("main");
	i = 0;
	mainloop_thread = chassis_event_thread_new(thr_name, i);
	g_string_free(thr_name, TRUE);
	chassis_event_threads_init_thread(chas->threads, mainloop_thread, chas);
	chassis_event_threads_add(chas->threads, mainloop_thread);

	chas->event_base = mainloop_thread->event_base; /* all global events go to the 1st thread */

	g_assert(chas->event_base);


	/* setup all plugins all plugins */
	for (i = 0; i < chas->modules->len; i++) {
		chassis_plugin *p = chas->modules->pdata[i];

		g_assert(p->apply_config);
		if (0 != p->apply_config(chas, p->config)) {
			g_critical("%s: applying config of plugin %s failed",
					G_STRLOC, p->name);
			return -1;
		}

		p->is_running_on_valgrind = chas->is_running_on_valgrind;
	}
	/**
	 * added by zhenfan, 2013/08/28
	 * 所有的xml配置已经读取，关闭DOM树
	 */
	g_message("All configs have been loaded from config.xml");
	if (NULL != chas->xml_docptr) {
		xmlFreeDoc(chas->xml_docptr);
		chas->xml_docptr = NULL;
	}
	/*
	 * drop root privileges if requested
	 */
#ifndef _WIN32
	if (chas->user) {
		struct passwd *user_info;
		uid_t user_id= geteuid();

		/* Don't bother if we aren't superuser */
		if (user_id) {
			g_critical("can only use the --user switch if running as root");
			return -1;
		}

		if (NULL == (user_info = getpwnam(chas->user))) {
			g_critical("unknown user: %s", chas->user);
			return -1;
		}

		if (chas->log->log_filename) {
			/* chown logfile */
			if (-1 == chown(chas->log->log_filename, user_info->pw_uid, user_info->pw_gid)) {
				g_critical("%s.%d: chown(%s) failed: %s",
							__FILE__, __LINE__,
							chas->log->log_filename,
							g_strerror(errno) );

				return -1;
			}
		}

		setgid(user_info->pw_gid);
		setuid(user_info->pw_uid);
		g_debug("now running as user: %s (%d/%d)",
				chas->user,
				user_info->pw_uid,
				user_info->pw_gid );
	}
#endif

	signal_set(&ev_sigterm, SIGTERM, sigterm_handler, NULL);
	event_base_set(chas->event_base, &ev_sigterm);
	signal_add(&ev_sigterm, NULL);

	signal_set(&ev_sigint, SIGINT, sigterm_handler, NULL);
	event_base_set(chas->event_base, &ev_sigint);
	signal_add(&ev_sigint, NULL);

#ifdef SIGHUP
	signal_set(&ev_sighup, SIGHUP, sighup_handler, chas);
	event_base_set(chas->event_base, &ev_sighup);
	if (signal_add(&ev_sighup, NULL)) {
		g_critical("%s: signal_add(SIGHUP) failed", G_STRLOC);
	}
#endif

	if (chas->event_thread_count < 1) chas->event_thread_count = 1;

	/* create the event-threads
	 *
	 * - dup the async-queue-ping-fds
	 * - setup the events notification
	 * */
	for (i = 1; i < (guint)chas->event_thread_count; i++) { /* we already have 1 event-thread running, the main-thread */
		chassis_event_thread_t *event_thread;
		GString *thr_name = NULL;

		thr_name = g_string_new("foo");
		g_string_printf(thr_name, "event_%d", i);
		event_thread = chassis_event_thread_new(thr_name, i);
		g_string_free(thr_name, TRUE);
		chassis_event_threads_init_thread(chas->threads, event_thread, chas);
		chassis_event_threads_add(chas->threads, event_thread);
	}
	/**
	 * added by zhenfan, 将admin线程加入到最后一个位置
	 */
	chassis_event_threads_add(chas->threads, chas->event_admin_thread);

	/* start the event threads */
	if (chas->event_thread_count > 1) {
		chassis_event_threads_start(chas->threads);
	}

	g_message("DBProxy Server is ready for accepting client's request.");

	/**
	 * handle signals and all basic events into the main-thread
	 *
	 * block until we are asked to shutdown
	 */
	chassis_event_thread_loop(mainloop_thread);

	signal_del(&ev_sigterm);
	signal_del(&ev_sigint);
#ifdef SIGHUP
	signal_del(&ev_sighup);
#endif
	return 0;
}




/*user pool config related */

/**
 * 回去一个用户对应的连接池的配置信息
 * @param chas 基础变量
 * @param username
 * @param type
 * @return
 */
user_pool_config *get_pool_config_for_user(chassis *chas,
		const gchar *username,
		proxy_rw type) {

	if (chas == NULL || username == NULL)
		return NULL;

	g_assert(type == PROXY_TYPE_READ || type == PROXY_TYPE_WRITE);

	user_pool_config *config = NULL;
	GString *key = g_string_new(username);
	if (chas->pool_config_per_user || chas->pool_config_per_user[type]) {
		g_rw_lock_reader_lock(&chas->pool_conf_lock[type]);
		config = g_hash_table_lookup(chas->pool_config_per_user[type], key);
		g_rw_lock_reader_unlock(&chas->pool_conf_lock[type]);
	}

	g_string_free(key, TRUE);
	return config;
}

user_pool_config *get_pool_config_for_user_copy(chassis *chas,
		const GString *username, proxy_rw type, user_pool_config *config_new) {
	user_pool_config *config = NULL;

	if (chas == NULL || username == NULL)
		return NULL;

	g_assert(type == PROXY_TYPE_READ || type == PROXY_TYPE_WRITE);
	g_assert(config_new);

	g_rw_lock_reader_lock(&chas->pool_conf_lock[type]);
	if (chas->pool_config_per_user || chas->pool_config_per_user[type]) {
		config = g_hash_table_lookup(chas->pool_config_per_user[type], username);
		if (config == NULL) {
			config = chas->default_pool_config[type];
		}
	} else {
		config = chas->default_pool_config[type];
	}
	config_new->max_connections = config->max_connections;
	config_new->min_connections = config->min_connections;
	config_new->max_idle_interval = config->max_idle_interval;
	g_rw_lock_reader_unlock(&chas->pool_conf_lock[type]);

	return config_new;
}

guint get_pool_config_min_connections_for_user(chassis *chas,
		const GString *username, proxy_rw type) {
	user_pool_config *config = NULL;
	guint min_connections = 0;

	if (chas == NULL || username == NULL )
		return 0;

	g_assert(type == PROXY_TYPE_READ || type == PROXY_TYPE_WRITE);

	min_connections = (chas->default_pool_config[type])->min_connections;
	g_rw_lock_reader_lock(&(chas->pool_conf_lock[type]));
	if (chas->pool_config_per_user || chas->pool_config_per_user[type]) {
		config = g_hash_table_lookup(chas->pool_config_per_user[type],
				username);
		if (config != NULL) {
			min_connections = config->min_connections;
		}
	}
	g_rw_lock_reader_unlock(&(chas->pool_conf_lock[type]));

	return min_connections;
}
guint get_pool_config_max_connections_for_user(chassis *chas,
		const GString *username, proxy_rw type) {
	user_pool_config *config = NULL;
	guint max_connections = 0;

	if (chas == NULL || username == NULL )
		return 0;

	g_assert(type == PROXY_TYPE_READ || type == PROXY_TYPE_WRITE);

	max_connections = (chas->default_pool_config[type])->max_connections;
	g_rw_lock_reader_lock(&(chas->pool_conf_lock[type]));
	if (chas->pool_config_per_user || chas->pool_config_per_user[type]) {
		config = g_hash_table_lookup(chas->pool_config_per_user[type],
				username);
		if (config != NULL) {
			max_connections = config->max_connections;
		}
	}
	g_rw_lock_reader_unlock(&(chas->pool_conf_lock[type]));

	return max_connections;
}
gint get_pool_config_max_idle_interval_for_user(chassis *chas,
		const GString *username, proxy_rw type) {
	user_pool_config *config = NULL;
	gint max_idle_interval = 0;

	if (chas == NULL || username == NULL )
		return 0;

	g_assert(type == PROXY_TYPE_READ || type == PROXY_TYPE_WRITE);

	max_idle_interval = (chas->default_pool_config[type])->max_idle_interval;
	g_rw_lock_reader_lock(&(chas->pool_conf_lock[type]));
	if (chas->pool_config_per_user || chas->pool_config_per_user[type]) {
		config = g_hash_table_lookup(chas->pool_config_per_user[type],
				username);
		if (config != NULL) {
			max_idle_interval = config->max_idle_interval;
		}
	}
	g_rw_lock_reader_unlock(&(chas->pool_conf_lock[type]));

	return max_idle_interval;
}

/**
 * 设置一个用户的连接池配置信息
 * @param chas
 * @param user
 * @param type
 * @param max_conn
 * @param min_conn
 * @param max_interval
 */
void set_pool_config_for_user(chassis *chas,
		const gchar* user,
		const proxy_rw type,
		const gint max_conn,
		const gint min_conn,
		const gint max_interval) {
	if (chas == NULL || user == NULL) {
		return;
	}

	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);

	if (chas->pool_config_per_user == NULL || chas->pool_config_per_user[type] == NULL) {
		return ;
	}

	GString *key = g_string_new(user);
	user_pool_config *pool_conf = NULL;
	gboolean is_new = FALSE;
	g_rw_lock_writer_lock(&chas->pool_conf_lock[type]);
	pool_conf = g_hash_table_lookup(chas->pool_config_per_user[type], key);
	if (!pool_conf) {
		is_new = TRUE;
		pool_conf = g_new0(user_pool_config, 1);
		pool_conf->max_connections = chas->default_pool_config[type]->max_connections;
		pool_conf->min_connections = chas->default_pool_config[type]->min_connections;
		pool_conf->max_idle_interval = chas->default_pool_config[type]->max_idle_interval;
	}

	if (max_conn >= 0) {
		pool_conf->max_connections = max_conn;
	}
	if (min_conn >= 0) {
		pool_conf->min_connections = min_conn;
	}
	if (max_interval > 0) {
		pool_conf->max_idle_interval = max_interval;
	}

	if (is_new) {
		g_hash_table_insert(chas->pool_config_per_user[type], key, pool_conf);
	} else {
		g_string_free(key, TRUE);
	}

	g_rw_lock_writer_unlock(&chas->pool_conf_lock[type]);
}

/**
 * 删除用户的连接池配置
 * 用户连接池配置包括最大、最小连接数、间隔时间等都会被删除，一个不留
 * @param chassis *chas 全局
 * @param gchar* user 用户名
 * @param proxy_rw type 读写类型
 */
gboolean del_pool_config_for_user(chassis *chas,
		const gchar* user,
		const proxy_rw type) {
	gboolean ret = FALSE;
	GString *key = NULL;
	user_pool_config *pool_conf = NULL;

	if (chas == NULL || user == NULL) {
		return FALSE;
	}
	g_assert(type == PROXY_TYPE_WRITE || type == PROXY_TYPE_READ);

	if (chas->pool_config_per_user == NULL || chas->pool_config_per_user[type] == NULL) {
		return FALSE;
	}

	key = g_string_new(user);
	g_rw_lock_writer_lock(&chas->pool_conf_lock[type]);

	/*其实直接hash_table_remove即可*/
	pool_conf = g_hash_table_lookup(chas->pool_config_per_user[type], key);
	if (pool_conf != NULL) {
		ret = g_hash_table_remove(chas->pool_config_per_user[type], key);
	}

	g_rw_lock_writer_unlock(&chas->pool_conf_lock[type]);
	g_string_free(key, TRUE);
	key = NULL;

	return ret;
}




/* user connection limit related */

/** 
 * added by jinxuan hou, 2013/04/09
 * for user connection limitation initialization
 * @@jinxuanhou
 * 初始化用户连接数限制的配置
 * 配置加载到chas->conn_limit
 */
gboolean init_conn_limit(chassis *chas) {

	g_assert(chas);
	g_assert(chas->conn_limit);
	

	// firstly, make sure the config path is not NULL
	// secondly, add element <user@ip, limit> to limits
	// thirdly, close the config file
	// here we just add two fake ones as stub

	return TRUE;
}

/**
 * 打印conn_limit键值
 * 键GString，值guint
 */
void print_conn_limit(gpointer key, gpointer value, gpointer UNUSED_PARAM(user_data))
{
    gint *num = (gint *)value;
    g_debug("%s ---> %d", ((GString *)key)->str, *num);
}
/**
 * 打印conn_limit散列表
 */
void display_conn_limit(GHashTable *table)
{
	g_debug("display_conn_limit\n");
    g_hash_table_foreach(table, print_conn_limit, NULL);
}

/**
 * @author sohu-inc.com
 * 获取某个用户在指定ip段的连接限制数
 * @param chas 基础变量
 * @param username 用户名
 * @param ip_str 用户的ip端信息
 * @return 对应用户的连接限制值
 */
gint* get_conn_limit(chassis *chas, proxy_rw type, const gchar *username,
		const gchar *ip_str) {
	GString *key = NULL;
	gint *ret = NULL;

	g_assert(chas);
	g_assert(username);
	g_assert(ip_str);
	g_assert(chas->conn_limit[type]);

	key = g_string_new(username);
	g_string_append_c(key, ':');
	g_string_append(key, ip_str);

	g_rw_lock_reader_lock(&chas->limit_lock[type]);
	ret = (gint *) g_hash_table_lookup(chas->conn_limit[type], key);
	g_rw_lock_reader_unlock(&chas->limit_lock[type]);

	g_string_free(key, TRUE);

	return ret;
}

/**
 * @author sohu-inc.com
 * 新增用户的连接限制数
 *
 * @param chas 基础变量
 * @param username 用户名
 * @param ip_str 用户ip段信息
 * @param num 设定的连接限制数
 */
void add_conn_limit(chassis *chas, const proxy_rw type, const gchar *username,
		const gchar *ip_str, const gint num) {
	gint *limit = NULL;
	GString *key = NULL;

	g_assert(chas);
	g_assert(username);
	g_assert(ip_str);
	g_assert(chas->conn_limit[type]);
	g_assert_cmpint(num , >= ,-1);

	limit = g_new0(gint, 1);
	*limit = num;

	key = g_string_new(username);
	g_string_append_c(key, ':');
	g_string_append(key, ip_str);

	g_debug("[%s]: add conn limit for %s, %d", G_STRLOC, key->str, *limit);

	g_rw_lock_writer_lock(&chas->limit_lock[type]);
	g_hash_table_insert(chas->conn_limit[type], key, limit);
	g_rw_lock_writer_unlock(&chas->limit_lock[type]);

	return;
}

void del_conn_limit(chassis *chas, const proxy_rw type, const gchar *username,
		const gchar *ip_str) {
	GString *key = NULL;

	g_assert(chas);
	g_assert(username);
	g_assert(ip_str);
	if (chas->conn_limit[type] == NULL) {
		return;
	}

	key = g_string_new(username);
	g_string_append_c(key, ':');
	g_string_append(key, ip_str);

	g_debug("[%s]: del conn limit for %s", G_STRLOC, key->str);

	g_rw_lock_writer_lock(&chas->limit_lock[type]);
	g_hash_table_remove(chas->conn_limit[type], key);
	g_rw_lock_writer_unlock(&chas->limit_lock[type]);

	g_string_free(key, TRUE);
	key = NULL;

	return;
}





/**
 * 打印用户信息键值，包括用户名和密码
 * 键GString，值user_info
 */
void print_user_infos(gpointer key, gpointer value, gpointer UNUSED_PARAM(user_data))
{
    user_info *num = (user_info *)value;
    g_debug("%s ---> %s", ((GString *)key)->str, num->passwd->str);
}
/**
 * 打印用户信息散列表
 */
void display_user_infos(GHashTable *table) {
	g_debug("display_user_infos");
	g_hash_table_foreach(table, print_user_infos, NULL);
}

// user info related
user_info * user_info_new(void) {
	user_info *user = g_new(user_info, 1);
	user->username = NULL;
	user->passwd = NULL;
	user->cli_ips = g_queue_new();
	g_rw_lock_init(&user->ip_queue_lock);
	return user;
}

void user_info_free(user_info *data) {
	ip_range *ip;

	if (data == NULL)
		return;

	if (data->username != NULL)
		g_string_free(data->username, TRUE);
	if (data->passwd != NULL)
		g_string_free(data->passwd, TRUE);

	g_rw_lock_writer_lock(&data->ip_queue_lock);
	if (data->cli_ips) {
		while ((ip = g_queue_pop_head(data->cli_ips)))
			ip_range_free(ip);
		g_queue_free(data->cli_ips);
		data->cli_ips = NULL;
	}
	g_rw_lock_writer_unlock(&data->ip_queue_lock);

	g_rw_lock_clear(&data->ip_queue_lock);

	g_free(data);

	return;
}

//added by jinxuan hou, for hashtable user_info value destroy
void g_user_info_free(gpointer data) {
	user_info_free(data);
}

/**
 * 往user_info加一个IP地址
 */
gboolean add_ip_range_to_user_info(const gchar *ip, user_info *user) {
	gint len = 0;
	gint idx = 0;
	ip_range *ip_tmp = NULL;
	ip_range *new_ip = NULL;

	g_assert(ip);
	g_assert(user);

	g_rw_lock_writer_lock(&user->ip_queue_lock);
	if (!user->cli_ips)
		user->cli_ips = g_queue_new();

	len = user->cli_ips->length;
	for (idx = 0; idx < len; idx++) {
		ip_tmp = g_queue_peek_nth(user->cli_ips, idx);
		if (!ip_tmp)
			break;
		if (0 == g_ascii_strcasecmp(ip, ip_tmp->ip->str)) {
			g_rw_lock_writer_unlock(&user->ip_queue_lock);
			g_message("[%s]: this ip range has been in the users ip list",
					G_STRLOC);
			return TRUE;
		}
	}

	new_ip = create_ip_range_from_str(ip);
	g_queue_push_head(user->cli_ips, new_ip);
	g_rw_lock_writer_unlock(&user->ip_queue_lock);
	return TRUE;
}

/**
 * 从user_info删一个IP地址
 * @return gboolean 是否删除了IP
 */
gboolean del_ip_range_from_user_info(const gchar *ip, user_info *user) {
	gint idx = 0;
	gint len = 0;
	ip_range *ip_tmp = NULL;
	gboolean found = FALSE;

	g_assert(ip);
	g_assert(user);
	g_rw_lock_writer_lock(&user->ip_queue_lock);
	if (user->cli_ips != NULL) {
		len = user->cli_ips->length;
		for (idx = 0; idx < len; idx++) {
			ip_tmp = g_queue_peek_nth(user->cli_ips, idx);
			if (ip_tmp == NULL) {
				continue;
			}
			if (0 == (g_ascii_strcasecmp(ip, ip_tmp->ip->str))) {
				g_debug("[%s]: found the ip range want to delete", G_STRLOC);
				found = TRUE;
				break;
			}
		}
		if (idx == len) {
			g_warning("[%s]: ip range %s not found in ip list of user %s", G_STRLOC,
					ip, user->username->str);
		} else {
			ip_tmp = (ip_range *) g_queue_pop_nth(user->cli_ips, idx);
			ip_range_free(ip_tmp);
			ip_tmp = NULL;
		}
	}
	g_rw_lock_writer_unlock(&user->ip_queue_lock);

	return found;
}

gboolean del_user_info_without_ip_nolock(GHashTable *user_infos, user_info *user, const GString *username, gboolean *del_user_noip) {
	gboolean noip = FALSE;
	if (user_infos == NULL || user == NULL || username == NULL) {
		return FALSE;
	}
	if (user->cli_ips == NULL) {
		noip = TRUE;
	} else if (user->cli_ips->length == 0) {
		noip = TRUE;
	}
	if (noip == TRUE) {
		g_message("[%s]: user without ip left will be deleted: %s", G_STRLOC, username->str);
		*del_user_noip = TRUE;
		return g_hash_table_remove(user_infos, username);
	} else {
		*del_user_noip = FALSE;
		return FALSE;
	}
}

/**< 查询某个ip端是否在用户的允许访问列表中 */
gboolean is_ip_range_allowed_for_user(const gchar *ip,
		user_info *user) {
	if (user == NULL || ip == NULL)
		return FALSE;

	gboolean ret = FALSE;
	ip_range *ip_r = create_ip_range_from_str(ip);
	if (ip_r == NULL)
		return FALSE;

	ip_range *ip_allow = NULL;
	g_rw_lock_reader_lock(&user->ip_queue_lock);
	if (user->cli_ips == NULL) {
		g_rw_lock_reader_unlock(&user->ip_queue_lock);
		ip_range_free(ip_r);
		return FALSE;
	}
	int len = user->cli_ips->length;
	int index = 0;
	for (index = 0; index < len; index++) {
		ip_allow = g_queue_peek_nth(user->cli_ips, index);
		if (ip_allow) {
			if (ip_allow->maxip == ip_r->maxip && ip_allow->minip == ip_r->minip) {
				ret = TRUE;
				break;
			}
		}
	}

	g_rw_lock_reader_unlock(&user->ip_queue_lock);
	ip_range_free(ip_r);
	return ret;
}

ip_range *create_ip_range_from_str(const gchar * ip_str) {
	ip_range *ip_r = NULL;
	guint tmp[2];
	gint result = 0;

	g_assert(ip_str);

	result = inet_pton4(ip_str, tmp);
	if (result == 0) {
		return NULL;
	}

	ip_r = ip_range_new();
	ip_r->minip = tmp[0];
	ip_r->maxip = tmp[1];
	g_string_assign(ip_r->ip, ip_str);

	return ip_r;
}

/**
 * added by jinxuan hou
 * auxiliary function for processing struct we added
 * @@jinxuanhou
 */
// ip range related
ip_range *ip_range_new(void) {
	ip_range *ip_r = g_new(ip_range, 1);
	ip_r->ip = g_string_new(NULL);
	return ip_r;
}

void ip_range_free(ip_range *data) {
	if (data) {
		if (data->ip)
			g_string_free(data->ip, TRUE);
		g_free(data);
	}
}

/**
 * added by jinxuan hou
 * get the upper int and lowwer int of an ip range
 * @param src 欲处理的ip地址段
 * @param dst[in|out] 用于保存ip地址段的对应的范围
 * 		  dst[0]:min value of ip range;
 * 		  dst[1]:max value of ip range
 * @return 0:执行失败,一般是因为ip地址段格式不正确;1:ip地址段处理成功
 * derived from glibc-2.9/resolv/inet_pton.c
 * jinxuanhou
 *
 */
int inet_pton4(const char *src, guint *dst) {
        gint saw_digit, octets, ch;
        gint saw_per;

        guchar tmp1[4], *tp1;
        guchar tmp2[4], *tp2;

        saw_digit = 0;
        saw_per = 0;
        octets = 0;

        *(tp1 = tmp1 + 3) = 0;
        *(tp2 = tmp2 + 3) = 0;

        gboolean has_get_per = 0; //to mark that have we encountered '%'

        while ((ch = *src++) != '\0') {

                if (ch >= '0' && ch <= '9') {
                        if (has_get_per)
                                return 0;
                        guint new = *tp1 * 10 + (ch - '0');

                        if (saw_digit && *tp1 == 0)
                                return (0);
                        if (new > 255)
                                return (0);
                        *tp1 = new;
                        *tp2 = *tp1;
                        if (! saw_digit) {
                                if (++octets > 4)
                                        return (0);
                                saw_digit = 1;
                        }
                } else if (ch == '.' && saw_digit) {
                        if (octets == 4)
                                return (0);
                        tp2--;
                        *--tp1 = 0;
                        saw_digit = 0;
                        saw_per = 0;
                } else if (ch == '.' && has_get_per) {
                        if (octets == 4)
                                return (0);
                        *--tp1 = 0;
                        *--tp2 = 255;
                        saw_digit = 0;
                        saw_per = 0;
                } else if (ch == '%') {
                        if (saw_per)
                                return 0;
                        else {
                                if (++octets > 4)
                                        return (0);
                                saw_per  = 1;
                        }

                        has_get_per = 1;
                        *tp1 = 0;
                        *tp2 = 255;
                        saw_digit = 0;
                        } else
                        return (0);
        }
        //we should take care of 10.% or % such ip ranges
        //if (octets < 4)
        //      return (0);
        /**
         * @note 严格要求为了避免X.% 与 X.%.%.%给DBA的运维造成困扰，
         * 		  我们只支持X.%.%.% 不支持%或X.%或X.%.%
         **/
        if (octets <4 ) {
        	// 如果ip地址段中点分段数<4 则认为是ip端不合法，返回错误
        	return 0;
        }
        if (octets < 4){
                if(!saw_per)
                        return 0;
                gint i = 4 - octets;
                for (; i>0; i--){
                        *--tp1 = 0;
                        *--tp2 = 255;
                }
        }
        memcpy(dst, tmp1, 4);
        memcpy(dst+1, tmp2, 4);
        return (1);
}

/**
 * added by jinxuan hou, 2013/04/10
 * 检查用户IP是否合法，并返回该IP地址段(一个新分配的字符串)
 * 将其修改为最精确的匹配原则
 * @param guint format of an ipv4
 * @param user user_info
 *
 * @@jinxuanhou
 */
gchar *get_ip_range(guint ipInint, user_info *user) {
	guint len = 0;
	guint i = 0;
	ip_range *ip_range_appropriate = NULL;
	ip_range *tmp = NULL;
	gchar *rest = NULL;

	if (!user)
		return NULL;

	g_rw_lock_reader_lock(&user->ip_queue_lock);
	if (!user->cli_ips)
		return NULL;

	len = user->cli_ips->length;
	for (i = 0; i < len; i++) {
		tmp = g_queue_peek_nth(user->cli_ips, i);
		if (!tmp)
			continue;
		if (tmp->minip <= ipInint && ipInint <= tmp->maxip) {
			// 接下来判断，tmp的范围是不是更精确,始终选取最精确的匹配ip段
			if (!ip_range_appropriate || (ip_range_appropriate->minip <= tmp->minip && ip_range_appropriate->maxip >= tmp->maxip)) {
				ip_range_appropriate = tmp;
			}
		}
	}
	if (ip_range_appropriate) {
		rest = g_strndup(S(ip_range_appropriate->ip));
	}
	g_rw_lock_reader_unlock(&user->ip_queue_lock);

	return rest;
}

/**
 * 获取用户允许访问的ip段列表，用';'分开
 * @param user
 * @return
 */
GString *get_all_ips_in_string(user_info *user) {
	if ((user == NULL) || (user->cli_ips == NULL) || (0 == user->cli_ips->length))
		return NULL;

	GString *ips = g_string_new(NULL);
	ip_range *tmp_ipr = NULL;
	g_rw_lock_reader_lock(&user->ip_queue_lock);
	GList *tmp_list = user->cli_ips->head;
	guint index = 0;
	for (index = 0; index < user->cli_ips->length; index++) {
		if (tmp_list != NULL) {
			tmp_ipr = (ip_range *) (tmp_list->data);
			if (0 != ips->len) {
				g_string_append(ips, ";");
			}
			g_string_append(ips, tmp_ipr->ip->str);
			tmp_list = tmp_list->next;
		}
	}
	g_rw_lock_reader_unlock(&user->ip_queue_lock);

	if (0 == ips->len) {
		g_string_free(ips, TRUE);
		ips = NULL;
	}
	return ips;
}

/**
 * added by jinxuan hou
 * get the password for given user
 * @bug 原先对直接返回密码的指针，现在是重新构造一个密码返回。避免对内存中密码进行修改！！
 *
 */
GString *get_passwd_for_user(GString *username, chassis *chas) {
	user_info *user = NULL;

	if (!chas || !chas->user_infos)
		return NULL;

	g_rw_lock_reader_lock(&chas->user_lock);
	user = (user_info *) g_hash_table_lookup(chas->user_infos, username);
	g_rw_lock_reader_unlock(&chas->user_lock);
	if (user) {
		/**
		 * @author sohu-inc.com
		 * 2013-09-06
		 * 修复测试过程中的bug，避免出现密码被修改的情况，复制一份而不是让其直接访问passwd的内存
		 */
		return g_string_new_len(user->passwd->str, user->passwd->len);
	} else {
		return NULL;
	}
}

/**
 * 从用户数据集中查找对应的用户username的配置信息
 * @param chas
 * @param username
 * @return
 */
user_info * get_user_info_for_user(chassis *chas,
		const gchar *username) {
	if (chas == NULL || username == NULL) {
		return NULL;
	}

	user_info * ret = NULL;
	g_rw_lock_reader_lock(&chas->user_lock);
	if (chas->user_infos == NULL) {
		ret = NULL;
	} else {
		GString *key = g_string_new(username);
		ret = g_hash_table_lookup(chas->user_infos, key);
		g_string_free(key, TRUE);
	}
	g_rw_lock_reader_unlock(&chas->user_lock);

	return ret;
}

gboolean check_user_existence(chassis *chas, const GString *username) {
	user_info *ui = NULL;
	g_rw_lock_reader_lock(&(chas->user_lock));
	ui = g_hash_table_lookup(chas->user_infos, username);
	g_rw_lock_reader_unlock(&(chas->user_lock));
	if (ui == NULL) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * 将用户信息添加到用户信息列表
 * @param chas
 * @param user
 * @return
 */
gboolean add_user_info(chassis *chas,
		user_info *user) {
	if ((chas == NULL) || (chas->user_infos == NULL)) {
		return FALSE;
	}

	if ((user == NULL) || (user->username == NULL))
		return FALSE;

	g_rw_lock_writer_lock(&chas->user_lock);
	GString *key = g_string_new(user->username->str);
	if (!chas->user_infos) {
		chas->user_infos = g_hash_table_new_full(g_hash_table_string_hash,
				g_hash_table_string_equal,
				g_hash_table_string_free,
				g_user_info_free);
	}
	g_hash_table_insert(chas->user_infos, key, user);
	g_rw_lock_writer_unlock(&chas->user_lock);

	return TRUE;
}

static void user_infos_name_queue_new_ht_foreach(gpointer key, gpointer UNUSED_PARAM(value),
		gpointer user_data) {
	GString *username = (GString *) key;
//	user_info *user = (user_info *) value; /**<没用到*/
	GQueue *users_queue = (GQueue *) user_data;
	GString *username_new = NULL;
//	g_debug("[%s]: key:%p %s, value: %p, ud: %p ", G_STRLOC, key, username->str, value, user_data);
	username_new = g_string_dup(username);
	g_queue_push_tail(users_queue, username_new);
	return;
}

GQueue *user_infos_name_queue_new(chassis *chas) {
	GQueue *users_queue = NULL;
	GHashTable *user_infos = NULL;
//	GHashTableIter iter;
//	gpointer key, value;

	g_assert(chas);

	users_queue = g_queue_new();
	if (users_queue != NULL) {
		/**
		 * @note
		 * GLib2散列表一些函数如g_hash_table_iter_init()不是线程安全的，所以这里不能用读锁，要用写锁，或者互斥锁
		 */
#if 1
		g_rw_lock_reader_lock(&(chas->user_lock));
		if (chas->user_infos != NULL ) {
			user_infos = chas->user_infos;
			g_hash_table_foreach(user_infos,
					user_infos_name_queue_new_ht_foreach, users_queue);
		}
		g_rw_lock_reader_unlock(&(chas->user_lock));
#else
		g_rw_lock_writer_lock(&(chas->user_lock));
		if (chas->user_infos != NULL) {
			user_infos = chas->user_infos;
			g_hash_table_iter_init(&iter, user_infos);
			while (g_hash_table_iter_next(&iter, &key, &value)) {
				GString *username = NULL;
				user_info *user = NULL;
				username = (GString *) key;
				user = (user_info *) value; /**<没用到*/
				g_queue_push_tail(users_queue, username);
			}
		}
		g_rw_lock_writer_unlock(&(chas->user_lock));
#endif
	}

	return users_queue;
}


/**
 * 获取用户连接数
 *
 * @author sohu-inc.com
 * @param chas 基础变量
 * @param username 用户名
 * @param ip_str ip段
 */
gint * get_login_users(chassis *chas, proxy_rw type, const gchar *username, const gchar *ip_str) {
	gint *ret = NULL;
	GString *key = NULL;

	g_assert(chas);
	g_assert(username);
	g_assert(ip_str);
	g_assert(chas->conn_used[type]);

	key = g_string_new(username);
	g_string_append_c(key, ':');
	g_string_append(key, ip_str);

	g_rw_lock_reader_lock(&chas->login_lock[type]);
	ret = g_hash_table_lookup(chas->conn_used[type], key);
	g_rw_lock_reader_unlock(&chas->login_lock[type]);

	g_string_free(key, TRUE);

	return ret;
}















/*eof*/
