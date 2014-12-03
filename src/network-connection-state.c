
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "chassis-timings.h"
#include "network-connection-state.h"

#define ARRAY_LENGTH(x) (sizeof(x)/sizeof(x[0]))


/* 状态名字 */

#define SS(x) { #x, sizeof(#x) - 1 }
static struct {
	const char *name;
	size_t name_len;
} CONNECTION_STATE_NAMES[] = {
	SS(CONNECTION_STATE_UNKNOWN),
	SS(CONNECTION_STATE_NEW_CREATED),
	SS(CONNECTION_STATE_ACCEPT),
	SS(CONNECTION_STATE_INIT),
	SS(CONNECTION_STATE_SEND_HANDSHAKE),
	SS(CONNECTION_STATE_READ_AUTH),
	SS(CONNECTION_STATE_SEND_AUTH_RESULT),
	SS(CONNECTION_STATE_READ_QUERY),
	SS(CONNECTION_STATE_PROCESS_READ_QUERY),
	SS(CONNECTION_STATE_GET_SERVER_LIST),
	SS(CONNECTION_STATE_GET_SERVER_CONNECTION_LIST),
	SS(CONNECTION_STATE_SEND_QUERY),
	SS(CONNECTION_STATE_READ_QUERY_RESULT),
	SS(CONNECTION_STATE_SEND_QUERY_RESULT),
	SS(CONNECTION_STATE_CLOSE),
	SS(CONNECTION_STATE_SEND_ERROR),
	SS(CONNECTION_STATE_SEND_ERROR_TO_CLIENT),
	{ NULL, 0 }
};
#undef SS

const gchar *connection_state_get_name(connection_state_id state_id, size_t *name_len) {
	if (state_id >= CONNECTION_STATE_LAST_ID) {
		return NULL;
	}

	if ( ARRAY_LENGTH(CONNECTION_STATE_NAMES) != CONNECTION_STATE_LAST_ID + 1 ) {
		g_error("connection_state_get_name() is out of sync [%"G_GSIZE_FORMAT" != %d]"
				, ARRAY_LENGTH(CONNECTION_STATE_NAMES)
				, CONNECTION_STATE_LAST_ID + 1);
	}

	if (name_len != NULL) {
		*name_len = CONNECTION_STATE_NAMES[state_id].name_len;
	}

	return CONNECTION_STATE_NAMES[state_id].name;
}

int connection_state_get_last_id(void) {
	/* the last one is not a state */
	return ARRAY_LENGTH(CONNECTION_STATE_NAMES) - 1;
}


/* 构造和销毁 connection_state */

static void connection_state_free(connection_state *cs) {
	if (cs != NULL) {
		cs->state_id = 0;
		cs->state_type = 0;
		cs->begin_timestamp = 0;
		g_free(cs);
	}
	return;
}

static connection_state *connection_state_new(void) {
	connection_state *cs = NULL;
	cs = g_new0(connection_state, 1);
	return cs;
}


/* 构造和销毁 connection_state_statistic */

static void connection_state_statistic_init(connection_state_statistic *css, connection_state_id state_id) {
	if (css != NULL) {
		css->cpu_count = 0;
		css->cpu_time = 0;
		css->iowait_count = 0;
		css->iowait_time = 0;
		css->state_id = state_id;
	}
	return;
}


/* 构造和销毁 connection_state_statistics */

void connection_state_statistics_clear(connection_state_statistics *stats) {
	gsize i = 0;
	if (stats != NULL) {
		for (i = 0; i < CONNECTION_STATE_LAST_ID; i++) {
			connection_state_statistic_init(&(stats->statistics[i]), i);
		}
	}
	return;
}

void connection_state_statistics_free(connection_state_statistics *stats) {
	connection_state_statistics_clear(stats);
	if (stats != NULL) {
		g_free(stats);
	}
	return;
}

connection_state_statistics *connection_state_statistics_new(void) {
	connection_state_statistics *stats = NULL;
	stats = g_new0(connection_state_statistics, 1);
	if (stats != NULL) {
		connection_state_statistics_clear(stats);
	}
	return stats;
}

static void connection_state_statistics_add(
	const connection_state_statistics *src, connection_state_statistics *dst) {
	gsize i = 0;
	const connection_state_statistic *s = NULL;
	connection_state_statistic *d = NULL;
	for (i = 0; i < CONNECTION_STATE_LAST_ID; i++) {
		s = &(src->statistics[i]);
		d = &(dst->statistics[i]);
		d->cpu_count += s->cpu_count;
		d->cpu_time += s->cpu_time;
		d->iowait_count += s->iowait_count;
		d->iowait_time += s->iowait_time;
	}
	return;
}


/* 构造和销毁 connection_state_set */

void connection_state_set_free(connection_state_set *cs_set) {
	if (cs_set != NULL) {
		if (cs_set->current != NULL) {
			connection_state_free(cs_set->current);
			cs_set->current = NULL;
		}
		if (cs_set->previous != NULL) {
			connection_state_free(cs_set->previous);
			cs_set->previous = NULL;
		}
		if (cs_set->statistics != NULL) {
			connection_state_statistics_free(cs_set->statistics);
			cs_set->statistics = NULL;
		}
		g_free(cs_set);
	}
	return;
}

connection_state_set *connection_state_set_new(void) {
	connection_state_set *cs_set = NULL;
	cs_set = g_new0(connection_state_set, 1);
	if (cs_set != NULL) {
		cs_set->current = connection_state_new();
		if (cs_set->current != NULL) {
			cs_set->current->state_id = CONNECTION_STATE_NEW_CREATED;
			cs_set->current->state_type = CONNECTION_STATE_TYPE_CPU;
			cs_set->current->begin_timestamp = chassis_get_rel_microseconds();
		}
		cs_set->previous = connection_state_new();
		cs_set->statistics = connection_state_statistics_new();
		if (cs_set->current == NULL || cs_set->previous == NULL || cs_set->statistics == NULL) {
			connection_state_set_free(cs_set);
			cs_set = NULL;
		}
	}
	return cs_set;
}


/* 构造和销毁 thread_connection_state_set */

void thread_connection_state_set_free(thread_connection_state_set *tcs_set) {
	if (tcs_set != NULL) {
		if (tcs_set->statistics != NULL) {
			connection_state_statistics_free(tcs_set->statistics);
			tcs_set->statistics = NULL;
		}
		if (tcs_set->incremental_statistics != NULL) {
			g_mutex_lock(&(tcs_set->incremental_statistics_mutex));
			connection_state_statistics_free(tcs_set->incremental_statistics);
			g_mutex_unlock(&(tcs_set->incremental_statistics_mutex));
		}
		g_mutex_clear(&(tcs_set->incremental_statistics_mutex));
		g_free(tcs_set);
	}
	return;
}

thread_connection_state_set *thread_connection_state_set_new(void) {
	thread_connection_state_set *tcs_set = NULL;
	tcs_set = g_new0(thread_connection_state_set, 1);
	if (tcs_set != NULL) {
		tcs_set->statistics = connection_state_statistics_new();

		g_mutex_init(&(tcs_set->incremental_statistics_mutex));
		g_mutex_lock(&(tcs_set->incremental_statistics_mutex));
		tcs_set->incremental_statistics = connection_state_statistics_new();
		g_mutex_unlock(&(tcs_set->incremental_statistics_mutex));

		if (tcs_set->statistics == NULL || tcs_set->incremental_statistics == NULL) {
			thread_connection_state_set_free(tcs_set);
			tcs_set = NULL;
		}
	}
	return tcs_set;
}


/* 构造和销毁 global_connection_state_set */

void global_connection_state_set_free(global_connection_state_set *gcs_set) {
	if (gcs_set != NULL) {
		if (gcs_set->statistics != NULL) {
			connection_state_statistics_free(gcs_set->statistics);
			gcs_set->statistics = NULL;
		}
		g_free(gcs_set);
	}
	return;
}

global_connection_state_set *global_connection_state_set_new(void) {
	global_connection_state_set *gcs_set = NULL;
	gcs_set = g_new0(global_connection_state_set, 1);
	if (gcs_set != NULL) {
		gcs_set->statistics = connection_state_statistics_new();
		if (gcs_set->statistics == NULL) {
			global_connection_state_set_free(gcs_set);
			gcs_set = NULL;
		}
	}
	return gcs_set;
}


/* 连接的统计信息 */

/**
 * 更新统计信息集
 * @param[INOUT] connection_state_set *cs_set 统计信息集
 * @param[IN] connection_state_id new_state_id 新状态标识
 * @param[IN] connection_state_type new_state_type 新状态类型
 * @param[IN] guint64 now 当前时间。0表示重新计算
 */
void connection_state_set_update(connection_state_set *cs_set,
	connection_state_id new_state_id, connection_state_type new_state_type,
	guint64 now) {
	connection_state *current = NULL;
	connection_state *previous = NULL;
	connection_state_statistics *statistics = NULL;
	guint64 timediff = 0;
	connection_state_statistic *css = NULL;

	g_assert(cs_set);
	g_assert(cs_set->current);
	g_assert(cs_set->previous);
	g_assert(cs_set->statistics);

	current = cs_set->current;
	previous = cs_set->previous;
	statistics = cs_set->statistics;
	if (new_state_id >= CONNECTION_STATE_LAST_ID) {
		new_state_id = CONNECTION_STATE_UNKNOWN; /*0*/
	}
	if (new_state_type > CONNECTION_STATE_TYPE_IOWAIT) {
		new_state_type = CONNECTION_STATE_TYPE_CPU; /*0*/
	}

	/* 状态相同，什么都不做 */
	if (current->state_id == new_state_id && current->state_type == new_state_type) {
		return;
	}

	if (now == 0) {
		now = chassis_get_rel_microseconds();
	}
	if (now >= current->begin_timestamp) {
		timediff = now - current->begin_timestamp;
	} else {
		timediff = 0;
	}

	css = &(statistics->statistics[current->state_id]);
	if (current->state_type == CONNECTION_STATE_TYPE_CPU) {
		css->cpu_time += timediff;
		css->cpu_count++;
	} else {
		css->iowait_time += timediff;
		css->iowait_count++;
	}

	previous->state_id = current->state_id;
	previous->state_type = current->state_type;
	previous->begin_timestamp = current->begin_timestamp;

	current->state_id = new_state_id;
	current->state_type = new_state_type;
	current->begin_timestamp = now;

	return;
}


/* 更新线程级的连接统计信息 */
void thread_connection_state_set_update(thread_connection_state_set *tcs_set,
	const connection_state_statistics *stats) {
	g_assert(tcs_set);
	g_assert(stats);
	connection_state_statistics_add(stats, tcs_set->statistics);
	g_mutex_lock(&(tcs_set->incremental_statistics_mutex));
	connection_state_statistics_add(stats, tcs_set->incremental_statistics);
	g_mutex_unlock(&(tcs_set->incremental_statistics_mutex));
	return;
}


/* 更新全局的连接统计信息 */
void global_connection_state_set_update(global_connection_state_set *gcs_set,
		thread_connection_state_set *tcs_set) {
	g_assert(gcs_set);
	g_assert(tcs_set);
	g_mutex_lock(&(tcs_set->incremental_statistics_mutex));
	connection_state_statistics_add(tcs_set->incremental_statistics, gcs_set->statistics);
	connection_state_statistics_clear(tcs_set->incremental_statistics);
	g_mutex_unlock(&(tcs_set->incremental_statistics_mutex));
	return;
}



/* 输出统计信息 */

static void connection_state_dump(const connection_state *cs) {
	size_t len = 0;
	time_t nowtime;
	struct tm *nowtm = NULL;
	char tmbuf[64] = {0};

	nowtime = cs->begin_timestamp/1000000;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%H:%M:%S", nowtm);

	g_debug("state: %s %s %s.%"G_GUINT64_FORMAT""
			, connection_state_get_name(cs->state_id, &len)
			, (cs->state_type == CONNECTION_STATE_TYPE_CPU)?"CPU":"IOWAIT"
			, tmbuf, cs->begin_timestamp-nowtime*1000000);
}

static void connection_state_statistic_dump(const connection_state_statistic *css) {
	size_t len = 0;
	if (css->cpu_count != 0 || css->cpu_time != 0 || css->iowait_count != 0 || css->iowait_time != 0) {
		g_debug("%s %"G_GUINT64_FORMAT" %"G_GUINT64_FORMAT" %"G_GUINT64_FORMAT" %"G_GUINT64_FORMAT""
				, connection_state_get_name(css->state_id, &len)
				, css->cpu_count, css->cpu_time
				, css->iowait_count, css->iowait_time);
	}
}

static void connection_state_statistics_dump(const connection_state_statistics *stats) {
	gsize i = 0;
	for (i = 0; i < CONNECTION_STATE_LAST_ID; i++) {
		connection_state_statistic_dump(&(stats->statistics[i]));
	}
}

void connection_state_set_dump(connection_state_set *cs_set) {
	g_debug("curr:");
	connection_state_dump(cs_set->current);
	g_debug("prev:");
	connection_state_dump(cs_set->previous);
	g_debug("cs:");
	connection_state_statistics_dump(cs_set->statistics);
}

void thread_connection_state_set_dump(thread_connection_state_set *tcs_set) {
	g_debug("tcs:");
	connection_state_statistics_dump(tcs_set->statistics);
	g_mutex_lock(&(tcs_set->incremental_statistics_mutex));
	g_debug("tcs.incr:");
	connection_state_statistics_dump(tcs_set->incremental_statistics);
	g_mutex_unlock(&(tcs_set->incremental_statistics_mutex));
}

void global_connection_state_set_dump(global_connection_state_set *gcs_set) {
	g_debug("gcs:");
	connection_state_statistics_dump(gcs_set->statistics);
}


/*eof*/
