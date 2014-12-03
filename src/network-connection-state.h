
#ifndef __NETWORK_CONNECTION_STATE_H_
#define __NETWORK_CONNECTION_STATE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "network-exports.h"

/* 连接状态标识 */
typedef enum {
	CONNECTION_STATE_UNKNOWN = 0,

	CONNECTION_STATE_NEW_CREATED,

	CONNECTION_STATE_ACCEPT,
	CONNECTION_STATE_INIT,
	CONNECTION_STATE_SEND_HANDSHAKE,
	CONNECTION_STATE_READ_AUTH,
	CONNECTION_STATE_SEND_AUTH_RESULT,
	CONNECTION_STATE_READ_QUERY,
	CONNECTION_STATE_PROCESS_READ_QUERY,
	CONNECTION_STATE_GET_SERVER_LIST,
	CONNECTION_STATE_GET_SERVER_CONNECTION_LIST,
	CONNECTION_STATE_SEND_QUERY,
	CONNECTION_STATE_READ_QUERY_RESULT,
	CONNECTION_STATE_SEND_QUERY_RESULT,
	CONNECTION_STATE_CLOSE,
	CONNECTION_STATE_SEND_ERROR,
	CONNECTION_STATE_SEND_ERROR_TO_CLIENT,

	CONNECTION_STATE_LAST_ID
} connection_state_id;

/* 连接状态类型 */
typedef enum {
	CONNECTION_STATE_TYPE_CPU = 0,
	CONNECTION_STATE_TYPE_IOWAIT = 1,
} connection_state_type;

/* 当前连接状态 */
typedef struct connection_state {
	connection_state_id state_id;
	connection_state_type state_type;
	guint64 begin_timestamp;
} connection_state;

/* 连接级的状态统计信息 */
typedef struct connection_state_statistic {
	connection_state_id state_id;
	guint64 cpu_time;
	guint64 cpu_count;
	guint64 iowait_time;
	guint64 iowait_count;
} connection_state_statistic;

/* 连接级的状态统计信息数组 */
typedef struct connection_state_statistics {
	connection_state_statistic statistics[CONNECTION_STATE_LAST_ID];
} connection_state_statistics;

/* 连接的状态和统计信息 */
typedef struct connection_state_set {
	/** 当前状态 */
	connection_state *current;
	/** 前次状态 */
	connection_state *previous;
	/** 各状态的统计信息 */
	connection_state_statistics *statistics;
} connection_state_set;

/* 线程级的连接统计信息 */
typedef struct thread_connection_state_set {
	connection_state_statistics *statistics;
	connection_state_statistics *incremental_statistics;
	GMutex incremental_statistics_mutex;
} thread_connection_state_set;

/* 全局的连接统计信息 */
typedef struct global_connection_state_set {
	connection_state_statistics *statistics;
} global_connection_state_set;

NETWORK_API const gchar *connection_state_get_name(connection_state_id state_id, size_t *name_len);
NETWORK_API int connection_state_get_last_id(void);

NETWORK_API void connection_state_statistics_clear(connection_state_statistics *stats);
NETWORK_API void connection_state_statistics_free(connection_state_statistics *stats);
NETWORK_API connection_state_statistics *connection_state_statistics_new(void);

NETWORK_API void connection_state_set_free(connection_state_set *cs_set);
NETWORK_API connection_state_set *connection_state_set_new(void);

NETWORK_API void thread_connection_state_set_free(thread_connection_state_set *tcs_set);
NETWORK_API thread_connection_state_set *thread_connection_state_set_new(void);

NETWORK_API void global_connection_state_set_free(global_connection_state_set *gcs_set);
NETWORK_API global_connection_state_set *global_connection_state_set_new(void);


NETWORK_API void connection_state_set_update(connection_state_set *cs_set,
	connection_state_id new_state_id, connection_state_type new_state_type,
	guint64 now);
#define connection_state_update(con, id, type) connection_state_set_update(con->connection_state, id, type, 0)
NETWORK_API void thread_connection_state_set_update(thread_connection_state_set *tcs_set,
	const connection_state_statistics *stats);
NETWORK_API void global_connection_state_set_update(global_connection_state_set *gcs_set,
		thread_connection_state_set *tcs_set);

NETWORK_API void connection_state_set_dump(connection_state_set *cs_set);
NETWORK_API void thread_connection_state_set_dump(thread_connection_state_set *tcs_set);
NETWORK_API void global_connection_state_set_dump(global_connection_state_set *gcs_set);


#endif /*__NETWORK_CONNECTION_STATE_H_*/

/*eof*/

