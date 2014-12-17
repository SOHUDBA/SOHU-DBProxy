
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <glib.h>

#include "chassis-log.h"
#include "network-connection-state.h"


void test_network_connection_state_get_name(void) {
	const char *s = NULL;
	size_t len = 0;

	s = connection_state_get_name(CONNECTION_STATE_UNKNOWN, &len);
	g_assert_cmpstr(s, == , "CONNECTION_STATE_UNKNOWN");
	g_assert_cmpuint(len, == , sizeof("CONNECTION_STATE_UNKNOWN")-1);

	s = connection_state_get_name(CONNECTION_STATE_ACCEPT, &len);
	g_assert_cmpstr(s, == , "CONNECTION_STATE_ACCEPT");
	g_assert_cmpuint(len, == , sizeof("CONNECTION_STATE_ACCEPT")-1);

	s = connection_state_get_name(CONNECTION_STATE_LAST_ID, &len);
	g_assert(s == NULL);

	s = connection_state_get_name(CONNECTION_STATE_LAST_ID+1, &len);
	g_assert(s == NULL);

	return;
}

void test_network_connection_state_update(void) {
	connection_state_set *cs_set = NULL;
	connection_state_statistic *css = NULL;

	cs_set = connection_state_set_new();
	g_assert(cs_set);
	g_assert(cs_set->current != NULL);
	g_assert(cs_set->previous != NULL);
	g_assert(cs_set->statistics != NULL);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_NEW_CREATED);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	//g_assert_cmpuint(cs_set->current->begin_timestamp, ==, ...);
	cs_set->current->begin_timestamp = 500000;

	connection_state_set_update(cs_set, CONNECTION_STATE_ACCEPT, CONNECTION_STATE_TYPE_CPU, 1000000);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_ACCEPT);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 1000000);
	g_assert_cmpuint(cs_set->previous->state_id, ==, CONNECTION_STATE_NEW_CREATED);
	g_assert_cmpuint(cs_set->previous->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->previous->begin_timestamp, ==, 500000);
	css = &(cs_set->statistics->statistics[CONNECTION_STATE_NEW_CREATED]);
	g_assert(css != NULL);
	g_assert_cmpuint(css->state_id, ==, CONNECTION_STATE_NEW_CREATED);
	g_assert_cmpuint(css->cpu_count, ==, 1);
	g_assert_cmpuint(css->cpu_time, ==, 500000);
	g_assert_cmpuint(css->iowait_count, ==, 0);
	g_assert_cmpuint(css->iowait_time, ==, 0);

	connection_state_set_update(cs_set, CONNECTION_STATE_ACCEPT, CONNECTION_STATE_TYPE_CPU, 2000000);
	g_assert(cs_set->current != NULL);
	g_assert(cs_set->previous != NULL);
	g_assert(cs_set->statistics != NULL);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_ACCEPT);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 1000000);

	connection_state_set_update(cs_set, CONNECTION_STATE_INIT, CONNECTION_STATE_TYPE_CPU, 3000000);
	g_assert(cs_set->current != NULL);
	g_assert(cs_set->previous != NULL);
	g_assert(cs_set->statistics != NULL);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 3000000);
	g_assert_cmpuint(cs_set->previous->state_id, ==, CONNECTION_STATE_ACCEPT);
	g_assert_cmpuint(cs_set->previous->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->previous->begin_timestamp, ==, 1000000);
	css = &(cs_set->statistics->statistics[CONNECTION_STATE_ACCEPT]);
	g_assert(css != NULL);
	g_assert_cmpuint(css->state_id, ==, CONNECTION_STATE_ACCEPT);
	g_assert_cmpuint(css->cpu_count, ==, 1);
	g_assert_cmpuint(css->cpu_time, ==, 2000000);
	g_assert_cmpuint(css->iowait_count, ==, 0);
	g_assert_cmpuint(css->iowait_time, ==, 0);

	connection_state_set_update(cs_set, CONNECTION_STATE_INIT, CONNECTION_STATE_TYPE_IOWAIT, 3500000);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_IOWAIT);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 3500000);
	g_assert_cmpuint(cs_set->previous->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->previous->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->previous->begin_timestamp, ==, 3000000);
	css = &(cs_set->statistics->statistics[CONNECTION_STATE_INIT]);
	g_assert(css != NULL);
	g_assert_cmpuint(css->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(css->cpu_count, ==, 1);
	g_assert_cmpuint(css->cpu_time, ==, 500000);
	g_assert_cmpuint(css->iowait_count, ==, 0);
	g_assert_cmpuint(css->iowait_time, ==, 0);

	connection_state_set_update(cs_set, CONNECTION_STATE_INIT, CONNECTION_STATE_TYPE_CPU, 3700000);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 3700000);
	g_assert_cmpuint(cs_set->previous->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->previous->state_type, ==, CONNECTION_STATE_TYPE_IOWAIT);
	g_assert_cmpuint(cs_set->previous->begin_timestamp, ==, 3500000);
	css = &(cs_set->statistics->statistics[CONNECTION_STATE_INIT]);
	g_assert(css != NULL);
	g_assert_cmpuint(css->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(css->cpu_count, ==, 1);
	g_assert_cmpuint(css->cpu_time, ==, 500000);
	g_assert_cmpuint(css->iowait_count, ==, 1);
	g_assert_cmpuint(css->iowait_time, ==, 200000);

	connection_state_set_update(cs_set, CONNECTION_STATE_INIT, CONNECTION_STATE_TYPE_IOWAIT, 4000000);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_IOWAIT);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 4000000);
	g_assert_cmpuint(cs_set->previous->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->previous->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->previous->begin_timestamp, ==, 3700000);
	css = &(cs_set->statistics->statistics[CONNECTION_STATE_INIT]);
	g_assert(css != NULL);
	g_assert_cmpuint(css->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(css->cpu_count, ==, 2);
	g_assert_cmpuint(css->cpu_time, ==, 800000);
	g_assert_cmpuint(css->iowait_count, ==, 1);
	g_assert_cmpuint(css->iowait_time, ==, 200000);

	connection_state_set_update(cs_set, CONNECTION_STATE_SEND_HANDSHAKE, CONNECTION_STATE_TYPE_CPU, 4100000);
	g_assert_cmpuint(cs_set->current->state_id, ==, CONNECTION_STATE_SEND_HANDSHAKE);
	g_assert_cmpuint(cs_set->current->state_type, ==, CONNECTION_STATE_TYPE_CPU);
	g_assert_cmpuint(cs_set->current->begin_timestamp, ==, 4100000);
	g_assert_cmpuint(cs_set->previous->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(cs_set->previous->state_type, ==, CONNECTION_STATE_TYPE_IOWAIT);
	g_assert_cmpuint(cs_set->previous->begin_timestamp, ==, 4000000);
	css = &(cs_set->statistics->statistics[CONNECTION_STATE_INIT]);
	g_assert(css != NULL);
	g_assert_cmpuint(css->state_id, ==, CONNECTION_STATE_INIT);
	g_assert_cmpuint(css->cpu_count, ==, 2);
	g_assert_cmpuint(css->cpu_time, ==, 800000);
	g_assert_cmpuint(css->iowait_count, ==, 2);
	g_assert_cmpuint(css->iowait_time, ==, 300000);

	connection_state_set_dump(cs_set);

	connection_state_set_free(cs_set);
	cs_set = NULL;
	return;
}

void test_network_connection_state_thread_update(void) {
	connection_state_set *cs_set = NULL;
	thread_connection_state_set *tcs_set = NULL;
	//connection_state_statistic *css = NULL;

	cs_set = connection_state_set_new();
	tcs_set = thread_connection_state_set_new();
	g_assert(cs_set);
	g_assert(tcs_set);
	g_assert(tcs_set->statistics != NULL);

	cs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count = 3;
	cs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time = 100;
	thread_connection_state_set_update(tcs_set, cs_set->statistics);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 3);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 100);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 3);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 100);
	thread_connection_state_set_update(tcs_set, cs_set->statistics);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 6);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 200);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 6);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 200);

	connection_state_set_dump(cs_set);
	thread_connection_state_set_dump(tcs_set);

	connection_state_set_free(cs_set);
	thread_connection_state_set_free(tcs_set);
	return;
}

void test_network_connection_state_global_update(void) {
	thread_connection_state_set *tcs_set = NULL;
	global_connection_state_set *gcs_set = NULL;

	tcs_set = thread_connection_state_set_new();
	gcs_set = global_connection_state_set_new();
	g_assert(tcs_set);
	g_assert(gcs_set);
	g_assert(tcs_set->statistics != NULL);

	tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count = 3;
	tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time = 100;
	tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count = 3;
	tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time = 100;
	global_connection_state_set_update(gcs_set, tcs_set);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 3);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 100);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 0);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 0);
	g_assert_cmpuint(gcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 3);
	g_assert_cmpuint(gcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 100);

	tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count = 3;
	tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time = 100;
	tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count = 3;
	tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time = 100;
	global_connection_state_set_update(gcs_set, tcs_set);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 3);
	g_assert_cmpuint(tcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 100);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 0);
	g_assert_cmpuint(tcs_set->incremental_statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 0);
	g_assert_cmpuint(gcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_count, ==, 6);
	g_assert_cmpuint(gcs_set->statistics->statistics[CONNECTION_STATE_ACCEPT].cpu_time, ==, 200);

	thread_connection_state_set_dump(tcs_set);
	thread_connection_state_set_free(tcs_set);

	global_connection_state_set_dump(gcs_set);
	global_connection_state_set_free(gcs_set);

	return;
}

int main(int argc, char **argv) {
	gint r = 0;
	chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	g_test_add_func("/core/network_connection_state_get_name", test_network_connection_state_get_name);
	g_test_add_func("/core/network_connection_state_update", test_network_connection_state_update);
	g_test_add_func("/core/network_connection_state_thread_update", test_network_connection_state_thread_update);
	g_test_add_func("/core/network_connection_state_global_update", test_network_connection_state_global_update);

	r = g_test_run();

	chassis_log_free(log);

	return r;
}

/*eof*/
