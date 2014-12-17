#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#endif /* WIN32 */

#include <glib.h>

#include "chassis-log.h"
#include "network-backend.h"
#include "network-backend-status-updater.h"

//network_backends_t *backends;


void test_master_elect_with_priority(void) {
	network_backends_t *backends = NULL;
	network_backend_t *b = NULL;

	backends = network_backends_new();
	network_backends_add(backends, "X.X.X.X:3306#2#UP", BACKEND_TYPE_RO);
	network_backends_add(backends, "X.X.X.X:3306#4#UP", BACKEND_TYPE_RO);
	network_backends_add(backends, "X.X.X.X:3306#1#UP", BACKEND_TYPE_RO);
	network_backends_add(backends, "X.X.X.X:3306#0#UP", BACKEND_TYPE_RO);

	b = master_elect_with_priority(backends);
	g_assert_cmpstr(b->addr->name->str, ==, "X.X.X.X:3306");

	b = network_backends_get(backends, 1);
	b->type = BACKEND_TYPE_RW;
	b = master_elect_with_priority(backends);
	g_assert_cmpstr(b->addr->name->str, ==, "X.X.X.X:3306");

	b = network_backends_get(backends, 0);
	b->state = BACKEND_STATE_DOWN;
	b = master_elect_with_priority(backends);
	g_assert_cmpstr(b->addr->name->str, ==, "X.X.X.X:3306");

	b = network_backends_get(backends, 2);
	b->state = BACKEND_STATE_DOWN;
	b = master_elect_with_priority(backends);
	g_assert(b == NULL);

	if (backends != NULL) {
		network_backends_free(backends);
		backends = NULL;
	}

	return;
}


int main(int argc, char **argv) {
	gint ret;
	chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;
	g_log_set_always_fatal(G_LOG_FATAL_MASK);

	//test_init();

	g_test_add_func("/core/backend/test_master_elect_with_priority", test_master_elect_with_priority);
	ret = g_test_run();

	//test_clear();

	return ret;
}

/*eof*/
