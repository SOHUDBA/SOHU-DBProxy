#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <event.h>

#include "chassis-mainloop.h"

void cb1(int UNUSED_PARAM(event_fd), short UNUSED_PARAM(events), void *UNUSED_PARAM(user_data)) {
	g_debug("call back 1");
	return;
}
void cb2(int UNUSED_PARAM(event_fd), short UNUSED_PARAM(events), void *UNUSED_PARAM(user_data)) {
	g_debug("call back 2");
	return;
}

void t_lib_libevent_add_a_event_twice_nicely(void) {
	struct event_base *eb;
	struct event ev1;
	struct timeval tv;
	struct timeval tv2;

	eb = event_init();

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	tv2.tv_sec = 1;
	tv2.tv_usec = 0;

	event_set(&ev1, -1, EV_TIMEOUT, cb1, NULL);
	event_add(&ev1, &tv);
	printf("111\n");
	event_del(&ev1);

	event_set(&ev1, -1, EV_TIMEOUT, cb2, NULL);
	event_add(&ev1, &tv);
	printf("222\n");

	event_base_dispatch(eb);
	event_del(&ev1);

	event_del(&ev1);
	//event_del(&ev2);

	//event_base_loop(eb, EVLOOP_NONBLOCK);
	//event_base_loopexit(eb, &tv2);

	event_base_free(eb);
	return;
}

void t_lib_libevent_add_a_event_twice_diff_type(void) {
	struct event_base *eb;
	struct event ev1;
	struct timeval tv;

	eb = event_init();

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	event_set(&ev1, 0, EV_READ|EV_TIMEOUT, cb1, NULL);
	//event_add(&ev1, &tv); //不能重复添加
	printf("111\n");

	event_set(&ev1, 0, EV_READ, cb2, NULL);
	event_add(&ev1, &tv);
	printf("222\n");

	//event_base_dispatch(eb);

	event_del(&ev1);
	event_base_free(eb);
	return;
}

void t_lib_libevent_add_a_event_twice_fail(void) {
	struct event_base *eb;
	struct event ev1;
	struct timeval tv;

	eb = event_init();

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	event_set(&ev1, -1, EV_TIMEOUT, cb1, NULL);
	//event_add(&ev1, &tv);  //去除此行注释就会报错，因为event_set会检查否已add过该event
	printf("111\n");

	event_set(&ev1, -1, EV_TIMEOUT, cb2, NULL);
	event_add(&ev1, &tv);
	printf("222\n");

	event_base_dispatch(eb);
	event_del(&ev1);

	event_del(&ev1);
	event_base_free(eb);
	return;
}

void t_lib_libevent_assign_a_event_twice(void) {
	struct event_base *eb;
	struct event ev1;
	struct timeval tv;

	eb = event_init();

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	event_set(&ev1, 0, EV_TIMEOUT, cb1, NULL);
	printf("111\n");

	event_set(&ev1, 0, EV_TIMEOUT, cb2, NULL);
	printf("222\n");

	event_add(&ev1, &tv);
	event_base_dispatch(eb);
	event_del(&ev1);

	event_del(&ev1);
	event_base_free(eb);
	return;
}

#if 0
int main(int argc, char **argv) {
	chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	event_enable_debug_mode();
	g_test_add_func("/lib/libevent/add_a_event_twice_nicely", t_lib_libevent_add_a_event_twice_nicely);
	g_test_add_func("/lib/libevent/add_a_event_twice_diff_type", t_lib_libevent_add_a_event_twice_diff_type);
	g_test_add_func("/lib/libevent/add_a_event_twice_fail", t_lib_libevent_add_a_event_twice_fail);
	g_test_add_func("/lib/libevent/assign_a_event_twice", t_lib_libevent_assign_a_event_twice);

	return g_test_run();

	//t_lib_libevent_add_a_event_twice();
	//return 0;
}
#else
int main(int argc, char **argv) {
	chassis_log *log = NULL;

	g_test_init(&argc, &argv, NULL);

	log = chassis_log_new();
	log->min_lvl = G_LOG_LEVEL_DEBUG; /* display messages while parsing or loading plugins */
	g_log_set_default_handler(chassis_log_func, log);
	log->log_file_fd = STDERR_FILENO;

	event_enable_debug_mode();
	t_lib_libevent_add_a_event_twice_nicely();

	return 0;

}
#endif
