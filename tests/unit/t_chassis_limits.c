#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef _WIN32
#include <stdio.h> /* for _getmaxstdio() */
#endif
#include <errno.h>
#include <stdlib.h>

#include "chassis-limits.h"

void t_chassis_limits_rlimit_max_core_size(void) {
	struct rlimit max_coresize_rlimit;

	g_assert(getrlimit(RLIMIT_CORE, &max_coresize_rlimit) != -1);

	max_coresize_rlimit.rlim_cur = 10000;
	max_coresize_rlimit.rlim_max = 20000;
	g_assert(setrlimit(RLIMIT_CORE, &max_coresize_rlimit) != -1);
	g_assert(getrlimit(RLIMIT_CORE, &max_coresize_rlimit) != -1);
	g_assert_cmpuint(max_coresize_rlimit.rlim_cur, ==, 10000);
	g_assert_cmpuint(max_coresize_rlimit.rlim_max, ==, 20000);

	max_coresize_rlimit.rlim_cur = 15000;
	max_coresize_rlimit.rlim_max = RLIM_INFINITY;
	g_assert(setrlimit(RLIMIT_CORE, &max_coresize_rlimit) != -1);
	g_assert(getrlimit(RLIMIT_CORE, &max_coresize_rlimit) != -1);
	g_assert_cmpuint(max_coresize_rlimit.rlim_cur, ==, 15000);
	g_assert_cmpuint(max_coresize_rlimit.rlim_max, ==, RLIM_INFINITY);

	return;
}

void t_chassis_limits_rlimit_string_to_int(void) {
	int n = 0;

	g_assert_cmpint(rlimit_string_to_int("1", &n), ==, 0);
	g_assert_cmpint(n, ==, 1);

	g_assert_cmpint(rlimit_string_to_int("0", &n), ==, 0);
	g_assert_cmpint(n, ==, 0);

	g_assert_cmpint(rlimit_string_to_int("-1", &n), ==, 0);
	g_assert_cmpint(n, ==, -1);

	g_assert_cmpint(rlimit_string_to_int("unlimited", &n), ==, 0);
	g_assert_cmpint(n, ==, -1);

	g_assert_cmpint(rlimit_string_to_int("012", &n), ==, 0);
	g_assert_cmpint(n, ==, 12);

	n = 100;
	g_assert_cmpint(rlimit_string_to_int("-012", &n), ==, -2);
	g_assert_cmpint(n, ==, 100);

	n = 101;
	g_assert_cmpint(rlimit_string_to_int("abc", &n), ==, -1);
	g_assert_cmpint(n, ==, 101);

	return;
}

void t_chassis_limits_coresizelimit_setget(void) {
	g_assert_cmpint(chassis_coresizelimit_set(0), ==, 0);
	g_assert_cmpint(chassis_coresizelimit_get(), ==, 0);

	g_assert_cmpint(chassis_coresizelimit_set(12345), ==, 0);
	g_assert_cmpint(chassis_coresizelimit_get(), ==, 12345);

	g_assert_cmpint(chassis_coresizelimit_set(-1), ==, 0);
	g_assert_cmpint(chassis_coresizelimit_get(), ==, RLIM_INFINITY);

	return;
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/chassis_limits_rlimit_max_core_size", t_chassis_limits_rlimit_max_core_size);
	g_test_add_func("/core/chassis_limits_rlimit_string_to_int", t_chassis_limits_rlimit_string_to_int);
	g_test_add_func("/core/chassis_limits_coresizelimit_setget", t_chassis_limits_coresizelimit_setget);

	return g_test_run();
}

/*eof*/
