/**
 * added by jinxuan hou ,for create ip range test from ip string
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


void test_get_ip_range_for_given_ip_found() {
	user_info *user = user_info_new();
        user->username = g_string_new("test");
        user->passwd = g_string_new("test");

        add_ip_range_to_user_info("X.X.%.%",user);
	
	add_ip_range_to_user_info("X.X.X.%",user);
	
	struct ip_range *ip_r = create_ip_range_from_str("X.X.X.X");

	char *ip = get_ip_range(ip_r->minip, user);
	
	ip_range_free(ip_r);

	g_assert(ip);
	g_assert_cmpstr(ip, ==, "X.X.X.%");

	ip_r = create_ip_range_from_str("X.X.X.X");

	ip = get_ip_range(ip_r->minip, user);
	
	ip_range_free(ip_r);

	g_assert(ip);
	g_assert_cmpstr(ip, ==, "X.X.%.%");

	user_info_free(user);
}

void test_get_ip_range_for_given_ip_not_found() {
        user_info *user = user_info_new();
        user->username = g_string_new("test");
        user->passwd = g_string_new("test");

        add_ip_range_to_user_info("X.X.%.%",user);

      //  add_ip_range_to_user_info("X.X.X.%",user);

        struct ip_range *ip_r = create_ip_range_from_str("X.X.X.X");

        char *ip = get_ip_range(ip_r->minip, user);

        g_assert(ip == NULL);
       // g_assert_cmpstr(ip, "X.X.X.%");
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	
	g_test_add_func("/core/test_get_ip_range_for_given_ip_not_found",test_get_ip_range_for_given_ip_not_found);
	g_test_add_func("/core/test_get_ip_range_for_given_ip_found",test_get_ip_range_for_given_ip_found);

	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */
