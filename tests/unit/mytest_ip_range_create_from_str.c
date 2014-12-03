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

void test_ip_range_create_with_per_5seg() {
	struct ip_range *ip_r = create_ip_range_from_str("X.X.X.%.%");
	g_assert(ip_r == NULL);

	ip_r = create_ip_range_from_str("X.X.%.%.%");
	g_assert(ip_r == NULL);

	ip_r = create_ip_range_from_str("X.%.%.%.%.%");
	g_assert(ip_r == NULL);

	ip_r = create_ip_range_from_str("%.%.%.%.%");
	g_assert(ip_r == NULL);
}

void test_ip_range_create_with_per1_4seg() {
	struct ip_range *ip_r = create_ip_range_from_str("X.X.X.%");
	g_assert(ip_r);
	g_assert_cmpint(ip_r->minip, ==, 168442624);
	g_assert_cmpint(ip_r->maxip, ==, 168442879);
	g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
	g_assert_cmpstr(ip_r->ip->str, ==, "X.X.X.%");
}

void test_ip_range_create_with_per2_4seg() {
        struct ip_range *ip_r = create_ip_range_from_str("X.X.%.%");
        g_assert(ip_r);
        g_assert_cmpint(ip_r->minip, ==, 168427520);
        g_assert_cmpint(ip_r->maxip, ==, 168493055);
        g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        g_assert_cmpstr(ip_r->ip->str, ==, "X.X.%.%");
}

void test_ip_range_create_with_per3_4seg() {
        struct ip_range *ip_r = create_ip_range_from_str("X.%.%.%");
        g_assert(ip_r);
        g_assert_cmpint(ip_r->minip, ==, 3221225472);
        g_assert_cmpint(ip_r->maxip, ==, 3238002687);
        g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        g_assert_cmpstr(ip_r->ip->str, ==, "X.%.%.%");
}

void test_ip_range_create_with_per4_4seg() {
        struct ip_range *ip_r = create_ip_range_from_str("%.%.%.%");
        g_assert(ip_r);
        g_assert_cmpint(ip_r->minip, ==, 0);
        g_assert_cmpint(ip_r->maxip, ==, 4294967295);
        g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        g_assert_cmpstr(ip_r->ip->str, ==, "%.%.%.%");
}

void test_ip_range_create_with_per1_3seg() {
        struct ip_range *ip_r = create_ip_range_from_str("X.X.%");
        g_assert(ip_r == NULL);
        //g_assert_cmpint(ip_r->minip, ==, 168493056);
        //g_assert_cmpint(ip_r->maxip, ==, 168558591);
        //g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        //g_assert_cmpstr(ip_r->ip->str, ==, "X.X.%");
}

void test_ip_range_create_with_per2_3seg() {
        struct ip_range *ip_r = create_ip_range_from_str("155.%.%");
        g_assert(ip_r == NULL);
        //g_assert_cmpint(ip_r->minip, ==, 2600468480);
        //g_assert_cmpint(ip_r->maxip, ==, 2617245695);
        //g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        //g_assert_cmpstr(ip_r->ip->str, ==, "155.%.%");
}

void test_ip_range_create_with_per3_3seg() {
        struct ip_range *ip_r = create_ip_range_from_str("%.%.%");
        g_assert(ip_r == NULL);
        //g_assert_cmpint(ip_r->minip, ==, 0);
        //g_assert_cmpint(ip_r->maxip, ==, 4294967295);
        //g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        //g_assert_cmpstr(ip_r->ip->str, ==, "%.%.%");
}

void test_ip_range_create_with_per1_2seg() {
        struct ip_range *ip_r = create_ip_range_from_str("255.%");
        g_assert(ip_r == NULL);
        //g_assert_cmpint(ip_r->minip, ==, 4278190080);
        //g_assert_cmpint(ip_r->maxip, ==, 4294967295);
        //g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        //g_assert_cmpstr(ip_r->ip->str, ==, "255.%");
}

void test_ip_range_create_with_per2_2seg() {
        struct ip_range *ip_r = create_ip_range_from_str("%.%");
        g_assert(ip_r == NULL);
        //g_assert_cmpint(ip_r->minip, ==, 0);
        //g_assert_cmpint(ip_r->maxip, ==, 4294967295);
        //g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        //g_assert_cmpstr(ip_r->ip->str, ==, "%.%");
}

void test_ip_range_create_with_per1_1seg() {
        struct ip_range *ip_r = create_ip_range_from_str("%");
        g_assert(ip_r == NULL);
        //g_assert_cmpint(ip_r->minip, ==, 0);
        //g_assert_cmpint(ip_r->maxip, ==, 4294967295);
        //g_assert_cmpint(ip_r->minip, <, ip_r->maxip);
        //g_assert_cmpstr(ip_r->ip->str, ==, "%");
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");
	
	// >=5 seg ip str
	g_test_add_func("/core/test_ip_range_create_with_per_5seg",test_ip_range_create_with_per_5seg);

	// 4 seg ip str
	g_test_add_func("/core/test_ip_range_create_with_per1_4seg",test_ip_range_create_with_per1_4seg);
	g_test_add_func("/core/test_ip_range_create_with_per2_4seg",test_ip_range_create_with_per2_4seg);
	g_test_add_func("/core/test_ip_range_create_with_per3_4seg",test_ip_range_create_with_per3_4seg);
	g_test_add_func("/core/test_ip_range_create_with_per4_4seg",test_ip_range_create_with_per4_4seg);

	// 3 seg ip str
	g_test_add_func("/core/test_ip_range_create_with_per1_3seg",test_ip_range_create_with_per1_3seg);
	g_test_add_func("/core/test_ip_range_create_with_per2_3seg",test_ip_range_create_with_per2_3seg);
	g_test_add_func("/core/test_ip_range_create_with_per3_3seg",test_ip_range_create_with_per3_3seg);
	
	// 2 seg ip str
	g_test_add_func("/core/test_ip_range_create_with_per1_2seg",test_ip_range_create_with_per1_2seg);
	g_test_add_func("/core/test_ip_range_create_with_per2_2seg",test_ip_range_create_with_per2_2seg);
	
	// 1 seg ip str
	g_test_add_func("/core/test_ip_range_create_with_per1_1seg",test_ip_range_create_with_per1_1seg);

	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */
