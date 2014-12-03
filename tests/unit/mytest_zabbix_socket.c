/*
 * mytest_zabbix_socket.c
 *
 *  Created on: 2013-6-26
 *      Author: jinxuanhou
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

#include "network-zabbix-socket.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
#define START_TEST(x) void(x)(void)

START_TEST(test_zabbix_socket_header_judge) {
	//gboolean ret = FALSE;

	zabbix_socket *sock = NULL;
	g_assert(!zabbix_head_is_valid(sock));

	sock = zabbix_socket_new();
	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "ZABBIX \1");

	g_assert(!zabbix_head_is_valid(sock));

	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "ZBXD\1");
	g_assert(zabbix_head_is_valid(sock));

	g_string_truncate(sock->result, 0);
	g_string_append(sock->result, "zbxd\1");
	g_assert(!zabbix_head_is_valid(sock));

	g_string_free(sock->result, TRUE);
	g_assert(!zabbix_head_is_valid(sock));
	sock->result = NULL;
	zabbix_socket_free(sock);

}

static void append_length(zabbix_socket *sock, const char *length_in_str) {
	if (!sock)
		return;

	if (!sock->result)
		return;

	g_assert(strlen(length_in_str) == 8);

	g_string_truncate(sock->result, 0);
	int index = 8 - 1;
	for (; index >= 0; index--) {
		g_string_append_c(sock->result, length_in_str[index] - '0');
	}
}

START_TEST(test_zabbix_socket_length_transform) {
	zabbix_socket *sock = NULL;
	guint64 data = 0;
	g_assert_cmpint(-1, ==, zabbix_letoh_guint64(NULL, &data));

	sock = zabbix_socket_new();

	append_length(sock, "00000008");
	g_assert_cmpint(0, ==, zabbix_letoh_guint64(sock->result, &data));
	g_assert_cmpint(8, ==, data);

	append_length(sock, "00000018");
	g_assert_cmpint(0, ==, zabbix_letoh_guint64(sock->result, &data));
	g_assert_cmpint(264, ==, data);

	append_length(sock, "00000108");
	g_assert_cmpint(0, ==, zabbix_letoh_guint64(sock->result, &data));
	g_assert_cmpint(65544, ==, data);

	append_length(sock, "00000000");
	g_assert_cmpint(0, ==, zabbix_letoh_guint64(sock->result, &data));
	g_assert_cmpint(0, ==, data);

	g_string_free(sock->result, TRUE);

	sock->result = NULL;
	g_assert_cmpint(-1, ==, zabbix_letoh_guint64(sock->result, &data));
	zabbix_socket_free(sock);

}

int main(int argc, char **argv) {

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");


	g_test_add_func("/core/test_zabbix_socket_header_judge",test_zabbix_socket_header_judge);
	g_test_add_func("/core/test_zabbix_socket_length_transform",test_zabbix_socket_length_transform);

	gint ret = g_test_run();

	return ret;
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */



