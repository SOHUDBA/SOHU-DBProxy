/*
 * mytest_packet_creation_and_append.c
 *
 *  Created on: 2013-6-4
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

#include "chassis-mainloop.h"
#include "network-mysqld-packet.h"
#include "network-packet.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1
chassis *chas = NULL;
void test_init_db_packet_append() {
	GString *packet = g_string_new(NULL);
	network_mysqld_init_db_packet_t* init_db_packet = network_mysqld_init_db_packet_new();
	g_string_assign(init_db_packet->schema, "test");
	network_mysqld_proto_append_init_db_packet(packet, init_db_packet);

	g_assert(packet->len >= 2);
	g_assert(packet->str);

	gint8 tag = (gint8)(0xff & packet->str[0]);

	g_assert_cmpint(tag, ==, 0x02);

	g_assert_cmpstr(packet->str + 1, ==, "test");

	network_mysqld_init_db_packet_free(init_db_packet);
	g_string_free(packet, TRUE);
}

void test_autocommit_packet_append() {
	GString *packet = g_string_new(NULL);

	network_mysqld_proto_append_autocommit_packet(packet, 1);
	g_assert(packet->len >= 2);
	g_assert(packet->str);

	gint8 tag = (gint8)(0xff & packet->str[0]);

	g_assert_cmpint(tag, ==, 0x03);

	g_assert_cmpstr(packet->str + 1, ==, "set autocommit = 1");
	g_string_free(packet, TRUE);
}

void test_is_correct_charsetname() {
	gboolean ret;

	ret = is_correct_charsetname("gbk");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_correct_charsetname("utf8");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_correct_charsetname("GBk");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_correct_charsetname("uTF8");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_correct_charsetname("aaaa");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_correct_charsetname("assdf8");
	g_assert_cmpint(ret, ==, FALSE);

	ret = is_correct_charsetname("latin1");
	g_assert_cmpint(ret, ==, TRUE);

	ret = is_correct_charsetname("LATIN1");
	g_assert_cmpint(ret, ==, TRUE);
}
void test_character_set_packet_append() {
	GString *packet = g_string_new(NULL);
	network_mysqld_proto_append_character_set_packet(packet, "character_set_connection", "GBK");

	gint8 tag = (gint8)(0xff & packet->str[0]);

	g_assert_cmpint(tag, ==, 0x03);

	g_assert_cmpstr(packet->str + 1, ==, "set character_set_connection = GBK");
	g_string_free(packet, TRUE);
}


int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/test_init_db_packet_append",test_init_db_packet_append);
	g_test_add_func("/core/test_autocommit_packet_append",test_autocommit_packet_append);

	//charset_regex *regex = charset_regex_new();
	g_test_add_func("/core/test_is_correct_charsetname",test_is_correct_charsetname);
	g_test_add_func("/core/test_character_set_packet_append",test_character_set_packet_append);

	return g_test_run();
}
#else /* GLIB_CHECK_VERSION */
int main() {
	return 77;
}
#endif /* GLIB_CHECK_VERSION */


