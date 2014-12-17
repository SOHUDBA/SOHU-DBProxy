#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "glib-ext.h"

#include "network-mysqld-proto.h"
#include "network-packet.h"
#include "network-asn1.h"
#include "network-spnego.h"

#define C(x) (x), sizeof(x) - 1
#define S(x) (x)->str, (x)->len

static void
t_asn1_get_id(void) {
	GError *gerr = NULL;
	network_packet p;
	ASN1Identifier id;

	p.data = g_string_new_len(C("\x60"));
	p.offset = 0;

	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_id(&p, &id, &gerr));
	g_assert_cmpint(id.klass, ==, ASN1_IDENTIFIER_KLASS_APPLICATION);
	g_assert_cmpint(id.type, ==, ASN1_IDENTIFIER_TYPE_CONSTRUCTED);
	g_assert_cmpint(id.value, ==, 0);

	/* we don't support long ids */
	g_string_assign_len(p.data, C("\x1f"));
	p.offset = 0;
	g_assert_cmpint(FALSE, ==, network_asn1_proto_get_id(&p, &id, &gerr));

	g_string_free(p.data, TRUE);
}

static void
t_asn1_get_length(void) {
	GError *gerr = NULL;
	network_packet p;
	ASN1Length len;

	p.data = g_string_new_len(C("\x60"));
	p.offset = 0;

	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_length(&p, &len, &gerr));
	g_assert_cmpint(len, ==, 0x60);

	g_string_assign_len(p.data, C("\x81\x80"));
	p.offset = 0;

	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_length(&p, &len, &gerr));
	g_assert_cmpint(len, ==, 0x80);

	g_string_assign_len(p.data, C("\x82\x01\x2d"));
	p.offset = 0;

	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_length(&p, &len, &gerr));
	g_assert_cmpint(len, ==, 0x12d);


	g_string_free(p.data, TRUE);
}

static void
t_asn1_get_oid(void) {
	GError *gerr = NULL;
	network_packet p;
	GString *oid;

	p.data = g_string_new_len(C("\x2b\x06\x01\x05\x05\x02"));
	p.offset = 0;

	oid = g_string_new(NULL);

	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_oid(&p, p.data->len, oid, &gerr));
	g_assert_cmpstr("1.3.6.1.5.5.2", ==, oid->str);

	g_string_assign_len(p.data, C("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"));
	p.offset = 0;
	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_oid(&p, p.data->len, oid, &gerr));
	g_assert_cmpstr("1.3.6.1.4.1.311.2.2.10", ==, oid->str);

	g_string_assign_len(p.data, C("\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"));
	p.offset = 0;
	g_assert_cmpint(TRUE, ==, network_asn1_proto_get_oid(&p, p.data->len, oid, &gerr));
	g_assert_cmpstr("1.2.840.48018.1.2.2", ==, oid->str);


	g_string_free(p.data, TRUE);
}

int
main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/asn1/get_id", t_asn1_get_id);
	g_test_add_func("/asn1/get_length", t_asn1_get_length);
	g_test_add_func("/asn1/get_id", t_asn1_get_oid);

	return g_test_run();

}
