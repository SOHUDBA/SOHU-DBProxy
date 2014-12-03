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
t_spnego_decode_init(void) {
	const char raw_packet[] = 
		"\x83\x00\x00\x03"
		"\x60\x81\x80\x06\x06\x2b\x06\x01\x05\x05\x02\xa0"
		"\x76\x30\x74\xa0\x30\x30\x2e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37"
		"\x02\x02\x0a\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02\x06\x09"
		"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x06\x0a\x2b\x06\x01\x04\x01"
		"\x82\x37\x02\x02\x1e\xa2\x40\x04\x3e\x4e\x54\x4c\x4d\x53\x53\x50"
		"\x00\x01\x00\x00\x00\x97\xb2\x08\xe2\x09\x00\x09\x00\x35\x00\x00"
		"\x00\x0d\x00\x0d\x00\x28\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00"
		"\x0f\x43\x53\x45\x47\x49\x45\x54\x48\x2d\x54\x34\x32\x30\x44\x45"
		"\x2d\x4f\x52\x41\x43\x4c\x45";

	network_packet packet;
	GError *gerr = NULL;
	GString *oid;
	network_spnego_init_token *token;

	packet.data = g_string_new_len(C(raw_packet));
	packet.offset = 0;
	g_assert_cmpint(0, ==, network_mysqld_proto_skip_network_header(&packet));

	oid = g_string_new(NULL);
	if (FALSE == network_gssapi_proto_get_message_header(&packet, oid, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}
	g_assert_cmpstr(oid->str, ==, SPNEGO_OID);
	g_string_free(oid, TRUE);

	if (FALSE == network_asn1_is_valid(&packet, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}

	token = network_spnego_init_token_new();
	if (FALSE == network_spnego_proto_get_init_token(&packet, token, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}
	g_assert_cmpint(4, ==, token->mechTypes->len);
	g_assert_cmpstr(((GString *)token->mechTypes->pdata[0])->str, ==, SPNEGO_OID_NTLM);
	g_assert_cmpstr(((GString *)token->mechTypes->pdata[1])->str, ==, "1.2.840.48018.1.2.2");
	g_assert_cmpstr(((GString *)token->mechTypes->pdata[2])->str, ==, "1.2.840.113554.1.2.2");
	g_assert_cmpstr(((GString *)token->mechTypes->pdata[3])->str, ==, "1.3.6.1.4.1.311.2.2.30");
	network_spnego_init_token_free(token);
}


static void
t_spnego_decode_response_accept_incomplete(void) {
	const char raw_packet[] = 
		"\x36\x01\x00\x04\x01\xa1\x82\x01\x31\x30\x82\x01\x2d\xa0\x03\x0a"
		"\x01\x01\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
		"\xa2\x82\x01\x16\x04\x82\x01\x12\x4e\x54\x4c\x4d\x53\x53\x50\x00"
		"\x02\x00\x00\x00\x1a\x00\x1a\x00\x38\x00\x00\x00\x15\xc2\x8a\xe2"
		"\xa1\x97\xf0\x6c\x03\x58\x6c\x8b\x40\xbb\xab\x01\x00\x00\x00\x00"
		"\xc0\x00\xc0\x00\x52\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f"
		"\x43\x00\x53\x00\x45\x00\x47\x00\x49\x00\x45\x00\x54\x00\x48\x00"
		"\x2d\x00\x54\x00\x34\x00\x32\x00\x30\x00\x02\x00\x1a\x00\x43\x00"
		"\x53\x00\x45\x00\x47\x00\x49\x00\x45\x00\x54\x00\x48\x00\x2d\x00"
		"\x54\x00\x34\x00\x32\x00\x30\x00\x01\x00\x1a\x00\x43\x00\x53\x00"
		"\x45\x00\x47\x00\x49\x00\x45\x00\x54\x00\x48\x00\x2d\x00\x54\x00"
		"\x34\x00\x32\x00\x30\x00\x04\x00\x36\x00\x43\x00\x53\x00\x45\x00"
		"\x47\x00\x49\x00\x45\x00\x54\x00\x48\x00\x2d\x00\x54\x00\x34\x00"
		"\x32\x00\x30\x00\x2e\x00\x64\x00\x65\x00\x2e\x00\x6f\x00\x72\x00"
		"\x61\x00\x63\x00\x6c\x00\x65\x00\x2e\x00\x63\x00\x6f\x00\x6d\x00"
		"\x03\x00\x36\x00\x43\x00\x53\x00\x45\x00\x47\x00\x49\x00\x45\x00"
		"\x54\x00\x48\x00\x2d\x00\x54\x00\x34\x00\x32\x00\x30\x00\x2e\x00"
		"\x64\x00\x65\x00\x2e\x00\x6f\x00\x72\x00\x61\x00\x63\x00\x6c\x00"
		"\x65\x00\x2e\x00\x63\x00\x6f\x00\x6d\x00\x07\x00\x08\x00\x5d\xf6"
		"\x7c\x01\xe5\x7c\xcc\x01\x00\x00\x00\x00";

	network_packet packet;
	GError *gerr = NULL;
	network_spnego_response_token *token;

	packet.data = g_string_new_len(C(raw_packet));
	packet.offset = 0;
	g_assert_cmpint(0, ==, network_mysqld_proto_skip_network_header(&packet));
	g_assert_cmpint(0, ==, network_mysqld_proto_skip(&packet, 1));

	if (FALSE == network_asn1_is_valid(&packet, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}

	token = network_spnego_response_token_new();
	if (FALSE == network_spnego_proto_get_response_token(&packet, token, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}
	g_assert_cmpint(token->negState, ==, SPNEGO_RESPONSE_STATE_ACCEPT_INCOMPLETE);
	g_assert_cmpstr(token->supportedMech->str, ==, SPNEGO_OID_NTLM);
	network_spnego_response_token_free(token);
}

static void
t_spnego_decode_response_accept_complete(void) {
	const char raw_packet[] = 
		"\x1e\x00\x00\x06\x01\xa1\x1b\x30\x19\xa0\x03\x0a\x01\x00\xa3\x12"
		"\x04\x10\x01\x00\x00\x00\x43\x87\xe0\x88\xc1\x36\xe3\xa9\x00\x00"
		"\x00\x00";

	network_packet packet;
	GError *gerr = NULL;
	network_spnego_response_token *token;

	packet.data = g_string_new_len(C(raw_packet));
	packet.offset = 0;
	g_assert_cmpint(0, ==, network_mysqld_proto_skip_network_header(&packet));
	g_assert_cmpint(0, ==, network_mysqld_proto_skip(&packet, 1));

	if (FALSE == network_asn1_is_valid(&packet, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}

	token = network_spnego_response_token_new();
	if (FALSE == network_spnego_proto_get_response_token(&packet, token, &gerr)) {
		g_error("%s: %s",
				G_STRLOC,
				gerr->message);
	}
	g_assert_cmpint(token->negState, ==, SPNEGO_RESPONSE_STATE_ACCEPT_COMPLETED);
#define MECHLISTMIC "\x01\x00\x00\x00\x43\x87\xe0\x88\xc1\x36\xe3\xa9\x00\x00\x00\x00"
	g_assert_cmpint(sizeof(MECHLISTMIC) - 1, ==, token->mechListMIC->len);
	g_assert_cmpint(0, ==, memcmp(token->mechListMIC->str, MECHLISTMIC, token->mechListMIC->len));
#undef MECHLISTMIC
	network_spnego_response_token_free(token);
}


int
main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/spnego/decode_init", t_spnego_decode_init);
	g_test_add_func("/spnego/decode_response_accept_incomplete", t_spnego_decode_response_accept_incomplete);
	g_test_add_func("/spnego/decode_response_accept_complete", t_spnego_decode_response_accept_complete);

	return g_test_run();

}
