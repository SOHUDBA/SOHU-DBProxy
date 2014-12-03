#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "glib-ext.h"

#include "network-packet.h" /* for mysql-packet */
#include "network-asn1.h"
#include "network-spnego.h"

#define C(x) (x), sizeof(x) - 1
#define S(x) (x)->str, (x)->len

network_spnego_init_token *
network_spnego_init_token_new(void) {
	network_spnego_init_token *token;

	token = g_slice_new(network_spnego_init_token);
	token->mechToken = g_string_new(NULL);
	token->mechTypes = g_ptr_array_new();

	return token;
}

void
network_spnego_init_token_free(network_spnego_init_token *token) {
	guint i;

	g_string_free(token->mechToken, TRUE);
	for (i = 0; i < token->mechTypes->len; i++) {
		g_string_free(token->mechTypes->pdata[i], TRUE);
	}
	g_ptr_array_free(token->mechTypes, TRUE);
	g_slice_free(network_spnego_init_token, token);
}

network_spnego_response_token *
network_spnego_response_token_new(void) {
	network_spnego_response_token *token;

	token = g_slice_new(network_spnego_response_token);
	token->responseToken = g_string_new(NULL);
	token->supportedMech = g_string_new(NULL);
	token->mechListMIC = g_string_new(NULL);

	return token;
}

void
network_spnego_response_token_free(network_spnego_response_token *token) {
	g_string_free(token->mechListMIC, TRUE);
	g_string_free(token->responseToken, TRUE);
	g_string_free(token->supportedMech, TRUE);
	g_slice_free(network_spnego_response_token, token);
}

gboolean
network_spnego_proto_get_init_token(network_packet *packet, network_spnego_init_token *token, GError **gerr) {
	ASN1Identifier seq_id;
	ASN1Length seq_len;
	gsize end_offset;
	ASN1Identifier spnego_id;
	ASN1Length spnego_len;

	if (FALSE == network_asn1_proto_get_header(packet, &spnego_id, &spnego_len, gerr)) {
		return FALSE;
	}

	if (spnego_id.klass != ASN1_IDENTIFIER_KLASS_CONTEXT_SPECIFIC ||
	    spnego_id.value != 0) {
		g_set_error(gerr,
			NETWORK_ASN1_ERROR,
			NETWORK_ASN1_ERROR_INVALID,
			"expected a init-token, got klass=%d, value=%"G_GUINT64_FORMAT,
			spnego_id.klass,
			spnego_id.value);

		return FALSE;
	}

	if (FALSE == network_asn1_proto_get_header(packet, &seq_id, &seq_len, gerr)) {
		return FALSE;
	}

	/* next should be a SEQUENCE */
	if (seq_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
	    seq_id.value != ASN1_IDENTIFIER_UNIVERSAL_SEQUENCE) {
		g_set_error(gerr,
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_INVALID,
				"expected a sequence");
		return FALSE;
	}

	end_offset = packet->offset + seq_len;

	while (packet->offset < end_offset) {
		ASN1Identifier app_id;
		ASN1Length app_len;
		ASN1Identifier mech_seq_id;
		ASN1Length mech_seq_len;
		ASN1Length mech_seq_end_offset;
		ASN1Identifier mech_token_id;
		ASN1Length mech_token_len;

		if (FALSE == network_asn1_proto_get_header(packet, &app_id, &app_len, gerr)) {
			return FALSE;
		}

		if (app_id.klass != ASN1_IDENTIFIER_KLASS_CONTEXT_SPECIFIC) {
			g_set_error(gerr,
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_INVALID,
					"expected a context specific tag");

			return FALSE;
		}

		switch (app_id.value) {
		case 0: /* MechTypes */
			if (FALSE == network_asn1_proto_get_header(packet, &mech_seq_id, &mech_seq_len, gerr)) {
				return FALSE;
			}

			if (mech_seq_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
			    mech_seq_id.value != ASN1_IDENTIFIER_UNIVERSAL_SEQUENCE) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			mech_seq_end_offset = packet->offset + mech_seq_len;

			while (packet->offset < mech_seq_end_offset) {
				ASN1Identifier mech_seq_oid_id;
				ASN1Length mech_seq_oid_len;
				GString *oid;

				if (FALSE == network_asn1_proto_get_header(packet, &mech_seq_oid_id, &mech_seq_oid_len, gerr)) {
					return FALSE;
				}

				if (mech_seq_oid_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
				    mech_seq_oid_id.value != ASN1_IDENTIFIER_UNIVERSAL_OID) {
					g_set_error(gerr,
							NETWORK_ASN1_ERROR,
							NETWORK_ASN1_ERROR_INVALID,
							"%s: ...", 
							G_STRLOC);

					return FALSE;
				}

				oid = g_string_new(NULL);
				if (FALSE == network_asn1_proto_get_oid(packet, mech_seq_oid_len, oid, gerr)) {
					g_string_free(oid, TRUE);
					return FALSE;
				}
				g_ptr_array_add(token->mechTypes, oid);
			}

			break;
		case 2: /* mechToken */
			if (FALSE == network_asn1_proto_get_header(packet, &mech_token_id, &mech_token_len, gerr)) {
				return FALSE;
			}

			if (mech_token_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
			    mech_token_id.value != ASN1_IDENTIFIER_UNIVERSAL_OCTET_STREAM) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			if (FALSE == network_packet_skip(packet, mech_token_len)) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			break;
		default:
			g_set_error(gerr,
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_UNSUPPORTED,
					"right now only MechTypes and mechToken are supported");

			return FALSE;
		}
	}

	return TRUE;
}

gboolean
network_spnego_proto_get_response_token(network_packet *packet, network_spnego_response_token *token, GError **gerr) {
	ASN1Identifier seq_id;
	ASN1Length seq_len;
	gsize end_offset;
	ASN1Identifier spnego_id;
	ASN1Length spnego_len;

	if (FALSE == network_asn1_proto_get_header(packet, &spnego_id, &spnego_len, gerr)) {
		return FALSE;
	}

	if (spnego_id.klass != ASN1_IDENTIFIER_KLASS_CONTEXT_SPECIFIC ||
	    spnego_id.value != 1) {
		g_set_error(gerr,
			NETWORK_ASN1_ERROR,
			NETWORK_ASN1_ERROR_INVALID,
			"expected a response-token, got klass=%d, value=%"G_GUINT64_FORMAT,
			spnego_id.klass,
			spnego_id.value);

		return FALSE;
	}

	if (FALSE == network_asn1_proto_get_header(packet, &seq_id, &seq_len, gerr)) {
		return FALSE;
	}

	/* next should be a SEQUENCE */
	if (seq_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
	    seq_id.value != ASN1_IDENTIFIER_UNIVERSAL_SEQUENCE) {
		g_set_error(gerr,
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_INVALID,
				"expected a sequence");
		return FALSE;
	}

	end_offset = packet->offset + seq_len;

	while (packet->offset < end_offset) {
		ASN1Identifier app_id;
		ASN1Length app_len;
		ASN1Identifier sub_id;
		ASN1Length sub_len;
		guint8 negState;

		if (FALSE == network_asn1_proto_get_header(packet, &app_id, &app_len, gerr)) {
			return FALSE;
		}

		if (app_id.klass != ASN1_IDENTIFIER_KLASS_CONTEXT_SPECIFIC) {
			g_set_error(gerr,
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_INVALID,
					"expected a context specific tag");

			return FALSE;
		}

		switch (app_id.value) {
		case 0: /* negState */
			if (FALSE == network_asn1_proto_get_header(packet, &sub_id, &sub_len, gerr)) {
				return FALSE;
			}

			if (sub_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
			    sub_id.value != ASN1_IDENTIFIER_UNIVERSAL_ENUM) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			/* we should only get one byte */

			if (FALSE == network_packet_get_data(packet, &negState, 1)) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			switch (negState) {
			case 0:
				token->negState = SPNEGO_RESPONSE_STATE_ACCEPT_COMPLETED;
				break;
			case 1:
				token->negState = SPNEGO_RESPONSE_STATE_ACCEPT_INCOMPLETE;
				break;
			case 2:
				token->negState = SPNEGO_RESPONSE_STATE_ACCEPT_INCOMPLETE;
				break;
			case 3:
				token->negState = SPNEGO_RESPONSE_STATE_ACCEPT_INCOMPLETE;
				break;
			default:
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			break;
		case 1: /* supportedMech */
			if (FALSE == network_asn1_proto_get_header(packet, &sub_id, &sub_len, gerr)) {
				return FALSE;
			}

			if (sub_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
			    sub_id.value != ASN1_IDENTIFIER_UNIVERSAL_OID) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			if (FALSE == network_asn1_proto_get_oid(packet, sub_len, token->supportedMech, gerr)) {
				return FALSE;
			}

			break;
		case 2: /* responseToken */
			if (FALSE == network_asn1_proto_get_header(packet, &sub_id, &sub_len, gerr)) {
				return FALSE;
			}

			if (sub_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
			    sub_id.value != ASN1_IDENTIFIER_UNIVERSAL_OCTET_STREAM) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			g_string_set_size(token->responseToken, sub_len);
			if (FALSE == network_packet_get_data(packet, token->responseToken->str, sub_len)) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: getting responseToken data failed: size of %"G_GSIZE_FORMAT, 
						G_STRLOC,
						sub_len);

				return FALSE;
			}
			token->responseToken->str[sub_len] = '\0'; /* terminate the string */
			token->responseToken->len = sub_len;

			break;
		case 3: /* mechListMIC */
			if (FALSE == network_asn1_proto_get_header(packet, &sub_id, &sub_len, gerr)) {
				return FALSE;
			}

			if (sub_id.klass != ASN1_IDENTIFIER_KLASS_UNIVERSAL ||
			    sub_id.value != ASN1_IDENTIFIER_UNIVERSAL_OCTET_STREAM) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: ...", 
						G_STRLOC);

				return FALSE;
			}

			g_string_set_size(token->mechListMIC, sub_len);
			if (FALSE == network_packet_get_data(packet, token->mechListMIC->str, sub_len)) {
				g_set_error(gerr,
						NETWORK_ASN1_ERROR,
						NETWORK_ASN1_ERROR_INVALID,
						"%s: getting mechListMIC data failed: size of %"G_GSIZE_FORMAT, 
						G_STRLOC,
						sub_len);

				return FALSE;
			}
			token->mechListMIC->str[sub_len] = '\0'; /* terminate the string */
			token->mechListMIC->len = sub_len;

			break;

		default:
			g_set_error(gerr,
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_UNSUPPORTED,
					"right now only MechTypes and mechToken are supported");

			return FALSE;
		}
	}

	return TRUE;
}

gboolean
network_gssapi_proto_get_message_header(network_packet *packet, GString *oid, GError **gerr) {
	ASN1Identifier gss_id;
	ASN1Length gss_len;
	ASN1Identifier oid_id;
	ASN1Length oid_len;

	if (FALSE == network_asn1_proto_get_header(packet, &gss_id, &gss_len, gerr)) {
		return FALSE;
	}

	/* first we have a GSS-API header */
	g_assert_cmpint(gss_id.klass, ==, ASN1_IDENTIFIER_KLASS_APPLICATION);
	g_assert_cmpint(gss_id.value, ==, 0);

	/* we should have as much data left in the packet as announced */
	if (!network_packet_has_more_data(packet, gss_len)) {
		g_set_error(gerr, 
			NETWORK_ASN1_ERROR,
			NETWORK_ASN1_ERROR_INVALID,
			"length field invalid");
		return FALSE;
	}

	/* good, now we should have a OID next */
	if (FALSE == network_asn1_proto_get_header(packet, &oid_id, &oid_len, gerr)) {
		return FALSE;
	}

	/* first we have a GSS-API header */
	g_assert_cmpint(oid_id.klass, ==, ASN1_IDENTIFIER_KLASS_UNIVERSAL);
	g_assert_cmpint(oid_id.value, ==, ASN1_IDENTIFIER_UNIVERSAL_OID); /* OID */

	if (FALSE == network_asn1_proto_get_oid(packet, oid_len, oid, gerr)) {
		return FALSE;
	}

	return TRUE;
}

