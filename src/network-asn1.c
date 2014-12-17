#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "glib-ext.h"

#include "network-packet.h" /* for mysql-packet */
#include "network-asn1.h"

#define C(x) (x), sizeof(x) - 1
#define S(x) (x)->str, (x)->len

GQuark
network_asn1_error(void) {
	return g_quark_from_static_string("network-der-error-quark");
}

gboolean
network_asn1_proto_get_id(network_packet *packet, ASN1Identifier *id, GError **gerr) {
	guint8 b;
	guint8 v;

	g_assert(packet);
	g_assert(id);

	if (!network_packet_get_data(packet, &b, 1)) {
		g_set_error(gerr, 
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_EOF,
				"failed to read 1 byte from packet for id");
		return FALSE;
	}

	id->klass = (b >> 6) & 0x3;
	id->type = (b >> 5) & 0x1;
	v = b & 0x1f;

	if (v == 0x1f) {
		g_set_error(gerr, 
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_UNSUPPORTED,
				"don't support types > 31 yet");
		return FALSE;
	}
	id->value = v;

	return TRUE;
}

gboolean
network_asn1_proto_get_length(network_packet *packet, ASN1Length *_len, GError **gerr) {
	guint8 b;

	/* short form is one byte, long form is several bytes */

	if (FALSE == network_packet_get_data(packet, &b, 1)) {
		g_set_error(gerr, 
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_EOF,
				"no data");
		return FALSE;
	}

	if (b & 0x80) {
		/* long form, 8th bit is indication, the other bits are the length of the len-field in bytes */
		guint8 len_len = b & 0x7f;
		guchar len_bytes[8];
		gsize ndx;
		guint64 len = 0;

		if (len_len == 0) {
			g_set_error(gerr, 
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_INVALID,
				"the extended length can't be 0");
			return FALSE;
		}

		if (len_len > 8) {
			g_set_error(gerr, 
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_UNSUPPORTED,
				"can only handle tag-length if 2^64 max");
			return FALSE;
		}

		g_assert_cmpint(len_len, <, sizeof(len_bytes));

		if (FALSE == network_packet_get_data(packet, len_bytes, len_len)) {
			g_set_error(gerr, 
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_EOF,
					"no data");
			return FALSE;
		}

		for (ndx = 0; ndx < len_len; ndx++) {
			len <<= 8;
			len |= len_bytes[ndx];
		}
		*_len = len;
	} else {
		*_len = b;
	}

	return TRUE;
}

gboolean
network_asn1_proto_get_header(network_packet *packet, ASN1Identifier *_id, ASN1Length *_len, GError **gerr) {
	return network_asn1_proto_get_id(packet, _id, gerr) &&
		network_asn1_proto_get_length(packet, _len, gerr);
}

gboolean
network_asn1_proto_get_oid(network_packet *packet, ASN1Length len, GString *oid, GError **gerr) {
	gsize end_offset = packet->offset + len;
	gboolean is_first = TRUE;

	g_string_truncate(oid, 0);

	while (packet->offset < end_offset) {
		guint8 b;

		/* short form is one byte, long form is several bytes */

		if (FALSE == network_packet_get_data(packet, &b, 1)) {
			g_set_error(gerr, 
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_EOF,
					"no data");
			return FALSE;
		}

		if (is_first) {
			/* first field is special, has 2 values */
			g_string_append_printf(oid, "%d.%d", b / 40, b % 40);
			is_first = FALSE;
		} else {
			guint64 n = 0;
			gsize rounds = 0;

			for (rounds = 0; b & 0x80; rounds++) {
				if (rounds > 9) {
					g_set_error(gerr, 
							NETWORK_ASN1_ERROR,
							NETWORK_ASN1_ERROR_EOF,
							"we can't represent OID segments with more than 9 bytes");
					return FALSE;
				}
				n <<= 7;
				n |= (b & 0x7f);

				if (FALSE == network_packet_get_data(packet, &b, 1)) {
					g_set_error(gerr, 
							NETWORK_ASN1_ERROR,
							NETWORK_ASN1_ERROR_EOF,
							"no data");
					return FALSE;
				}

			}

			n <<= 7;
			n |= b; /* b is already without the 0x80, no need to filter that out */
		       	
			g_string_append_printf(oid, ".%"G_GUINT64_FORMAT, n);
		}
	}

	return TRUE;
}

static gboolean
network_asn1_is_valid_internal(network_packet *packet, GError **gerr) {
	ASN1Identifier id;
	ASN1Length     len;
	network_packet sub_packet;
	GString sub_packet_str;
	gsize          initial_offset  __attribute__((unused)) = packet->offset;
	
	if (FALSE == network_asn1_proto_get_header(packet, &id, &len, gerr)) {
		return FALSE;
	}

#if 0
	g_debug("%s: id = (klass = %d, type = %"G_GUINT64_FORMAT"), len = %"G_GSIZE_FORMAT" (packet.len = %"G_GSIZE_FORMAT,
			G_STRLOC,
			id.klass,
			id.value,
			len,
			packet->data->len - initial_offset);
#endif

	/* check if we have as much data left in this sub-packet as the length field says */
	if (!network_packet_has_more_data(packet, len)) {
		g_set_error(gerr,
				NETWORK_ASN1_ERROR,
				NETWORK_ASN1_ERROR_INVALID,
				"announced length > octets left: %"G_GSIZE_FORMAT" > %"G_GSIZE_FORMAT,
				len, packet->data->len);

		return FALSE;
	}

	while (len) {
		if ((id.klass == ASN1_IDENTIFIER_KLASS_APPLICATION) ||
		    (id.klass == ASN1_IDENTIFIER_KLASS_CONTEXT_SPECIFIC) ||
		    (id.klass == ASN1_IDENTIFIER_KLASS_UNIVERSAL && id.value == ASN1_IDENTIFIER_UNIVERSAL_SEQUENCE)) {
			sub_packet_str.str = packet->data->str + packet->offset;
			sub_packet_str.len = len;
			sub_packet.data = &sub_packet_str;
			sub_packet.offset = 0;

			if (FALSE == network_asn1_is_valid_internal(&sub_packet, gerr)) {
				return FALSE;
			}

			g_assert_cmpint(sub_packet.offset, <=, len);

			network_packet_skip(packet, sub_packet.offset); /* skip as many bytes in our current packet as the sub-packet parsed */

			len -= sub_packet.offset;

			if (id.klass == ASN1_IDENTIFIER_KLASS_UNIVERSAL && id.value == ASN1_IDENTIFIER_UNIVERSAL_SEQUENCE) {
				/* a SEQUENCE .. parse the next packet */
			} else if (len != 0) {
				g_set_error(gerr,
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_INVALID,
					"expected the packet to be parsed completely, but still have %"G_GSIZE_FORMAT" bytes left",
					len);

				return FALSE;
			}
		} else {
			/* as simple field that contains no other tag */
			if (FALSE == network_packet_skip(packet, len)) {
				g_set_error(gerr,
					NETWORK_ASN1_ERROR,
					NETWORK_ASN1_ERROR_INVALID,
					"couldn't skip the basic data: announced len = %"G_GSIZE_FORMAT", packet-len-left = %"G_GSIZE_FORMAT,
					len,
					packet->data->len - packet->offset);
				return FALSE;
			}
			len = 0;
		}
	}

	return TRUE;
}

gboolean
network_asn1_is_valid(network_packet *packet, GError **gerr) {
	gsize old_offset = packet->offset;
	gboolean ret;

	ret = network_asn1_is_valid_internal(packet, gerr);

	packet->offset = old_offset;

	return ret;
}

