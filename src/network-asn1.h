#ifndef __NETWORK_ASN1_H__
#define __NETWORK_ASN1_H__

#include <glib.h>

#include "network-exports.h"

typedef enum {
	ASN1_IDENTIFIER_KLASS_UNIVERSAL,
	ASN1_IDENTIFIER_KLASS_APPLICATION,
	ASN1_IDENTIFIER_KLASS_CONTEXT_SPECIFIC,
	ASN1_IDENTIFIER_KLASS_PRIVATE
} ASN1IdentifierKlass;

typedef enum {
	ASN1_IDENTIFIER_TYPE_PRIMITIVE,
	ASN1_IDENTIFIER_TYPE_CONSTRUCTED
} ASN1IdentifierType;

typedef struct {
	ASN1IdentifierKlass klass;
	ASN1IdentifierType type;
	guint64 value; /* we don't support larger values */
} ASN1Identifier;

typedef guint64 ASN1Length; /* we don't support longer lengths */

typedef enum {
	ASN1_IDENTIFIER_UNIVERSAL_OCTET_STREAM = 0x04,
	ASN1_IDENTIFIER_UNIVERSAL_OID = 0x06,
	ASN1_IDENTIFIER_UNIVERSAL_ENUM = 0x0a,
	ASN1_IDENTIFIER_UNIVERSAL_SEQUENCE = 0x10
} ASN1IdentifierUniversalType;

#define NETWORK_ASN1_ERROR network_asn1_error()
GQuark
network_asn1_error(void);

enum {
	NETWORK_ASN1_ERROR_UNSUPPORTED,
	NETWORK_ASN1_ERROR_INVALID,
	NETWORK_ASN1_ERROR_EOF
};

/**
 * @param gerr 
 * @returns TRUE on success, FALSE on error
 */
gboolean
network_asn1_is_valid(network_packet *packet, GError **gerr);

gboolean
network_asn1_proto_get_oid(network_packet *packet, ASN1Length len, GString *oid, GError **gerr);

gboolean
network_asn1_proto_get_header(network_packet *packet, ASN1Identifier *_id, ASN1Length *_len, GError **gerr);

gboolean
network_asn1_proto_get_length(network_packet *packet, ASN1Length *_len, GError **gerr);

gboolean
network_asn1_proto_get_id(network_packet *packet, ASN1Identifier *id, GError **gerr);

#endif
