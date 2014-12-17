#ifndef __NETWORK_SPNEGO_H__
#define __NETWORK_SPNEGO_H__

#include <glib.h>

/**
 * SECTION:
 *
 * implementation of RFC4178
 *
 */
#define SPNEGO_OID         "1.3.6.1.5.5.2"
#define SPNEGO_OID_NTLM    "1.3.6.1.4.1.311.2.2.10"
#define SPNEGO_OID_MS_KRB5 "1.2.840.48018.1.2.2"
#define SPNEGO_OID_KRB5    "1.2.840.113554.1.2.2"
#define SPNEGO_OID_NEGOEX  "1.3.6.1.4.1.311.2.2.30"

typedef enum {
	SPNEGO_RESPONSE_STATE_ACCEPT_COMPLETED,
	SPNEGO_RESPONSE_STATE_ACCEPT_INCOMPLETE,
	SPNEGO_RESPONSE_STATE_REJECTED,
	SPNEGO_RESPONSE_STATE_MICSOMETHING
} network_spnego_response_state;

typedef struct {
	network_spnego_response_state negState;

	GString *supportedMech;

	GString *responseToken;
	GString *mechListMIC;
} network_spnego_response_token;

typedef struct {
	GPtrArray *mechTypes; /* array of strings */

	GString *mechToken;
} network_spnego_init_token;

gboolean
network_gssapi_proto_get_message_header(network_packet *packet, GString *oid, GError **gerr);

/**
 * network_spnego_response_token_new:
 *
 */
network_spnego_response_token *
network_spnego_response_token_new(void);

/**
 * network_spnego_response_token_free:
 */
void 
network_spnego_response_token_free(network_spnego_response_token *);

gboolean
network_spnego_proto_get_response_token(network_packet *packet, network_spnego_response_token *token, GError **gerr);

network_spnego_init_token *
network_spnego_init_token_new(void);

void
network_spnego_init_token_free(network_spnego_init_token *);

gboolean
network_spnego_proto_get_init_token(network_packet *packet, network_spnego_init_token *token, GError **gerr);

#endif
