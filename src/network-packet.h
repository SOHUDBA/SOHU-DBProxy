#ifndef __NETWORK_PACKET_H__
#define __NETWORK_PACKET_H__

#include "network-exports.h"

typedef struct {
	GString *data;

	guint offset;
} network_packet;

/**
 * create a new network packet
 */
NETWORK_API network_packet *
network_packet_new(void);

NETWORK_API void
network_packet_free(network_packet *packet);

NETWORK_API gboolean
network_packet_has_more_data(network_packet *packet, gsize len);

NETWORK_API gboolean
network_packet_skip(network_packet *packet, gsize len);

NETWORK_API gboolean
network_packet_peek_data(network_packet *packet, gpointer dst, gsize len);

NETWORK_API gboolean
network_packet_get_data(network_packet *packet, gpointer dst, gsize len);

#endif
