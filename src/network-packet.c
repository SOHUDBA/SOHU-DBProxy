#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "network-packet.h"

network_packet *
network_packet_new(void) {
	network_packet *packet;

	packet = g_new0(network_packet, 1);

	return packet;
}

void
network_packet_free(network_packet *packet) {
	if (!packet) return;

	g_free(packet);
}

gboolean
network_packet_has_more_data(network_packet *packet, gsize len) {
	if (packet->offset > packet->data->len) return FALSE; /* we are already out of bounds, shouldn't happen */
	if (len > packet->data->len - packet->offset) return FALSE;

	return TRUE;
}

gboolean
network_packet_skip(network_packet *packet, gsize len) {
	if (!network_packet_has_more_data(packet, len)) {
		return FALSE;
	}

	packet->offset += len;
	return TRUE;
}

gboolean
network_packet_peek_data(network_packet *packet, gpointer dst, gsize len) {
	if (!network_packet_has_more_data(packet, len)) return FALSE;

	memcpy(dst, packet->data->str + packet->offset, len);

	return TRUE;
}


gboolean
network_packet_get_data(network_packet *packet, gpointer dst, gsize len) {
	if (!network_packet_peek_data(packet, dst, len)) {
		return FALSE;
	}

	packet->offset += len;

	return TRUE;
}

