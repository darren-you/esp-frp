// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_frp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EFRP_UDP_MAX_PAYLOAD_SIZE 65507u
#define EFRP_UDP_MAX_ZONE_SIZE 255u
#define EFRP_UDP_BINARY_TYPE 19u
#define EFRP_UDP_MAX_HEADER_SIZE 555u
#define EFRP_UDP_IPV4 4u
#define EFRP_UDP_IPV6 6u

typedef struct {
    uint8_t family; /* EFRP_UDP_IPV4 or EFRP_UDP_IPV6 */
    uint8_t ip[16]; /* IPv4 uses the first four bytes. */
    uint16_t port; /* Zero is a valid protocol value. */
    const uint8_t *zone; /* Borrowed UTF-8 bytes; IPv4 requires an empty zone. */
    size_t zone_length;
} efrp_udp_address_t;

typedef struct {
    bool has_local_address;
    efrp_udp_address_t local_address, remote_address;
    const uint8_t *payload; /* Borrowed binary datagram, NULL allowed when empty. */
    size_t payload_length;
} efrp_udp_packet_t;

/* FRP v0.71.0 binary-v1 codec. Both APIs operate on the complete wire MESSAGE
 * payload: big-endian uint16 type 19 followed by the binary UDP body. The eight
 * byte wire frame header is not included. Remote address is always required.
 * Datagram length <=65507 and total MESSAGE payload <=65536 are both enforced.
 * No allocation, socket, retained state or partial output. Inputs and encoder
 * output must not overlap. On failure *length is zero and output is unchanged.
 * IPv4-mapped IPv6 input is encoded as IPv4, matching the official encoder. */
efrp_result_t efrp_udp_packet_encode(const efrp_udp_packet_t *packet,
                                    uint8_t *output, size_t capacity, size_t *length);
/* The decoder copies IP bytes but borrows zone and datagram pointers from input.
 * Keep that input alive and unchanged while using the packet; copy before queueing.
 * It requires exactly one complete MESSAGE payload, rejecting trailing bytes.
 * On failure *packet is cleared. No address or payload is delivered before the
 * entire input has passed validation. */
efrp_result_t efrp_udp_packet_decode(const uint8_t *input, size_t length,
                                    efrp_udp_packet_t *packet);
/* Validate metadata from an incrementally retained MESSAGE payload prefix.
 * frame_payload_length is the wire header's complete MESSAGE payload length.
 * WOULD_BLOCK requests more prefix bytes; no more than MAX_HEADER_SIZE bytes
 * are needed. OK proves type, addresses, UTF-8 zones and declared datagram size
 * exactly match that frame length, but does not prove the datagram arrived.
 * packet->payload remains NULL; zone pointers borrow input. The caller must
 * receive or drain exactly frame_payload_length bytes before another frame.
 * On failure or WOULD_BLOCK, packet and payload_offset are cleared. */
efrp_result_t efrp_udp_packet_header_decode(const uint8_t *input, size_t prefix_length,
                                           size_t frame_payload_length,
                                           efrp_udp_packet_t *packet, size_t *payload_offset);

#ifdef __cplusplus
}
#endif
