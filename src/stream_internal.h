// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_transport.h"
#include <stdint.h>
#define EFRP_STREAM_NONE UINT64_MAX
typedef uint64_t efrp_stream_id_t;
typedef struct {
    size_t readable_bytes, pending_bytes;
    bool local_fin, remote_fin, reset;
} efrp_stream_info_t;

/* Client-initiated bidi only, at most four live stream slots. QUIC ID 0 is
   valid. IDs are native protocol IDs and are never reused in a connection. */
efrp_result_t efrp_stream_open(efrp_transport_t *transport, efrp_stream_id_t *id);
/* Candidate peer provider accepts actual remotely initiated bidi IDs. Other
   transport roles reject this operation; no fake client/server ID mapping. */
efrp_result_t efrp_stream_accept(efrp_transport_t *transport, efrp_stream_id_t *id);
efrp_result_t efrp_stream_info(const efrp_transport_t *transport, efrp_stream_id_t id, efrp_stream_info_t *info);
/* Write copies the accepted prefix; caller may reuse it immediately. Backends
   retain copied data until TLS owns it (TCP) or peer ACK/stream_close (QUIC).
   WOULD_BLOCK and all failures report zero; OK reports a positive prefix. */
efrp_result_t efrp_stream_write(efrp_transport_t *transport, efrp_stream_id_t id,
                               const uint8_t *bytes, size_t length, size_t *written);
/* Credit is returned only for bytes actually copied to caller. EOF follows
   remote FIN after all preceding buffered data. Reset never masquerades EOF. */
efrp_result_t efrp_stream_read(efrp_transport_t *transport, efrp_stream_id_t id,
                              uint8_t *bytes, size_t capacity, size_t *read);
/* Idempotent one-direction FIN; read remains live. Retries on bounded queue
   pressure without losing bytes or creating a second FIN. */
efrp_result_t efrp_stream_close_write(efrp_transport_t *transport, efrp_stream_id_t id);
efrp_result_t efrp_stream_reset(efrp_transport_t *transport, efrp_stream_id_t id);
/* Requires both FIN and a drained receive buffer, or reset. QUIC additionally
   waits for stream_close2 so ngtcp2 no longer borrows transmit data. Pending
   protocol references return WOULD_BLOCK and retain the slot. */
efrp_result_t efrp_stream_release(efrp_transport_t *transport, efrp_stream_id_t id);
/* Only after transport EOF and all caller control/AEAD buffers are drained.
   Pending backend input returns WOULD_BLOCK; a partial TCP/Yamux frame then
   returns TRUNCATED. Other work receive rings do not block structural finish. */
efrp_result_t efrp_stream_finish(const efrp_transport_t *transport);
