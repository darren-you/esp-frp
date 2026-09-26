// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_frp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EFRP_YAMUX_STREAMS 4u
/* Incremental staging, not a DATA or receive-credit limit. */
#define EFRP_YAMUX_RING_BYTES 1024u
#define EFRP_YAMUX_HEADER_BYTES 12u
#define EFRP_YAMUX_INITIAL_WINDOW 262144u
#define EFRP_YAMUX_CONTROL_SLOTS 8u
#define EFRP_YAMUX_DISCARD_LIMIT (4u * EFRP_YAMUX_INITIAL_WINDOW)
#define EFRP_YAMUX_STALL_MS 2500u
#define EFRP_YAMUX_IO_TIMEOUT_MS 5000u
#define EFRP_YAMUX_OPEN_TIMEOUT_MS 10000u
#if defined(EFRP_LAB_TIMEOUT_TRACE)
typedef enum {
    EFRP_YAMUX_TIMEOUT_NONE = 0, EFRP_YAMUX_TIMEOUT_OUTPUT,
    EFRP_YAMUX_TIMEOUT_INPUT, EFRP_YAMUX_TIMEOUT_HEADER,
    EFRP_YAMUX_TIMEOUT_DISCARD, EFRP_YAMUX_TIMEOUT_PING,
    EFRP_YAMUX_TIMEOUT_RING, EFRP_YAMUX_TIMEOUT_OPEN
} efrp_yamux_timeout_source_t;
#endif

/* Private storage layout is exposed only for caller-owned/static allocation.
 * One owner; open allocates one receive ring per active stream. Destroy after
 * the final use (and before re-init) to release rings still owned by the mux.
 * No callbacks, timers, sockets or retained input pointers. */
typedef struct {
    uint32_t id, send_credit, receive_credit, return_credit;
    size_t head, used;
    uint64_t opened_ms, blocked_ms;
    bool acknowledged, local_fin, remote_fin, reset, blocked;
    uint8_t *ring;
} efrp_yamux_stream_t;

typedef struct {
    efrp_yamux_stream_t streams[EFRP_YAMUX_STREAMS];
    uint8_t controls[EFRP_YAMUX_CONTROL_SLOTS][EFRP_YAMUX_HEADER_BYTES];
    size_t control_head, control_count;
    uint8_t output[EFRP_YAMUX_HEADER_BYTES + EFRP_YAMUX_RING_BYTES];
    size_t output_used, output_offset;
    uint32_t output_grant_id, output_grant_bytes;
    unsigned credit_cursor;
    uint8_t header[EFRP_YAMUX_HEADER_BYTES];
    size_t header_used;
    uint32_t frame_id, frame_remaining, next_id, peer_last_id, discarded_bytes;
    uint16_t frame_flags;
    uint64_t now_ms, input_progress_ms, output_progress_ms, ping_started_ms;
    uint64_t header_started_ms, drain_started_ms;
    uint32_t ping_id;
    bool frame_active, frame_discard, local_goaway, remote_goaway, ping_pending, prefer_data;
    efrp_result_t failure;
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    /* Last timeout decision; read-only diagnostic, never consulted by flow control. */
    efrp_yamux_timeout_source_t timeout_source;
    uint32_t timeout_stream_id, timeout_age_ms, timeout_pending_bytes;
#endif
} efrp_yamux_t;

typedef struct {
    size_t readable_bytes;
    uint32_t send_credit;
    bool acknowledged, local_fin, remote_fin, reset;
} efrp_yamux_stream_info_t;

void efrp_yamux_init(efrp_yamux_t *mux, uint64_t now_ms);
void efrp_yamux_destroy(efrp_yamux_t *mux);
efrp_result_t efrp_yamux_tick(efrp_yamux_t *mux, uint64_t now_ms);
/* Only client-initiated odd stream IDs are opened. Incoming server SYN is
 * rejected by RST: FRP control/work streams are all client-initiated. */
efrp_result_t efrp_yamux_open(efrp_yamux_t *mux, uint32_t *stream_id);
efrp_result_t efrp_yamux_info(const efrp_yamux_t *mux, uint32_t stream_id,
                             efrp_yamux_stream_info_t *info);
/* Accepted bytes are copied; partial success is explicit in written/read.
 * read returns EOF only after FIN and all preceding DATA have been consumed. */
efrp_result_t efrp_yamux_write(efrp_yamux_t *mux, uint32_t stream_id,
                              const uint8_t *bytes, size_t length, size_t *written);
efrp_result_t efrp_yamux_read(efrp_yamux_t *mux, uint32_t stream_id,
                             uint8_t *bytes, size_t capacity, size_t *read);
efrp_result_t efrp_yamux_close_write(efrp_yamux_t *mux, uint32_t stream_id);
efrp_result_t efrp_yamux_reset(efrp_yamux_t *mux, uint32_t stream_id);
/* Free only reset streams or drained streams with FIN in both directions.
 * IDs are never reused; late DATA is drained within a session-wide byte limit. */
efrp_result_t efrp_yamux_release(efrp_yamux_t *mux, uint32_t stream_id);
efrp_result_t efrp_yamux_ping(efrp_yamux_t *mux, uint32_t opaque_id);
efrp_result_t efrp_yamux_goaway(efrp_yamux_t *mux);

/* Feed may consume a prefix then return WOULD_BLOCK. Retain the unconsumed
 * suffix and stop transport reads. Drain stream rings/output, then resume.
 * A zero-length feed also resumes a header waiting for a control queue slot. */
efrp_result_t efrp_yamux_feed(efrp_yamux_t *mux, const uint8_t *bytes,
                             size_t length, size_t *consumed);
efrp_result_t efrp_yamux_finish(const efrp_yamux_t *mux);
/* Output is immutable until consume_output; transmit only the exposed prefix.
 * Credit is replenished only after the complete WindowUpdate reaches transport.
 * On terminal failure close transport immediately; do not flush stale output. */
efrp_result_t efrp_yamux_output(efrp_yamux_t *mux, const uint8_t **bytes, size_t *length);
efrp_result_t efrp_yamux_consume_output(efrp_yamux_t *mux, size_t length);

#ifdef __cplusplus
}
#endif
