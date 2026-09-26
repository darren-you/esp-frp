// SPDX-License-Identifier: Apache-2.0
#include "work_internal.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void run(efrp_work_phase_t phase, bool incoming, bool outgoing, bool partial,
    uint64_t now, uint64_t deadline, unsigned expected_source)
{
    efrp_yamux_t mux;
    efrp_yamux_init(&mux, 0);
    uint32_t id = 0;
    assert(efrp_yamux_open(&mux, &id) == EFRP_OK);
    efrp_work_set_t work;
    efrp_session_config_t config = {.local_ipv4 = {127, 0, 0, 1}, .local_port = 1};
    efrp_work_init(&work, &config, "timeout-fixture");
    efrp_work_stream_t *stream = calloc(1, sizeof *stream);
    assert(stream); work.streams[0] = stream;
    stream->phase = phase;
    stream->stream_id = id;
    stream->deadline = deadline;
    stream->last_activity = 1;
    stream->partial_header = partial;
    if (incoming) { stream->incoming_used = 64; stream->incoming_offset = 16; }
    if (outgoing) { stream->outgoing_used = 64; stream->outgoing_offset = 16; }
    assert(efrp_work_step(&work, &mux, now, "unused", NULL, 0, 1) == EFRP_OK);
    efrp_work_status_t status;
    efrp_work_status(&work, &status);
    assert(status.failed == 1 && status.last_error == EFRP_TIMEOUT);
    assert(status.active == 0 && status.waiting == 0 && status.cleaning == 0);
    assert(!work.streams[0] && efrp_work_cancel(&work));
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    assert((unsigned)status.timeout_source == expected_source);
    assert(status.timeout_stream_id == id);
    assert(status.timeout_age_ms == now);
    assert(status.timeout_incoming_bytes == (incoming ? 48 : 0));
    assert(status.timeout_outgoing_bytes == (outgoing ? 48 : 0));
#else
    (void)expected_source;
#endif
    efrp_yamux_destroy(&mux);
}

int main(void)
{
    run(EFRP_WORK_ACTIVE, true, false, false, EFRP_YAMUX_STALL_MS, 0,
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        EFRP_WORK_TIMEOUT_INCOMING_LOCAL);
#else
        0);
#endif
    run(EFRP_WORK_ACTIVE, false, true, false, EFRP_YAMUX_STALL_MS, 0,
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        EFRP_WORK_TIMEOUT_OUTGOING_YAMUX);
#else
        0);
#endif
    run(EFRP_WORK_SENDING, false, false, false, EFRP_SESSION_RESPONSE_MS, EFRP_SESSION_RESPONSE_MS,
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        EFRP_WORK_TIMEOUT_HANDSHAKE_SEND);
#else
        0);
#endif
    run(EFRP_WORK_WAITING, false, false, true, EFRP_SESSION_RESPONSE_MS, EFRP_SESSION_RESPONSE_MS,
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        EFRP_WORK_TIMEOUT_HANDSHAKE_FRAME);
#else
        0);
#endif
    return 0;
}
