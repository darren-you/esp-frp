// SPDX-License-Identifier: Apache-2.0
#include "stream_backend.h"
#include "esp_frp_yamux.h"
#include "crypto_backend.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    efrp_transport_t base;
    efrp_tls_t *tls;
    efrp_yamux_t mux;
    efrp_transport_status_t status;
    uint8_t input[1024];
    size_t input_used, input_offset, staged;
    uint64_t now;
    bool cancelled;
} efrp_yamux_transport_t;
_Static_assert(EFRP_TLS_TX_BYTES >= EFRP_YAMUX_HEADER_BYTES + EFRP_YAMUX_RING_BYTES,
    "strict TLS must stage one complete Yamux output");

static efrp_result_t stop(efrp_yamux_transport_t *t, efrp_result_t result)
{
    efrp_tls_status_t tls;
    if (efrp_tls_status(t->tls, &tls) == EFRP_OK) {
        t->status.tls_error = tls.library_error; t->status.verify_flags = tls.verify_flags;
    }
    t->status.result = result; t->status.state = EFRP_TRANSPORT_FAILED;
    t->status.next_deadline_ms = UINT64_MAX; t->status.want = EFRP_TRANSPORT_WANT_NONE;
    (void)efrp_tls_cancel(t->tls); return result;
}
static uint64_t next_deadline(const efrp_yamux_t *m)
{
    uint64_t at = UINT64_MAX;
#define DEADLINE(condition, start, duration) do { if ((condition) && (start) + (duration) < at) at = (start) + (duration); } while (0)
    DEADLINE(m->output_used || m->control_count, m->output_progress_ms, EFRP_YAMUX_IO_TIMEOUT_MS);
    DEADLINE(m->header_used || m->frame_active, m->input_progress_ms, EFRP_YAMUX_IO_TIMEOUT_MS);
    DEADLINE(!m->frame_active && m->header_used, m->header_started_ms, EFRP_YAMUX_IO_TIMEOUT_MS);
    DEADLINE(m->frame_active && m->frame_discard, m->drain_started_ms, EFRP_YAMUX_IO_TIMEOUT_MS);
    DEADLINE(m->ping_pending, m->ping_started_ms, EFRP_YAMUX_IO_TIMEOUT_MS);
    for (unsigned i = 0; i < EFRP_YAMUX_STREAMS; ++i) {
        const efrp_yamux_stream_t *s = &m->streams[i];
        if (!s->id || s->reset) continue;
        DEADLINE(s->blocked, s->blocked_ms, EFRP_YAMUX_STALL_MS);
        DEADLINE(!s->acknowledged, s->opened_ms, EFRP_YAMUX_OPEN_TIMEOUT_MS);
    }
#undef DEADLINE
    return at;
}
static efrp_result_t ready(const efrp_yamux_transport_t *t)
{ return t->cancelled ? EFRP_CANCELLED : t->status.result; }
static size_t pending_data(const efrp_yamux_t *m)
{
    /* Only DATA payload is accepted application data. Control headers and TLS
       staging are the same borrowed wire prefix and must not be counted twice. */
    if (m->output_used <= EFRP_YAMUX_HEADER_BYTES || m->output[1] != 0) return 0;
    size_t at = m->output_offset < EFRP_YAMUX_HEADER_BYTES ? EFRP_YAMUX_HEADER_BYTES : m->output_offset;
    return m->output_used - at;
}
static efrp_result_t step(efrp_transport_t *base, uint64_t now)
{
    efrp_yamux_transport_t *t = (efrp_yamux_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    if (now < t->now || now > UINT64_MAX - EFRP_YAMUX_OPEN_TIMEOUT_MS) return EFRP_INVALID_ARGUMENT;
    t->now = now;
    efrp_result_t result = efrp_yamux_tick(&t->mux, now);
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    t->status.timeout_source = (unsigned)t->mux.timeout_source;
    t->status.timeout_stream_id = t->mux.timeout_stream_id;
    t->status.timeout_age_ms = t->mux.timeout_age_ms;
    t->status.timeout_pending_bytes = t->mux.timeout_pending_bytes;
#endif
    if (result != EFRP_OK) return stop(t, result);
    for (unsigned turn = 0; turn < 8; ++turn) {
        if (!t->status.eof) {
            result = efrp_tls_step(t->tls, now);
            if (result == EFRP_EOF) t->status.eof = true;
            else if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return stop(t, result);
        }
        efrp_tls_status_t tls; result = efrp_tls_status(t->tls, &tls);
        if (result != EFRP_OK) return stop(t, result);
        t->status.tls_error = tls.library_error; t->status.verify_flags = tls.verify_flags;
        t->status.want = tls.want == EFRP_TLS_WANT_WRITE ? EFRP_TRANSPORT_WANT_WRITE : EFRP_TRANSPORT_WANT_READ;
        if (t->staged && !tls.pending_bytes && tls.state == EFRP_TLS_OPEN) {
            result = efrp_yamux_consume_output(&t->mux, t->staged);
            if (result != EFRP_OK) return stop(t, result);
            t->staged = 0;
        }
        if (!t->input_used && !t->status.eof) {
            size_t used = 0;
            result = efrp_tls_read(t->tls, now, t->input, sizeof t->input, &used);
            if (result == EFRP_EOF) t->status.eof = true;
            else if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return stop(t, result);
            t->input_used = used; t->input_offset = 0;
        }
        size_t consumed = 0;
        result = efrp_yamux_feed(&t->mux, t->input + t->input_offset, t->input_used - t->input_offset, &consumed);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return stop(t, result);
        t->input_offset += consumed;
        if (t->input_offset == t->input_used) t->input_offset = t->input_used = 0;
        if (!t->staged && !t->status.eof) {
            const uint8_t *p; size_t length;
            result = efrp_yamux_output(&t->mux, &p, &length);
            if (result == EFRP_OK) {
                result = efrp_tls_write(t->tls, now, p, length, &t->staged);
                if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return stop(t, result);
            } else if (result != EFRP_WOULD_BLOCK) return stop(t, result);
        }
    }
    t->status.pending_tx_bytes = pending_data(&t->mux);
    t->status.next_deadline_ms = next_deadline(&t->mux);
    if (t->status.eof && !t->input_used) {
        return EFRP_EOF;
    }
    return EFRP_OK;
}
static efrp_result_t status(const efrp_transport_t *base, efrp_transport_status_t *out)
{ const efrp_yamux_transport_t *t = (const efrp_yamux_transport_t *)base; *out = t->status;
  out->pending_tx_bytes = pending_data(&t->mux);
  if (ready(t) == EFRP_OK) out->next_deadline_ms = next_deadline(&t->mux);
  return EFRP_OK; }
static efrp_result_t open_stream(efrp_transport_t *base, efrp_stream_id_t *id)
{
    efrp_yamux_transport_t *t = (efrp_yamux_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    if (t->status.eof) return EFRP_SESSION_CLOSED;
    uint32_t native = 0; efrp_result_t r = efrp_yamux_open(&t->mux, &native);
    if (r == EFRP_OK) *id = native;
    return r;
}
static efrp_result_t info(const efrp_transport_t *base, efrp_stream_id_t id, efrp_stream_info_t *out)
{
    const efrp_yamux_transport_t *t = (const efrp_yamux_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    if (id > UINT32_MAX) return EFRP_INVALID_ARGUMENT;
    efrp_yamux_stream_info_t native;
    efrp_result_t r = efrp_yamux_info(&t->mux, (uint32_t)id, &native);
    if (r == EFRP_OK) *out = (efrp_stream_info_t){.readable_bytes = native.readable_bytes,
        .local_fin = native.local_fin, .remote_fin = native.remote_fin, .reset = native.reset};
    if (r == EFRP_OK && pending_data(&t->mux)) {
        const uint8_t *header = t->mux.output;
        uint32_t output_id = ((uint32_t)header[4] << 24) | ((uint32_t)header[5] << 16) |
            ((uint32_t)header[6] << 8) | header[7];
        if (output_id == id) out->pending_bytes = pending_data(&t->mux);
    }
    return r;
}
static efrp_result_t write_stream(efrp_transport_t *base, efrp_stream_id_t id, const uint8_t *p, size_t n, size_t *used)
{
    efrp_yamux_transport_t *t = (efrp_yamux_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    if (id > UINT32_MAX) return EFRP_INVALID_ARGUMENT;
    if (t->status.eof) return EFRP_SESSION_CLOSED;
    return efrp_yamux_write(&t->mux, (uint32_t)id, p, n, used);
}
static efrp_result_t read_stream(efrp_transport_t *base, efrp_stream_id_t id, uint8_t *p, size_t n, size_t *used)
{
    efrp_yamux_transport_t *t = (efrp_yamux_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    if (id > UINT32_MAX) return EFRP_INVALID_ARGUMENT;
    return efrp_yamux_read(&t->mux, (uint32_t)id, p, n, used);
}
#define STREAM_ACTION(name) \
static efrp_result_t name(efrp_transport_t *base, efrp_stream_id_t id) \
{ efrp_yamux_transport_t *t = (efrp_yamux_transport_t *)base; \
  if (ready(t) != EFRP_OK) return ready(t); \
  return id > UINT32_MAX ? EFRP_INVALID_ARGUMENT : efrp_yamux_##name(&t->mux, (uint32_t)id); }
STREAM_ACTION(close_write)
STREAM_ACTION(reset)
STREAM_ACTION(release)
#undef STREAM_ACTION
static efrp_result_t finish(const efrp_transport_t *base)
{
    const efrp_yamux_transport_t *t = (const efrp_yamux_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    return t->input_used ? EFRP_WOULD_BLOCK : efrp_yamux_finish(&t->mux);
}
static efrp_result_t cancel(efrp_transport_t *base)
{
    efrp_yamux_transport_t *t = (efrp_yamux_transport_t *)base;
    if (!t->cancelled) {
        t->cancelled = true; efrp_yamux_destroy(&t->mux);
        efrp_crypto_zero(t->input, sizeof t->input); t->input_used = t->input_offset = t->staged = 0;
        t->status = (efrp_transport_status_t){.kind = EFRP_TRANSPORT_YAMUX_TLS, .state = EFRP_TRANSPORT_CLOSED,
            .result = EFRP_CANCELLED, .next_deadline_ms = UINT64_MAX};
        (void)efrp_tls_cancel(t->tls);
    }
    return EFRP_OK;
}
static efrp_result_t destroy(efrp_transport_t **base)
{ (void)cancel(*base); efrp_crypto_zero(*base, sizeof(efrp_yamux_transport_t)); free(*base); *base = NULL; return EFRP_OK; }
static const efrp_stream_operations_t operations = {.step = step, .status = status,
    .open = open_stream, .info = info, .write = write_stream, .read = read_stream,
    .close_write = close_write, .reset = reset, .release = release, .finish = finish, .cancel = cancel, .destroy = destroy};
efrp_result_t efrp_transport_yamux_create(efrp_tls_t *tls, uint64_t now, efrp_transport_t **out)
{
    if (!out || !tls || now > UINT64_MAX - EFRP_YAMUX_OPEN_TIMEOUT_MS) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    efrp_tls_status_t state;
    if (efrp_tls_status(tls, &state) != EFRP_OK || state.state != EFRP_TLS_OPEN || state.pending_bytes)
        return EFRP_INVALID_STATE;
    efrp_yamux_transport_t *t = calloc(1, sizeof *t);
    if (!t) return EFRP_NO_MEMORY;
    t->base.operations = &operations; t->tls = tls; t->now = now;
    t->status = (efrp_transport_status_t){.kind = EFRP_TRANSPORT_YAMUX_TLS, .state = EFRP_TRANSPORT_OPEN, .next_deadline_ms = UINT64_MAX,
        .verify_flags = state.verify_flags};
    efrp_yamux_init(&t->mux, now); *out = &t->base; return EFRP_OK;
}
