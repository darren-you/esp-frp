// SPDX-License-Identifier: Apache-2.0
// Independently implemented pull-based client for the Yamux wire specification.
// No upstream implementation is vendored or translated. See source provenance.
#include "esp_frp_yamux.h"
#include <string.h>

enum { DATA = 0, WINDOW = 1, PING = 2, GOAWAY = 3 };
enum { SYN = 1, ACK = 2, FIN = 4, RST = 8 };

static uint32_t load32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void store32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}
static void header(uint8_t *p, uint8_t type, uint16_t flags, uint32_t id, uint32_t value)
{
    p[0] = 0; p[1] = type; p[2] = (uint8_t)(flags >> 8); p[3] = (uint8_t)flags;
    store32(p + 4, id); store32(p + 8, value);
}
static efrp_result_t ready(const efrp_yamux_t *m)
{
    return m ? m->failure : EFRP_INVALID_ARGUMENT;
}
static efrp_result_t fail(efrp_yamux_t *m, efrp_result_t error)
{
    m->failure = error;
    return error;
}
#if defined(EFRP_LAB_TIMEOUT_TRACE)
static void trace_timeout(efrp_yamux_t *m, efrp_yamux_timeout_source_t source,
    uint32_t stream_id, uint64_t age, size_t pending)
{
    m->timeout_source = source;
    m->timeout_stream_id = stream_id;
    m->timeout_age_ms = age > UINT32_MAX ? UINT32_MAX : (uint32_t)age;
    m->timeout_pending_bytes = pending > UINT32_MAX ? UINT32_MAX : (uint32_t)pending;
}
#define TRACE_TIMEOUT(m, source, id, age, pending) trace_timeout((m), (source), (id), (age), (pending))
#else
#define TRACE_TIMEOUT(m, source, id, age, pending) ((void)0)
#endif
static efrp_yamux_stream_t *stream(efrp_yamux_t *m, uint32_t id)
{
    if (id) for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i)
        if (m->streams[i].id == id) return &m->streams[i];
    return NULL;
}
static efrp_result_t queue(efrp_yamux_t *m, uint8_t type, uint16_t flags, uint32_t id, uint32_t value)
{
    if (m->control_count == EFRP_YAMUX_CONTROL_SLOTS) return EFRP_WOULD_BLOCK;
    size_t slot = (m->control_head + m->control_count) % EFRP_YAMUX_CONTROL_SLOTS;
    header(m->controls[slot], type, flags, id, value);
    if (!m->control_count && !m->output_used) m->output_progress_ms = m->now_ms;
    ++m->control_count;
    return EFRP_OK;
}
static void reset_state(efrp_yamux_t *m, efrp_yamux_stream_t *s)
{
    s->reset = true; s->used = s->head = 0; s->return_credit = 0; s->blocked = false;
    if (m->frame_active && m->frame_id == s->id && !m->frame_discard) {
        m->frame_discard = true;
        m->drain_started_ms = m->now_ms;
    }
    memset(s->ring, 0, sizeof s->ring);
}

void efrp_yamux_init(efrp_yamux_t *m, uint64_t now)
{
    if (m) *m = (efrp_yamux_t){.next_id = 1, .now_ms = now};
}

efrp_result_t efrp_yamux_open(efrp_yamux_t *m, uint32_t *id)
{
    if (id) *id = 0;
    if (!m || !id) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    if (m->local_goaway || m->remote_goaway) return EFRP_SESSION_CLOSED;
    if (!m->next_id) return EFRP_CAPACITY_EXCEEDED;
    efrp_yamux_stream_t *s = NULL;
    for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i) if (!m->streams[i].id) { s = &m->streams[i]; break; }
    if (!s) return EFRP_CAPACITY_EXCEEDED;
    efrp_result_t result = queue(m, WINDOW, SYN, m->next_id, 0);
    if (result != EFRP_OK) return result;
    *s = (efrp_yamux_stream_t){.id = m->next_id, .send_credit = EFRP_YAMUX_INITIAL_WINDOW,
        .receive_credit = EFRP_YAMUX_INITIAL_WINDOW, .opened_ms = m->now_ms};
    *id = s->id;
    m->next_id = s->id == UINT32_MAX ? 0 : s->id + 2;
    return EFRP_OK;
}

efrp_result_t efrp_yamux_info(const efrp_yamux_t *m, uint32_t id, efrp_yamux_stream_info_t *info)
{
    if (!m || !info || !id) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i) {
        const efrp_yamux_stream_t *s = &m->streams[i];
        if (s->id == id) {
            *info = (efrp_yamux_stream_info_t){.readable_bytes = s->used, .send_credit = s->send_credit,
                .acknowledged = s->acknowledged, .local_fin = s->local_fin,
                .remote_fin = s->remote_fin, .reset = s->reset};
            return EFRP_OK;
        }
    }
    return EFRP_INVALID_ARGUMENT;
}

efrp_result_t efrp_yamux_output(efrp_yamux_t *m, const uint8_t **bytes, size_t *length)
{
    if (bytes) *bytes = NULL;
    if (length) *length = 0;
    if (!m || !bytes || !length) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    if (!m->output_used) {
        if (m->control_count) {
            memcpy(m->output, m->controls[m->control_head], EFRP_YAMUX_HEADER_BYTES);
            m->control_head = (m->control_head + 1) % EFRP_YAMUX_CONTROL_SLOTS;
            --m->control_count;
            m->output_used = EFRP_YAMUX_HEADER_BYTES;
        } else for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i) {
            unsigned slot = (m->credit_cursor + i) % EFRP_YAMUX_STREAMS;
            efrp_yamux_stream_t *s = &m->streams[slot];
            if (s->id && !s->reset && !s->remote_fin && s->return_credit) {
                header(m->output, WINDOW, 0, s->id, s->return_credit);
                m->output_grant_id = s->id; m->output_grant_bytes = s->return_credit;
                s->return_credit = 0;
                m->output_used = EFRP_YAMUX_HEADER_BYTES;
                m->output_progress_ms = m->now_ms;
                m->credit_cursor = (slot + 1) % EFRP_YAMUX_STREAMS;
                m->prefer_data = true;
                break;
            }
        }
    }
    if (!m->output_used) return EFRP_WOULD_BLOCK;
    *bytes = m->output + m->output_offset;
    *length = m->output_used - m->output_offset;
    return EFRP_OK;
}

efrp_result_t efrp_yamux_consume_output(efrp_yamux_t *m, size_t length)
{
    if (!m || length > m->output_used - m->output_offset) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    if (!length) return EFRP_OK;
    m->output_offset += length; m->output_progress_ms = m->now_ms;
    if (m->output_offset == m->output_used) {
        efrp_yamux_stream_t *s = stream(m, m->output_grant_id);
        if (s && !s->reset) {
            if (m->output_grant_bytes > EFRP_YAMUX_INITIAL_WINDOW - s->receive_credit)
                return fail(m, EFRP_PROTOCOL_ERROR);
            s->receive_credit += m->output_grant_bytes;
        }
        m->output_grant_id = m->output_grant_bytes = 0;
        m->output_offset = m->output_used = 0;
    }
    return EFRP_OK;
}

efrp_result_t efrp_yamux_write(efrp_yamux_t *m, uint32_t id,
                              const uint8_t *bytes, size_t length, size_t *written)
{
    if (written) *written = 0;
    if (!m || !written || (!bytes && length)) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    efrp_yamux_stream_t *s = stream(m, id);
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_STREAM_RESET;
    if (s->local_fin) return EFRP_INVALID_STATE;
    if (!length) return EFRP_OK;
    const uint8_t *pending; size_t pending_length;
    /* Mandatory control frames keep priority. Automatic credit grants yield
     * one free output slot to DATA; otherwise steady reads can forever create
     * another WindowUpdate before any application write gets accepted. */
    if (((m->output_used || m->control_count || !m->prefer_data) &&
         efrp_yamux_output(m, &pending, &pending_length) == EFRP_OK) || !s->send_credit)
        return EFRP_WOULD_BLOCK;
    size_t n = length < EFRP_YAMUX_RING_BYTES ? length : EFRP_YAMUX_RING_BYTES;
    if (n > s->send_credit) n = s->send_credit;
    header(m->output, DATA, 0, id, (uint32_t)n);
    memcpy(m->output + EFRP_YAMUX_HEADER_BYTES, bytes, n);
    m->output_used = EFRP_YAMUX_HEADER_BYTES + n; m->output_progress_ms = m->now_ms;
    m->prefer_data = false;
    s->send_credit -= (uint32_t)n; *written = n;
    return EFRP_OK;
}

efrp_result_t efrp_yamux_read(efrp_yamux_t *m, uint32_t id,
                             uint8_t *bytes, size_t capacity, size_t *read)
{
    if (read) *read = 0;
    if (!m || !read || !bytes || !capacity) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    efrp_yamux_stream_t *s = stream(m, id);
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_STREAM_RESET;
    if (!s->used) return s->remote_fin ? EFRP_EOF : EFRP_WOULD_BLOCK;
    size_t n = capacity < s->used ? capacity : s->used;
    size_t first = EFRP_YAMUX_RING_BYTES - s->head;
    if (first > n) first = n;
    memcpy(bytes, s->ring + s->head, first);
    memcpy(bytes + first, s->ring, n - first);
    s->head = (s->head + n) % EFRP_YAMUX_RING_BYTES;
    s->used -= n; s->return_credit += (uint32_t)n; s->blocked = false;
    *read = n;
    return EFRP_OK;
}

efrp_result_t efrp_yamux_close_write(efrp_yamux_t *m, uint32_t id)
{
    if (ready(m) != EFRP_OK) return ready(m);
    efrp_yamux_stream_t *s = stream(m, id);
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_STREAM_RESET;
    if (s->local_fin) return EFRP_OK;
    efrp_result_t result = queue(m, WINDOW, FIN, id, 0);
    if (result == EFRP_OK) s->local_fin = true;
    return result;
}

efrp_result_t efrp_yamux_reset(efrp_yamux_t *m, uint32_t id)
{
    if (ready(m) != EFRP_OK) return ready(m);
    efrp_yamux_stream_t *s = stream(m, id);
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_OK;
    efrp_result_t result = queue(m, WINDOW, RST, id, 0);
    if (result == EFRP_OK) reset_state(m, s);
    return result;
}

efrp_result_t efrp_yamux_release(efrp_yamux_t *m, uint32_t id)
{
    if (ready(m) != EFRP_OK) return ready(m);
    efrp_yamux_stream_t *s = stream(m, id);
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (!s->reset && !(s->local_fin && s->remote_fin && !s->used)) return EFRP_INVALID_STATE;
    if (m->frame_active && m->frame_id == id) m->frame_discard = true;
    memset(s, 0, sizeof *s);
    return EFRP_OK;
}

efrp_result_t efrp_yamux_ping(efrp_yamux_t *m, uint32_t id)
{
    if (ready(m) != EFRP_OK) return ready(m);
    if (m->ping_pending) return EFRP_WOULD_BLOCK;
    efrp_result_t result = queue(m, PING, SYN, 0, id);
    if (result == EFRP_OK) { m->ping_pending = true; m->ping_id = id; m->ping_started_ms = m->now_ms; }
    return result;
}

efrp_result_t efrp_yamux_goaway(efrp_yamux_t *m)
{
    if (ready(m) != EFRP_OK) return ready(m);
    if (m->local_goaway) return EFRP_OK;
    efrp_result_t result = queue(m, GOAWAY, 0, 0, 0);
    if (result == EFRP_OK) m->local_goaway = true;
    return result;
}

static void end_frame(efrp_yamux_t *m)
{
    efrp_yamux_stream_t *s = stream(m, m->frame_id);
    if (s && !s->reset && (m->frame_flags & FIN)) s->remote_fin = true;
    m->frame_active = false; m->header_used = 0;
}

static efrp_result_t start_frame(efrp_yamux_t *m)
{
    uint8_t type = m->header[1];
    uint16_t flags = (uint16_t)(((uint16_t)m->header[2] << 8) | m->header[3]);
    uint32_t id = load32(m->header + 4), value = load32(m->header + 8);
    if (m->header[0] || type > GOAWAY || (flags & ~15u)) return fail(m, EFRP_PROTOCOL_ERROR);
    if (type == PING) {
        if (id || (flags != SYN && flags != ACK)) return fail(m, EFRP_PROTOCOL_ERROR);
        if (flags == SYN) {
            efrp_result_t result = queue(m, PING, ACK, 0, value);
            if (result != EFRP_OK) return result;
        } else if (m->ping_pending && value == m->ping_id) m->ping_pending = false;
        else return fail(m, EFRP_PROTOCOL_ERROR);
        m->header_used = 0;
        return EFRP_OK;
    }
    if (type == GOAWAY) {
        if (id || flags || value > 2) return fail(m, EFRP_PROTOCOL_ERROR);
        if (value) return fail(m, EFRP_SESSION_CLOSED);
        m->remote_goaway = true; m->header_used = 0;
        return EFRP_OK;
    }
    if (!id || ((flags & (SYN | ACK)) == (SYN | ACK)) || ((flags & (FIN | RST)) == (FIN | RST)))
        return fail(m, EFRP_PROTOCOL_ERROR);
    efrp_yamux_stream_t *s = stream(m, id);
    if (flags & SYN) {
        if ((id & 1u) || id <= m->peer_last_id || (flags & RST)) return fail(m, EFRP_PROTOCOL_ERROR);
        efrp_result_t result = queue(m, WINDOW, RST, id, 0);
        if (result != EFRP_OK) return result;
        m->peer_last_id = id;
    } else if ((id & 1u) ? (m->next_id && id >= m->next_id) : id > m->peer_last_id)
        return fail(m, EFRP_PROTOCOL_ERROR);
    if (s && !s->reset) {
        if ((flags & ACK) && s->acknowledged) return fail(m, EFRP_PROTOCOL_ERROR);
        if (!s->acknowledged && !(flags & (ACK | RST))) return fail(m, EFRP_PROTOCOL_ERROR);
        if (s->remote_fin && !(flags & RST) && (type == DATA || (flags & FIN))) return fail(m, EFRP_PROTOCOL_ERROR);
        if (type == DATA && value > s->receive_credit) return fail(m, EFRP_PROTOCOL_ERROR);
        if (type == WINDOW && value > UINT32_MAX - s->send_credit) return fail(m, EFRP_PROTOCOL_ERROR);
        if (flags & ACK) s->acknowledged = true;
        if (type == DATA) s->receive_credit -= value;
        else s->send_credit += value;
        if (flags & RST) reset_state(m, s);
    }
    bool discard = !s || s->reset;
    if (type == DATA && discard && (value > EFRP_YAMUX_INITIAL_WINDOW || value > EFRP_YAMUX_DISCARD_LIMIT - m->discarded_bytes))
        return fail(m, EFRP_PROTOCOL_ERROR);
    m->frame_id = id; m->frame_flags = flags; m->frame_discard = discard;
    if (discard) m->drain_started_ms = m->now_ms;
    m->frame_remaining = type == DATA ? value : 0;
    m->frame_active = true;
    if (!m->frame_remaining) end_frame(m);
    return EFRP_OK;
}

efrp_result_t efrp_yamux_feed(efrp_yamux_t *m, const uint8_t *bytes, size_t length, size_t *consumed)
{
    if (consumed) *consumed = 0;
    if (!m || !consumed || (!bytes && length)) return EFRP_INVALID_ARGUMENT;
    if (ready(m) != EFRP_OK) return ready(m);
    while (*consumed < length || (!m->frame_active && m->header_used == EFRP_YAMUX_HEADER_BYTES)) {
        if (!m->frame_active) {
            size_t n = EFRP_YAMUX_HEADER_BYTES - m->header_used;
            if (n > length - *consumed) n = length - *consumed;
            if (n) {
                if (!m->header_used) m->header_started_ms = m->now_ms;
                memcpy(m->header + m->header_used, bytes + *consumed, n);
                m->header_used += n; *consumed += n; m->input_progress_ms = m->now_ms;
            }
            if (m->header_used != EFRP_YAMUX_HEADER_BYTES) break;
            efrp_result_t result = start_frame(m);
            if (result != EFRP_OK) return result;
            if (!m->frame_active) continue;
        }
        if (*consumed == length) break;
        size_t n = length - *consumed;
        if (n > m->frame_remaining) n = m->frame_remaining;
        if (m->frame_discard) {
            if (n > EFRP_YAMUX_DISCARD_LIMIT - m->discarded_bytes) return fail(m, EFRP_PROTOCOL_ERROR);
            m->discarded_bytes += (uint32_t)n;
        } else {
            efrp_yamux_stream_t *s = stream(m, m->frame_id);
            if (!s) return fail(m, EFRP_INVALID_STATE);
            size_t available = EFRP_YAMUX_RING_BYTES - s->used;
            if (!available) {
                if (!s->blocked) { s->blocked = true; s->blocked_ms = m->now_ms; }
                return EFRP_WOULD_BLOCK;
            }
            if (n > available) n = available;
            size_t tail = (s->head + s->used) % EFRP_YAMUX_RING_BYTES;
            size_t first = EFRP_YAMUX_RING_BYTES - tail;
            if (first > n) first = n;
            memcpy(s->ring + tail, bytes + *consumed, first);
            memcpy(s->ring, bytes + *consumed + first, n - first);
            s->used += n;
        }
        *consumed += n; m->frame_remaining -= (uint32_t)n; m->input_progress_ms = m->now_ms;
        if (!m->frame_remaining) end_frame(m);
    }
    return EFRP_OK;
}

efrp_result_t efrp_yamux_finish(const efrp_yamux_t *m)
{
    if (ready(m) != EFRP_OK) return ready(m);
    return m->header_used || m->frame_active ? EFRP_TRUNCATED : EFRP_OK;
}

efrp_result_t efrp_yamux_tick(efrp_yamux_t *m, uint64_t now)
{
    if (ready(m) != EFRP_OK) return ready(m);
    if (now < m->now_ms) return fail(m, EFRP_INVALID_ARGUMENT);
    m->now_ms = now;
    if ((m->output_used || m->control_count) && now - m->output_progress_ms >= EFRP_YAMUX_IO_TIMEOUT_MS) {
        TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_OUTPUT, 0, now - m->output_progress_ms,
            m->output_used - m->output_offset + m->control_count * EFRP_YAMUX_HEADER_BYTES);
        return fail(m, EFRP_TIMEOUT);
    }
    if ((m->header_used || m->frame_active) && now - m->input_progress_ms >= EFRP_YAMUX_IO_TIMEOUT_MS) {
        TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_INPUT, m->frame_active ? m->frame_id : 0,
            now - m->input_progress_ms, m->frame_active ? m->frame_remaining : m->header_used);
        return fail(m, EFRP_TIMEOUT);
    }
    if (!m->frame_active && m->header_used && now - m->header_started_ms >= EFRP_YAMUX_IO_TIMEOUT_MS) {
        TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_HEADER, 0, now - m->header_started_ms, m->header_used);
        return fail(m, EFRP_TIMEOUT);
    }
    if (m->frame_active && m->frame_discard && now - m->drain_started_ms >= EFRP_YAMUX_IO_TIMEOUT_MS) {
        TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_DISCARD, m->frame_id,
            now - m->drain_started_ms, m->frame_remaining);
        return fail(m, EFRP_TIMEOUT);
    }
    if (m->ping_pending && now - m->ping_started_ms >= EFRP_YAMUX_IO_TIMEOUT_MS) {
        TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_PING, 0, now - m->ping_started_ms, 0);
        return fail(m, EFRP_TIMEOUT);
    }
    for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i) {
        efrp_yamux_stream_t *s = &m->streams[i];
        if (!s->id || s->reset) continue;
        if ((s->blocked && now - s->blocked_ms >= EFRP_YAMUX_STALL_MS) ||
            (!s->acknowledged && now - s->opened_ms >= EFRP_YAMUX_OPEN_TIMEOUT_MS)) {
            if (s->blocked)
                TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_RING, s->id, now - s->blocked_ms, s->used);
            else
                TRACE_TIMEOUT(m, EFRP_YAMUX_TIMEOUT_OPEN, s->id, now - s->opened_ms, 0);
            if (efrp_yamux_reset(m, s->id) != EFRP_OK) return fail(m, EFRP_CAPACITY_EXCEEDED);
        }
    }
    return EFRP_OK;
}
