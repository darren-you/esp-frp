// SPDX-License-Identifier: Apache-2.0
/* Deterministic TLS application I/O fixture. Production Yamux pump/parser are
 * used unchanged; TLS cryptographic interoperability is a separate real gate. */
#include "esp_frp_transport.h"
#include "esp_frp_yamux.h"
#include "stream_internal.h"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct efrp_tls {
    uint8_t input[4096]; size_t length, offset;
    efrp_tls_status_t status; bool eof, fail, cancelled;
};
efrp_result_t efrp_tls_status(const efrp_tls_t *tls, efrp_tls_status_t *out) { *out = tls->status; return EFRP_OK; }
efrp_result_t efrp_tls_step(efrp_tls_t *tls, uint64_t now)
{
    (void)now;
    if (tls->fail) { tls->status.state = EFRP_TLS_FAILED; tls->status.library_error = -1234; tls->status.verify_flags = 0x42; return EFRP_TLS_ERROR; }
    return tls->eof && tls->offset == tls->length ? EFRP_EOF : EFRP_OK;
}
efrp_result_t efrp_tls_read(efrp_tls_t *tls, uint64_t now, uint8_t *p, size_t n, size_t *used)
{
    (void)now; *used = 0; size_t available = tls->length - tls->offset;
    if (!available) return tls->eof ? EFRP_EOF : EFRP_WOULD_BLOCK;
    if (n > available) n = available;
    memcpy(p, tls->input + tls->offset, n); tls->offset += n; *used = n; return EFRP_OK;
}
efrp_result_t efrp_tls_write(efrp_tls_t *tls, uint64_t now, const uint8_t *p, size_t n, size_t *used)
{ (void)tls; (void)now; (void)p; *used = n; return EFRP_OK; }
efrp_result_t efrp_tls_cancel(efrp_tls_t *tls)
{ tls->cancelled = true; tls->status.library_error = 0; tls->status.verify_flags = UINT32_MAX; return EFRP_OK; }
static void big32(uint8_t *p, uint32_t value)
{ p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16); p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value; }
static void frame(efrp_tls_t *tls, uint8_t type, uint8_t flags, uint32_t id, size_t length)
{
    assert(tls->length + 12 + length <= sizeof tls->input);
    uint8_t *p = tls->input + tls->length; memset(p, 0, 12); p[1] = type; p[3] = flags;
    big32(p + 4, id); big32(p + 8, (uint32_t)length);
    for (size_t i = 0; i < length; ++i) p[12 + i] = (uint8_t)i;
    tls->length += 12 + length;
}
static void eof_tail(bool truncated)
{
    efrp_tls_t tls = {.status = {.state = EFRP_TLS_OPEN, .verify_flags = 0}};
    efrp_transport_t *transport = NULL; assert(efrp_transport_yamux_create(&tls, 100, &transport) == EFRP_OK);
    efrp_stream_id_t control, work; assert(efrp_stream_open(transport, &control) == EFRP_OK);
    assert(efrp_stream_open(transport, &work) == EFRP_OK); assert(control == 1 && work == 3);
    frame(&tls, 1, 2, 1, 0); frame(&tls, 1, 2, 3, 0);
    frame(&tls, 0, 0, 1, 5); frame(&tls, 0, 4, 3, 1500);
    if (truncated) { memset(tls.input + tls.length, 0, 4); tls.length += 4; }
    tls.eof = true;
    assert(efrp_transport_step(transport, 101) == EFRP_OK);
    efrp_transport_status_t status; assert(efrp_transport_status(transport, &status) == EFRP_OK);
    assert(status.eof && efrp_stream_finish(transport) == EFRP_WOULD_BLOCK);
    uint8_t bytes[1024]; size_t used;
    assert(efrp_stream_read(transport, control, bytes, sizeof bytes, &used) == EFRP_OK && used == 5);
    assert(efrp_stream_read(transport, control, bytes, sizeof bytes, &used) == EFRP_WOULD_BLOCK && !used);
    /* Raw TLS EOF must never fabricate a control stream FIN. */
    assert(efrp_stream_read(transport, work, bytes, sizeof bytes, &used) == EFRP_OK && used == 1024);
    for (size_t i = 0; i < used; ++i) assert(bytes[i] == (uint8_t)i);
    assert(efrp_transport_step(transport, 102) == EFRP_EOF);
    assert(efrp_stream_finish(transport) == (truncated ? EFRP_TRUNCATED : EFRP_OK));
    /* Complete framing is allowed despite the other work's unread tail. */
    assert(efrp_stream_read(transport, work, bytes, sizeof bytes, &used) == EFRP_OK && used == 476);
    for (size_t i = 0; i < used; ++i) assert(bytes[i] == (uint8_t)(i + 1024));
    assert(efrp_stream_read(transport, work, bytes, sizeof bytes, &used) == EFRP_EOF && !used);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport && tls.cancelled);
}
static void diagnostics_and_deadline(void)
{
    efrp_tls_t tls = {.status = {.state = EFRP_TLS_OPEN, .verify_flags = 0}};
    efrp_transport_t *transport = NULL; assert(efrp_transport_yamux_create(&tls, 100, &transport) == EFRP_OK);
    efrp_transport_status_t status; assert(efrp_transport_status(transport, &status) == EFRP_OK);
    assert(status.next_deadline_ms == UINT64_MAX);
    efrp_stream_id_t id; assert(efrp_stream_open(transport, &id) == EFRP_OK);
    assert(efrp_transport_status(transport, &status) == EFRP_OK);
    assert(status.next_deadline_ms == 100 + EFRP_YAMUX_IO_TIMEOUT_MS); /* Pending SYN output owns the earlier deadline. */
    tls.fail = true; assert(efrp_transport_step(transport, 101) == EFRP_TLS_ERROR);
    assert(efrp_transport_status(transport, &status) == EFRP_OK);
    assert(status.kind == EFRP_TRANSPORT_YAMUX_TLS && status.tls_error == -1234 && status.verify_flags == 0x42);
    assert(status.next_deadline_ms == UINT64_MAX && tls.cancelled);
    assert(efrp_transport_cancel(transport) == EFRP_OK);
    assert(efrp_transport_status(transport, &status) == EFRP_OK && status.kind == EFRP_TRANSPORT_YAMUX_TLS);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
}
int main(void)
{ eof_tail(false); eof_tail(true); diagnostics_and_deadline(); puts("Yamux transport EOF/backpressure/truncation and diagnostics/deadline passed"); return 0; }
