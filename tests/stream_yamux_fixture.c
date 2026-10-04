// SPDX-License-Identifier: Apache-2.0
#include "stream_yamux_fixture.h"
static efrp_yamux_t *raw(efrp_transport_t *base)
{ return ((efrp_test_yamux_transport_t *)base)->mux; }
static const efrp_yamux_t *raw_const(const efrp_transport_t *base)
{ return ((const efrp_test_yamux_transport_t *)base)->mux; }
static efrp_result_t step(efrp_transport_t *base, uint64_t now)
{ return efrp_yamux_tick(raw(base), now); }
static efrp_result_t status(const efrp_transport_t *base, efrp_transport_status_t *out)
{
    const efrp_yamux_t *mux = raw_const(base);
    *out = (efrp_transport_status_t){.state = EFRP_TRANSPORT_OPEN, .result = mux->failure,
        .next_deadline_ms = UINT64_MAX}; return EFRP_OK;
}
static efrp_result_t open_stream(efrp_transport_t *base, efrp_stream_id_t *id)
{
    uint32_t native = 0; efrp_result_t result = efrp_yamux_open(raw(base), &native);
    if (result == EFRP_OK) *id = native; return result;
}
static efrp_result_t info(const efrp_transport_t *base, efrp_stream_id_t id, efrp_stream_info_t *out)
{
    if (id > UINT32_MAX) return EFRP_INVALID_ARGUMENT;
    efrp_yamux_stream_info_t native;
    efrp_result_t result = efrp_yamux_info(raw_const(base), (uint32_t)id, &native);
    if (result == EFRP_OK) *out = (efrp_stream_info_t){.readable_bytes = native.readable_bytes,
        .local_fin = native.local_fin, .remote_fin = native.remote_fin, .reset = native.reset};
    return result;
}
static efrp_result_t write_stream(efrp_transport_t *base, efrp_stream_id_t id,
    const uint8_t *bytes, size_t length, size_t *used)
{ return id > UINT32_MAX ? EFRP_INVALID_ARGUMENT : efrp_yamux_write(raw(base), (uint32_t)id, bytes, length, used); }
static efrp_result_t read_stream(efrp_transport_t *base, efrp_stream_id_t id,
    uint8_t *bytes, size_t capacity, size_t *used)
{ return id > UINT32_MAX ? EFRP_INVALID_ARGUMENT : efrp_yamux_read(raw(base), (uint32_t)id, bytes, capacity, used); }
#define ACTION(name) \
static efrp_result_t name(efrp_transport_t *base, efrp_stream_id_t id) \
{ return id > UINT32_MAX ? EFRP_INVALID_ARGUMENT : efrp_yamux_##name(raw(base), (uint32_t)id); }
ACTION(close_write)
ACTION(reset)
ACTION(release)
#undef ACTION
static efrp_result_t finish(const efrp_transport_t *base)
{ return efrp_yamux_finish(raw_const(base)); }
static efrp_result_t cancel(efrp_transport_t *base)
{ efrp_yamux_destroy(raw(base)); return EFRP_OK; }
static efrp_result_t destroy(efrp_transport_t **base)
{ (void)cancel(*base); *base = NULL; return EFRP_OK; }
static const efrp_stream_operations_t operations = {.step = step, .status = status, .open = open_stream,
    .info = info, .write = write_stream, .read = read_stream, .close_write = close_write,
    .reset = reset, .release = release, .finish = finish, .cancel = cancel, .destroy = destroy};
void efrp_test_yamux_transport_init(efrp_test_yamux_transport_t *fixture, efrp_yamux_t *mux)
{ *fixture = (efrp_test_yamux_transport_t){.base = {.operations = &operations}, .mux = mux}; }
