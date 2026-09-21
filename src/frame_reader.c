// SPDX-License-Identifier: Apache-2.0
// Protocol reference: fatedier/frp v0.71.0 pkg/proto/wire/wire.go.
// Independently structured incremental, caller-owned C implementation.
#include "esp_frp_wire.h"
#include <string.h>

const uint8_t efrp_wire_magic[EFRP_WIRE_MAGIC_SIZE] = {'F', 'R', 'P', 0, 2, '\r', '\n'};

static bool valid_kind(unsigned kind)
{
    return kind == EFRP_CLIENT_HELLO || kind == EFRP_SERVER_HELLO || kind == EFRP_MESSAGE;
}

efrp_result_t efrp_wire_init(efrp_wire_reader_t *r, uint8_t *storage,
                            size_t capacity, bool expect_magic,
                            efrp_frame_handler_t handler, void *context)
{
    if (!r || !storage || !capacity || capacity > EFRP_WIRE_MAX_PAYLOAD || !handler)
        return EFRP_INVALID_ARGUMENT;
    *r = (efrp_wire_reader_t){.payload = storage, .capacity = capacity,
        .expect_magic = expect_magic, .handler = handler, .context = context};
    return EFRP_OK;
}

efrp_result_t efrp_wire_header(efrp_frame_kind_t kind, size_t length, uint8_t out[8])
{
    if (!out || !valid_kind(kind)) return EFRP_INVALID_ARGUMENT;
    if (length > EFRP_WIRE_MAX_PAYLOAD) return EFRP_CAPACITY_EXCEEDED;
    out[0] = (uint8_t)((unsigned)kind >> 8);
    out[1] = (uint8_t)kind;
    out[2] = out[3] = 0;
    out[4] = (uint8_t)(length >> 24);
    out[5] = (uint8_t)(length >> 16);
    out[6] = (uint8_t)(length >> 8);
    out[7] = (uint8_t)length;
    return EFRP_OK;
}

efrp_result_t efrp_wire_feed(efrp_wire_reader_t *r, const uint8_t *bytes,
                            size_t length, size_t *consumed)
{
    if (consumed) *consumed = 0;
    if (!r || !consumed || (!bytes && length) || !r->handler || !r->payload)
        return EFRP_INVALID_ARGUMENT;
    if (r->failure != EFRP_OK) return r->failure;
    while (*consumed < length) {
        if (r->expect_magic && r->magic_used < EFRP_WIRE_MAGIC_SIZE) {
            if (bytes[(*consumed)++] != efrp_wire_magic[r->magic_used++])
                return r->failure = EFRP_PROTOCOL_ERROR;
            continue;
        }
        if (r->header_used < EFRP_WIRE_HEADER_SIZE) {
            r->header[r->header_used++] = bytes[(*consumed)++];
            if (r->header_used != EFRP_WIRE_HEADER_SIZE) continue;
            unsigned kind = ((unsigned)r->header[0] << 8) | r->header[1];
            if (!valid_kind(kind) || r->header[2] || r->header[3])
                return r->failure = EFRP_PROTOCOL_ERROR;
            r->kind = (efrp_frame_kind_t)kind;
            r->payload_expected = ((uint32_t)r->header[4] << 24) |
                ((uint32_t)r->header[5] << 16) | ((uint32_t)r->header[6] << 8) | r->header[7];
            if (r->payload_expected > r->capacity)
                return r->failure = EFRP_CAPACITY_EXCEEDED;
        }
        size_t remaining = r->payload_expected - r->payload_used;
        size_t available = length - *consumed;
        size_t take = remaining < available ? remaining : available;
        if (take) memcpy(r->payload + r->payload_used, bytes + *consumed, take);
        r->payload_used += take;
        *consumed += take;
        if (r->payload_used == r->payload_expected) {
            if (!r->handler(r->context, r->kind, r->payload, r->payload_expected))
                return r->failure = EFRP_CALLBACK_REJECTED;
            r->header_used = r->payload_used = r->payload_expected = 0;
        }
    }
    return EFRP_OK;
}

efrp_result_t efrp_wire_finish(const efrp_wire_reader_t *r)
{
    if (!r || !r->handler || !r->payload) return EFRP_INVALID_ARGUMENT;
    if (r->failure != EFRP_OK) return r->failure;
    if ((r->expect_magic && r->magic_used != EFRP_WIRE_MAGIC_SIZE) || r->header_used)
        return EFRP_TRUNCATED;
    return EFRP_OK;
}
