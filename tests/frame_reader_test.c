// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_wire.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned count; size_t length; bool accept; } capture_t;
static bool capture(void *ctx, efrp_frame_kind_t kind, const uint8_t *data, size_t n)
{
    capture_t *c = ctx;
    assert(kind == EFRP_MESSAGE);
    for (size_t i = 0; i < n; ++i) assert(data[i] == (uint8_t)i);
    ++c->count;
    c->length = n;
    return c->accept;
}

int main(void)
{
    uint8_t *storage = malloc(EFRP_WIRE_MAX_PAYLOAD);
    uint8_t *input = malloc(EFRP_WIRE_MAX_PAYLOAD + 15);
    assert(storage && input);
    memcpy(input, efrp_wire_magic, 7);
    assert(efrp_wire_header(EFRP_MESSAGE, EFRP_WIRE_MAX_PAYLOAD, input + 7) == EFRP_OK);
    for (size_t i = 0; i < EFRP_WIRE_MAX_PAYLOAD; ++i) input[15 + i] = (uint8_t)i;
    /* Every possible header split, plus byte-at-a-time and many DATA-sized chunks. */
    for (size_t chunk = 1; chunk <= 8192; chunk = chunk < 16 ? chunk + 1 : chunk * 2) {
        efrp_wire_reader_t r;
        capture_t c = {.accept = true};
        assert(efrp_wire_init(&r, storage, EFRP_WIRE_MAX_PAYLOAD, true, capture, &c) == EFRP_OK);
        size_t offset = 0;
        while (offset < EFRP_WIRE_MAX_PAYLOAD + 15) {
            size_t take = EFRP_WIRE_MAX_PAYLOAD + 15 - offset;
            if (take > chunk) take = chunk;
            size_t used;
            assert(efrp_wire_feed(&r, input + offset, take, &used) == EFRP_OK && used == take);
            offset += used;
            if (offset < EFRP_WIRE_MAX_PAYLOAD + 15) assert(c.count == 0);
        }
        assert(c.count == 1 && c.length == EFRP_WIRE_MAX_PAYLOAD);
        assert(efrp_wire_finish(&r) == EFRP_OK);
    }
    efrp_wire_reader_t r;
    capture_t c = {.accept = true};
    size_t used;
    uint8_t joined[16];
    assert(efrp_wire_header(EFRP_MESSAGE, 0, joined) == EFRP_OK);
    memcpy(joined + 8, joined, 8);
    assert(efrp_wire_init(&r, storage, 16, false, capture, &c) == EFRP_OK);
    assert(efrp_wire_feed(&r, joined, sizeof joined, &used) == EFRP_OK);
    assert(c.count == 2 && used == 16);
    assert(efrp_wire_feed(&r, NULL, 0, &used) == EFRP_OK && used == 0);
    assert(efrp_wire_feed(&r, NULL, 1, &used) == EFRP_INVALID_ARGUMENT);
    assert(efrp_wire_header(EFRP_MESSAGE, 65537, joined) == EFRP_CAPACITY_EXCEEDED);
    /* Illegal flags, unknown frame kind, over-capacity, bad magic, incomplete EOF. */
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        assert(efrp_wire_init(&r, storage, 16, scenario == 3, capture, &c) == EFRP_OK);
        assert(efrp_wire_header(EFRP_MESSAGE, 0, joined) == EFRP_OK);
        if (scenario == 0) joined[3] = 1;
        if (scenario == 1) joined[1] = 99;
        if (scenario == 2) joined[7] = 17;
        efrp_result_t result = efrp_wire_feed(&r, joined, scenario == 4 ? 7 : 8, &used);
        if (scenario == 4) {
            assert(result == EFRP_OK && efrp_wire_finish(&r) == EFRP_TRUNCATED);
        } else {
            assert(result == (scenario == 2 ? EFRP_CAPACITY_EXCEEDED : EFRP_PROTOCOL_ERROR));
            assert(efrp_wire_feed(&r, joined, 8, &used) == result && used == 0);
        }
    }
    c.accept = false;
    assert(efrp_wire_init(&r, storage, 16, false, capture, &c) == EFRP_OK);
    assert(efrp_wire_header(EFRP_MESSAGE, 0, joined) == EFRP_OK);
    assert(efrp_wire_feed(&r, joined, 8, &used) == EFRP_CALLBACK_REJECTED);
    free(storage);
    free(input);
    return 0;
}
