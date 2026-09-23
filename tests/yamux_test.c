// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_yamux.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void frame(uint8_t *p, unsigned type, unsigned flags, uint32_t id, uint32_t value)
{
    p[0] = 0; p[1] = (uint8_t)type; p[2] = (uint8_t)(flags >> 8); p[3] = (uint8_t)flags;
    for (unsigned i = 0; i < 4; ++i) {
        p[4 + i] = (uint8_t)(id >> (24 - 8 * i));
        p[8 + i] = (uint8_t)(value >> (24 - 8 * i));
    }
}
static uint32_t word(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void flush(efrp_yamux_t *m)
{
    const uint8_t *p; size_t n;
    while (efrp_yamux_output(m, &p, &n) == EFRP_OK) {
        assert(p && n);
        assert(efrp_yamux_consume_output(m, n) == EFRP_OK);
    }
}
static void header_in(efrp_yamux_t *m, unsigned type, unsigned flags, uint32_t id, uint32_t value)
{
    uint8_t p[12]; size_t n;
    frame(p, type, flags, id, value);
    assert(efrp_yamux_feed(m, p, sizeof p, &n) == EFRP_OK && n == sizeof p);
}
static uint32_t open_stream(efrp_yamux_t *m)
{
    uint32_t id; assert(efrp_yamux_open(m, &id) == EFRP_OK);
    flush(m); header_in(m, 1, 2, id, 0);
    return id;
}
static void large_frames(void)
{
    uint8_t *input = malloc(EFRP_YAMUX_INITIAL_WINDOW + 24), out[4096];
    efrp_yamux_t *m = malloc(sizeof *m); assert(input && m);
    for (size_t step = 1; step <= EFRP_YAMUX_INITIAL_WINDOW; step = step < 16 ? step + 1 : step * 2) {
        efrp_yamux_init(m, 0); uint32_t id = open_stream(m);
        frame(input, 0, 4, id, EFRP_YAMUX_INITIAL_WINDOW);
        for (size_t i = 0; i < EFRP_YAMUX_INITIAL_WINDOW; ++i) input[12 + i] = (uint8_t)(i * 17u);
        frame(input + 12 + EFRP_YAMUX_INITIAL_WINDOW, 2, 1, 0, 0x12345678);
        size_t fed = 0, read = 0;
        while (fed < EFRP_YAMUX_INITIAL_WINDOW + 24) {
            size_t n = EFRP_YAMUX_INITIAL_WINDOW + 24 - fed, used;
            if (n > step) n = step;
            efrp_result_t r = efrp_yamux_feed(m, input + fed, n, &used);
            assert(r == EFRP_OK || r == EFRP_WOULD_BLOCK); fed += used;
            size_t got;
            while ((r = efrp_yamux_read(m, id, out, sizeof out, &got)) == EFRP_OK) {
                for (size_t i = 0; i < got; ++i) assert(out[i] == (uint8_t)((read + i) * 17u));
                read += got;
            }
            assert(r == EFRP_WOULD_BLOCK || (r == EFRP_EOF && read == EFRP_YAMUX_INITIAL_WINDOW));
            flush(m);
        }
        assert(read == EFRP_YAMUX_INITIAL_WINDOW && efrp_yamux_finish(m) == EFRP_OK);
        assert(efrp_yamux_release(m, id) == EFRP_INVALID_STATE);
        assert(efrp_yamux_close_write(m, id) == EFRP_OK);
        assert(efrp_yamux_release(m, id) == EFRP_OK); flush(m);
    }
    free(input); free(m);
}
static void window_and_output(void)
{
    efrp_yamux_t m; efrp_yamux_init(&m, 0); uint32_t id;
    assert(efrp_yamux_open(&m, &id) == EFRP_OK && id == 1);
    const uint8_t expected[] = {0,1,0,1,0,0,0,1,0,0,0,0};
    const uint8_t *p; size_t n, written;
    assert(efrp_yamux_output(&m, &p, &n) == EFRP_OK && n == 12 && !memcmp(p, expected, n));
    uint8_t payload[4096]; memset(payload, 0xa5, sizeof payload);
    assert(efrp_yamux_consume_output(&m, 13) == EFRP_INVALID_ARGUMENT);
    assert(efrp_yamux_consume_output(&m, 7) == EFRP_OK);
    assert(efrp_yamux_write(&m, id, payload, 1, &written) == EFRP_WOULD_BLOCK && !written);
    assert(efrp_yamux_output(&m, &p, &n) == EFRP_OK && n == 5 && !memcmp(p, expected + 7, n));
    flush(&m);
    /* Data is permitted before ACK, as in the protocol's zero-RTT stream open. */
    for (size_t total = 0; total < EFRP_YAMUX_INITIAL_WINDOW; total += written) {
        assert(efrp_yamux_write(&m, id, payload, sizeof payload, &written) == EFRP_OK && written == EFRP_YAMUX_RING_BYTES);
        assert(efrp_yamux_output(&m, &p, &n) == EFRP_OK && n == EFRP_YAMUX_HEADER_BYTES + written);
        assert(p[1] == 0 && word(p + 4) == id && word(p + 8) == written && !memcmp(p + 12, payload, written));
        flush(&m);
    }
    assert(efrp_yamux_write(&m, id, payload, 1, &written) == EFRP_WOULD_BLOCK);
    header_in(&m, 1, 2, id, 6 * 1024 * 1024 - EFRP_YAMUX_INITIAL_WINDOW);
    assert(efrp_yamux_write(&m, id, payload, 1, &written) == EFRP_OK && written == 1); flush(&m);
    uint8_t incoming[15]; frame(incoming, 0, 0, id, 3); memcpy(incoming + 12, "abc", 3);
    assert(efrp_yamux_feed(&m, incoming, sizeof incoming, &n) == EFRP_OK && n == 15);
    assert(m.streams[0].receive_credit == EFRP_YAMUX_INITIAL_WINDOW - 3);
    assert(efrp_yamux_read(&m, id, payload, sizeof payload, &n) == EFRP_OK && n == 3 && !memcmp(payload, "abc", 3));
    assert(efrp_yamux_output(&m, &p, &n) == EFRP_OK && n == 12 && p[1] == 1 && word(p + 8) == 3);
    assert(efrp_yamux_consume_output(&m, 11) == EFRP_OK);
    assert(m.streams[0].receive_credit == EFRP_YAMUX_INITIAL_WINDOW - 3);
    assert(efrp_yamux_consume_output(&m, 1) == EFRP_OK);
    assert(m.streams[0].receive_credit == EFRP_YAMUX_INITIAL_WINDOW);
    header_in(&m, 1, 4, id, 0);
    assert(efrp_yamux_read(&m, id, payload, sizeof payload, &n) == EFRP_EOF);
    assert(efrp_yamux_write(&m, id, payload, 1, &n) == EFRP_OK); flush(&m);
    assert(efrp_yamux_close_write(&m, id) == EFRP_OK);
    assert(efrp_yamux_write(&m, id, payload, 1, &n) == EFRP_INVALID_STATE);
    flush(&m); assert(efrp_yamux_release(&m, id) == EFRP_OK);
}
static void stalled_and_late_data(void)
{
    efrp_yamux_t m; efrp_yamux_init(&m, 0);
    uint32_t first = open_stream(&m), second = open_stream(&m);
    uint8_t input[8192 + 25], out[8]; size_t used, got;
    frame(input, 0, 4, first, 8192); memset(input + 12, 0xa7, 8192);
    frame(input + 8204, 0, 0, second, 1); input[8216] = 0x42;
    assert(efrp_yamux_feed(&m, input, sizeof input, &used) == EFRP_WOULD_BLOCK && used == 12 + EFRP_YAMUX_RING_BYTES);
    efrp_yamux_stream_info_t info;
    assert(efrp_yamux_info(&m, second, &info) == EFRP_OK && !info.readable_bytes);
    assert(efrp_yamux_tick(&m, 2499) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 2500) == EFRP_OK);
    assert(efrp_yamux_read(&m, first, out, sizeof out, &got) == EFRP_STREAM_RESET);
    assert(efrp_yamux_release(&m, first) == EFRP_OK);
    uint32_t third; assert(efrp_yamux_open(&m, &third) == EFRP_OK && third == 5);
    assert(efrp_yamux_feed(&m, input + used, sizeof input - used, &got) == EFRP_OK && got == sizeof input - used);
    assert(efrp_yamux_read(&m, second, out, sizeof out, &got) == EFRP_OK && got == 1 && out[0] == 0x42);
    assert(efrp_yamux_info(&m, third, &info) == EFRP_OK && !info.readable_bytes && !info.remote_fin);
    flush(&m);
    frame(input, 0, 0, first, 3); memcpy(input + 12, "old", 3);
    assert(efrp_yamux_feed(&m, input, 15, &used) == EFRP_OK && used == 15);
    assert(efrp_yamux_info(&m, third, &info) == EFRP_OK && !info.readable_bytes);
    assert(m.discarded_bytes == 8192 - EFRP_YAMUX_RING_BYTES + 3);
}
static void control_and_capacity(void)
{
    efrp_yamux_t m; efrp_yamux_init(&m, 0); uint32_t ids[4], extra;
    for (unsigned i = 0; i < 4; ++i) { ids[i] = open_stream(&m); assert(ids[i] == 1 + i * 2); }
    assert(efrp_yamux_open(&m, &extra) == EFRP_CAPACITY_EXCEEDED && !extra);
    for (unsigned i = 0; i < EFRP_YAMUX_CONTROL_SLOTS; ++i) header_in(&m, 2, 1, 0, i);
    uint8_t h[12]; size_t used; frame(h, 2, 1, 0, 999);
    assert(efrp_yamux_feed(&m, h, 12, &used) == EFRP_WOULD_BLOCK && used == 12);
    flush(&m);
    assert(efrp_yamux_feed(&m, NULL, 0, &used) == EFRP_OK && !used);
    const uint8_t *p; size_t n;
    assert(efrp_yamux_output(&m, &p, &n) == EFRP_OK && n == 12 && p[1] == 2 && p[3] == 2 && word(p + 8) == 999);
    flush(&m);
    assert(efrp_yamux_ping(&m, 7) == EFRP_OK && efrp_yamux_ping(&m, 8) == EFRP_WOULD_BLOCK);
    flush(&m); header_in(&m, 2, 2, 0, 7); assert(!m.ping_pending);
    header_in(&m, 1, 1, 2, 0);
    assert(efrp_yamux_output(&m, &p, &n) == EFRP_OK && p[3] == 8 && word(p + 4) == 2); flush(&m);
    header_in(&m, 1, 8, ids[0], 0);
    assert(efrp_yamux_release(&m, ids[0]) == EFRP_OK);
    header_in(&m, 3, 0, 0, 0);
    assert(efrp_yamux_open(&m, &extra) == EFRP_SESSION_CLOSED);
    assert(efrp_yamux_goaway(&m) == EFRP_OK); flush(&m);
}
static void invalid_frames(void)
{
    for (unsigned scenario = 0; scenario < 15; ++scenario) {
        efrp_yamux_t m; efrp_yamux_init(&m, 0); uint32_t id = open_stream(&m);
        uint8_t h[12]; size_t used; frame(h, 0, 0, id, 0);
        switch (scenario) {
        case 0: h[0] = 1; break;
        case 1: h[1] = 4; break;
        case 2: h[3] = 16; break;
        case 3: frame(h, 0, 0, 0, 0); break;
        case 4: frame(h, 0, 0, id, EFRP_YAMUX_INITIAL_WINDOW + 1); break;
        case 5: frame(h, 1, 0, id, UINT32_MAX); break;
        case 6: frame(h, 1, 2, id, 0); break;
        case 7: frame(h, 0, 0, 99, 0); break;
        case 8: frame(h, 1, 1, 3, 0); break;
        case 9: frame(h, 2, 1, id, 1); break;
        case 10: frame(h, 2, 0, 0, 1); break;
        case 11: frame(h, 3, 0, 0, 3); break;
        case 12: frame(h, 3, 1, 0, 0); break;
        case 13: frame(h, 0, 12, id, 0); break;
        case 14: frame(h, 1, 3, id, 0); break;
        }
        assert(efrp_yamux_feed(&m, h, 12, &used) == EFRP_PROTOCOL_ERROR);
        assert(efrp_yamux_feed(&m, h, 12, &used) == EFRP_PROTOCOL_ERROR && !used);
        assert(efrp_yamux_tick(&m, 1) == EFRP_PROTOCOL_ERROR);
    }
    efrp_yamux_t m; uint8_t h[12]; size_t used;
    efrp_yamux_init(&m, 0); uint32_t id = open_stream(&m);
    header_in(&m, 1, 4, id, 0); frame(h, 0, 0, id, 1);
    assert(efrp_yamux_feed(&m, h, 12, &used) == EFRP_PROTOCOL_ERROR);
    efrp_yamux_init(&m, 0); header_in(&m, 1, 1, 2, 0); frame(h, 1, 1, 2, 0);
    assert(efrp_yamux_feed(&m, h, 12, &used) == EFRP_PROTOCOL_ERROR);
    efrp_yamux_init(&m, 0); id = open_stream(&m); header_in(&m, 1, 4, id, 0);
    header_in(&m, 0, 8, id, 0); // RST may abort an already half-closed stream.
    assert(efrp_yamux_release(&m, id) == EFRP_OK);
    for (size_t cut = 1; cut < 13; ++cut) {
        efrp_yamux_init(&m, 0); id = open_stream(&m); frame(h, 0, 0, id, 1);
        assert(efrp_yamux_feed(&m, h, cut, &used) == EFRP_OK && used == cut);
        assert(efrp_yamux_finish(&m) == EFRP_TRUNCATED);
    }
}
static void combined_flags(void)
{
    efrp_yamux_t m; efrp_yamux_init(&m, 0); uint32_t id;
    assert(efrp_yamux_open(&m, &id) == EFRP_OK); flush(&m);
    uint8_t input[32], out[8]; size_t used, n;
    frame(input, 0, 2 | 4, id, 3); memcpy(input + 12, "fin", 3);
    assert(efrp_yamux_feed(&m, input, 13, &used) == EFRP_OK);
    efrp_yamux_stream_info_t info;
    assert(efrp_yamux_info(&m, id, &info) == EFRP_OK && info.acknowledged && !info.remote_fin);
    assert(efrp_yamux_read(&m, id, out, sizeof out, &n) == EFRP_OK && n == 1 && out[0] == 'f');
    assert(efrp_yamux_read(&m, id, out, sizeof out, &n) == EFRP_WOULD_BLOCK);
    assert(efrp_yamux_feed(&m, input + 13, 2, &used) == EFRP_OK && used == 2);
    assert(efrp_yamux_read(&m, id, out, sizeof out, &n) == EFRP_OK && n == 2 && !memcmp(out, "in", 2));
    assert(efrp_yamux_read(&m, id, out, sizeof out, &n) == EFRP_EOF);
    frame(input, 0, 8, id, 3); memcpy(input + 12, "rst", 3);
    frame(input + 15, 2, 1, 0, 97);
    assert(efrp_yamux_feed(&m, input, 27, &used) == EFRP_OK && used == 27);
    assert(efrp_yamux_read(&m, id, out, sizeof out, &n) == EFRP_STREAM_RESET);
    assert(m.discarded_bytes == 3); flush(&m);
    efrp_yamux_init(&m, 0); frame(input, 0, 1, 2, 3); memcpy(input + 12, "syn", 3);
    assert(efrp_yamux_feed(&m, input, 15, &used) == EFRP_OK && used == 15 && m.discarded_bytes == 3);
    for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i) assert(!m.streams[i].id);
    flush(&m); frame(input, 3, 0, 0, 1);
    assert(efrp_yamux_feed(&m, input, 12, &used) == EFRP_SESSION_CLOSED);
}
static void deadlines_and_reuse(void)
{
    efrp_yamux_t m; uint32_t id; size_t used; uint8_t h[12];
    efrp_yamux_init(&m, 0); id = open_stream(&m); frame(h, 0, 0, id, 1);
    assert(efrp_yamux_feed(&m, h, 1, &used) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 4999) == EFRP_OK && efrp_yamux_tick(&m, 5000) == EFRP_TIMEOUT);
    efrp_yamux_init(&m, 0); id = open_stream(&m); frame(h, 0, 0, id, 1);
    assert(efrp_yamux_feed(&m, h, 1, &used) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 4000) == EFRP_OK);
    assert(efrp_yamux_feed(&m, h + 1, 1, &used) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 5000) == EFRP_TIMEOUT); // Trickle does not extend header deadline.
    efrp_yamux_init(&m, 0); assert(efrp_yamux_open(&m, &id) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 5000) == EFRP_TIMEOUT);
    efrp_yamux_init(&m, 0); assert(efrp_yamux_open(&m, &id) == EFRP_OK); flush(&m);
    assert(efrp_yamux_tick(&m, 9999) == EFRP_OK && efrp_yamux_tick(&m, 10000) == EFRP_OK);
    efrp_yamux_stream_info_t info;
    assert(efrp_yamux_info(&m, id, &info) == EFRP_OK && info.reset);
    efrp_yamux_init(&m, 1); assert(efrp_yamux_tick(&m, 0) == EFRP_INVALID_ARGUMENT);
    efrp_yamux_init(&m, 0); assert(efrp_yamux_ping(&m, 1) == EFRP_OK); flush(&m);
    assert(efrp_yamux_tick(&m, 5000) == EFRP_TIMEOUT);
    efrp_yamux_init(&m, 0);
    for (unsigned cycle = 0; cycle < 1000; ++cycle) {
        id = open_stream(&m); assert(id == cycle * 2 + 1);
        assert(efrp_yamux_reset(&m, id) == EFRP_OK);
        assert(efrp_yamux_release(&m, id) == EFRP_OK); flush(&m);
        assert(!m.control_count && !m.output_used);
        for (size_t i = 0; i < EFRP_YAMUX_STREAMS; ++i) assert(!m.streams[i].id && !m.streams[i].used);
    }
    m.next_id = UINT32_MAX; assert(efrp_yamux_open(&m, &id) == EFRP_OK && id == UINT32_MAX);
    assert(efrp_yamux_open(&m, &id) == EFRP_CAPACITY_EXCEEDED);
}
static void bounded_discard(void)
{
    efrp_yamux_t m; efrp_yamux_init(&m, 0); uint32_t id = open_stream(&m);
    assert(efrp_yamux_reset(&m, id) == EFRP_OK && efrp_yamux_release(&m, id) == EFRP_OK); flush(&m);
    uint8_t *p = calloc(1, 12 + EFRP_YAMUX_INITIAL_WINDOW); assert(p);
    frame(p, 0, 0, id, EFRP_YAMUX_INITIAL_WINDOW); size_t used;
    for (unsigned i = 0; i < 4; ++i)
        assert(efrp_yamux_feed(&m, p, 12 + EFRP_YAMUX_INITIAL_WINDOW, &used) == EFRP_OK && used == 12 + EFRP_YAMUX_INITIAL_WINDOW);
    frame(p, 0, 0, id, 1);
    assert(efrp_yamux_feed(&m, p, 13, &used) == EFRP_PROTOCOL_ERROR && used == 12);
    efrp_yamux_init(&m, 0); id = open_stream(&m);
    assert(efrp_yamux_reset(&m, id) == EFRP_OK && efrp_yamux_release(&m, id) == EFRP_OK); flush(&m);
    frame(p, 0, 0, id, 4096);
    assert(efrp_yamux_feed(&m, p, 13, &used) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 4000) == EFRP_OK);
    assert(efrp_yamux_feed(&m, p + 13, 1, &used) == EFRP_OK);
    assert(efrp_yamux_tick(&m, 5000) == EFRP_TIMEOUT); // Absolute bounded drain, even with progress.
    free(p);
}
static void continuous_receive_and_send(void)
{
    efrp_yamux_t m; efrp_yamux_init(&m, 0);
    uint32_t ids[2] = {open_stream(&m), open_stream(&m)};
    uint8_t input[76], out[64];
    unsigned data_frames = 0, grants[2] = {0};
    /* Every scheduling turn makes more receive credit available. A sender
     * must still make progress, and both receivers must get their credit. */
    for (unsigned turn = 0; turn < 1024; ++turn) {
        assert(efrp_yamux_tick(&m, turn * 10u) == EFRP_OK);
        for (unsigned i = 0; i < 2; ++i) {
            frame(input, 0, 0, ids[i], sizeof out);
            memset(input + 12, (int)i, sizeof out);
            size_t used;
            assert(efrp_yamux_feed(&m, input, sizeof input, &used) == EFRP_OK && used == sizeof input);
            assert(efrp_yamux_read(&m, ids[i], out, sizeof out, &used) == EFRP_OK && used == sizeof out);
        }
        size_t written, length; const uint8_t *bytes;
        efrp_result_t result = efrp_yamux_write(&m, ids[1], (const uint8_t *)"x", 1, &written);
        assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
        assert(efrp_yamux_output(&m, &bytes, &length) == EFRP_OK);
        if (bytes[1] == 0) {
            assert(result == EFRP_OK && written == 1 && word(bytes + 4) == ids[1]);
            ++data_frames;
        } else {
            assert(bytes[1] == 1 && result == EFRP_WOULD_BLOCK && !written);
            unsigned index = word(bytes + 4) == ids[0] ? 0 : 1;
            assert(word(bytes + 4) == ids[index]); ++grants[index];
        }
        assert(efrp_yamux_consume_output(&m, length) == EFRP_OK);
    }
    printf("Continuous receive/send: DATA=%u grants=%u/%u\n", data_frames, grants[0], grants[1]);
    fflush(stdout);
    assert(data_frames >= 512 && grants[0] >= 256 && grants[1] >= 256);
    flush(&m);
    for (unsigned i = 0; i < 2; ++i)
        assert(m.streams[i].receive_credit == EFRP_YAMUX_INITIAL_WINDOW);
    /* Even after a credit grant yielded a DATA slot, queued protocol controls
     * must precede application data (including SYN before a new stream). */
    assert(efrp_yamux_ping(&m, 0x1234) == EFRP_OK);
    size_t written, length; const uint8_t *bytes;
    assert(efrp_yamux_write(&m, ids[1], (const uint8_t *)"x", 1, &written) == EFRP_WOULD_BLOCK && !written);
    assert(efrp_yamux_output(&m, &bytes, &length) == EFRP_OK && bytes[1] == 2 && word(bytes + 8) == 0x1234);
    assert(efrp_yamux_consume_output(&m, length) == EFRP_OK);
}
int main(void)
{
    large_frames(); window_and_output(); stalled_and_late_data(); control_and_capacity();
    invalid_frames(); combined_flags(); deadlines_and_reuse(); bounded_discard(); continuous_receive_and_send();
    printf("Yamux host checks passed; caller-owned session bytes: %zu\n", sizeof(efrp_yamux_t));
    return 0;
}
