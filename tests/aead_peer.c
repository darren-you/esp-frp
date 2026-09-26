// SPDX-License-Identifier: Apache-2.0
// Bounded binary fixture peer for the optional official FRP interop test.
#include "esp_frp_aead.h"
#include "esp_frp_flash_reader.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t bytes[EFRP_AEAD_MAX_PLAINTEXT];
    uint64_t generation, lease;
    bool recovered, busy;
} flash_fixture_t;
static flash_fixture_t flash;
static efrp_result_t flash_recover(void *context)
{
    flash_fixture_t *f = context;
    memset(f->bytes, 0xff, sizeof f->bytes);
    f->recovered = true; f->busy = false; f->lease = 0; ++f->generation;
    return EFRP_OK;
}
static efrp_result_t flash_begin(void *context, uint64_t *lease)
{
    flash_fixture_t *f = context;
    if (!f->recovered || f->busy) return EFRP_STORAGE_ERROR;
    memset(f->bytes, 0xff, sizeof f->bytes);
    f->busy = true; f->lease = ++f->generation; *lease = f->lease;
    return EFRP_OK;
}
static efrp_result_t flash_write(void *context, uint64_t lease, size_t offset,
                                  const uint8_t *bytes, size_t length)
{
    flash_fixture_t *f = context;
    if (!f->busy || f->lease != lease || offset > sizeof f->bytes ||
        length > sizeof f->bytes - offset) return EFRP_STORAGE_ERROR;
    memcpy(f->bytes + offset, bytes, length);
    return EFRP_OK;
}
static efrp_result_t flash_read(void *context, uint64_t lease, size_t offset,
                                 uint8_t *bytes, size_t length)
{
    flash_fixture_t *f = context;
    if (!f->busy || f->lease != lease || offset > sizeof f->bytes ||
        length > sizeof f->bytes - offset) return EFRP_STORAGE_ERROR;
    memcpy(bytes, f->bytes + offset, length);
    return EFRP_OK;
}
static efrp_result_t flash_clear(void *context, uint64_t lease)
{
    flash_fixture_t *f = context;
    if (!f->busy || f->lease != lease) return EFRP_STORAGE_ERROR;
    f->busy = false; f->lease = 0;
    return EFRP_OK;
}
static void check_flash_reader(const uint8_t key[32], const uint8_t *wire, size_t wire_length,
                                const uint8_t *expected, size_t expected_length)
{
    efrp_aead_flash_store_t store = {.context = &flash, .recover = flash_recover,
        .begin = flash_begin, .write = flash_write, .read = flash_read, .clear = flash_clear};
    uint8_t window[EFRP_AEAD_RX_CHUNK_BYTES];
    efrp_aead_flash_reader_t reader = {0};
    assert(efrp_aead_flash_store_recover(&store) == EFRP_OK);
    assert(efrp_aead_flash_reader_init(&reader, key, &store, window, sizeof window) == EFRP_OK);
    size_t offset = 0, total = 0;
    while (offset < wire_length) {
        size_t take = wire_length - offset, consumed;
        if (take > 17) take = 17;
        efrp_result_t result = efrp_aead_flash_feed(&reader, wire + offset, take, &consumed);
        assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
        offset += consumed;
        const uint8_t *bytes; size_t n;
        for (;;) {
            efrp_result_t state = efrp_aead_flash_plaintext(&reader, &bytes, &n);
            if (state == EFRP_WOULD_BLOCK) break;
            assert(state == EFRP_OK && total <= expected_length);
            assert(n <= expected_length - total && memcmp(bytes, expected + total, n) == 0);
            total += n;
            assert(efrp_aead_flash_consume_plaintext(&reader, n) == EFRP_OK);
        }
    }
    assert(total == expected_length && efrp_aead_flash_finish(&reader) == EFRP_OK);
    assert(efrp_aead_flash_reader_close(&reader) == EFRP_OK);
}

static uint32_t number(void)
{
    uint8_t p[4]; assert(fread(p, 1, 4, stdin) == 4);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint8_t *blob(size_t *length, size_t limit)
{
    *length = number(); assert(*length <= limit);
    uint8_t *p = malloc(*length + 1); assert(p);
    assert(fread(p, 1, *length, stdin) == *length);
    return p;
}
int main(void)
{
    size_t capacity = number(), tn, cn, sn, wn;
    assert(capacity >= 33 && capacity <= EFRP_AEAD_TX_MAX_BYTES);
    uint8_t *token = blob(&tn, 1024), *client = blob(&cn, 65536), *server = blob(&sn, 65536);
    uint8_t *wire = blob(&wn, 500000), *plain = malloc(400001);
    uint8_t *tx = malloc(capacity);
    assert(plain && tx && getchar() == EOF);
    efrp_aead_keys_t keys;
    efrp_aead_reader_t r = {0}; efrp_aead_writer_t w = {0};
    int exit_code = 10;
    assert(efrp_aead_derive(token, tn, client, cn, server, sn, &keys) == EFRP_OK);
#if defined(EFRP_LAB_ESP32_IRAM_AEAD_RX)
    assert(efrp_aead_reader_init_words(&r, keys.server_to_client, calloc, free) == EFRP_OK);
#else
    assert(efrp_aead_reader_init_chunked(&r, keys.server_to_client, calloc, free) == EFRP_OK);
#endif
    size_t offset = 0, total = 0;
    while (offset < wn) {
        size_t take = wn - offset, consumed;
        if (take > 17) take = 17;
        efrp_result_t result = efrp_aead_feed(&r, wire + offset, take, &consumed);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) goto done;
        offset += consumed;
        size_t n;
#if defined(EFRP_LAB_ESP32_IRAM_AEAD_RX)
        while (efrp_aead_copy_plaintext(&r, plain + total, 400001 - total, &n) == EFRP_OK) {
            total += n;
#else
        const uint8_t *p;
        while (efrp_aead_plaintext(&r, &p, &n) == EFRP_OK) {
            assert(n <= 400001 - total); memcpy(plain + total, p, n); total += n;
#endif
            assert(efrp_aead_consume_plaintext(&r, n) == EFRP_OK);
        }
    }
    if (efrp_aead_finish(&r) != EFRP_OK) goto done;
    check_flash_reader(keys.server_to_client, wire, wn, plain, total);
    assert(fwrite(keys.transcript_hash, 1, 32, stdout) == 32);
    assert(efrp_aead_writer_init(&w, keys.client_to_server, tx, capacity) == EFRP_OK);
    offset = 0;
    while (offset < total) {
        size_t n;
        assert(efrp_aead_write(&w, plain + offset, total - offset, &n) == EFRP_OK && n);
        offset += n;
        const uint8_t *p;
        while (efrp_aead_output(&w, &p, &n) == EFRP_OK) {
            if (n > 31) n = 31;
            assert(fwrite(p, 1, n, stdout) == n);
            assert(efrp_aead_consume_output(&w, n) == EFRP_OK);
        }
    }
    assert(fflush(stdout) == 0); exit_code = 0;
done:
    efrp_aead_reader_destroy(&r); efrp_aead_writer_destroy(&w); efrp_aead_clear_keys(&keys);
    free(token); free(client); free(server); free(wire); free(plain); free(tx);
    return exit_code;
}
