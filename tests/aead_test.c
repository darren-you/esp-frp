// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_aead.h"
#include "crypto_backend.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const uint8_t token[] = "esp-frp-public-fixture-token";
static const uint8_t client[] = " {\"fixture\":\"client\", \"raw\":\"bytes\"} ";
static const uint8_t server[] = "{\"fixture\": \"server\"}";
static void all_zero(const void *bytes, size_t n)
{
    const uint8_t *p = bytes;
    for (size_t i = 0; i < n; ++i) assert(!p[i]);
}
static efrp_aead_keys_t keys(void)
{
    efrp_aead_keys_t value;
    assert(efrp_aead_derive(token, sizeof token - 1, client, sizeof client - 1, server, sizeof server - 1, &value) == EFRP_OK);
    return value;
}
static size_t encode(uint8_t *wire, const uint8_t *plain, size_t length, size_t capacity)
{
    efrp_aead_keys_t k = keys();
    uint8_t *storage = malloc(capacity); assert(storage);
    efrp_aead_writer_t w = {0};
    assert(efrp_aead_writer_init(&w, k.client_to_server, storage, capacity) == EFRP_OK);
    size_t accepted = 0, total = 0, n;
    assert(efrp_aead_write(&w, NULL, 0, &n) == EFRP_OK && !n && !w.nonce_sent);
    while (accepted < length) {
        assert(efrp_aead_write(&w, plain + accepted, length - accepted, &n) == EFRP_OK && n);
        accepted += n;
        const uint8_t *p; size_t count;
        assert(efrp_aead_output(&w, &p, &count) == EFRP_OK);
        assert(efrp_aead_write(&w, plain, 1, &n) == EFRP_WOULD_BLOCK && !n);
        assert(efrp_aead_consume_output(&w, count + 1) == EFRP_INVALID_ARGUMENT);
        while (efrp_aead_output(&w, &p, &count) == EFRP_OK) {
            size_t take = count < 37 ? count : 37;
            memcpy(wire + total, p, take); total += take;
            assert(efrp_aead_consume_output(&w, take) == EFRP_OK);
        }
        all_zero(storage, capacity);
    }
    efrp_aead_writer_destroy(&w); all_zero(&w, sizeof w); all_zero(storage, capacity);
    efrp_aead_clear_keys(&k); all_zero(&k, sizeof k); free(storage);
    return total;
}
static void round_trips(void)
{
    uint8_t *plain = malloc(70001), *wire = malloc(200000), *rx = malloc(EFRP_AEAD_RX_BYTES);
    assert(plain && wire && rx);
    for (size_t i = 0; i < 70001; ++i) plain[i] = (uint8_t)(i * 31);
    const size_t lengths[] = {1,15,16,17,511,512,513,65535,65536,65537,70001};
    const size_t steps[] = {1,11,12,13,15,16,17,511,4096,200000};
    for (size_t item = 0; item < sizeof lengths / sizeof lengths[0]; ++item) {
        size_t size = encode(wire, plain, lengths[item], EFRP_AEAD_TX_MAX_BYTES);
        for (size_t split = 0; split < sizeof steps / sizeof steps[0]; ++split) {
            efrp_aead_keys_t k = keys(); efrp_aead_reader_t r = {0};
            assert(efrp_aead_reader_init(&r, k.client_to_server, rx, EFRP_AEAD_RX_BYTES) == EFRP_OK);
            assert(efrp_aead_reader_init(&r, k.client_to_server, rx, EFRP_AEAD_RX_BYTES) == EFRP_INVALID_STATE);
            size_t fed = 0, verified = 0;
            while (fed < size) {
                size_t n = size - fed, used;
                if (n > steps[split]) n = steps[split];
                efrp_result_t result = efrp_aead_feed(&r, wire + fed, n, &used);
                assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK); fed += used;
                const uint8_t *p; size_t count;
                while (efrp_aead_plaintext(&r, &p, &count) == EFRP_OK) {
                    assert(verified + count <= lengths[item]);
                    size_t take = count < 193 ? count : 193;
                    assert(!memcmp(p, plain + verified, take)); verified += take;
                    assert(efrp_aead_consume_plaintext(&r, take) == EFRP_OK);
                }
            }
            assert(verified == lengths[item] && efrp_aead_finish(&r) == EFRP_OK);
            all_zero(rx, EFRP_AEAD_RX_BYTES);
            efrp_aead_reader_destroy(&r); efrp_aead_clear_keys(&k);
        }
    }
    /* Small output buffers still produce valid record sequences. */
    size_t size = encode(wire, plain, 100, 33);
    assert(size == 12 + 100 * 21);
    free(plain); free(wire); free(rx);
}
static void failure_cases(void)
{
    uint8_t plain[65], wire[256], bad[256], rx[EFRP_AEAD_RX_BYTES];
    memset(plain, 0xab, sizeof plain);
    size_t size = encode(wire, plain, sizeof plain, EFRP_AEAD_TX_MAX_BYTES), used;
    efrp_aead_keys_t k = keys();
    const size_t changes[] = {0,11,16,31,70,96};
    assert(size == 97);
    for (size_t i = 0; i < sizeof changes / sizeof changes[0] + 1; ++i) {
        efrp_aead_reader_t r = {0}; memcpy(bad, wire, size);
        if (i < sizeof changes / sizeof changes[0]) bad[changes[i]] ^= 1;
        uint8_t key[32]; memcpy(key, k.client_to_server, 32);
        if (i == sizeof changes / sizeof changes[0]) key[0] ^= 1;
        assert(efrp_aead_reader_init(&r, key, rx, sizeof rx) == EFRP_OK);
        assert(efrp_aead_feed(&r, bad, size - 1, &used) == EFRP_OK && used == size - 1);
        const uint8_t *p; size_t n;
        assert(efrp_aead_plaintext(&r, &p, &n) == EFRP_WOULD_BLOCK && !p && !n);
        assert(efrp_aead_feed(&r, bad + size - 1, 1, &used) == EFRP_AUTHENTICATION_FAILED);
        assert(efrp_aead_plaintext(&r, &p, &n) == EFRP_AUTHENTICATION_FAILED && !p && !n);
        assert(efrp_aead_feed(&r, wire, size, &used) == EFRP_AUTHENTICATION_FAILED && !used);
        all_zero(rx, sizeof rx); all_zero(r.key, sizeof r.key); efrp_aead_reader_destroy(&r);
    }
    for (size_t cut = 0; cut < size; ++cut) {
        efrp_aead_reader_t r = {0};
        assert(efrp_aead_reader_init(&r, k.client_to_server, rx, sizeof rx) == EFRP_OK);
        assert(efrp_aead_feed(&r, wire, cut, &used) == EFRP_OK);
        assert(efrp_aead_finish(&r) == ((!cut || cut == 12) ? EFRP_OK : EFRP_TRUNCATED));
        efrp_aead_reader_destroy(&r);
    }
    for (unsigned i = 0; i < 4; ++i) {
        efrp_aead_reader_t r = {0}; memcpy(bad, wire, size);
        uint32_t value = i == 0 ? 0 : i == 1 ? 15 : i == 2 ? 65553 : UINT32_MAX;
        for (unsigned b = 0; b < 4; ++b) bad[12+b] = (uint8_t)(value >> (24-8*b));
        assert(efrp_aead_reader_init(&r, k.client_to_server, rx, sizeof rx) == EFRP_OK);
        assert(efrp_aead_feed(&r, bad, size, &used) == EFRP_PROTOCOL_ERROR && used == 16);
        all_zero(rx, sizeof rx); efrp_aead_reader_destroy(&r);
    }
    /* A changed length inside the legal range must also fail authentication. */
    {
        efrp_aead_reader_t altered = {0}; memcpy(bad, wire, size); --bad[15];
        assert(efrp_aead_reader_init(&altered, k.client_to_server, rx, sizeof rx) == EFRP_OK);
        assert(efrp_aead_feed(&altered, bad, size, &used) == EFRP_AUTHENTICATION_FAILED && used == size - 1);
        all_zero(rx, sizeof rx); efrp_aead_reader_destroy(&altered);
    }
    efrp_aead_reader_t r = {0};
    assert(efrp_aead_reader_init(&r, k.client_to_server, rx, sizeof rx) == EFRP_OK);
    assert(efrp_aead_feed(&r, wire, size, &used) == EFRP_OK);
    assert(efrp_aead_feed(&r, wire + 12, size - 12, &used) == EFRP_WOULD_BLOCK && !used);
    assert(efrp_aead_consume_plaintext(&r, sizeof plain) == EFRP_OK);
    assert(efrp_aead_feed(&r, wire + 12, size - 12, &used) == EFRP_AUTHENTICATION_FAILED);
    efrp_aead_reader_destroy(&r); efrp_aead_clear_keys(&k);
}
static void empty_and_limits(void)
{
    efrp_aead_keys_t k = keys(); uint8_t tx[4128], rx[EFRP_AEAD_RX_BYTES], wire[32] = {0};
    wire[15] = 16;
    assert(efrp_crypto_gcm(true, k.client_to_server, wire, wire, wire + 16, 0) == EFRP_OK);
    efrp_aead_reader_t r = {0}; size_t n; const uint8_t *p;
    assert(efrp_aead_reader_init(&r, k.client_to_server, rx, sizeof rx) == EFRP_OK);
    assert(efrp_aead_feed(&r, wire, sizeof wire, &n) == EFRP_OK && n == 32 && r.records == 1);
    assert(efrp_aead_plaintext(&r, &p, &n) == EFRP_WOULD_BLOCK);
    efrp_aead_reader_destroy(&r);
    for (unsigned scenario = 0; scenario < 2; ++scenario) {
        efrp_aead_writer_t w = {0};
        assert(efrp_aead_writer_init(&w, k.client_to_server, tx, sizeof tx) == EFRP_OK);
        if (scenario == 0) w.records = EFRP_AEAD_MAX_RECORDS;
        else memset(w.nonce, 255, sizeof w.nonce);
        assert(efrp_aead_write(&w, wire, 1, &n) == EFRP_COUNTER_EXHAUSTED && !n);
        assert(efrp_aead_output(&w, &p, &n) == EFRP_COUNTER_EXHAUSTED && !p && !n);
        all_zero(tx, sizeof tx); efrp_aead_writer_destroy(&w);
        assert(efrp_aead_reader_init(&r, k.client_to_server, rx, sizeof rx) == EFRP_OK);
        if (scenario == 0) r.records = EFRP_AEAD_MAX_RECORDS;
        else memset(wire, 255, 12);
        assert(efrp_aead_feed(&r, wire, sizeof wire, &n) == EFRP_COUNTER_EXHAUSTED);
        efrp_aead_reader_destroy(&r);
    }
    uint8_t previous[12] = {0};
    for (unsigned cycle = 0; cycle < 100; ++cycle) {
        efrp_aead_writer_t w = {0};
        assert(efrp_aead_writer_init(&w, k.client_to_server, tx, sizeof tx) == EFRP_OK);
        assert(memcmp(previous, w.stream_nonce, 12)); memcpy(previous, w.stream_nonce, 12);
        assert(efrp_aead_write(&w, wire, sizeof wire, &n) == EFRP_OK && n == sizeof wire);
        efrp_aead_writer_destroy(&w); all_zero(tx, sizeof tx); all_zero(&w, sizeof w);
    }
    efrp_aead_keys_t changed;
    assert(efrp_aead_derive(token, sizeof token - 1, client + 1, sizeof client - 2, server, sizeof server - 1, &changed) == EFRP_OK);
    assert(memcmp(changed.transcript_hash, k.transcript_hash, 32));
    assert(memcmp(k.client_to_server, k.server_to_client, 32));
    assert(efrp_aead_derive(token, 0, client, sizeof client - 1, server, sizeof server - 1, &changed) == EFRP_INVALID_ARGUMENT);
    all_zero(&changed, sizeof changed); efrp_aead_clear_keys(&k);
}
int main(void)
{
    round_trips(); failure_cases(); empty_and_limits();
    puts("AEAD: boundaries, authentication-before-delivery, replay, truncation, counters and zeroization passed");
    return 0;
}
