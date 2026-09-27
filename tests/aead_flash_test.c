// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_flash_reader.h"
#include "crypto_backend.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t bytes[EFRP_AEAD_MAX_PLAINTEXT];
    uint64_t generation, lease;
    size_t begins, clears, reads, read_bytes, writes, partial_writes, fail_read_after;
    bool recovered, busy, quarantined, fail_recover, fail_read, short_read;
    bool fail_write, partial_write, fail_clear;
} fake_flash_t;
static fake_flash_t flash;
static uint8_t plain[EFRP_AEAD_MAX_PLAINTEXT], wire[EFRP_AEAD_TX_MAX_BYTES];
static uint8_t window[EFRP_AEAD_RX_CHUNK_BYTES];
static const uint8_t key[32] = {1, 3, 7, 9};

static efrp_result_t recover(void *context)
{
    fake_flash_t *f = context;
    if (f->fail_recover) {
        f->recovered = false; f->quarantined = true;
        return EFRP_STORAGE_ERROR;
    }
    memset(f->bytes, 0xff, sizeof f->bytes);
    f->lease = 0; f->busy = false; f->quarantined = false; f->recovered = true;
    ++f->generation;
    return EFRP_OK;
}
static efrp_result_t begin(void *context, uint64_t *lease)
{
    fake_flash_t *f = context;
    if (!f->recovered || f->busy || f->quarantined || !lease) return EFRP_STORAGE_ERROR;
    memset(f->bytes, 0xff, sizeof f->bytes);
    f->lease = ++f->generation;
    f->busy = true; *lease = f->lease; ++f->begins;
    return EFRP_OK;
}
static efrp_result_t write_flash(void *context, uint64_t lease, size_t offset,
                                  const uint8_t *bytes, size_t length)
{
    fake_flash_t *f = context;
    if (!f->busy || f->quarantined || lease != f->lease || !length || f->fail_write ||
        offset > sizeof f->bytes || length > sizeof f->bytes - offset)
        return EFRP_STORAGE_ERROR;
    if (f->partial_write && length) {
        size_t partial = length / 2;
        if (!partial) partial = 1;
        memcpy(f->bytes + offset, bytes, partial);
        ++f->partial_writes;
        return EFRP_STORAGE_ERROR;
    }
    memcpy(f->bytes + offset, bytes, length); ++f->writes;
    return EFRP_OK;
}
static efrp_result_t read_flash(void *context, uint64_t lease, size_t offset,
                                 uint8_t *bytes, size_t length)
{
    fake_flash_t *f = context;
    if (!f->busy || f->quarantined || lease != f->lease || f->fail_read ||
        (f->fail_read_after && f->reads >= f->fail_read_after) ||
        offset > sizeof f->bytes || length > sizeof f->bytes - offset)
        return EFRP_STORAGE_ERROR;
    if (f->short_read && length) {
        memcpy(bytes, f->bytes + offset, length - 1);
        return EFRP_STORAGE_ERROR;
    }
    memcpy(bytes, f->bytes + offset, length);
    ++f->reads; f->read_bytes += length;
    return EFRP_OK;
}
static efrp_result_t clear(void *context, uint64_t lease)
{
    fake_flash_t *f = context;
    if (!f->busy || lease != f->lease) return EFRP_STORAGE_ERROR;
    if (f->fail_clear) { f->quarantined = true; return EFRP_STORAGE_ERROR; }
    f->busy = false; f->quarantined = false; f->lease = 0; ++f->clears;
    return EFRP_OK;
}
static efrp_aead_flash_store_t store(void)
{
    return (efrp_aead_flash_store_t){.context = &flash, .recover = recover,
        .begin = begin, .write = write_flash, .read = read_flash, .clear = clear};
}
static void init_flash(void)
{
    memset(&flash, 0, sizeof flash);
    efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_store_recover(&s) == EFRP_OK);
}
static size_t make_record(const uint8_t *bytes, size_t length)
{
    static uint8_t output[EFRP_AEAD_TX_MAX_BYTES];
    efrp_aead_writer_t writer = {0};
    size_t written, n; const uint8_t *p;
    assert(efrp_aead_writer_init(&writer, key, output, sizeof output) == EFRP_OK);
    assert(efrp_aead_write(&writer, bytes, length, &written) == EFRP_OK && written == length);
    assert(efrp_aead_output(&writer, &p, &n) == EFRP_OK);
    memcpy(wire, p, n);
    efrp_aead_writer_destroy(&writer);
    return n;
}
static void feed_all(efrp_aead_flash_reader_t *r, const uint8_t *bytes, size_t length)
{
    for (size_t offset = 0; offset < length;) {
        size_t take = length - offset, consumed = 0;
        if (take > 1031) take = 1031;
        assert(efrp_aead_flash_feed(r, bytes + offset, take, &consumed) == EFRP_OK);
        assert(consumed == take); offset += take;
    }
}
static void all_zero(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i) assert(bytes[i] == 0);
}
static void full_record(void)
{
    init_flash();
    for (size_t i = 0; i < sizeof plain; ++i) plain[i] = (uint8_t)(i * 29u + 7u);
    size_t size = make_record(plain, sizeof plain);
    assert(size == sizeof plain + 32);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    memset(window, 0x55, sizeof window);
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    all_zero(window, sizeof window);
    feed_all(&r, wire, size - 1);
    const uint8_t *bytes; size_t length;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_WOULD_BLOCK);
    assert(flash.busy && flash.reads == 0);
    feed_all(&r, wire + size - 1, 1);
    assert(flash.busy && flash.read_bytes == sizeof plain);
    uint64_t stale_lease = r.lease;
    assert(memcmp(flash.bytes, plain, sizeof plain) != 0);
    size_t consumed = 1;
    assert(efrp_aead_flash_feed(&r, wire, 1, &consumed) == EFRP_WOULD_BLOCK && consumed == 0);
    for (size_t offset = 0; offset < sizeof plain;) {
        assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
        assert(length == sizeof window && memcmp(bytes, plain + offset, length) == 0);
        assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
        offset += length;
    }
    assert(r.flash_records == 1 && r.flash_passes == 17 &&
           r.flash_read_bytes == 17u * sizeof plain);
    assert(flash.read_bytes == (1u + sizeof plain / sizeof window) * sizeof plain);
    assert(!flash.busy);
    assert(read_flash(&flash, stale_lease, 0, window, 1) == EFRP_STORAGE_ERROR);
    assert(memcmp(flash.bytes, wire + 16, sizeof plain) == 0);
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_WOULD_BLOCK);
    assert(efrp_aead_flash_finish(&r) == EFRP_OK);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void exact_header_boundary(void)
{
    for (unsigned split = 0; split < 2; ++split) {
        init_flash();
        for (size_t i = 0; i < sizeof plain; ++i)
            plain[i] = (uint8_t)(i * 29u + 7u);
        size_t size = make_record(plain, sizeof plain);
        efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
        assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
        size_t consumed = 0;
        if (split) {
            assert(efrp_aead_flash_feed(&r, wire, 12, &consumed) == EFRP_OK && consumed == 12);
            assert(!flash.busy && flash.begins == 0 && flash.writes == 0);
            assert(efrp_aead_flash_feed(&r, wire + 12, 4, &consumed) == EFRP_OK && consumed == 4);
        } else {
            assert(efrp_aead_flash_feed(&r, wire, 16, &consumed) == EFRP_OK && consumed == 16);
        }
        assert(flash.busy && flash.begins == 1 && flash.writes == 0 && flash.reads == 0 && r.leased);
        const uint8_t *bytes = NULL; size_t length = 0;
        assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_WOULD_BLOCK &&
               bytes == NULL && length == 0);
        feed_all(&r, wire + 16, size - 16);
        assert(flash.writes > 0 && r.flash_passes == 1 && r.flash_read_bytes == sizeof plain);
        assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK &&
               length == sizeof window && memcmp(bytes, plain, length) == 0);
        assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
        assert(efrp_aead_flash_reader_close(&r) == EFRP_OK && !flash.busy && flash.clears == 1);
    }
}
static void small_and_boundary_records(void)
{
    for (size_t size = 4096; size <= 4097; ++size) {
        init_flash();
        size_t wire_size = make_record(plain, size);
        efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
        assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
        feed_all(&r, wire, wire_size);
        const uint8_t *bytes; size_t length, offset = 0;
        do {
            assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
            assert(memcmp(bytes, plain + offset, length) == 0);
            assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
            offset += length;
        } while (offset < size);
        assert(offset == size);
        assert(flash.begins == (size > sizeof window ? 1u : 0u));
        assert(flash.clears == flash.begins);
        if (size > sizeof window) assert(flash.writes > 0);
        else assert(flash.writes == 0);
        assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
    }
    init_flash();
    size_t size = make_record(plain, 95); /* normal control heartbeat size */
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    assert(flash.begins == 0 && flash.clears == 0 && flash.writes == 0);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void empty_record(void)
{
    init_flash();
    uint8_t nonce[12] = {4, 1, 2, 3}, aad[16] = {0}, empty_wire[32] = {0};
    uint8_t tag[16] = {0};
    memcpy(aad, nonce, 12); aad[15] = 16;
    memcpy(empty_wire, nonce, 12); empty_wire[15] = 16;
    assert(efrp_crypto_gcm(true, key, nonce, aad, tag, 0) == EFRP_OK);
    memcpy(empty_wire + 16, tag, 16);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, empty_wire, sizeof empty_wire);
    const uint8_t *bytes; size_t length;
    assert(r.records == 1 && !flash.busy && flash.begins == 0);
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_WOULD_BLOCK);
    assert(efrp_aead_flash_finish(&r) == EFRP_OK);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void altered_record(void)
{
    init_flash();
    size_t size = make_record(plain, 1000);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    wire[20] ^= 0x80;
    size_t consumed = 0;
    assert(efrp_aead_flash_feed(&r, wire, size, &consumed) == EFRP_AUTHENTICATION_FAILED);
    assert(consumed == size && !flash.busy);
    all_zero(window, sizeof window); all_zero(r.key, sizeof r.key);
    assert(efrp_aead_flash_feed(&r, wire, size, &consumed) == EFRP_AUTHENTICATION_FAILED && !consumed);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void bad_max_tag_and_short_read(void)
{
    init_flash(); size_t size = make_record(plain, sizeof plain);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    wire[size - 1] ^= 1;
    size_t consumed = 0;
    assert(efrp_aead_flash_feed(&r, wire, size, &consumed) == EFRP_AUTHENTICATION_FAILED);
    assert(consumed == size && flash.begins == 1 && flash.clears == 1 && !flash.busy);
    all_zero(window, sizeof window);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);

    init_flash(); size = make_record(plain, 5000);
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    flash.short_read = true;
    assert(efrp_aead_flash_feed(&r, wire, size, &consumed) == EFRP_STORAGE_ERROR);
    assert(consumed == size && flash.begins == 1 && flash.clears == 1 && !flash.busy);
    all_zero(window, sizeof window);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void mutated_scratch(void)
{
    init_flash(); size_t size = make_record(plain, 9000);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    const uint8_t *bytes; size_t length;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
    assert(memcmp(bytes, plain, length) == 0);
    assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
    flash.bytes[8000] ^= 1;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_AUTHENTICATION_FAILED);
    assert(!bytes && !length && !flash.busy);
    all_zero(window, sizeof window);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);

    init_flash(); size = make_record(plain, 5000);
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
    assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
    ++r.record_sequence; /* fault injection: GCM still valid, digest must reject */
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_STORAGE_ERROR);
    assert(!bytes && !length && !flash.busy);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void authenticated_substitution(void)
{
    init_flash(); size_t size = make_record(plain, 5000);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    /* A second valid record with the same nonce/AAD but different ciphertext
     * and tag must not be joined with the first record's delivered window. */
    uint8_t aad[16], body[5016], nonce[12], new_tag[16];
    memcpy(nonce, r.record_nonce, sizeof nonce);
    memcpy(aad, r.stream_nonce, 12); memcpy(aad + 12, r.header, 4);
    memcpy(body, plain, 5000); body[4500] ^= 1;
    assert(efrp_crypto_gcm(true, key, nonce, aad, body, 5000) == EFRP_OK);
    memcpy(new_tag, body + 5000, sizeof new_tag);
    const uint8_t *bytes; size_t length;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
    assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
    memcpy(flash.bytes, body, 5000); memcpy(r.tag, new_tag, sizeof new_tag);
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_STORAGE_ERROR);
    assert(!bytes && !length && !flash.busy);
    all_zero(window, sizeof window);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void failure_and_recovery(void)
{
    init_flash(); size_t size = make_record(plain, 6000);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    flash.fail_write = true;
    size_t consumed = 0;
    assert(efrp_aead_flash_feed(&r, wire, size, &consumed) == EFRP_STORAGE_ERROR);
    assert(consumed == 16 && !flash.busy);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);

    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    flash.fail_write = false; flash.fail_clear = true;
    assert(efrp_aead_flash_feed(&r, wire, 32, &consumed) == EFRP_OK && consumed == 32);
    static uint8_t second_window[EFRP_AEAD_RX_CHUNK_BYTES];
    efrp_aead_flash_reader_t second = {0};
    assert(efrp_aead_flash_reader_init(&second, key, &s, second_window, sizeof second_window) == EFRP_OK);
    assert(efrp_aead_flash_feed(&second, wire, 16, &consumed) == EFRP_STORAGE_ERROR && consumed == 16);
    assert(efrp_aead_flash_reader_close(&second) == EFRP_OK && flash.busy);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_STORAGE_ERROR && flash.busy && flash.quarantined);
    uint64_t denied_lease = 0;
    assert(begin(&flash, &denied_lease) == EFRP_STORAGE_ERROR);
    flash.fail_clear = false;
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK && !flash.busy);

    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    assert(efrp_aead_flash_feed(&r, wire, 100, &consumed) == EFRP_OK && consumed == 100);
    uint64_t stale_lease = r.lease;
    assert(efrp_aead_flash_store_recover(&s) == EFRP_OK); /* simulated power loss / boot recovery */
    assert(read_flash(&flash, stale_lease, 0, window, 1) == EFRP_STORAGE_ERROR);
    memset(&r, 0, sizeof r); /* volatile reader vanished on power loss */
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void partial_write_failure(void)
{
    init_flash(); size_t size = make_record(plain, 6000), consumed = 0;
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    assert(efrp_aead_flash_feed(&r, wire, 1016, &consumed) == EFRP_OK && consumed == 1016);
    assert(flash.busy && flash.writes == 1);
    uint64_t stale_lease = r.lease;
    flash.partial_write = true;
    assert(efrp_aead_flash_feed(&r, wire + 1016, size - 1016, &consumed) == EFRP_STORAGE_ERROR);
    assert(consumed == 0 && flash.partial_writes == 1 && flash.clears == 1 && !flash.busy);
    assert(flash.bytes[1000] == wire[1016] && flash.bytes[3500] == 0xff);
    assert(read_flash(&flash, stale_lease, 0, window, 1) == EFRP_STORAGE_ERROR);
    const uint8_t *bytes = window; size_t length = 1;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_STORAGE_ERROR);
    assert(!bytes && !length);
    all_zero(window, sizeof window); all_zero(r.key, sizeof r.key);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void window_reread_failure(void)
{
    init_flash(); size_t size = make_record(plain, 9000);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    assert(r.flash_records == 1 && r.flash_passes == 1 && flash.busy);
    uint64_t stale_lease = r.lease;
    size_t reads_before = flash.reads;
    flash.fail_read_after = reads_before + 3;
    const uint8_t *bytes = window; size_t length = 1;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_STORAGE_ERROR);
    assert(!bytes && !length && flash.reads == reads_before + 3 && !flash.busy);
    assert(r.flash_passes == 1 && r.flash_read_bytes == 9000 + 3 * 512);
    assert(read_flash(&flash, stale_lease, 0, window, 1) == EFRP_STORAGE_ERROR);
    all_zero(window, sizeof window); all_zero(r.key, sizeof r.key);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
static void clear_failure_after_authentication(void)
{
    init_flash(); size_t size = make_record(plain, 5000);
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    uint64_t stale_lease = r.lease;
    const uint8_t *bytes; size_t length;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
    assert(length == 4096 && memcmp(bytes, plain, length) == 0);
    assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_OK);
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_OK);
    assert(length == 904 && memcmp(bytes, plain + 4096, length) == 0);
    flash.fail_clear = true;
    assert(efrp_aead_flash_consume_plaintext(&r, length) == EFRP_STORAGE_ERROR);
    assert(flash.busy && flash.quarantined && r.active && r.leased);
    uint64_t denied_lease = 0;
    assert(begin(&flash, &denied_lease) == EFRP_STORAGE_ERROR && denied_lease == 0);
    all_zero(window, sizeof window); all_zero(r.key, sizeof r.key);
    assert(read_flash(&flash, stale_lease, 0, window, 1) == EFRP_STORAGE_ERROR);
    bytes = window; length = 1;
    assert(efrp_aead_flash_plaintext(&r, &bytes, &length) == EFRP_STORAGE_ERROR);
    assert(!bytes && !length);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_STORAGE_ERROR);
    assert(r.active && r.leased && r.window == window && flash.busy && flash.quarantined);
    flash.fail_clear = false;
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
    assert(!flash.busy && !flash.quarantined && flash.clears == 1);
    all_zero(window, sizeof window);
    uint64_t next_lease = 0;
    assert(begin(&flash, &next_lease) == EFRP_OK && next_lease != stale_lease);
    assert(clear(&flash, next_lease) == EFRP_OK);
}
static void recovery_precondition(void)
{
    memset(&flash, 0, sizeof flash);
    size_t size = make_record(plain, 5000), consumed = 0;
    efrp_aead_flash_reader_t r = {0}; efrp_aead_flash_store_t s = store();
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    assert(efrp_aead_flash_feed(&r, wire, size, &consumed) == EFRP_STORAGE_ERROR);
    assert(consumed == 16 && !flash.busy && flash.begins == 0);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
    flash.fail_recover = true;
    assert(efrp_aead_flash_store_recover(&s) == EFRP_STORAGE_ERROR);
    assert(!flash.recovered && flash.quarantined);
    flash.fail_recover = false;
    assert(efrp_aead_flash_store_recover(&s) == EFRP_OK);
    assert(efrp_aead_flash_reader_init(&r, key, &s, window, sizeof window) == EFRP_OK);
    feed_all(&r, wire, size);
    assert(efrp_aead_flash_reader_close(&r) == EFRP_OK);
}
int main(void)
{
    full_record(); exact_header_boundary(); small_and_boundary_records(); empty_record(); altered_record(); bad_max_tag_and_short_read();
    mutated_scratch(); authenticated_substitution(); failure_and_recovery();
    partial_write_failure(); window_reread_failure(); clear_failure_after_authentication();
    recovery_precondition();
    puts("aead flash: ok");
    return 0;
}
