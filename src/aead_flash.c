// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_flash_reader.h"
#include "crypto_backend.h"
#include <string.h>

static bool next_nonce(uint8_t nonce[12])
{
    for (size_t i = 12; i > 0; --i) if (++nonce[i - 1]) return true;
    return false;
}
efrp_result_t efrp_aead_flash_store_recover(const efrp_aead_flash_store_t *store)
{
    if (!store || !store->recover) return EFRP_INVALID_ARGUMENT;
    return store->recover(store->context);
}
static bool record_available(const efrp_aead_flash_reader_t *r)
{
    if (r->records >= EFRP_AEAD_MAX_RECORDS) return false;
    for (size_t i = 0; i < sizeof r->nonce; ++i)
        if (r->nonce[i] != UINT8_MAX) return true;
    return false;
}
static efrp_result_t ready(const efrp_aead_flash_reader_t *r)
{
    if (!r || !r->active) return EFRP_INVALID_STATE;
    return r->failure;
}
static efrp_result_t release_store(efrp_aead_flash_reader_t *r)
{
    if (!r->leased) return EFRP_OK;
    if (r->store.clear(r->store.context, r->lease) != EFRP_OK) return EFRP_STORAGE_ERROR;
    r->leased = false; r->lease = 0;
    return EFRP_OK;
}
static efrp_result_t fail(efrp_aead_flash_reader_t *r, efrp_result_t error)
{
    efrp_crypto_zero(r->window, r->capacity);
    efrp_crypto_zero(r->key, sizeof r->key);
    r->ready = false; r->plain_used = r->plain_offset = 0;
    r->window_used = r->window_offset = 0;
    r->failure = release_store(r) == EFRP_OK ? error : EFRP_STORAGE_ERROR;
    return r->failure;
}
static void reset_record(efrp_aead_flash_reader_t *r)
{
    efrp_crypto_zero(r->header, sizeof r->header);
    efrp_crypto_zero(r->record_nonce, sizeof r->record_nonce);
    efrp_crypto_zero(r->tag, sizeof r->tag);
    efrp_crypto_zero(r->digest, sizeof r->digest);
    r->header_used = r->body_used = r->body_expected = 0;
    r->plain_used = r->plain_offset = r->window_used = r->window_offset = 0;
    r->record_sequence = 0; r->ready = false; r->in_memory = false;
}
efrp_result_t efrp_aead_flash_reader_init(efrp_aead_flash_reader_t *r,
                                          const uint8_t key[32],
                                          const efrp_aead_flash_store_t *store,
                                          uint8_t *window, size_t capacity)
{
    if (!r || !key || !store || !store->recover || !store->begin || !store->write ||
        !store->read || !store->clear || !window ||
        capacity != EFRP_AEAD_RX_CHUNK_BYTES) return EFRP_INVALID_ARGUMENT;
    if (r->active) return EFRP_INVALID_STATE;
    *r = (efrp_aead_flash_reader_t){.active = true, .store = *store,
                                    .window = window, .capacity = capacity};
    memcpy(r->key, key, sizeof r->key);
    efrp_crypto_zero(window, capacity);
    return EFRP_OK;
}
static efrp_result_t read_store(void *context, size_t offset, uint8_t *bytes, size_t length)
{
    efrp_aead_flash_reader_t *r = context;
    efrp_result_t result = r->store.read(r->store.context, r->lease, offset, bytes, length);
    if (result == EFRP_OK) r->flash_read_bytes += length;
    return result;
}
static efrp_result_t verify(efrp_aead_flash_reader_t *r, size_t offset,
                            size_t length, const uint8_t expected[32])
{
    uint8_t aad[16], digest[32];
    memcpy(aad, r->stream_nonce, 12); memcpy(aad + 12, r->header, 4);
    efrp_result_t result = efrp_crypto_gcm_decrypt_store(
        r->key, r->record_nonce, aad, r->record_sequence,
        read_store, r, r->body_expected - EFRP_AEAD_TAG_BYTES, r->tag,
        offset, r->window, length, expected, digest);
    if (result == EFRP_OK && !expected) memcpy(r->digest, digest, sizeof r->digest);
    if (result == EFRP_OK) ++r->flash_passes;
    efrp_crypto_zero(digest, sizeof digest);
    return result;
}
efrp_result_t efrp_aead_flash_feed(efrp_aead_flash_reader_t *r,
                                   const uint8_t *bytes, size_t length,
                                   size_t *consumed)
{
    if (consumed) *consumed = 0;
    if (!consumed || (!bytes && length)) return EFRP_INVALID_ARGUMENT;
    efrp_result_t state = ready(r);
    if (state != EFRP_OK) return state;
    while (*consumed < length) {
        if (r->ready) return EFRP_WOULD_BLOCK;
        if (r->nonce_used < sizeof r->stream_nonce) {
            size_t n = sizeof r->stream_nonce - r->nonce_used;
            if (n > length - *consumed) n = length - *consumed;
            memcpy(r->stream_nonce + r->nonce_used, bytes + *consumed, n);
            r->nonce_used += n; *consumed += n;
            if (r->nonce_used != sizeof r->stream_nonce) continue;
            memcpy(r->nonce, r->stream_nonce, sizeof r->nonce);
        }
        if (r->header_used < sizeof r->header) {
            size_t n = sizeof r->header - r->header_used;
            if (n > length - *consumed) n = length - *consumed;
            memcpy(r->header + r->header_used, bytes + *consumed, n);
            r->header_used += n; *consumed += n;
            if (r->header_used != sizeof r->header) continue;
            uint32_t size = ((uint32_t)r->header[0] << 24) |
                ((uint32_t)r->header[1] << 16) | ((uint32_t)r->header[2] << 8) | r->header[3];
            if (size < EFRP_AEAD_TAG_BYTES || size > EFRP_AEAD_RX_BYTES)
                return fail(r, EFRP_PROTOCOL_ERROR);
            if (!record_available(r)) return fail(r, EFRP_COUNTER_EXHAUSTED);
            r->body_expected = size; r->record_sequence = r->records;
            r->in_memory = size - EFRP_AEAD_TAG_BYTES <= r->capacity;
            memcpy(r->record_nonce, r->nonce, sizeof r->record_nonce);
            if (!r->in_memory) {
                if (r->store.begin(r->store.context, &r->lease) != EFRP_OK || !r->lease)
                    return fail(r, EFRP_STORAGE_ERROR);
                r->leased = true;
            }
        }
        size_t plain_length = r->body_expected - EFRP_AEAD_TAG_BYTES;
        size_t n = r->body_expected - r->body_used;
        if (n > length - *consumed) n = length - *consumed;
        if (r->body_used < plain_length) {
            size_t ciphertext = plain_length - r->body_used;
            if (n > ciphertext) n = ciphertext;
            if (r->in_memory) memcpy(r->window + r->body_used, bytes + *consumed, n);
            else if (r->store.write(r->store.context, r->lease, r->body_used,
                                    bytes + *consumed, n) != EFRP_OK)
                return fail(r, EFRP_STORAGE_ERROR);
        } else {
            memcpy(r->tag + r->body_used - plain_length, bytes + *consumed, n);
        }
        r->body_used += n; *consumed += n;
        if (r->body_used != r->body_expected) continue;
        efrp_result_t result;
        if (r->in_memory) {
            uint8_t *chunks[1] = {r->window};
            size_t sizes[1] = {plain_length};
            uint8_t aad[16];
            memcpy(aad, r->stream_nonce, 12); memcpy(aad + 12, r->header, 4);
            result = efrp_crypto_gcm_decrypt_chunks(r->key, r->record_nonce, aad,
                chunks, sizes, plain_length ? 1 : 0, r->tag, false);
        } else result = verify(r, 0, 0, NULL);
        if (result != EFRP_OK) return fail(r, result);
        if (!r->in_memory) ++r->flash_records;
        if (!next_nonce(r->nonce)) return fail(r, EFRP_COUNTER_EXHAUSTED);
        ++r->records; r->plain_used = plain_length;
        if (plain_length) r->ready = true;
        else {
            if (release_store(r) != EFRP_OK) return fail(r, EFRP_STORAGE_ERROR);
            reset_record(r);
        }
    }
    return EFRP_OK;
}
efrp_result_t efrp_aead_flash_plaintext(efrp_aead_flash_reader_t *r,
                                        const uint8_t **bytes, size_t *length)
{
    if (bytes) *bytes = NULL;
    if (length) *length = 0;
    if (!bytes || !length) return EFRP_INVALID_ARGUMENT;
    efrp_result_t state = ready(r);
    if (state != EFRP_OK) return state;
    if (!r->ready) return EFRP_WOULD_BLOCK;
    if (r->in_memory) {
        *bytes = r->window + r->plain_offset;
        *length = r->plain_used - r->plain_offset;
        return EFRP_OK;
    }
    if (!r->window_used) {
        size_t n = r->plain_used - r->plain_offset;
        if (n > r->capacity) n = r->capacity;
        efrp_result_t result = verify(r, r->plain_offset, n, r->digest);
        if (result != EFRP_OK) return fail(r, result);
        r->window_used = n; r->window_offset = 0;
    }
    *bytes = r->window + r->window_offset;
    *length = r->window_used - r->window_offset;
    return EFRP_OK;
}
efrp_result_t efrp_aead_flash_consume_plaintext(efrp_aead_flash_reader_t *r,
                                                size_t length)
{
    efrp_result_t state = ready(r);
    if (state != EFRP_OK) return state;
    if (!r->ready || !length || (r->in_memory ? length > r->plain_used - r->plain_offset :
                      !r->window_used || length > r->window_used - r->window_offset))
        return EFRP_INVALID_ARGUMENT;
    if (r->in_memory) {
        efrp_crypto_zero(r->window + r->plain_offset, length);
        r->plain_offset += length;
    } else {
        efrp_crypto_zero(r->window + r->window_offset, length);
        r->window_offset += length; r->plain_offset += length;
        if (r->window_offset == r->window_used) r->window_offset = r->window_used = 0;
    }
    if (r->plain_offset == r->plain_used) {
        if (release_store(r) != EFRP_OK) return fail(r, EFRP_STORAGE_ERROR);
        reset_record(r);
    }
    return EFRP_OK;
}
efrp_result_t efrp_aead_flash_finish(const efrp_aead_flash_reader_t *r)
{
    efrp_result_t state = ready(r);
    if (state != EFRP_OK) return state;
    if (r->ready) return EFRP_OK;
    return ((r->nonce_used && r->nonce_used != sizeof r->stream_nonce) ||
            r->header_used || r->body_used) ? EFRP_TRUNCATED : EFRP_OK;
}
efrp_result_t efrp_aead_flash_reader_close(efrp_aead_flash_reader_t *r)
{
    if (!r) return EFRP_INVALID_ARGUMENT;
    if (!r->active) return EFRP_OK;
    efrp_crypto_zero(r->window, r->capacity);
    efrp_crypto_zero(r->key, sizeof r->key);
    if (release_store(r) != EFRP_OK) {
        r->failure = EFRP_STORAGE_ERROR;
        return EFRP_STORAGE_ERROR;
    }
    efrp_crypto_zero(r, sizeof *r);
    return EFRP_OK;
}
