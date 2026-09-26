// SPDX-License-Identifier: Apache-2.0
// Original incremental record layer; primitives belong to SDK/OpenSSL.
#include "esp_frp_aead.h"
#include "crypto_backend.h"
#include "word_storage.h"
#include <string.h>

void efrp_crypto_zero(void *buffer, size_t length)
{
    volatile uint8_t *p = buffer;
    while (length--) *p++ = 0;
}
static void big64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (56u - 8u * i));
}
static void big32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (24u - 8u * i));
}
static bool increment(uint8_t nonce[12])
{
    for (size_t i = 12; i > 0; --i) if (++nonce[i - 1]) return true;
    return false;
}
static bool available(const uint8_t nonce[12], uint64_t records)
{
    if (records >= EFRP_AEAD_MAX_RECORDS) return false;
    for (size_t i = 0; i < 12; ++i) if (nonce[i] != 255) return true;
    return false;
}
void efrp_aead_clear_keys(efrp_aead_keys_t *keys)
{
    if (keys) efrp_crypto_zero(keys, sizeof *keys);
}
efrp_result_t efrp_aead_derive(const uint8_t *token, size_t token_length,
                               const uint8_t *client, size_t client_length,
                               const uint8_t *server, size_t server_length, efrp_aead_keys_t *keys)
{
    if (!keys) return EFRP_INVALID_ARGUMENT;
    efrp_aead_clear_keys(keys);
    if (!token || !token_length || token_length > EFRP_AEAD_MAX_TOKEN_BYTES || !client || !server ||
        !client_length || !server_length || client_length > 65536 || server_length > 65536)
        return EFRP_INVALID_ARGUMENT;
    static const uint8_t label[] = "frp wire v2 crypto transcript";
    static const uint8_t client_label[] = "\0client hello\0", server_label[] = "\0server hello\0";
    uint8_t client_size[8], server_size[8]; big64(client_size, client_length); big64(server_size, server_length);
    const efrp_crypto_span_t spans[] = {
        {label, sizeof label - 1}, {client_label, sizeof client_label - 1}, {client_size, 8}, {client, client_length},
        {server_label, sizeof server_label - 1}, {server_size, 8}, {server, server_length}
    };
    efrp_result_t result = efrp_crypto_hash(spans, sizeof spans / sizeof spans[0], keys->transcript_hash);
    if (result == EFRP_OK) result = efrp_crypto_hkdf(token, token_length, keys->transcript_hash,
        "frp wire v2 control aead aes-256-gcm client-to-server", keys->client_to_server);
    if (result == EFRP_OK) result = efrp_crypto_hkdf(token, token_length, keys->transcript_hash,
        "frp wire v2 control aead aes-256-gcm server-to-client", keys->server_to_client);
    if (result != EFRP_OK) efrp_aead_clear_keys(keys);
    return result;
}
static efrp_result_t reader_ready(const efrp_aead_reader_t *r)
{
    if (!r || !r->active) return EFRP_INVALID_STATE;
    return r->failure;
}
static void reader_clear_chunks(efrp_aead_reader_t *r)
{
    for (size_t i = 0; i < r->chunk_count; ++i) {
        if (!r->chunks[i]) continue;
        if (r->words_only) efrp_words_zero(r->chunks[i], r->chunk_sizes[i]);
        else efrp_crypto_zero(r->chunks[i], r->chunk_sizes[i]);
        r->release(r->chunks[i]); r->chunks[i] = NULL;
    }
    r->chunk_count = 0;
    efrp_crypto_zero(r->tag, sizeof r->tag);
}
static efrp_result_t reader_fail(efrp_aead_reader_t *r, efrp_result_t error)
{
    if (r->chunked) reader_clear_chunks(r);
    else efrp_crypto_zero(r->storage, EFRP_AEAD_RX_BYTES);
    efrp_crypto_zero(r->key, sizeof r->key);
    r->plain_used = r->plain_offset = 0; r->failure = error;
    return error;
}
efrp_result_t efrp_aead_reader_init(efrp_aead_reader_t *r, const uint8_t key[32], uint8_t *storage, size_t capacity)
{
    if (!r || !key || !storage || capacity < EFRP_AEAD_RX_BYTES) return EFRP_INVALID_ARGUMENT;
    if (r->active) return EFRP_INVALID_STATE;
    *r = (efrp_aead_reader_t){.storage = storage, .active = true};
    memcpy(r->key, key, 32); efrp_crypto_zero(storage, EFRP_AEAD_RX_BYTES);
    return EFRP_OK;
}
efrp_result_t efrp_aead_reader_init_chunked(efrp_aead_reader_t *r, const uint8_t key[32],
                                           void *(*allocate)(size_t, size_t), void (*release)(void *))
{
    if (!r || !key || !allocate || !release) return EFRP_INVALID_ARGUMENT;
    if (r->active) return EFRP_INVALID_STATE;
    *r = (efrp_aead_reader_t){.active = true, .chunked = true, .allocate = allocate, .release = release};
    memcpy(r->key, key, sizeof r->key);
    return EFRP_OK;
}
efrp_result_t efrp_aead_reader_init_words(efrp_aead_reader_t *r, const uint8_t key[32],
                                         void *(*allocate)(size_t, size_t), void (*release)(void *))
{
    efrp_result_t result = efrp_aead_reader_init_chunked(r, key, allocate, release);
    if (result == EFRP_OK) r->words_only = true;
    return result;
}
static efrp_result_t reader_store_chunked(efrp_aead_reader_t *r, const uint8_t *bytes,
                                          size_t length, size_t *stored)
{
    size_t plain_length = r->body_expected - EFRP_AEAD_TAG_BYTES;
    *stored = 0;
    while (length) {
        size_t offset = r->body_used;
        size_t n;
        if (offset < plain_length) {
            size_t index = offset / EFRP_AEAD_RX_CHUNK_BYTES;
            size_t inside = offset % EFRP_AEAD_RX_CHUNK_BYTES;
            if (!r->chunks[index]) {
                if (index != r->chunk_count) return reader_fail(r, EFRP_PROTOCOL_ERROR);
                size_t capacity = plain_length - index * EFRP_AEAD_RX_CHUNK_BYTES;
                if (capacity > EFRP_AEAD_RX_CHUNK_BYTES) capacity = EFRP_AEAD_RX_CHUNK_BYTES;
                size_t allocated = r->words_only ? (capacity + 3u) & ~(size_t)3u : capacity;
                r->chunks[index] = r->allocate(1, allocated);
                if (!r->chunks[index]) return reader_fail(r, EFRP_NO_MEMORY);
                if (r->words_only) {
                    if ((uintptr_t)r->chunks[index] % 4u) {
                        r->release(r->chunks[index]); r->chunks[index] = NULL;
                        return reader_fail(r, EFRP_INVALID_ARGUMENT);
                    }
                    efrp_words_zero(r->chunks[index], allocated);
                }
                r->chunk_sizes[index] = capacity;
                ++r->chunk_count;
            }
            n = r->chunk_sizes[index] - inside;
            if (n > length) n = length;
            if (r->words_only) efrp_words_store(r->chunks[index], inside, bytes, n);
            else memcpy(r->chunks[index] + inside, bytes, n);
        } else {
            size_t inside = offset - plain_length;
            n = sizeof r->tag - inside;
            if (n > length) n = length;
            memcpy(r->tag + inside, bytes, n);
        }
        r->body_used += n; bytes += n; length -= n; *stored += n;
    }
    return EFRP_OK;
}
efrp_result_t efrp_aead_feed(efrp_aead_reader_t *r, const uint8_t *bytes, size_t length, size_t *consumed)
{
    if (consumed) *consumed = 0;
    if (!consumed || (!bytes && length)) return EFRP_INVALID_ARGUMENT;
    if (reader_ready(r) != EFRP_OK) return reader_ready(r);
    while (*consumed < length) {
        if (r->plain_used) return EFRP_WOULD_BLOCK;
        if (r->nonce_used < 12) {
            size_t n = 12 - r->nonce_used;
            if (n > length - *consumed) n = length - *consumed;
            memcpy(r->stream_nonce + r->nonce_used, bytes + *consumed, n);
            r->nonce_used += n; *consumed += n;
            if (r->nonce_used != 12) continue;
            memcpy(r->nonce, r->stream_nonce, 12);
        }
        if (r->header_used < 4) {
            size_t n = 4 - r->header_used;
            if (n > length - *consumed) n = length - *consumed;
            memcpy(r->header + r->header_used, bytes + *consumed, n);
            r->header_used += n; *consumed += n;
            if (r->header_used != 4) continue;
            uint32_t size = ((uint32_t)r->header[0] << 24) | ((uint32_t)r->header[1] << 16) |
                ((uint32_t)r->header[2] << 8) | r->header[3];
            if (size < 16 || size > EFRP_AEAD_RX_BYTES) return reader_fail(r, EFRP_PROTOCOL_ERROR);
            if (!available(r->nonce, r->records)) return reader_fail(r, EFRP_COUNTER_EXHAUSTED);
            r->body_expected = size;
        }
        size_t n = r->body_expected - r->body_used;
        if (n > length - *consumed) n = length - *consumed;
        if (r->chunked) {
            size_t stored;
            efrp_result_t result = reader_store_chunked(r, bytes + *consumed, n, &stored);
            *consumed += stored;
            if (result != EFRP_OK) return result;
        } else {
            memcpy(r->storage + r->body_used, bytes + *consumed, n);
            r->body_used += n; *consumed += n;
        }
        if (r->body_used != r->body_expected) continue;
        uint8_t aad[16]; memcpy(aad, r->stream_nonce, 12); memcpy(aad + 12, r->header, 4);
        size_t plain_length = r->body_expected - 16;
        efrp_result_t result = r->chunked ?
            efrp_crypto_gcm_decrypt_chunks(r->key, r->nonce, aad, r->chunks, r->chunk_sizes,
                                           r->chunk_count, r->tag, r->words_only) :
            efrp_crypto_gcm(false, r->key, r->nonce, aad, r->storage, plain_length);
        if (result != EFRP_OK) return reader_fail(r, result);
        if (!increment(r->nonce)) return reader_fail(r, EFRP_COUNTER_EXHAUSTED);
        ++r->records; r->plain_used = plain_length; r->plain_offset = 0;
        if (r->chunked) efrp_crypto_zero(r->tag, sizeof r->tag);
        else efrp_crypto_zero(r->storage + plain_length, 16);
        if (r->chunked && !plain_length) reader_clear_chunks(r);
        r->header_used = r->body_used = r->body_expected = 0;
    }
    return EFRP_OK;
}
efrp_result_t efrp_aead_plaintext(const efrp_aead_reader_t *r, const uint8_t **bytes, size_t *length)
{
    if (bytes) *bytes = NULL;
    if (length) *length = 0;
    if (!bytes || !length) return EFRP_INVALID_ARGUMENT;
    if (reader_ready(r) != EFRP_OK) return reader_ready(r);
    if (!r->plain_used) return EFRP_WOULD_BLOCK;
    if (r->words_only) return EFRP_INVALID_STATE;
    if (r->chunked) {
        size_t index = r->plain_offset / EFRP_AEAD_RX_CHUNK_BYTES;
        size_t inside = r->plain_offset % EFRP_AEAD_RX_CHUNK_BYTES;
        *bytes = r->chunks[index] + inside;
        *length = r->chunk_sizes[index] - inside;
    } else {
        *bytes = r->storage + r->plain_offset; *length = r->plain_used - r->plain_offset;
    }
    return EFRP_OK;
}
efrp_result_t efrp_aead_copy_plaintext(const efrp_aead_reader_t *r,
                                      uint8_t *bytes, size_t capacity, size_t *copied)
{
    if (copied) *copied = 0;
    if (!copied || !bytes || !capacity) return EFRP_INVALID_ARGUMENT;
    if (reader_ready(r) != EFRP_OK) return reader_ready(r);
    if (!r->plain_used) return EFRP_WOULD_BLOCK;
    size_t n = r->plain_used - r->plain_offset;
    if (r->chunked) {
        size_t index = r->plain_offset / EFRP_AEAD_RX_CHUNK_BYTES;
        size_t inside = r->plain_offset % EFRP_AEAD_RX_CHUNK_BYTES;
        n = r->chunk_sizes[index] - inside;
        if (n > capacity) n = capacity;
        if (r->words_only) efrp_words_load(r->chunks[index], inside, bytes, n);
        else memcpy(bytes, r->chunks[index] + inside, n);
    } else {
        if (n > capacity) n = capacity;
        memcpy(bytes, r->storage + r->plain_offset, n);
    }
    *copied = n;
    return EFRP_OK;
}
efrp_result_t efrp_aead_consume_plaintext(efrp_aead_reader_t *r, size_t length)
{
    if (reader_ready(r) != EFRP_OK) return reader_ready(r);
    if (length > r->plain_used - r->plain_offset) return EFRP_INVALID_ARGUMENT;
    if (r->chunked) {
        size_t index = r->plain_offset / EFRP_AEAD_RX_CHUNK_BYTES;
        size_t inside = r->plain_offset % EFRP_AEAD_RX_CHUNK_BYTES;
        if (length > r->chunk_sizes[index] - inside) return EFRP_INVALID_ARGUMENT;
        if (r->words_only) efrp_words_clear(r->chunks[index], inside, length);
        else efrp_crypto_zero(r->chunks[index] + inside, length);
        r->plain_offset += length;
        if (r->plain_offset == r->plain_used) {
            reader_clear_chunks(r); r->plain_offset = r->plain_used = 0;
        } else if (inside + length == r->chunk_sizes[index]) {
            r->release(r->chunks[index]); r->chunks[index] = NULL;
        }
    } else {
        efrp_crypto_zero(r->storage + r->plain_offset, length); r->plain_offset += length;
        if (r->plain_offset == r->plain_used) r->plain_offset = r->plain_used = 0;
    }
    return EFRP_OK;
}
efrp_result_t efrp_aead_finish(const efrp_aead_reader_t *r)
{
    if (reader_ready(r) != EFRP_OK) return reader_ready(r);
    return ((r->nonce_used && r->nonce_used != 12) || r->header_used || r->body_used) ? EFRP_TRUNCATED : EFRP_OK;
}
void efrp_aead_reader_destroy(efrp_aead_reader_t *r)
{
    if (!r) return;
    if (r->active) {
        if (r->chunked) reader_clear_chunks(r);
        else efrp_crypto_zero(r->storage, EFRP_AEAD_RX_BYTES);
    }
    efrp_crypto_zero(r, sizeof *r);
}
static efrp_result_t writer_ready(const efrp_aead_writer_t *w)
{
    if (!w || !w->active) return EFRP_INVALID_STATE;
    return w->failure;
}
static efrp_result_t writer_fail(efrp_aead_writer_t *w, efrp_result_t error)
{
    efrp_crypto_zero(w->storage, w->capacity); efrp_crypto_zero(w->key, sizeof w->key);
    w->output_offset = w->output_used = 0; w->failure = error;
    return error;
}
efrp_result_t efrp_aead_writer_init(efrp_aead_writer_t *w, const uint8_t key[32], uint8_t *storage, size_t capacity)
{
    if (!w || !key || !storage || capacity < 33 || capacity > EFRP_AEAD_TX_MAX_BYTES) return EFRP_INVALID_ARGUMENT;
    if (w->active) return EFRP_INVALID_STATE;
    *w = (efrp_aead_writer_t){.active = true, .storage = storage, .capacity = capacity};
    efrp_crypto_zero(storage, capacity); memcpy(w->key, key, 32);
    efrp_result_t result = efrp_crypto_random(w->stream_nonce, 12);
    if (result != EFRP_OK) return writer_fail(w, result);
    memcpy(w->nonce, w->stream_nonce, 12);
    return EFRP_OK;
}
efrp_result_t efrp_aead_write(efrp_aead_writer_t *w, const uint8_t *bytes, size_t length, size_t *written)
{
    if (written) *written = 0;
    if (!written || (!bytes && length)) return EFRP_INVALID_ARGUMENT;
    if (writer_ready(w) != EFRP_OK) return writer_ready(w);
    if (!length) return EFRP_OK;
    if (w->output_used) return EFRP_WOULD_BLOCK;
    if (!available(w->nonce, w->records)) return writer_fail(w, EFRP_COUNTER_EXHAUSTED);
    size_t n = length < w->capacity - 32 ? length : w->capacity - 32;
    size_t prefix = w->nonce_sent ? 0 : 12;
    if (prefix) memcpy(w->storage, w->stream_nonce, 12);
    big32(w->storage + prefix, (uint32_t)n + 16);
    memcpy(w->storage + prefix + 4, bytes, n);
    uint8_t aad[16]; memcpy(aad, w->stream_nonce, 12); memcpy(aad + 12, w->storage + prefix, 4);
    efrp_result_t result = efrp_crypto_gcm(true, w->key, w->nonce, aad, w->storage + prefix + 4, n);
    if (result != EFRP_OK) return writer_fail(w, result);
    if (!increment(w->nonce)) return writer_fail(w, EFRP_COUNTER_EXHAUSTED);
    ++w->records; w->nonce_sent = true; w->output_used = prefix + 4 + n + 16; *written = n;
    return EFRP_OK;
}
efrp_result_t efrp_aead_output(const efrp_aead_writer_t *w, const uint8_t **bytes, size_t *length)
{
    if (bytes) *bytes = NULL;
    if (length) *length = 0;
    if (!bytes || !length) return EFRP_INVALID_ARGUMENT;
    if (writer_ready(w) != EFRP_OK) return writer_ready(w);
    if (!w->output_used) return EFRP_WOULD_BLOCK;
    *bytes = w->storage + w->output_offset; *length = w->output_used - w->output_offset;
    return EFRP_OK;
}
efrp_result_t efrp_aead_consume_output(efrp_aead_writer_t *w, size_t length)
{
    if (writer_ready(w) != EFRP_OK) return writer_ready(w);
    if (length > w->output_used - w->output_offset) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(w->storage + w->output_offset, length); w->output_offset += length;
    if (w->output_offset == w->output_used) w->output_offset = w->output_used = 0;
    return EFRP_OK;
}
void efrp_aead_writer_destroy(efrp_aead_writer_t *w)
{
    if (!w) return;
    if (w->active) efrp_crypto_zero(w->storage, w->capacity);
    efrp_crypto_zero(w, sizeof *w);
}
