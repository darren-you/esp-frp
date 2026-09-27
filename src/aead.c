// SPDX-License-Identifier: Apache-2.0
// Original incremental record layer; primitives belong to SDK/OpenSSL.
#include "esp_frp_aead.h"
#include "crypto_backend.h"
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
