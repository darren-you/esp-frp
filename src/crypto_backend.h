// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_aead.h"
typedef struct { const uint8_t *bytes; size_t length; } efrp_crypto_span_t;
efrp_result_t efrp_crypto_hash(const efrp_crypto_span_t *spans, size_t count, uint8_t output[32]);
/* Required only by official FRP Token authentication, not a general signature. */
efrp_result_t efrp_crypto_md5(const efrp_crypto_span_t *spans, size_t count, uint8_t output[16]);
efrp_result_t efrp_crypto_hkdf(const uint8_t *token, size_t length, const uint8_t salt[32],
                              const char *info, uint8_t output[32]);
efrp_result_t efrp_crypto_random(uint8_t *output, size_t length);
/* buffer contains plaintext for encrypt, ciphertext+tag for decrypt. Backends
 * use bounded disjoint chunks where overlap is not guaranteed. Caller must not
 * inspect output before success; record layer wipes storage on any failure. */
efrp_result_t efrp_crypto_gcm(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t aad[16], uint8_t *buffer, size_t plain_length);
/* Chunks remain private to the reader until the complete tag verifies. On any
 * failure the reader wipes and releases every chunk. */
efrp_result_t efrp_crypto_gcm_decrypt_chunks(const uint8_t key[32], const uint8_t nonce[12],
                                            const uint8_t aad[16], uint8_t *const chunks[],
                                            const size_t sizes[], size_t count, const uint8_t tag[16],
                                            bool words_only);
void efrp_crypto_zero(void *buffer, size_t length);
/* A complete GCM verification over exact store reads. The private window is
 * wiped on every failure. A verified digest binds AAD, record nonce/number,
 * tag and all ciphertext bytes; later calls must match it before exposure. */
typedef efrp_result_t (*efrp_crypto_store_read_t)(void *context, size_t offset,
                                                   uint8_t *bytes, size_t length);
efrp_result_t efrp_crypto_gcm_decrypt_store(const uint8_t key[32], const uint8_t nonce[12],
                                           const uint8_t aad[16], uint64_t sequence,
                                           efrp_crypto_store_read_t read_store, void *context,
                                           size_t plain_length, const uint8_t tag[16],
                                           size_t window_offset, uint8_t *window, size_t window_length,
                                           const uint8_t expected_digest[32], uint8_t digest[32]);
