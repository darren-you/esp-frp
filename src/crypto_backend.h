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
void efrp_crypto_zero(void *buffer, size_t length);
