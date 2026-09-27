// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_frp_types.h"
#ifdef __cplusplus
extern "C" {
#endif
#define EFRP_AEAD_KEY_BYTES 32u
#define EFRP_AEAD_NONCE_BYTES 12u
#define EFRP_AEAD_TAG_BYTES 16u
#define EFRP_AEAD_MAX_PLAINTEXT 65536u
#define EFRP_AEAD_RX_BYTES (EFRP_AEAD_MAX_PLAINTEXT + EFRP_AEAD_TAG_BYTES)
#define EFRP_AEAD_TX_MAX_BYTES (EFRP_AEAD_RX_BYTES + 16u)
#define EFRP_AEAD_MAX_RECORDS (UINT64_C(1) << 32)
#define EFRP_AEAD_MAX_TOKEN_BYTES 1024u
#define EFRP_AEAD_RX_CHUNK_BYTES 4096u
#define EFRP_AEAD_RX_MAX_CHUNKS (EFRP_AEAD_MAX_PLAINTEXT / EFRP_AEAD_RX_CHUNK_BYTES)

typedef struct {
    uint8_t client_to_server[32], server_to_client[32], transcript_hash[32];
} efrp_aead_keys_t;
/* Hash exact serialized Hello payloads, not reserialized JSON. Caller first
 * validates aes-256-gcm selection and login outcome. Inputs are not retained. */
efrp_result_t efrp_aead_derive(const uint8_t *token, size_t token_length,
                               const uint8_t *client_hello, size_t client_length,
                               const uint8_t *server_hello, size_t server_length,
                               efrp_aead_keys_t *keys);
void efrp_aead_clear_keys(efrp_aead_keys_t *keys);

typedef struct {
    uint8_t key[32], stream_nonce[12], nonce[12];
    uint8_t *storage;
    size_t capacity, output_used, output_offset;
    uint64_t records;
    bool active, nonce_sent;
    efrp_result_t failure;
} efrp_aead_writer_t;

/* Writer capacity 33..65568. Smaller buffers create smaller legal records.
 * Init generates a fresh CSPRNG nonce; derive new session/direction keys.
 * write copies/accepts a prefix, not proof of transport or peer delivery. */
efrp_result_t efrp_aead_writer_init(efrp_aead_writer_t *writer, const uint8_t key[32],
                                    uint8_t *storage, size_t capacity);
efrp_result_t efrp_aead_write(efrp_aead_writer_t *writer, const uint8_t *bytes,
                              size_t length, size_t *written);
efrp_result_t efrp_aead_output(const efrp_aead_writer_t *writer, const uint8_t **bytes, size_t *length);
efrp_result_t efrp_aead_consume_output(efrp_aead_writer_t *writer, size_t length);
void efrp_aead_writer_destroy(efrp_aead_writer_t *writer);
#ifdef __cplusplus
}
#endif
