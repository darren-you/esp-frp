// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_aead.h"
#include "esp_frp_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define EFRP_HANDSHAKE_RX_BYTES 4096u
#define EFRP_HANDSHAKE_TX_BYTES 4096u
#define EFRP_RUN_ID_BYTES 129u
#define EFRP_HANDSHAKE_TIMEOUT_MS UINT64_C(10000)

typedef enum {
    EFRP_HANDSHAKE_NEW = 0, EFRP_HANDSHAKE_SEND, EFRP_HANDSHAKE_HELLO,
    EFRP_HANDSHAKE_LOGIN, EFRP_HANDSHAKE_DONE, EFRP_HANDSHAKE_TAKEN,
    EFRP_HANDSHAKE_FAILED
} efrp_handshake_state_t;
typedef struct {
    const uint8_t *token;
    size_t token_length;
    /* Optional UTF-8 strings, each <=128 bytes; NULL means empty. */
    const char *hostname, *user, *client_id, *previous_run_id;
    int64_t unix_seconds; /* positive trusted wall clock, provided by owner */
} efrp_handshake_config_t;
/* Caller-owned, zero initialize; single owner, fields are not for mutation.
 * Run only over already authenticated TLS + a newly opened Yamux control stream.
 * No socket, timer or task is created here. cJSON/crypto may allocate internally. */
typedef struct {
    efrp_wire_reader_t frames;
    efrp_aead_keys_t keys;
    uint8_t token[EFRP_AEAD_MAX_TOKEN_BYTES], client_hello[512];
    uint8_t output[EFRP_HANDSHAKE_TX_BYTES];
    uint8_t *storage;
    char run_id[EFRP_RUN_ID_BYTES];
    size_t token_length, hello_length, output_length, output_offset;
    uint64_t deadline_ms, last_now_ms;
    efrp_handshake_state_t state;
    efrp_result_t failure;
    bool active;
} efrp_handshake_t;

/* Implements official lowercase hex MD5(Token || decimal Unix seconds).
 * Used by login and later scoped heartbeat/work authentication. */
efrp_result_t efrp_token_auth(const uint8_t *token, size_t length, int64_t unix_seconds, char output[33]);
efrp_result_t efrp_handshake_init(efrp_handshake_t *handshake, const efrp_handshake_config_t *config,
                                  uint8_t *storage, size_t capacity, uint64_t now_ms);
efrp_result_t efrp_handshake_output(const efrp_handshake_t *handshake, const uint8_t **bytes, size_t *length);
efrp_result_t efrp_handshake_consume_output(efrp_handshake_t *handshake, size_t length);
/* Consume only ServerHello + LoginResp. Always retain the unconsumed tail:
 * after DONE it starts the encrypted control stream, possibly in the same read. */
efrp_result_t efrp_handshake_feed(efrp_handshake_t *handshake, const uint8_t *bytes, size_t length, size_t *consumed);
efrp_result_t efrp_handshake_tick(efrp_handshake_t *handshake, uint64_t now_ms);
efrp_result_t efrp_handshake_finish(efrp_handshake_t *handshake);
/* Exactly once after DONE. Moves result to disjoint caller outputs, wipes and
 * releases the borrowed storage. Destroy never touches that storage again.
 * Caller clears keys immediately after creating direction-specific AEAD objects. */
efrp_result_t efrp_handshake_take_result(efrp_handshake_t *handshake, efrp_aead_keys_t *keys,
                                        char run_id[EFRP_RUN_ID_BYTES]);
void efrp_handshake_destroy(efrp_handshake_t *handshake);
#ifdef __cplusplus
}
#endif
