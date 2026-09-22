// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_frp_types.h"
#ifdef __cplusplus
extern "C" {
#endif
#define EFRP_TLS_MAX_CA_BYTES 16384u
#define EFRP_TLS_TX_BYTES 4096u
#define EFRP_TLS_HANDSHAKE_MS UINT64_C(10000)
#define EFRP_TLS_IO_MS UINT64_C(5000)
typedef struct efrp_tls efrp_tls_t;
/* Nonblocking, single-owner callbacks. OK requires 1..length bytes; WOULD_BLOCK
 * and EOF require zero. EOF is valid only for recv and means raw TCP EOF.
 * Do not re-enter TLS. The caller owns the socket and closes it after terminal
 * status. Callback context remains borrowed until failure/close/cancel/destroy. */
typedef efrp_result_t (*efrp_tls_send_t)(void *context, const uint8_t *bytes, size_t length, size_t *sent);
typedef efrp_result_t (*efrp_tls_recv_t)(void *context, uint8_t *bytes, size_t length, size_t *received);
typedef struct {
    const char *hostname; /* expected peer identity and SNI, max 253 ASCII bytes */
    const uint8_t *ca_pem; /* PEM, length excludes terminating NUL; copied/parsed */
    size_t ca_length;
    bool time_is_trusted; /* owner has synchronized the actual system wall clock */
    efrp_tls_send_t send;
    efrp_tls_recv_t recv;
    void *io_context;
} efrp_tls_config_t;
typedef enum { EFRP_TLS_HANDSHAKING, EFRP_TLS_OPEN, EFRP_TLS_CLOSING, EFRP_TLS_CLOSED, EFRP_TLS_FAILED } efrp_tls_state_t;
typedef enum { EFRP_TLS_WANT_NONE, EFRP_TLS_WANT_READ, EFRP_TLS_WANT_WRITE } efrp_tls_want_t;
typedef struct {
    efrp_tls_state_t state;
    efrp_tls_want_t want;
    efrp_result_t result;
    int library_error;
    uint32_t verify_flags; /* UINT32_MAX means not yet available */
    size_t pending_bytes;
    uint16_t negotiated_version; /* TLS wire version 0x0303 or 0x0304 */
} efrp_tls_status_t;

/* *output must be NULL; nonblocking TLS over an already connected transport.
 * Creates no DNS request, socket, task or timer. Uses SDK Mbed TLS on ESP.
 * CA and hostname inputs are not retained after return. No insecure option. */
efrp_result_t efrp_tls_create(const efrp_tls_config_t *config, uint64_t now_ms, efrp_tls_t **output);
/* Drive at most one TLS handshake/write/close operation. WANT_NONE with
 * WOULD_BLOCK means internal progress: schedule another step without polling.
 * Call step while writes are pending; keep the same handle until they drain. */
efrp_result_t efrp_tls_step(efrp_tls_t *tls, uint64_t now_ms);
efrp_result_t efrp_tls_read(efrp_tls_t *tls, uint64_t now_ms, uint8_t *bytes, size_t capacity, size_t *received);
/* Copies a prefix into a 4 KiB queue; accepted is not a delivery receipt. */
efrp_result_t efrp_tls_write(efrp_tls_t *tls, uint64_t now_ms, const uint8_t *bytes, size_t length, size_t *accepted);
/* Drain queued bytes and send close_notify within 5 seconds via step.
 * CLOSED frees TLS resources but does not close caller's socket. */
efrp_result_t efrp_tls_close(efrp_tls_t *tls, uint64_t now_ms);
efrp_result_t efrp_tls_cancel(efrp_tls_t *tls);
efrp_result_t efrp_tls_status(const efrp_tls_t *tls, efrp_tls_status_t *status);
void efrp_tls_destroy(efrp_tls_t *tls);
#ifdef __cplusplus
}
#endif
