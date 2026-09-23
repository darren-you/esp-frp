// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define EFRP_CONNECT_DNS_MS UINT64_C(10000)
#define EFRP_CONNECT_TCP_MS UINT64_C(10000)
typedef struct efrp_connect efrp_connect_t;
typedef enum { EFRP_CONNECT_RESOLVING, EFRP_CONNECT_CONNECTING, EFRP_CONNECT_OPEN,
    EFRP_CONNECT_DRAINING, EFRP_CONNECT_CLOSED } efrp_connect_state_t;
typedef struct {
    efrp_connect_state_t state;
    efrp_result_t result; /* DRAINING exposes the cancellation/error reason. */
    int system_error;
    bool pending_dns, owns_socket;
} efrp_connect_status_t;
/* IDF: IPv4, one DNS request and one TCP connection attempt. Copies hostname,
 * uses SDK async DNS; requires initialized esp_netif/lwIP. Single owner,
 * no added task/timer, fallback address or automatic retry. */
efrp_result_t efrp_connect_create(const char *hostname, uint16_t port, uint64_t now_ms, efrp_connect_t **out);
/* Fixed local target: copies four IPv4 bytes, performs no DNS. step starts TCP.
 * Rejects unspecified, multicast and reserved first-octet destinations. */
efrp_result_t efrp_connect_create_ipv4(const uint8_t address[4], uint16_t port,
                                     uint64_t now_ms, efrp_connect_t **out);
efrp_result_t efrp_connect_step(efrp_connect_t *connection, uint64_t now_ms);
/* Borrow only while OPEN; do not close or change socket flags. */
efrp_result_t efrp_connect_fd(const efrp_connect_t *connection, int *fd);
/* TLS-compatible callbacks. Raw TCP EOF does not close the fd. */
efrp_result_t efrp_connect_send(void *connection, const uint8_t *bytes, size_t length, size_t *sent);
efrp_result_t efrp_connect_recv(void *connection, uint8_t *bytes, size_t capacity, size_t *received);
/* Half-close only after all application output has been accepted. EOF on recv
 * remains independent. A transient FIN allocation failure requires retry. */
efrp_result_t efrp_connect_close_write(efrp_connect_t *connection);
/* Only after recv EOF and successful close_write: normal close retains queued
 * bytes/FIN while the stack drains them. IDF reuses the positive linger chosen
 * by close_write; WOULD_BLOCK retains the handle for another attempt. */
efrp_result_t efrp_connect_finish(efrp_connect_t *connection);
/* Cancels logical work and requests abortive TCP close. In-flight SDK DNS and
 * transient socket-option/close failures can delay actual fd release;
 * WOULD_BLOCK retains ownership until a later retry succeeds. */
efrp_result_t efrp_connect_cancel(efrp_connect_t *connection);
efrp_result_t efrp_connect_status(const efrp_connect_t *connection, efrp_connect_status_t *status);
/* Cancels if necessary; WOULD_BLOCK while DNS/socket cleanup remains.
 * Only OK frees and nulls *connection. No callback references it afterward. */
efrp_result_t efrp_connect_destroy(efrp_connect_t **connection);
#ifdef __cplusplus
}
#endif
