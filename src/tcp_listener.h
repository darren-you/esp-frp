// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_connect.h"

typedef struct efrp_tcp_listener efrp_tcp_listener_t;
/* One explicit unicast IPv4 listener, backlog two, no task or DNS. On failed
 * setup an IDF close retry can retain *out; the caller must destroy it. */
efrp_result_t efrp_tcp_listener_create(const uint8_t address[4], uint16_t port,
    efrp_tcp_listener_t **out);
/* Nonblocking readiness; first retries cleanup of an accepted fd whose
 * adoption failed. No new accepted fd exists while that cleanup is pending. */
efrp_result_t efrp_tcp_listener_ready(efrp_tcp_listener_t *listener);
/* Success transfers one connected socket to the existing TCP adapter. On
 * failure this listener retains any raw fd until abortive cleanup completes. */
efrp_result_t efrp_tcp_listener_accept(efrp_tcp_listener_t *listener,
    uint64_t now_ms, efrp_connect_t **out);
bool efrp_tcp_listener_pending(const efrp_tcp_listener_t *listener);
/* IDF close failure retains the listener and every owned fd for retry. */
efrp_result_t efrp_tcp_listener_destroy(efrp_tcp_listener_t **listener);
