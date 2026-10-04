// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct efrp_udp_local efrp_udp_local_t;
/* Single owner, fixed IPv4 target, no DNS/task/timer. Create is allocation-only;
 * the first step opens a nonblocking connected datagram socket. */
efrp_result_t efrp_udp_local_create(const uint8_t address[4], uint16_t port, efrp_udp_local_t **out);
efrp_result_t efrp_udp_local_step(efrp_udp_local_t *local);
/* Success accepts one complete datagram, including an empty one. */
efrp_result_t efrp_udp_local_send(efrp_udp_local_t *local, const uint8_t *payload, size_t length);
/* buffer must hold max_payload + 1 bytes. The extra byte detects oversize
 * datagrams: the whole datagram is consumed and no prefix is returned. */
efrp_result_t efrp_udp_local_recv(efrp_udp_local_t *local, uint8_t *buffer, size_t max_payload, size_t *length);
/* On IDF a transient close failure retains the owned fd and handle for retry. */
efrp_result_t efrp_udp_local_destroy(efrp_udp_local_t **local);
