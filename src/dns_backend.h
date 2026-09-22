// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_types.h"
#include <stdint.h>
typedef struct efrp_dns_request efrp_dns_request_t;
/* Single owner polls/cancels/destroys. SDK callbacks only publish completion;
 * they never call the owner. An in-flight request MUST drain before destroy. */
efrp_result_t efrp_dns_start(const char *hostname, efrp_dns_request_t **request);
efrp_result_t efrp_dns_poll(efrp_dns_request_t *request, uint8_t ipv4[4], int *error);
void efrp_dns_cancel(efrp_dns_request_t *request);
efrp_result_t efrp_dns_destroy(efrp_dns_request_t **request);
