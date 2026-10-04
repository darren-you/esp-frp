// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_proxy.h"
#include "esp_frp_types.h"
#include <stdint.h>
typedef struct efrp_proxy_owned efrp_proxy_owned_t;
/* NULL options means no optional values. TCP/UDP accept remote_port (zero
 * requests allocation); the other types require remote_port == 0. */
efrp_result_t efrp_proxy_validate(efrp_proxy_type_t type,
    const efrp_proxy_options_t *options, const char *proxy_name, uint16_t remote_port);
/* Encodes one complete wire v2 NewProxy MESSAGE (numeric type 3), with JSON.
 * Failure sets length to zero and clears bounded output. Inputs remain borrowed. */
efrp_result_t efrp_proxy_encode(efrp_proxy_type_t type,
    const efrp_proxy_options_t *options, const char *proxy_name, uint16_t remote_port,
    uint8_t *output, size_t capacity, size_t *length);
/* One exact allocation for active fields and the domain pointer table. TCP/UDP
 * with no active options succeed with a NULL owner. Clone checks type/field
 * bounds; validate must additionally bind the proxy name and registration size. */
efrp_result_t efrp_proxy_owned_clone(efrp_proxy_type_t type,
    const efrp_proxy_options_t *options, efrp_proxy_owned_t **out);
const efrp_proxy_options_t *efrp_proxy_owned_options(const efrp_proxy_owned_t *owner);
void efrp_proxy_owned_destroy(efrp_proxy_owned_t **owner);
