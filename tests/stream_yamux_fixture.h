// SPDX-License-Identifier: Apache-2.0
#pragma once
/* Test-only assembly: exercise the real raw Yamux parser while work consumes
 * the same private stream operations as production. No runtime raw setter. */
#include "stream_backend.h"
#include "esp_frp_yamux.h"
typedef struct { efrp_transport_t base; efrp_yamux_t *mux; } efrp_test_yamux_transport_t;
void efrp_test_yamux_transport_init(efrp_test_yamux_transport_t *fixture, efrp_yamux_t *mux);
