// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp.h"
#include <stdbool.h>

/* Lab assembly only. The public library retains its separate typed APIs. */
typedef enum { SAMPLE_ROLE_INVALID = 0, SAMPLE_ROLE_PROVIDER, SAMPLE_ROLE_STCP_VISITOR, SAMPLE_ROLE_XTCP_VISITOR } sample_role_t;
typedef enum { SAMPLE_BACKEND_INVALID = 0, SAMPLE_BACKEND_TCP_ECHO, SAMPLE_BACKEND_UDP_ECHO, SAMPLE_BACKEND_EXTERNAL, SAMPLE_BACKEND_NONE } sample_backend_t;
enum { SAMPLE_UDP_MAX_BYTES = 1500 };
typedef struct {
    sample_role_t role;
    sample_backend_t backend;
    union {
        efrp_config_t provider;
        efrp_stcp_visitor_config_t stcp_visitor;
        efrp_xtcp_visitor_config_t xtcp_visitor;
    } client;
} sample_configuration_t;

/* Checks the sample's role/backend boundary before any network initialization.
 * Complete protocol validation remains in the corresponding public create API. */
bool sample_config_valid(const sample_configuration_t *configuration);
uint16_t sample_config_backend_port(const sample_configuration_t *configuration);
efrp_transport_kind_t sample_config_transport(const sample_configuration_t *configuration);
efrp_result_t sample_config_create(const sample_configuration_t *configuration,
    efrp_time_trusted_t trusted, const efrp_aead_flash_store_t *store,
    const char *run_id, efrp_client_t **client);
