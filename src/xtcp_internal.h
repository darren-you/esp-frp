// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_xtcp.h"
#include "work_internal.h"
typedef struct efrp_xtcp efrp_xtcp_t;
typedef struct {
    efrp_xtcp_role_t role;
    const char *proxy_name, *secret_key;
    efrp_xtcp_options_t options;
    uint8_t local_ipv4[4]; uint16_t local_port;
    bool (*time_is_trusted)(void *context); void *context;
} efrp_xtcp_config_t;
/* No I/O at create. Authenticated server ID is supplied once per session,
 * before starting listener/work admission. All input values are copied. */
efrp_result_t efrp_xtcp_create(const efrp_xtcp_config_t *config, efrp_xtcp_t **out);
efrp_result_t efrp_xtcp_set_control_id(efrp_xtcp_t *xtcp, const uint8_t control_id[32]);
efrp_result_t efrp_xtcp_start(efrp_xtcp_t *xtcp);
void efrp_xtcp_request(efrp_xtcp_t *xtcp);
efrp_result_t efrp_xtcp_step(efrp_xtcp_t *xtcp, efrp_transport_t *control,
    uint64_t now_ms, int64_t unix_seconds, const char *run_id,
    const uint8_t *token, size_t token_length);
/* Owned contiguous frame remains stable until fully consumed. Session emits
 * AEAD plaintext records of <=1024 bytes without interleaving another frame. */
efrp_result_t efrp_xtcp_output(efrp_xtcp_t *xtcp, const uint8_t **bytes, size_t *length);
efrp_result_t efrp_xtcp_consume_output(efrp_xtcp_t *xtcp, size_t length);
efrp_result_t efrp_xtcp_response(efrp_xtcp_t *xtcp, efrp_frame_kind_t kind,
    const uint8_t *payload, size_t length, uint64_t now_ms, int64_t unix_seconds);
void efrp_xtcp_status(const efrp_xtcp_t *xtcp, efrp_xtcp_status_t *status,
    efrp_work_status_t *work);
efrp_result_t efrp_xtcp_cancel(efrp_xtcp_t *xtcp, uint64_t now_ms);
efrp_result_t efrp_xtcp_destroy(efrp_xtcp_t **xtcp, uint64_t now_ms);
