// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_session.h"
#include "stcp_visitor_internal.h"
#include "xtcp_internal.h"
typedef struct {
    efrp_handshake_config_t login;
    efrp_stcp_visitor_settings_t visitor;
    const efrp_aead_flash_store_t *flash_store;
} efrp_session_visitor_config_t;
/* A separate typed role: no NewProxy, provider destination or ReqWorkConn. */
efrp_result_t efrp_session_visitor_create(const efrp_session_visitor_config_t *config,
    efrp_transport_t *transport, uint64_t now_ms, efrp_session_t **out);
typedef struct {
    efrp_handshake_config_t login;
    efrp_xtcp_config_t xtcp;
    const efrp_aead_flash_store_t *flash_store;
} efrp_session_xtcp_config_t;
efrp_result_t efrp_session_xtcp_create(const efrp_session_xtcp_config_t *config,
    efrp_transport_t *transport, uint64_t now_ms, efrp_session_t **out);
/* Advances only child cancellation/close deadlines after parent cancellation. */
void efrp_session_drain(efrp_session_t *session, uint64_t now_ms);
