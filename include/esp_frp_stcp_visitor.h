// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_flash_reader.h"
#include "esp_frp_transport.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct efrp_client efrp_client_t;
typedef struct efrp_status efrp_status_t;

/* Independent STCP visitor role. There is no provider registration or local
 * backend destination in this config. The target is the exact wire name,
 * including its authenticated provider user prefix when that user is nonempty.
 * The visitor's Login user must be permitted by the provider's allow_users. */
typedef struct {
    const char *server_hostname; /* one DNS/TLS identity, <=253 ASCII bytes */
    uint16_t server_port;
    efrp_transport_kind_t transport;
    efrp_quic_profile_t quic_profile;
    const uint8_t *ca_pem; size_t ca_length;
    const uint8_t *token; size_t token_length;
    const char *hostname, *user, *client_id; /* optional UTF-8, <=128 bytes each */
    const char *run_id; /* optional session identity, <=64 UTF-8 bytes */
    const char *server_proxy_name; /* required exact target, <=128 UTF-8 bytes */
    const char *secret_key; /* required STCP secret, <=128 UTF-8 bytes */
    uint8_t bind_ipv4[4]; uint16_t bind_port; /* one explicit, non-wildcard listener */
    bool (*time_is_trusted)(void *context);
    const efrp_aead_flash_store_t *flash_store;
    void (*on_event)(void *context, const efrp_status_t *status);
    void *context;
} efrp_stcp_visitor_config_t;

/* Copies byte/string inputs and the Flash callback table; context and the
 * Flash provider's context stay borrowed until successful destroy. Creates
 * an idle worker without network I/O. Callbacks run on the sole worker with
 * the lifetime/reentrancy rules in esp_frp.h. Shares
 * efrp_start/stop/destroy/get_status with provider clients. READY means an
 * authenticated control session, Pong and a bound local listener; a target
 * connection is admitted separately for every accepted local socket. Strict
 * FRPS TLS and trusted wall time are required before sending credentials. */
efrp_result_t efrp_stcp_visitor_create(const efrp_stcp_visitor_config_t *config,
    efrp_client_t **out);

#ifdef __cplusplus
}
#endif
