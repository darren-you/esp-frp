// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "xtcp_codec.h"
#include "esp_frp_quic_peer.h"

#define EFRP_XTCP_STUN_MAX_COUNT 2u
#define EFRP_XTCP_MAPPED_MAX_COUNT 4u
#define EFRP_XTCP_NAT_ATTEMPT_MS UINT64_C(60000)
#define EFRP_XTCP_STUN_RESPONSE_MS UINT64_C(3000)

typedef struct efrp_xtcp_nat efrp_xtcp_nat_t;
typedef struct {
    efrp_xtcp_endpoint_t stun_servers[EFRP_XTCP_STUN_MAX_COUNT];
    size_t stun_server_count;
    uint8_t bind_ipv4[4]; /* All zero permits the route-selected IPv4. */
    uint16_t bind_port; /* Zero asks the OS for one ephemeral port. */
    const uint8_t *secret;
    size_t secret_length;
} efrp_xtcp_nat_config_t;
typedef enum {
    EFRP_XTCP_NAT_DISCOVERING = 0, EFRP_XTCP_NAT_MAPPED,
    EFRP_XTCP_NAT_PUNCHING, EFRP_XTCP_NAT_PUNCHED,
    EFRP_XTCP_NAT_TRANSFERRED, EFRP_XTCP_NAT_CANCELLED, EFRP_XTCP_NAT_FAILED
} efrp_xtcp_nat_state_t;
typedef struct {
    efrp_xtcp_nat_state_t state;
    efrp_result_t last_error;
    bool owns_socket;
    efrp_xtcp_endpoint_t local, remote;
    efrp_xtcp_endpoint_t mapped_addresses[EFRP_XTCP_MAPPED_MAX_COUNT];
    size_t mapped_address_count;
    uint64_t next_deadline_ms, rejected_datagrams, sent_datagrams;
} efrp_xtcp_nat_status_t;

/* One worker owns one unconnected nonblocking UDP socket. All configuration,
 * secret bytes, candidate addresses and detect behavior are copied. A complete
 * create -> STUN -> signal wait -> detect -> transfer attempt has an absolute
 * 60-second limit. No background work, DNS or implicit second socket exists. */
efrp_result_t efrp_xtcp_nat_create(const efrp_xtcp_nat_config_t *config, uint64_t now_ms,
                                  efrp_xtcp_nat_t **nat);
efrp_result_t efrp_xtcp_nat_step(efrp_xtcp_nat_t *nat, uint64_t now_ms);
efrp_result_t efrp_xtcp_nat_status(const efrp_xtcp_nat_t *nat, efrp_xtcp_nat_status_t *status);
/* Parent verifies the authenticated manifest and local binding before calling
 * this method. The borrowed signal decode storage can then be wiped. Official
 * requests for additional random listening sockets are explicitly rejected. */
efrp_result_t efrp_xtcp_nat_start_detect(efrp_xtcp_nat_t *nat, const char *sid,
                                        const efrp_xtcp_signal_response_t *response, uint64_t now_ms);
/* On OK the peer transport owns exactly this fd; on any failure NAT retains
 * it for bounded cancellation/close retry. Endpoints must equal status values.
 * No more reads/sends occur after PUNCHED, preserving queued QUIC packets. */
efrp_result_t efrp_xtcp_nat_handoff(efrp_xtcp_nat_t *nat, const efrp_quic_peer_config_t *config,
                                   uint64_t now_ms, efrp_transport_t **transport);
efrp_result_t efrp_xtcp_nat_cancel(efrp_xtcp_nat_t *nat);
efrp_result_t efrp_xtcp_nat_destroy(efrp_xtcp_nat_t **nat);
