// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_transport.h"
#include "esp_frp_xtcp_binding.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Explicit candidate configuration. STUN endpoints are numeric IPv4; no DNS
 * or separate probing socket is created. At most one rendezvous and one peer
 * connection exist, with two concurrent business streams. */
typedef struct { uint8_t ipv4[4]; uint16_t port; } efrp_xtcp_stun_server_t;
typedef struct {
    efrp_quic_profile_t peer_profile;
    efrp_xtcp_stun_server_t stun_servers[2];
    size_t stun_server_count;
    uint8_t udp_bind_ipv4[4]; uint16_t udp_bind_port;
} efrp_xtcp_options_t;
typedef enum {
    EFRP_XTCP_IDLE, EFRP_XTCP_DISCOVERING, EFRP_XTCP_SIGNALING,
    EFRP_XTCP_PUNCHING, EFRP_XTCP_HANDSHAKING, EFRP_XTCP_PROVING,
    EFRP_XTCP_READY, EFRP_XTCP_DRAINING, EFRP_XTCP_STOPPED
} efrp_xtcp_phase_t;
typedef struct {
    efrp_xtcp_phase_t phase;
    efrp_result_t error;
    uint64_t attempts, established, failed, rejected;
} efrp_xtcp_status_t;
#ifdef __cplusplus
}
#endif
