// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "sample_config.h"
/* Copy outside the repository; protect both input and build artifacts.
 * These placeholders compile but stop before any network initialization. */
static const char sample_wifi_ssid[] = "";
static const char sample_wifi_password[] = "";
static const char sample_ntp_server[] = "";
/* Empty keeps the DHCP DNS server. A nonempty IPv4 explicitly selects one
 * lab resolver; backup/fallback slots are cleared, never guessed. */
static const char sample_dns_ipv4[] = "";
/* The sample itself binds its dedicated frp_scratch partition and recovers
 * it before Wi-Fi/FRP startup; private inputs provide no fake store. */
static const uint8_t sample_ca_pem[] = "";
static const uint8_t sample_token[] = "";
/* Every role/backend is selected explicitly; configuration changes require
 * destroy/create with newly built input, never protocol fallback. */
static const sample_configuration_t sample_configuration = {
    .role = SAMPLE_ROLE_PROVIDER, .backend = SAMPLE_BACKEND_TCP_ECHO,
    .client.provider = {
    .server_hostname = "frp.example.invalid", .server_port = 7000,
    .ca_pem = sample_ca_pem, .ca_length = sizeof sample_ca_pem - 1,
    .token = sample_token, .token_length = sizeof sample_token - 1,
    .hostname = "esp-frp-sample", .client_id = "esp-frp-sample",
    .proxy_type = EFRP_PROXY_TCP, .transport = EFRP_TRANSPORT_YAMUX_TLS,
    .proxy_name = "esp-frp-sample", .remote_port = 0,
    .local_ipv4 = {127, 0, 0, 1}, .local_port = 8765,
    },
};
