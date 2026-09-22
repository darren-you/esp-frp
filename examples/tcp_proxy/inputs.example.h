// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp.h"
/* Copy outside the repository; protect both input and build artifacts.
 * These placeholders compile but stop before any network initialization. */
static const char sample_wifi_ssid[] = "";
static const char sample_wifi_password[] = "";
static const char sample_ntp_server[] = "";
/* Empty keeps the DHCP DNS server. A nonempty IPv4 explicitly selects one
 * lab resolver; backup/fallback slots are cleared, never guessed. */
static const char sample_dns_ipv4[] = "";
static const uint8_t sample_ca_pem[] = "";
static const uint8_t sample_token[] = "";
static const efrp_config_t sample_frp_config = {
    .server_hostname = "frp.example.invalid", .server_port = 7000,
    .ca_pem = sample_ca_pem, .ca_length = sizeof sample_ca_pem - 1,
    .token = sample_token, .token_length = sizeof sample_token - 1,
    .hostname = "esp-frp-sample", .client_id = "esp-frp-sample",
    .proxy_name = "esp-frp-sample", .remote_port = 0,
    .local_ipv4 = {127, 0, 0, 1}, .local_port = 8765,
};
