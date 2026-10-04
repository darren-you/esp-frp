// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_xtcp_binding.h"
#include "esp_frp_wire.h"
#include <stdbool.h>

#define EFRP_XTCP_SIGNAL_MAX_BYTES 4096u
#define EFRP_XTCP_CERTIFICATE_MAX_BYTES 1024u
#define EFRP_XTCP_ADDRESS_MAX_COUNT 16u
#define EFRP_XTCP_PORT_RANGE_MAX_COUNT 16u
#define EFRP_XTCP_DATAGRAM_MAX_BYTES 550u
typedef struct { uint8_t ipv4[4]; uint16_t port; } efrp_xtcp_endpoint_t;
typedef struct { uint16_t from, to; } efrp_xtcp_port_range_t;
typedef enum { EFRP_XTCP_DETECT_SENDER = 1, EFRP_XTCP_DETECT_RECEIVER = 2 } efrp_xtcp_detect_role_t;
typedef struct {
    efrp_xtcp_detect_role_t role;
    uint8_t mode, ttl;
    uint32_t send_delay_ms, read_timeout_ms;
    uint16_t send_random_ports, listen_random_ports;
    size_t port_range_count;
    efrp_xtcp_port_range_t port_ranges[EFRP_XTCP_PORT_RANGE_MAX_COUNT];
} efrp_xtcp_detect_behavior_t;
typedef struct {
    efrp_xtcp_role_t role;
    const char *transaction_id;
    const char *proxy_name;
    const char *sid;
    const uint8_t *secret; size_t secret_length;
    const uint8_t *control_id;
    const uint8_t *nonce;
    const uint8_t *spki_sha256;
    const uint8_t *certificate; size_t certificate_length;
    int64_t timestamp_seconds;
    const efrp_xtcp_endpoint_t *mapped_addresses; size_t mapped_address_count;
    const efrp_xtcp_endpoint_t *assisted_addresses; size_t assisted_address_count;
} efrp_xtcp_signal_request_t;
typedef struct {
    /* All variable spans borrow caller decode storage until it is wiped/reused.
       No JSON tree remains owned. */
    const char *transaction_id, *sid, *error;
    const uint8_t *manifest, *peer_certificate;
    size_t manifest_length, peer_certificate_length;
    const efrp_xtcp_endpoint_t *candidate_addresses, *assisted_addresses;
    size_t candidate_address_count, assisted_address_count;
    efrp_xtcp_detect_behavior_t detect;
} efrp_xtcp_signal_response_t;
/* Complete v2 MESSAGE20/21 header+payload, without stream magic. Failed output
   is cleared. Caller sends in bounded records and wipes the owned frame. */
efrp_result_t efrp_xtcp_codec_request(const efrp_xtcp_signal_request_t *request,
                                      uint8_t *output, size_t capacity, size_t *length);
efrp_result_t efrp_xtcp_codec_response(efrp_frame_kind_t kind,
                                       const uint8_t *payload, size_t length,
                                       uint8_t *storage, size_t capacity, size_t *storage_used,
                                       efrp_xtcp_signal_response_t *response);
efrp_result_t efrp_xtcp_codec_work_sid(efrp_frame_kind_t kind,
                                       const uint8_t *payload, size_t length, char sid[65]);
efrp_result_t efrp_xtcp_codec_report(const char *sid, bool success,
                                      uint8_t *output, size_t capacity, size_t *length);
typedef struct { char sid[65], transaction_id[65], nonce[65]; bool response; } efrp_xtcp_sid_message_t;
efrp_result_t efrp_xtcp_codec_sid_encode(const efrp_xtcp_sid_message_t *message,
                                         const uint8_t *secret, size_t secret_length,
                                         uint8_t *output, size_t capacity, size_t *length);
efrp_result_t efrp_xtcp_codec_sid_decode(const uint8_t *wire, size_t length,
                                         const uint8_t *secret, size_t secret_length,
                                         efrp_xtcp_sid_message_t *message);
