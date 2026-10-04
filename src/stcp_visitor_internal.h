// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_stcp_visitor.h"
#include "esp_frp_wire.h"

#define EFRP_STCP_VISITOR_REQUEST_MAX_BYTES 1024u
#define EFRP_STCP_VISITOR_NAME_MAX_BYTES 128u
#define EFRP_STCP_VISITOR_SECRET_MAX_BYTES 128u

/* Typed session/work assembly. Strings are borrowed from the session's
 * owned target/secret; listener address and port are copied by value. */
typedef struct {
    const char *server_proxy_name, *secret_key;
    uint8_t bind_ipv4[4];
    uint16_t bind_port;
} efrp_stcp_visitor_settings_t;

/* Role-specific validation; the shared client create path validates the
 * server, CA, Token, callbacks and Flash provider independently. */
efrp_result_t efrp_stcp_visitor_validate(const char *server_proxy_name,
    const char *secret_key, const uint8_t bind_ipv4[4], uint16_t bind_port);

typedef struct efrp_stcp_visitor_owned efrp_stcp_visitor_owned_t;
efrp_result_t efrp_stcp_visitor_owned_clone(const char *server_proxy_name,
    const char *secret_key, efrp_stcp_visitor_owned_t **out);
const char *efrp_stcp_visitor_owned_proxy_name(const efrp_stcp_visitor_owned_t *owner);
const char *efrp_stcp_visitor_owned_secret_key(const efrp_stcp_visitor_owned_t *owner);
/* Cancels credential use while retaining target/layout for socket cleanup. */
void efrp_stcp_visitor_owned_clear_secret(efrp_stcp_visitor_owned_t *owner);
void efrp_stcp_visitor_owned_destroy(efrp_stcp_visitor_owned_t **owner);

/* Complete v2 magic followed by a MESSAGE9 frame, ready to send on a new
 * Yamux stream. No Hello or control AEAD is added to the visitor data stream.
 * The 1024-byte bound includes cJSON's five-byte printing reserve; individually
 * bounded escaped fields may exceed it and return CAPACITY_EXCEEDED. Failure
 * clears the bounded output and sets length to zero. */
efrp_result_t efrp_stcp_visitor_encode_request(const char *run_id,
    const char *server_proxy_name, const char *secret_key, int64_t unix_seconds,
    uint8_t *output, size_t capacity, size_t *length);

/* Payload includes the two-byte wire v2 message ID, as passed by the wire
 * reader callback. Caller owns framing, truncation checks and parser storage.
 * Only OK permits raw TCP forwarding after this exact response. */
efrp_result_t efrp_stcp_visitor_accept_response(efrp_frame_kind_t kind,
    const uint8_t *payload, size_t length, const char *server_proxy_name);
