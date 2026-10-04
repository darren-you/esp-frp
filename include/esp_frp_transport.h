// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_tls.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct efrp_transport efrp_transport_t;
typedef enum { EFRP_TRANSPORT_YAMUX_TLS, EFRP_TRANSPORT_QUIC } efrp_transport_kind_t;
typedef enum { EFRP_TRANSPORT_RESOLVING, EFRP_TRANSPORT_HANDSHAKING,
    EFRP_TRANSPORT_OPEN, EFRP_TRANSPORT_DRAINING, EFRP_TRANSPORT_CLOSED,
    EFRP_TRANSPORT_FAILED } efrp_transport_state_t;
typedef enum { EFRP_TRANSPORT_WANT_NONE, EFRP_TRANSPORT_WANT_READ,
    EFRP_TRANSPORT_WANT_WRITE } efrp_transport_want_t;
typedef enum {
    /* TLS1.3 ECDSA P-256 CertificateVerify, AES128-GCM/SHA256, X25519.
       No 0-RTT, RSA/other-curve promise, insecure option or fallback. */
    EFRP_QUIC_PROFILE_P256_AES128_X25519 = 1
} efrp_quic_profile_t;
typedef struct {
    const char *hostname; /* same DNS/TLS identity; 1..253 ASCII bytes */
    uint16_t port;
    const uint8_t *ca_pem; size_t ca_length;
    efrp_quic_profile_t profile; /* explicit supported value required */
    bool (*time_is_trusted)(void *context); /* current actual wall clock */
    void *context; /* callback context borrowed until destroy succeeds */
} efrp_quic_config_t;
typedef struct {
    efrp_transport_kind_t kind;
    efrp_transport_state_t state;
    efrp_transport_want_t want;
    efrp_result_t result;
    int system_error, tls_error;
    uint32_t verify_flags;
    uint64_t next_deadline_ms; /* UINT64_MAX if no deadline */
    size_t pending_tx_bytes; /* accepted application data still owned */
    bool eof, pending_dns, owns_socket;
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    unsigned timeout_source;
    uint64_t timeout_stream_id;
    uint32_t timeout_age_ms, timeout_pending_bytes;
#endif
} efrp_transport_status_t;

/* *out must be NULL. Yamux owns its stream/pump state and borrows an already
   OPEN strict TLS handle with no pending write. Destroy session before this
   transport, and this transport before caller-owned TLS/socket. */
efrp_result_t efrp_transport_yamux_create(efrp_tls_t *tls, uint64_t now_ms, efrp_transport_t **out);
/* Copies hostname and parses CA; creates one IPv4 DNS request followed by one
   nonblocking connected UDP socket. Creates no task/timer or parallel retry. */
efrp_result_t efrp_transport_quic_create(const efrp_quic_config_t *config,
                                        uint64_t now_ms, efrp_transport_t **out);
/* Single owner, bounded I/O turns. Drives transport and pacing/expiry only;
   FRP heartbeat/registration/application deadlines stay with their owners. */
efrp_result_t efrp_transport_step(efrp_transport_t *transport, uint64_t now_ms);
efrp_result_t efrp_transport_status(const efrp_transport_t *transport, efrp_transport_status_t *status);
/* Cancels logical streams immediately. Retry while owned DNS/socket cleanup
   returns WOULD_BLOCK. No stale queued business data is flushed on cancel. */
efrp_result_t efrp_transport_cancel(efrp_transport_t *transport);
/* Only OK frees/nulls *transport; other results retain ownership for retry.
   Caller must stop/destroy all sessions first. */
efrp_result_t efrp_transport_destroy(efrp_transport_t **transport);
#ifdef __cplusplus
}
#endif
