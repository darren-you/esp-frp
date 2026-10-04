// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_transport.h"
#include "esp_frp_xtcp_binding.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct efrp_quic_peer_identity efrp_quic_peer_identity_t;
typedef struct { uint8_t ipv4[4]; uint16_t port; } efrp_quic_peer_endpoint_t;
typedef struct {
    efrp_xtcp_role_t role; /* provider=server, visitor=client */
    efrp_quic_profile_t profile; /* explicit P256/AES128/X25519 */
    efrp_quic_peer_identity_t *identity; /* borrowed until transport destroyed */
    efrp_quic_peer_endpoint_t local, remote;
    uint8_t peer_spki_sha256[32], manifest_sha256[32]; /* immutable attempt binding */
    bool (*time_is_trusted)(void *context);
    void *context; /* borrowed until destroy succeeds; callback must not block/reenter */
} efrp_quic_peer_config_t;
/* *identity must be NULL. Fresh one-attempt PSA identity; no private key export or durable storage.
   The DER view/SPKI hash are public authenticated signaling material. */
efrp_result_t efrp_quic_peer_identity_create(efrp_xtcp_role_t role,
                                            bool (*time_is_trusted)(void *context), void *context,
                                            efrp_quic_peer_identity_t **identity);
/* DER is an immutable borrowed view until identity destruction; never free
   or modify it. The SPKI hash is copied into the caller's output. */
efrp_result_t efrp_quic_peer_identity_certificate(const efrp_quic_peer_identity_t *identity,
                                                 const uint8_t **der, size_t *length, uint8_t spki_sha256[32]);
void efrp_quic_peer_identity_destroy(efrp_quic_peer_identity_t **identity);
/* Authenticated signal certificate admission and the handshake share this
   exact role SAN, P256/SHA256 self-signature, date, KU/EKU and SPKI contract.
   One complete DER certificate, at most 1024 bytes; no system-root fallback. */
efrp_result_t efrp_quic_peer_certificate_check(const uint8_t *der, size_t length,
                                              efrp_xtcp_role_t role, const uint8_t spki_sha256[32],
                                              bool (*time_is_trusted)(void *context), void *context);
/* *transport must be NULL. Explicit candidate ALPN, mutual certificate/CV and per-attempt SPKI pins.
   Takes the bound hole-punch UDP fd only on OK (*socket becomes -1); no DNS,
   parallel socket, task, timer or fallback. Endpoints must match actual fd.
   OPEN means authenticated TLS; backend bytes still require both reserved
   stream proofs from esp_frp_xtcp_binding. Destroy before identity owner. */
efrp_result_t efrp_transport_quic_peer_create(const efrp_quic_peer_config_t *config,
                                            int *socket, uint64_t now_ms, efrp_transport_t **transport);
/* TLS1.3 non-early exporter, fixed candidate label and config's manifest hash.
   Refuses FRPS transport, incomplete handshake and untrusted actual time. */
efrp_result_t efrp_quic_peer_exporter(efrp_transport_t *transport, uint8_t output[32]);
#ifdef __cplusplus
}
#endif
