// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_xtcp_binding.h"
#include "esp_frp_quic_peer.h"
#include "quic_certificate.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"
struct efrp_quic_peer_identity {
    ptls_sign_certificate_t callback;
    mbedtls_pk_context key;
    mbedtls_svc_key_id_t key_id;
    ptls_iovec_t certificate;
    uint8_t spki_sha256[32];
    efrp_xtcp_role_t role;
};
/* Copies the one DER certificate and imports the raw 32-byte P256 scalar into
 * PSA. Its public key must equal the certificate, date/KU/role EKU must pass. */
efrp_result_t efrp_quic_peer_identity_init(efrp_quic_peer_identity_t *identity,
                                         efrp_xtcp_role_t role, const uint8_t *certificate,
                                         size_t certificate_length, const uint8_t private_scalar[32]);
void efrp_quic_peer_identity_dispose(efrp_quic_peer_identity_t *identity);
/* Fresh in-memory self-signed identity for one rendezvous; P256 PSA private
 * key stays opaque, DER has fixed role SAN/EKU and 120-second validity. */
efrp_result_t efrp_quic_peer_identity_generate(efrp_quic_peer_identity_t *identity,
                                             efrp_xtcp_role_t role,
                                             bool (*time_is_trusted)(void *context), void *context);
extern ptls_on_client_hello_t efrp_quic_peer_client_hello;
