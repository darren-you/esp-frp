// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include "picotls.h"
#include "mbedtls/x509_crt.h"

typedef struct {
    ptls_verify_certificate_t certificate;
    mbedtls_x509_crt ca;
    bool (*time_is_trusted)(void *context);
    void *context;
    unsigned chain_checks, signature_checks;
    bool pinned, peer_is_server;
    uint8_t peer_spki_sha256[32];
} efrp_quic_certificate_t;

/* TLS1.3 only advertises ECDSA P-256/SHA256 CertificateVerify.
 * CA, hostname, validity dates, serverAuth and digitalSignature are required.
 * Existing system wall clock is used; caller must prove it remains trusted. */
int efrp_quic_certificate_init(efrp_quic_certificate_t *verifier,
                              const uint8_t *ca_pem, size_t ca_length,
                              bool (*time_is_trusted)(void *context), void *context);
void efrp_quic_certificate_dispose(efrp_quic_certificate_t *verifier);
/* Candidate peer mode is an explicit per-attempt SPKI trust anchor received
 * through authenticated signaling. It never changes the CA/hostname path. */
int efrp_quic_certificate_pin_init(efrp_quic_certificate_t *verifier,
                                  const uint8_t peer_spki_sha256[32], bool peer_is_server,
                                  bool (*time_is_trusted)(void *context), void *context);
/* Already parsed certificate form of the candidate's public admission check. */
bool efrp_quic_peer_certificate_parsed_check(mbedtls_x509_crt *certificate,
                                            bool peer_is_server, const uint8_t spki_sha256[32]);
