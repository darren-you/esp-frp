// SPDX-License-Identifier: Apache-2.0
#include "quic_peer_security.h"
#include <stdlib.h>
#include <string.h>
efrp_result_t efrp_quic_peer_certificate_check(const uint8_t *der, size_t length,
                                              efrp_xtcp_role_t role, const uint8_t spki_sha256[32],
                                              bool (*time_is_trusted)(void *context), void *context)
{
    if (!der || !length || length > 1024 || !spki_sha256 || !time_is_trusted ||
        (role != EFRP_XTCP_PROVIDER && role != EFRP_XTCP_VISITOR)) return EFRP_INVALID_ARGUMENT;
    if (!time_is_trusted(context)) return EFRP_TIME_UNTRUSTED;
    if (psa_crypto_init() != PSA_SUCCESS) return EFRP_CRYPTO_ERROR;
    mbedtls_x509_crt parsed; mbedtls_x509_crt_init(&parsed);
    bool valid = !mbedtls_x509_crt_parse_der(&parsed, der, length) && parsed.raw.len == length &&
        efrp_quic_peer_certificate_parsed_check(&parsed, role == EFRP_XTCP_PROVIDER, spki_sha256);
    mbedtls_x509_crt_free(&parsed); return valid ? EFRP_OK : EFRP_TLS_TRUST_ERROR;
}
efrp_result_t efrp_quic_peer_identity_create(efrp_xtcp_role_t role,
                                            bool (*time_is_trusted)(void *context), void *context,
                                            efrp_quic_peer_identity_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    efrp_quic_peer_identity_t *identity = calloc(1, sizeof *identity);
    if (!identity) return EFRP_NO_MEMORY;
    efrp_result_t result = efrp_quic_peer_identity_generate(identity, role, time_is_trusted, context);
    if (result != EFRP_OK) { free(identity); return result; }
    *out = identity; return EFRP_OK;
}
efrp_result_t efrp_quic_peer_identity_certificate(const efrp_quic_peer_identity_t *identity,
                                                 const uint8_t **der, size_t *length, uint8_t spki_sha256[32])
{
    if (der) *der = NULL;
    if (length) *length = 0;
    if (!identity || !der || !length || !spki_sha256 || !identity->key_id || !identity->certificate.base)
        return EFRP_INVALID_ARGUMENT;
    *der = identity->certificate.base; *length = identity->certificate.len; memcpy(spki_sha256, identity->spki_sha256, 32); return EFRP_OK;
}
void efrp_quic_peer_identity_destroy(efrp_quic_peer_identity_t **identity)
{ if (identity && *identity) { efrp_quic_peer_identity_dispose(*identity); free(*identity); *identity = NULL; } }
