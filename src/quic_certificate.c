// SPDX-License-Identifier: Apache-2.0
#include "quic_certificate.h"
#include <stdlib.h>
#include <string.h>
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"

#if !defined(MBEDTLS_HAVE_TIME_DATE)
#error "QUIC certificate validation requires real date checks"
#endif

typedef struct {
    mbedtls_x509_crt chain;
    efrp_quic_certificate_t *owner;
} signature_context_t;

static const uint16_t signature_algorithms[] = {PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, UINT16_MAX};

bool efrp_quic_peer_certificate_parsed_check(mbedtls_x509_crt *certificate,
                                            bool peer_is_server, const uint8_t spki_sha256[32])
{
    const char *name = peer_is_server ? "esp-frp-xtcp-provider" : "esp-frp-xtcp-visitor";
    const char *usage = peer_is_server ? MBEDTLS_OID_SERVER_AUTH : MBEDTLS_OID_CLIENT_AUTH;
    const int required = MBEDTLS_X509_EXT_KEY_USAGE | MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE | MBEDTLS_X509_EXT_SUBJECT_ALT_NAME;
    if (!certificate || !spki_sha256 || certificate->next || certificate->raw.len > 1024 ||
        mbedtls_pk_get_bitlen(&certificate->pk) != 256 ||
        certificate->MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 ||
        certificate->MBEDTLS_PRIVATE(sig_pk) != MBEDTLS_PK_SIGALG_ECDSA ||
        (certificate->MBEDTLS_PRIVATE(ext_types) & required) != required ||
        mbedtls_x509_time_is_past(&certificate->valid_to) || mbedtls_x509_time_is_future(&certificate->valid_from) ||
        mbedtls_x509_crt_check_key_usage(certificate, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ||
        mbedtls_x509_crt_check_extended_key_usage(certificate, usage, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH))) return false;
    const mbedtls_x509_sequence *san = &certificate->subject_alt_names;
    const mbedtls_x509_sequence *extended = &certificate->ext_key_usage;
    if (san->next || ((unsigned)san->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) != MBEDTLS_X509_SAN_DNS_NAME ||
        san->buf.len != strlen(name) || !san->buf.p || memcmp(san->buf.p, name, san->buf.len) ||
        extended->next || extended->buf.tag != MBEDTLS_ASN1_OID || !extended->buf.p ||
        extended->buf.len != MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH) ||
        memcmp(extended->buf.p, usage, extended->buf.len)) return false;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    int attribute_result = mbedtls_pk_get_psa_attributes(&certificate->pk, PSA_KEY_USAGE_VERIFY_HASH, &attributes);
    bool curve = !attribute_result && psa_get_key_type(&attributes) == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
    psa_reset_key_attributes(&attributes); if (!curve) return false;
    uint8_t hash[32]; size_t length = 0; unsigned different = 0;
    if (!certificate->pk_raw.p || psa_hash_compute(PSA_ALG_SHA_256, certificate->pk_raw.p, certificate->pk_raw.len,
        hash, sizeof hash, &length) != PSA_SUCCESS || length != sizeof hash) return false;
    for (unsigned i = 0; i < 32; ++i) different |= hash[i] ^ spki_sha256[i];
    memset(hash, 0, sizeof hash); if (different) return false;
    bool signature = psa_hash_compute(PSA_ALG_SHA_256, certificate->tbs.p, certificate->tbs.len,
        hash, sizeof hash, &length) == PSA_SUCCESS && length == sizeof hash &&
        mbedtls_pk_verify_ext(certificate->MBEDTLS_PRIVATE(sig_pk), &certificate->pk, MBEDTLS_MD_SHA256,
            hash, length, certificate->MBEDTLS_PRIVATE(sig).p, certificate->MBEDTLS_PRIVATE(sig).len) == 0;
    memset(hash, 0, sizeof hash); return signature;
}

static int verify_signature(void *context, uint16_t algorithm, ptls_iovec_t data, ptls_iovec_t signature)
{
    signature_context_t *state = context;
    int result = PTLS_ALERT_DECRYPT_ERROR;
    /* Picotls calls this empty pair to release state after an intervening error. */
    if (!data.len && !signature.len) { result = 0; goto done; }
    ++state->owner->signature_checks;
    if (!state->owner->time_is_trusted(state->owner->context) ||
        algorithm != PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 || !data.base || !signature.base ||
        !data.len || !signature.len || mbedtls_pk_get_bitlen(&state->chain.pk) != 256)
        goto done;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t hash[PSA_HASH_MAX_SIZE]; size_t hash_length = 0;
    if (mbedtls_pk_get_psa_attributes(&state->chain.pk, PSA_KEY_USAGE_VERIFY_HASH, &attributes) != 0)
        goto done;
    /* Exactly the TLS1.3 scheme's curve, not any 256-bit public key. */
    if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)) {
        psa_reset_key_attributes(&attributes); goto done;
    }
    psa_reset_key_attributes(&attributes);
    /* TLS sends DER ECDSA; Mbed TLS owns strict DER-to-raw conversion and
       verification through PSA. Passing DER directly to psa_verify_hash is
       incorrect because PSA requires the fixed-width r || s representation. */
    if (psa_hash_compute(PSA_ALG_SHA_256, data.base, data.len, hash, sizeof hash, &hash_length) == PSA_SUCCESS &&
        mbedtls_pk_verify(&state->chain.pk, MBEDTLS_MD_SHA256, hash, hash_length,
                          signature.base, signature.len) == 0)
        result = 0;
    memset(hash, 0, sizeof hash);
done:
    mbedtls_x509_crt_free(&state->chain); free(state);
    return result;
}

static int verify_chain(ptls_verify_certificate_t *callback, ptls_t *tls, const char *hostname,
                         int (**verify_sign)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t),
                         void **verify_data, ptls_iovec_t *certificates, size_t count)
{
    (void)tls;
    efrp_quic_certificate_t *verifier = (efrp_quic_certificate_t *)callback;
    *verify_sign = NULL; *verify_data = NULL;
    ++verifier->chain_checks;
    if ((!verifier->pinned && (!hostname || !*hostname)) || !count || count > 4 || !certificates ||
        !verifier->time_is_trusted(verifier->context)) return PTLS_ALERT_BAD_CERTIFICATE;
    signature_context_t *state = calloc(1, sizeof *state);
    if (!state) return PTLS_ERROR_NO_MEMORY;
    mbedtls_x509_crt_init(&state->chain); state->owner = verifier;
    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!certificates[i].base || !certificates[i].len || certificates[i].len > 8192 ||
            total > 16384 - certificates[i].len ||
            mbedtls_x509_crt_parse_der(&state->chain, certificates[i].base, certificates[i].len) != 0)
            goto reject;
        total += certificates[i].len;
    }
    uint32_t flags = 0;
    if (verifier->pinned) {
        if (count != 1 || !efrp_quic_peer_certificate_parsed_check(&state->chain,
            verifier->peer_is_server, verifier->peer_spki_sha256)) goto reject;
    } else if (mbedtls_x509_crt_verify(&state->chain, &verifier->ca, NULL, hostname, &flags, NULL, NULL) != 0 || flags)
        goto reject;
    const char *usage = verifier->pinned && !verifier->peer_is_server ? MBEDTLS_OID_CLIENT_AUTH : MBEDTLS_OID_SERVER_AUTH;
    if (mbedtls_x509_crt_check_key_usage(&state->chain, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0 ||
        mbedtls_x509_crt_check_extended_key_usage(&state->chain, usage, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0)
        goto reject;
    *verify_sign = verify_signature; *verify_data = state;
    return 0;
reject:
    mbedtls_x509_crt_free(&state->chain); free(state);
    return PTLS_ALERT_BAD_CERTIFICATE;
}

int efrp_quic_certificate_pin_init(efrp_quic_certificate_t *verifier,
                                  const uint8_t peer_spki_sha256[32], bool peer_is_server,
                                  bool (*time_is_trusted)(void *context), void *context)
{
    if (!verifier || !peer_spki_sha256 || !time_is_trusted || psa_crypto_init() != PSA_SUCCESS) return -1;
    unsigned nonzero = 0; for (unsigned i = 0; i < 32; ++i) nonzero |= peer_spki_sha256[i];
    if (!nonzero) return -1;
    *verifier = (efrp_quic_certificate_t){.certificate = {.cb = verify_chain, .algos = signature_algorithms},
        .time_is_trusted = time_is_trusted, .context = context, .pinned = true, .peer_is_server = peer_is_server};
    mbedtls_x509_crt_init(&verifier->ca); memcpy(verifier->peer_spki_sha256, peer_spki_sha256, 32); return 0;
}

int efrp_quic_certificate_init(efrp_quic_certificate_t *verifier,
                              const uint8_t *ca_pem, size_t ca_length,
                              bool (*time_is_trusted)(void *context), void *context)
{
    if (!verifier || !ca_pem || !ca_length || ca_length > 16384 || !time_is_trusted ||
        psa_crypto_init() != PSA_SUCCESS) return -1;
    *verifier = (efrp_quic_certificate_t){.certificate = {.cb = verify_chain, .algos = signature_algorithms},
        .time_is_trusted = time_is_trusted, .context = context};
    mbedtls_x509_crt_init(&verifier->ca);
    uint8_t *pem = calloc(1, ca_length + 1);
    if (!pem) return -1;
    memcpy(pem, ca_pem, ca_length);
    int result = mbedtls_x509_crt_parse(&verifier->ca, pem, ca_length + 1);
    free(pem);
    if (result != 0 || !verifier->ca.raw.len) { efrp_quic_certificate_dispose(verifier); return -1; }
    return 0;
}

void efrp_quic_certificate_dispose(efrp_quic_certificate_t *verifier)
{
    if (!verifier) return;
    mbedtls_x509_crt_free(&verifier->ca); memset(verifier, 0, sizeof *verifier);
}
