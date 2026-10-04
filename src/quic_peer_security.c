// SPDX-License-Identifier: Apache-2.0
#include "quic_peer_security.h"
#include "crypto_backend.h"
#include "mbedtls/oid.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(MBEDTLS_X509_CRT_WRITE_C)
#error "XTCP peer identities require the official Mbed TLS certificate writer"
#endif
static int sign_certificate(ptls_sign_certificate_t *callback, ptls_t *tls, ptls_async_job_t **async,
                             uint16_t *selected, ptls_buffer_t *output, ptls_iovec_t input,
                             const uint16_t *algorithms, size_t count)
{
    (void)tls; (void)async; efrp_quic_peer_identity_t *identity = (efrp_quic_peer_identity_t *)callback;
    size_t algorithm = 0; while (algorithm < count && algorithms[algorithm] != PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) ++algorithm;
    if (algorithm == count) return PTLS_ALERT_HANDSHAKE_FAILURE;
    uint8_t hash[32], signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE]; size_t hash_length = 0, signature_length = 0;
    int result = PTLS_ERROR_LIBRARY;
    if (psa_hash_compute(PSA_ALG_SHA_256, input.base, input.len, hash, sizeof hash, &hash_length) == PSA_SUCCESS &&
        mbedtls_pk_sign(&identity->key, MBEDTLS_MD_SHA256, hash, hash_length,
                        signature, sizeof signature, &signature_length) == 0) {
        result = ptls_buffer_reserve(output, signature_length);
        if (!result) { memcpy(output->base + output->off, signature, signature_length); output->off += signature_length;
            *selected = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256; }
    }
    efrp_crypto_zero(hash, sizeof hash); efrp_crypto_zero(signature, sizeof signature); return result;
}
static int client_hello(ptls_on_client_hello_t *callback, ptls_t *tls, ptls_on_client_hello_parameters_t *parameters)
{
    (void)callback;
    for (size_t i = 0; i < parameters->negotiated_protocols.count; ++i) {
        ptls_iovec_t value = parameters->negotiated_protocols.list[i];
        if (value.len == sizeof EFRP_XTCP_BINDING_ALPN - 1 && !memcmp(value.base, EFRP_XTCP_BINDING_ALPN, value.len))
            return ptls_set_negotiated_protocol(tls, EFRP_XTCP_BINDING_ALPN, value.len);
    }
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}
ptls_on_client_hello_t efrp_quic_peer_client_hello = {client_hello};
void efrp_quic_peer_identity_dispose(efrp_quic_peer_identity_t *identity)
{
    if (!identity) return;
    mbedtls_pk_free(&identity->key);
    if (identity->key_id) (void)psa_destroy_key(identity->key_id);
    if (identity->certificate.base) { efrp_crypto_zero(identity->certificate.base, identity->certificate.len); free(identity->certificate.base); }
    efrp_crypto_zero(identity, sizeof *identity);
}
efrp_result_t efrp_quic_peer_identity_init(efrp_quic_peer_identity_t *identity,
                                         efrp_xtcp_role_t role, const uint8_t *certificate,
                                         size_t certificate_length, const uint8_t private_scalar[32])
{
    if (!identity || (role != EFRP_XTCP_PROVIDER && role != EFRP_XTCP_VISITOR) || !certificate || !certificate_length ||
        certificate_length > 8192 || !private_scalar) return EFRP_INVALID_ARGUMENT;
    *identity = (efrp_quic_peer_identity_t){.callback = {sign_certificate}, .role = role};
    mbedtls_pk_init(&identity->key); if (psa_crypto_init() != PSA_SUCCESS) return EFRP_CRYPTO_ERROR;
    mbedtls_x509_crt parsed; mbedtls_x509_crt_init(&parsed);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t public_key = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t expected[65], actual[65]; size_t expected_length = 0, actual_length = 0, hash_length = 0;
    efrp_result_t result = EFRP_TLS_TRUST_ERROR;
    const char *usage = role == EFRP_XTCP_PROVIDER ? MBEDTLS_OID_SERVER_AUTH : MBEDTLS_OID_CLIENT_AUTH;
    if (mbedtls_x509_crt_parse_der(&parsed, certificate, certificate_length) || mbedtls_pk_get_bitlen(&parsed.pk) != 256 ||
        mbedtls_x509_time_is_past(&parsed.valid_to) || mbedtls_x509_time_is_future(&parsed.valid_from) ||
        mbedtls_x509_crt_check_key_usage(&parsed, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ||
        mbedtls_x509_crt_check_extended_key_usage(&parsed, usage, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) ||
        mbedtls_pk_get_psa_attributes(&parsed.pk, PSA_KEY_USAGE_VERIFY_HASH, &attributes) ||
        psa_get_key_type(&attributes) != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) ||
        mbedtls_pk_import_into_psa(&parsed.pk, &attributes, &public_key)) goto done;
    if (psa_export_public_key(public_key, expected, sizeof expected, &expected_length) != PSA_SUCCESS) goto done;
    psa_reset_key_attributes(&attributes);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)); psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH); psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_import_key(&attributes, private_scalar, 32, &identity->key_id) != PSA_SUCCESS ||
        psa_export_public_key(identity->key_id, actual, sizeof actual, &actual_length) != PSA_SUCCESS ||
        actual_length != expected_length) goto done;
    unsigned different = 0; for (size_t i = 0; i < actual_length; ++i) different |= actual[i] ^ expected[i];
    if (different || mbedtls_pk_wrap_psa(&identity->key, identity->key_id) ||
        psa_hash_compute(PSA_ALG_SHA_256, parsed.pk_raw.p, parsed.pk_raw.len, identity->spki_sha256,
                         sizeof identity->spki_sha256, &hash_length) != PSA_SUCCESS || hash_length != 32) goto done;
    identity->certificate.base = malloc(certificate_length);
    if (!identity->certificate.base) { result = EFRP_NO_MEMORY; goto done; }
    memcpy(identity->certificate.base, certificate, certificate_length); identity->certificate.len = certificate_length;
    result = EFRP_OK;
done:
    if (public_key) (void)psa_destroy_key(public_key);
    psa_reset_key_attributes(&attributes); mbedtls_x509_crt_free(&parsed);
    efrp_crypto_zero(expected, sizeof expected); efrp_crypto_zero(actual, sizeof actual);
    if (result != EFRP_OK) efrp_quic_peer_identity_dispose(identity);
    return result;
}

efrp_result_t efrp_quic_peer_identity_generate(efrp_quic_peer_identity_t *identity,
                                             efrp_xtcp_role_t role,
                                             bool (*time_is_trusted)(void *context), void *context)
{
    if (!identity || (role != EFRP_XTCP_PROVIDER && role != EFRP_XTCP_VISITOR) || !time_is_trusted)
        return EFRP_INVALID_ARGUMENT;
    if (!time_is_trusted(context)) return EFRP_TIME_UNTRUSTED;
    *identity = (efrp_quic_peer_identity_t){.callback = {sign_certificate}, .role = role}; mbedtls_pk_init(&identity->key);
    if (psa_crypto_init() != PSA_SUCCESS) return EFRP_CRYPTO_ERROR;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)); psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH); psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    efrp_result_t result = EFRP_CRYPTO_ERROR;
    mbedtls_x509write_cert writer; mbedtls_x509write_crt_init(&writer);
    mbedtls_x509_crt parsed; mbedtls_x509_crt_init(&parsed);
    uint8_t der[1024], serial[16]; char starts[15], expires[15]; size_t hash_length = 0;
    if (psa_generate_key(&attributes, &identity->key_id) != PSA_SUCCESS ||
        mbedtls_pk_wrap_psa(&identity->key, identity->key_id) || psa_generate_random(serial, sizeof serial) != PSA_SUCCESS) goto done;
    serial[0] &= 0x7f; serial[0] |= 1;
    time_t now = time(NULL); if (now < 30) { result = EFRP_TIME_UNTRUSTED; goto done; }
    time_t before = now - 30, after = now + 120; struct tm date;
    if (!gmtime_r(&before, &date) || strftime(starts, sizeof starts, "%Y%m%d%H%M%S", &date) != 14 ||
        !gmtime_r(&after, &date) || strftime(expires, sizeof expires, "%Y%m%d%H%M%S", &date) != 14) goto done;
    const char *name = role == EFRP_XTCP_PROVIDER ? "esp-frp-xtcp-provider" : "esp-frp-xtcp-visitor";
    const char *subject = role == EFRP_XTCP_PROVIDER ? "CN=esp-frp-xtcp-provider" : "CN=esp-frp-xtcp-visitor";
    const char *usage = role == EFRP_XTCP_PROVIDER ? MBEDTLS_OID_SERVER_AUTH : MBEDTLS_OID_CLIENT_AUTH;
    mbedtls_x509_san_list san = {.node = {.type = MBEDTLS_X509_SAN_DNS_NAME,
        .san.unstructured_name = {.tag = MBEDTLS_ASN1_IA5_STRING, .len = strlen(name), .p = (uint8_t *)name}}};
    mbedtls_asn1_sequence extended = {.buf = {.tag = MBEDTLS_ASN1_OID,
        .len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH), .p = (uint8_t *)usage}};
    mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&writer, &identity->key); mbedtls_x509write_crt_set_issuer_key(&writer, &identity->key);
    if (mbedtls_x509write_crt_set_serial_raw(&writer, serial, sizeof serial) ||
        mbedtls_x509write_crt_set_validity(&writer, starts, expires) ||
        mbedtls_x509write_crt_set_subject_name(&writer, subject) || mbedtls_x509write_crt_set_issuer_name(&writer, subject) ||
        mbedtls_x509write_crt_set_basic_constraints(&writer, 0, -1) ||
        mbedtls_x509write_crt_set_key_usage(&writer, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ||
        mbedtls_x509write_crt_set_ext_key_usage(&writer, &extended) ||
        mbedtls_x509write_crt_set_subject_alternative_name(&writer, &san)) goto done;
    int length = mbedtls_x509write_crt_der(&writer, der, sizeof der);
    if (length <= 0 || (size_t)length > sizeof der) goto done;
    if (mbedtls_x509_crt_parse_der(&parsed, der + sizeof der - (size_t)length, (size_t)length) ||
        psa_hash_compute(PSA_ALG_SHA_256, parsed.pk_raw.p, parsed.pk_raw.len, identity->spki_sha256,
                         sizeof identity->spki_sha256, &hash_length) != PSA_SUCCESS || hash_length != 32) goto done;
    identity->certificate.base = malloc((size_t)length);
    if (!identity->certificate.base) { result = EFRP_NO_MEMORY; goto done; }
    memcpy(identity->certificate.base, der + sizeof der - (size_t)length, (size_t)length); identity->certificate.len = (size_t)length;
    result = EFRP_OK;
done:
    psa_reset_key_attributes(&attributes); mbedtls_x509write_crt_free(&writer); mbedtls_x509_crt_free(&parsed);
    efrp_crypto_zero(der, sizeof der); efrp_crypto_zero(serial, sizeof serial);
    if (result != EFRP_OK) efrp_quic_peer_identity_dispose(identity);
    return result;
}
