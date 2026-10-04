// SPDX-License-Identifier: Apache-2.0
/* Signed same-key role variants exercise the production peer admission check. */
#include "quic_peer_security.h"
#include "mbedtls/oid.h"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static bool trusted(void *context) { (void)context; return true; }

static size_t signed_variant(efrp_quic_peer_identity_t *identity, efrp_xtcp_role_t role,
                             const char *variant, uint8_t der[1024])
{
    const bool provider = role == EFRP_XTCP_PROVIDER;
    const bool wrong = !strcmp(variant, "wrong_role");
    const char *name = provider != wrong ? "esp-frp-xtcp-provider" : "esp-frp-xtcp-visitor";
    const char *subject = provider != wrong ? "CN=esp-frp-xtcp-provider" : "CN=esp-frp-xtcp-visitor";
    const char *usage = provider != wrong ? MBEDTLS_OID_SERVER_AUTH : MBEDTLS_OID_CLIENT_AUTH;
    const char *other_usage = provider ? MBEDTLS_OID_CLIENT_AUTH : MBEDTLS_OID_SERVER_AUTH;
    const char *other_name = "other.example";
    mbedtls_x509_san_list other_san = {.node = {.type = MBEDTLS_X509_SAN_DNS_NAME,
        .san.unstructured_name = {.tag = MBEDTLS_ASN1_IA5_STRING, .len = strlen(other_name), .p = (uint8_t *)other_name}}};
    mbedtls_x509_san_list san = {.node = {.type = MBEDTLS_X509_SAN_DNS_NAME,
        .san.unstructured_name = {.tag = MBEDTLS_ASN1_IA5_STRING, .len = strlen(name), .p = (uint8_t *)name}},
        .next = !strcmp(variant, "extra_san") ? &other_san : NULL};
    mbedtls_asn1_sequence other_extended = {.buf = {.tag = MBEDTLS_ASN1_OID,
        .len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH), .p = (uint8_t *)other_usage}};
    mbedtls_asn1_sequence extended = {.buf = {.tag = MBEDTLS_ASN1_OID,
        .len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH), .p = (uint8_t *)usage},
        .next = !strcmp(variant, "extra_eku") ? &other_extended : NULL};
    time_t now = time(NULL), before = now - 30, after = now + 120;
    assert(now > 30);
    struct tm date; char starts[15], expires[15];
    assert(gmtime_r(&before, &date) && strftime(starts, sizeof starts, "%Y%m%d%H%M%S", &date) == 14);
    assert(gmtime_r(&after, &date) && strftime(expires, sizeof expires, "%Y%m%d%H%M%S", &date) == 14);
    uint8_t serial[16]; assert(psa_generate_random(serial, sizeof serial) == PSA_SUCCESS);
    serial[0] &= 0x7f; serial[0] |= 1;
    mbedtls_x509write_cert writer; mbedtls_x509write_crt_init(&writer);
    mbedtls_x509write_crt_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&writer, &identity->key);
    mbedtls_x509write_crt_set_issuer_key(&writer, &identity->key);
    assert(!mbedtls_x509write_crt_set_serial_raw(&writer, serial, sizeof serial));
    assert(!mbedtls_x509write_crt_set_validity(&writer, starts, expires));
    assert(!mbedtls_x509write_crt_set_subject_name(&writer, subject));
    assert(!mbedtls_x509write_crt_set_issuer_name(&writer, subject));
    assert(!mbedtls_x509write_crt_set_basic_constraints(&writer, 0, -1));
    assert(!mbedtls_x509write_crt_set_key_usage(&writer, MBEDTLS_X509_KU_DIGITAL_SIGNATURE));
    assert(!mbedtls_x509write_crt_set_ext_key_usage(&writer, &extended));
    assert(!mbedtls_x509write_crt_set_subject_alternative_name(&writer, &san));
    int length = mbedtls_x509write_crt_der(&writer, der, 1024);
    mbedtls_x509write_crt_free(&writer);
    assert(length > 0 && length <= 1024);
    size_t size = (size_t)length; memmove(der, der + 1024 - size, size);
    return size;
}

int main(void)
{
    unsigned failures = 0;
    const efrp_xtcp_role_t roles[] = {EFRP_XTCP_PROVIDER, EFRP_XTCP_VISITOR};
    const char *variants[] = {"normal", "extra_san", "extra_eku", "wrong_role"};
    for (size_t r = 0; r < sizeof roles / sizeof roles[0]; ++r) {
        efrp_quic_peer_identity_t *identity = NULL;
        assert(efrp_quic_peer_identity_create(roles[r], trusted, NULL, &identity) == EFRP_OK);
        const uint8_t *original; size_t original_length; uint8_t pin[32];
        assert(efrp_quic_peer_identity_certificate(identity, &original, &original_length, pin) == EFRP_OK);
        assert(efrp_quic_peer_certificate_check(original, original_length, roles[r], pin, trusted, NULL) == EFRP_OK);
        for (size_t v = 0; v < sizeof variants / sizeof variants[0]; ++v) {
            uint8_t der[1024]; size_t length = signed_variant(identity, roles[r], variants[v], der);
            efrp_result_t result = efrp_quic_peer_certificate_check(der, length, roles[r], pin, trusted, NULL);
            printf("signed role=%d variant=%s result=%d\n", roles[r], variants[v], result);
            if (result != (v ? EFRP_TLS_TRUST_ERROR : EFRP_OK)) {
                fprintf(stderr, "role certificate contract mismatch: role=%d variant=%s\n", roles[r], variants[v]);
                ++failures;
            }
        }
        efrp_quic_peer_identity_destroy(&identity); assert(!identity);
    }
    return failures ? 1 : 0;
}
