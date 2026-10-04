// SPDX-License-Identifier: Apache-2.0
/* Real Picotls TLS1.3 records, PSA-generated opaque P256 keys/signers and
 * pinned Mbed TLS certificate/CV verification. No fake crypto callbacks. */
#include "quic_peer_security.h"
#include <picotls/minicrypto.h>
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
static bool trusted(void *context) { return *(bool *)context; }
static void exchange(const char *mode)
{
    bool time_trusted = true;
    efrp_quic_peer_identity_t *provider = NULL, *visitor = NULL;
    assert(efrp_quic_peer_identity_create(EFRP_XTCP_PROVIDER, trusted, &time_trusted, &provider) == EFRP_OK);
    assert(efrp_quic_peer_identity_create(EFRP_XTCP_VISITOR, trusted, &time_trusted, &visitor) == EFRP_OK);
    const uint8_t *der; size_t length; uint8_t provider_pin[32], visitor_pin[32];
    assert(efrp_quic_peer_identity_certificate(provider, &der, &length, provider_pin) == EFRP_OK && length && der);
    assert(efrp_quic_peer_certificate_check(der, length, EFRP_XTCP_PROVIDER, provider_pin, trusted, &time_trusted) == EFRP_OK);
    assert(efrp_quic_peer_certificate_check(der, length, EFRP_XTCP_VISITOR, provider_pin, trusted, &time_trusted) == EFRP_TLS_TRUST_ERROR);
    uint8_t changed[1025], wrong_pin[32]; assert(length < sizeof changed - 1);
    memcpy(changed, der, length); memcpy(wrong_pin, provider_pin, 32); wrong_pin[0] ^= 1;
    assert(efrp_quic_peer_certificate_check(der, length, EFRP_XTCP_PROVIDER, wrong_pin, trusted, &time_trusted) == EFRP_TLS_TRUST_ERROR);
    changed[length - 1] ^= 1;
    assert(efrp_quic_peer_certificate_check(changed, length, EFRP_XTCP_PROVIDER, provider_pin, trusted, &time_trusted) == EFRP_TLS_TRUST_ERROR);
    memcpy(changed, der, length); changed[length] = 0;
    assert(efrp_quic_peer_certificate_check(changed, length + 1, EFRP_XTCP_PROVIDER, provider_pin, trusted, &time_trusted) == EFRP_TLS_TRUST_ERROR);
    time_trusted = false;
    assert(efrp_quic_peer_certificate_check(der, length, EFRP_XTCP_PROVIDER, provider_pin, trusted, &time_trusted) == EFRP_TIME_UNTRUSTED);
    time_trusted = true;
    assert(efrp_quic_peer_identity_certificate(visitor, &der, &length, visitor_pin) == EFRP_OK && length && der);
    if (!strcmp(mode, "wrong-provider")) provider_pin[0] ^= 1;
    if (!strcmp(mode, "wrong-visitor")) visitor_pin[0] ^= 1;
    efrp_quic_certificate_t provider_verify, visitor_verify;
    assert(!efrp_quic_certificate_pin_init(&provider_verify, visitor_pin, false, trusted, &time_trusted));
    assert(!efrp_quic_certificate_pin_init(&visitor_verify, provider_pin, true, trusted, &time_trusted));
    ptls_cipher_suite_t *ciphers[] = {&ptls_minicrypto_aes128gcmsha256, NULL};
    ptls_key_exchange_algorithm_t *exchanges[] = {&ptls_minicrypto_x25519, NULL};
    ptls_context_t server_context = {.random_bytes = ptls_minicrypto_random_bytes, .get_time = &ptls_get_time,
        .cipher_suites = ciphers, .key_exchanges = exchanges, .verify_certificate = &provider_verify.certificate,
        .sign_certificate = &provider->callback, .certificates = {&provider->certificate, 1},
        .on_client_hello = &efrp_quic_peer_client_hello, .require_client_authentication = 1,
        .use_exporter = 1, .max_buffer_size = 16384};
    ptls_context_t client_context = {.random_bytes = ptls_minicrypto_random_bytes, .get_time = &ptls_get_time,
        .cipher_suites = ciphers, .key_exchanges = exchanges, .verify_certificate = &visitor_verify.certificate,
        .sign_certificate = &visitor->callback, .certificates = {&visitor->certificate, 1},
        .use_exporter = 1, .max_buffer_size = 16384};
    if (!strcmp(mode, "missing-client")) { client_context.certificates.count = 0; client_context.sign_certificate = NULL; }
    ptls_t *client = ptls_new(&client_context, 0), *server = ptls_new(&server_context, 1); assert(client && server);
    const char *protocol = !strcmp(mode, "wrong-alpn") ? "frp" : EFRP_XTCP_BINDING_ALPN;
    ptls_iovec_t protocols[] = {ptls_iovec_init(protocol, strlen(protocol))};
    ptls_handshake_properties_t properties = {0}; properties.client.negotiated_protocols.list = protocols;
    properties.client.negotiated_protocols.count = 1;
    uint8_t client_memory[2048], server_memory[2048]; ptls_buffer_t client_bytes, server_bytes;
    ptls_buffer_init(&client_bytes, client_memory, sizeof client_memory); ptls_buffer_init(&server_bytes, server_memory, sizeof server_memory);
    size_t input_length = 0; int result = ptls_handshake(client, &client_bytes, NULL, &input_length, &properties);
    assert(result == PTLS_ERROR_IN_PROGRESS);
    for (unsigned turn = 0; turn < 10; ++turn) {
        input_length = client_bytes.off;
        result = ptls_handshake(server, &server_bytes, client_bytes.base, &input_length, NULL);
        client_bytes.off = 0;
        if (result && result != PTLS_ERROR_IN_PROGRESS) break;
        if (!ptls_handshake_is_complete(client)) {
            input_length = server_bytes.off;
            result = ptls_handshake(client, &client_bytes, server_bytes.base, &input_length, &properties);
            server_bytes.off = 0;
            if (result && result != PTLS_ERROR_IN_PROGRESS) break;
        }
        if (ptls_handshake_is_complete(server) && ptls_handshake_is_complete(client)) break;
    }
    bool success = !strcmp(mode, "ok") || !strcmp(mode, "different-context");
    fprintf(stderr, "peer %s result=%d client=%d server=%d verifies=%u/%u signatures=%u/%u\n", mode, result,
        ptls_handshake_is_complete(client), ptls_handshake_is_complete(server), visitor_verify.chain_checks,
        provider_verify.chain_checks, visitor_verify.signature_checks, provider_verify.signature_checks);
    if (success) {
        assert((!result || result == PTLS_ERROR_IN_PROGRESS) && ptls_handshake_is_complete(client) && ptls_handshake_is_complete(server));
        assert(provider_verify.chain_checks == 1 && provider_verify.signature_checks == 1);
        assert(visitor_verify.chain_checks == 1 && visitor_verify.signature_checks == 1);
        uint8_t context[32] = {1}, a[32], b[32];
        assert(!ptls_export_secret(client, a, sizeof a, EFRP_XTCP_EXPORTER_LABEL, ptls_iovec_init(context, sizeof context), 0));
        if (!strcmp(mode, "different-context")) context[0] ^= 1;
        assert(!ptls_export_secret(server, b, sizeof b, EFRP_XTCP_EXPORTER_LABEL, ptls_iovec_init(context, sizeof context), 0));
        assert((memcmp(a, b, sizeof a) == 0) == !strcmp(mode, "ok"));
    } else assert(result && result != PTLS_ERROR_IN_PROGRESS);
    ptls_buffer_dispose(&client_bytes); ptls_buffer_dispose(&server_bytes); ptls_free(client); ptls_free(server);
    efrp_quic_certificate_dispose(&provider_verify); efrp_quic_certificate_dispose(&visitor_verify);
    efrp_quic_peer_identity_destroy(&provider); efrp_quic_peer_identity_destroy(&visitor);
    assert(!provider && !visitor); printf("peer mutual TLS1.3 %s passed\n", mode);
}
int main(void)
{
    bool time_trusted = false; efrp_quic_peer_identity_t *identity = NULL;
    assert(efrp_quic_peer_identity_create(EFRP_XTCP_PROVIDER, trusted, &time_trusted, &identity) == EFRP_TIME_UNTRUSTED && !identity);
    const char *cases[] = {"ok", "wrong-provider", "wrong-visitor", "missing-client", "wrong-alpn", "different-context"};
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; ++i) exchange(cases[i]); return 0;
}
