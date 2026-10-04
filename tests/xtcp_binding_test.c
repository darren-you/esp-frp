// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_xtcp_binding.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static efrp_xtcp_binding_manifest_t fixture(void)
{
    efrp_xtcp_binding_manifest_t m = {0};
    m.proxy_name = (const uint8_t *)"provider.private"; m.proxy_name_length = 16;
    uint8_t *fields[] = {m.sid, m.provider_control_id, m.visitor_control_id, m.provider_nonce,
        m.visitor_nonce, m.provider_spki_sha256, m.visitor_spki_sha256};
    for (size_t i = 0; i < 7; ++i) memset(fields[i], (int)((i + 1) * 17), 32);
    m.issued_at_seconds = 1700000000; m.expires_at_seconds = 1700000010;
    return m;
}
static void hex(const uint8_t bytes[32], char output[65])
{
    const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        output[i * 2] = digits[bytes[i] >> 4]; output[i * 2 + 1] = digits[bytes[i] & 15];
    }
    output[64] = 0;
}
int main(void)
{
    efrp_xtcp_binding_manifest_t m = fixture(), decoded;
    uint8_t wire[EFRP_XTCP_BINDING_MANIFEST_MAX_BYTES], hash[32], exporter[32], proof[69];
    memset(exporter, 0x88, sizeof exporter);
    size_t length = 99; char text[65];
    assert(efrp_xtcp_binding_validate(&m, 1700000000) == EFRP_OK);
    assert(efrp_xtcp_binding_validate(&m, 1699999999) == EFRP_TIMEOUT);
    assert(efrp_xtcp_binding_validate(&m, 1700000010) == EFRP_TIMEOUT);
    assert(efrp_xtcp_binding_encode(&m, wire, sizeof wire, &length) == EFRP_OK && length == 265);
    assert(efrp_xtcp_binding_decode(wire, length, 1700000001, &decoded) == EFRP_OK);
    assert(decoded.proxy_name == wire + 9 && decoded.proxy_name_length == 16);
    assert(efrp_xtcp_binding_hash(&decoded, hash) == EFRP_OK);
    hex(hash, text); assert(strcmp(text, "2cd8f421a36fce3f5af0fff18fad4ef8d8876fd200ab0690cfee9c87f737ae15") == 0);
    assert(efrp_xtcp_binding_check_local(&m, EFRP_XTCP_PROVIDER, m.provider_control_id,
        m.provider_nonce, m.provider_spki_sha256) == EFRP_OK);
    assert(efrp_xtcp_binding_check_local(&m, EFRP_XTCP_VISITOR, m.provider_control_id,
        m.provider_nonce, m.provider_spki_sha256) == EFRP_AUTHENTICATION_FAILED);
    assert(efrp_xtcp_binding_make_proof(&m, EFRP_XTCP_PROVIDER, exporter, proof) == EFRP_OK);
    hex(proof + 37, text); assert(strcmp(text, "bd833d1a648605ff12850fa945e0fbe9708fad46d7d7f5b1992a0fc45f84b773") == 0);
    assert(efrp_xtcp_binding_verify_proof(&m, EFRP_XTCP_PROVIDER, exporter, proof, sizeof proof) == EFRP_OK);
    const char *secret = "public-signal-secret";
    assert(efrp_xtcp_binding_signal_proof((const uint8_t *)secret, strlen(secret), EFRP_XTCP_PROVIDER,
        m.proxy_name, m.proxy_name_length, m.provider_control_id, m.provider_nonce,
        m.provider_spki_sha256, 1700000000, hash) == EFRP_OK);
    hex(hash, text); assert(strcmp(text, "a878b434dcbff0878865b5d9910923557d0124f5bf6fa47fa21292eafe474715") == 0);
    uint8_t long_secret[128]; memset(long_secret, 'k', sizeof long_secret);
    assert(efrp_xtcp_binding_signal_proof(long_secret, sizeof long_secret, EFRP_XTCP_PROVIDER,
        m.proxy_name, m.proxy_name_length, m.provider_control_id, m.provider_nonce,
        m.provider_spki_sha256, 1700000000, hash) == EFRP_OK);
    hex(hash, text); assert(strcmp(text, "01ad5c9bdd4e32c52652af37f328912db5ba9539882f693169bd7b04e459903c") == 0);
    assert(efrp_xtcp_binding_verify_proof(&m, EFRP_XTCP_VISITOR, exporter, proof, sizeof proof) == EFRP_PROTOCOL_ERROR);
    exporter[0] ^= 1;
    assert(efrp_xtcp_binding_verify_proof(&m, EFRP_XTCP_PROVIDER, exporter, proof, sizeof proof) == EFRP_AUTHENTICATION_FAILED);
    exporter[0] ^= 1;
    uint8_t *fields[] = {m.sid, m.provider_control_id, m.visitor_control_id, m.provider_nonce,
        m.visitor_nonce, m.provider_spki_sha256, m.visitor_spki_sha256};
    for (size_t i = 0; i < 7; ++i) {
        fields[i][0] ^= 1;
        assert(efrp_xtcp_binding_verify_proof(&m, EFRP_XTCP_PROVIDER, exporter, proof, sizeof proof) == EFRP_AUTHENTICATION_FAILED);
        fields[i][0] ^= 1;
    }
    m.proxy_name = (const uint8_t *)"provider.wrongxx";
    assert(efrp_xtcp_binding_verify_proof(&m, EFRP_XTCP_PROVIDER, exporter, proof, sizeof proof) == EFRP_AUTHENTICATION_FAILED);
    m = fixture(); m.expires_at_seconds += 51;
    assert(efrp_xtcp_binding_hash(&m, hash) == EFRP_INVALID_ARGUMENT);
    m = fixture(); --m.expires_at_seconds;
    assert(efrp_xtcp_binding_verify_proof(&m, EFRP_XTCP_PROVIDER, exporter, proof, sizeof proof) == EFRP_AUTHENTICATION_FAILED);
    m = fixture();
    assert(efrp_xtcp_binding_encode(&m, wire, 264, &length) == EFRP_CAPACITY_EXCEEDED && length == 0);
    for (size_t i = 0; i < 264; ++i) assert(wire[i] == 0);
    assert(efrp_xtcp_binding_encode(&m, wire, sizeof wire, &length) == EFRP_OK);
    assert(efrp_xtcp_binding_decode(wire, length - 1, 1700000001, &decoded) == EFRP_PROTOCOL_ERROR && decoded.proxy_name == NULL);
    wire[length] = 0;
    assert(efrp_xtcp_binding_decode(wire, length + 1, 1700000001, &decoded) == EFRP_PROTOCOL_ERROR);
    assert(efrp_xtcp_binding_decode(wire, length, 1700000010, &decoded) == EFRP_TIMEOUT && decoded.proxy_name == NULL);
    wire[0] ^= 1;
    assert(efrp_xtcp_binding_decode(wire, length, 1700000001, &decoded) == EFRP_PROTOCOL_ERROR);
    char proxy[128]; memset(proxy, 'p', sizeof proxy); m.proxy_name = (const uint8_t *)proxy; m.proxy_name_length = sizeof proxy;
    assert(efrp_xtcp_binding_encode(&m, wire, sizeof wire, &length) == EFRP_OK && length == sizeof wire);
    assert(efrp_xtcp_binding_decode(wire, length, 1700000001, &decoded) == EFRP_OK);
    puts("XTCP candidate canonical manifest/channel/role proof tests passed");
    return 0;
}
