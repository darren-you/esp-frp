// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_xtcp_binding.h"
#include "xtcp_binding_internal.h"
#include "json_internal.h"
#include <stdbool.h>
#include <string.h>

static const uint8_t manifest_magic[8] = {'E','F','R','P','X','T','C','1'};
static const uint8_t proof_magic[4] = {'X','T','P','1'};
static const char proof_domain[] = "esp-frp-xtcp-proof-v1";

static bool nonzero(const uint8_t bytes[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; ++i) any |= bytes[i];
    return any != 0;
}
static bool equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    uint8_t mismatch = 0;
    for (size_t i = 0; i < length; ++i) mismatch |= (uint8_t)(left[i] ^ right[i]);
    return mismatch == 0;
}
static bool role_valid(efrp_xtcp_role_t role)
{
    return role == EFRP_XTCP_PROVIDER || role == EFRP_XTCP_VISITOR;
}
static void store_u64(uint8_t output[8], uint64_t value)
{
    for (size_t i = 0; i < 8; ++i) output[i] = (uint8_t)(value >> (56u - 8u * i));
}
static uint64_t load_u64(const uint8_t input[8])
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | input[i];
    return value;
}
static efrp_result_t shape(const efrp_xtcp_binding_manifest_t *m)
{
    if (!m || !m->proxy_name || !m->proxy_name_length ||
        m->proxy_name_length > EFRP_XTCP_BINDING_PROXY_MAX_BYTES ||
        !efrp_json_utf8(m->proxy_name, m->proxy_name_length) ||
        !m->issued_at_seconds || m->expires_at_seconds <= m->issued_at_seconds ||
        m->expires_at_seconds - m->issued_at_seconds > EFRP_XTCP_BINDING_MAX_LIFETIME_SECONDS)
        return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < m->proxy_name_length; ++i)
        if (m->proxy_name[i] < 0x20 || m->proxy_name[i] == 0x7f) return EFRP_INVALID_ARGUMENT;
    if (!nonzero(m->sid) || !nonzero(m->provider_control_id) || !nonzero(m->visitor_control_id) ||
        !nonzero(m->provider_nonce) || !nonzero(m->visitor_nonce) ||
        !nonzero(m->provider_spki_sha256) || !nonzero(m->visitor_spki_sha256)) return EFRP_INVALID_ARGUMENT;
    return EFRP_OK;
}
efrp_result_t efrp_xtcp_binding_validate(const efrp_xtcp_binding_manifest_t *m, uint64_t now)
{
    efrp_result_t result = shape(m);
    if (result != EFRP_OK) return result;
    return now < m->issued_at_seconds || now >= m->expires_at_seconds ? EFRP_TIMEOUT : EFRP_OK;
}
static size_t make_spans(const efrp_xtcp_binding_manifest_t *m, uint8_t *proxy_length,
                         uint8_t times[16], efrp_crypto_span_t spans[11])
{
    *proxy_length = (uint8_t)m->proxy_name_length;
    store_u64(times, m->issued_at_seconds); store_u64(times + 8, m->expires_at_seconds);
    spans[0] = (efrp_crypto_span_t){manifest_magic, sizeof manifest_magic};
    spans[1] = (efrp_crypto_span_t){proxy_length, 1};
    spans[2] = (efrp_crypto_span_t){m->proxy_name, m->proxy_name_length};
    const uint8_t *fields[] = {m->sid, m->provider_control_id, m->visitor_control_id,
        m->provider_nonce, m->visitor_nonce, m->provider_spki_sha256, m->visitor_spki_sha256};
    for (size_t i = 0; i < 7; ++i) spans[3 + i] = (efrp_crypto_span_t){fields[i], 32};
    spans[10] = (efrp_crypto_span_t){times, 16};
    return 11;
}
efrp_result_t efrp_xtcp_binding_encode(const efrp_xtcp_binding_manifest_t *m,
                                      uint8_t *output, size_t capacity, size_t *length)
{
    if (!length) return EFRP_INVALID_ARGUMENT;
    *length = 0;
    if (output && capacity) efrp_crypto_zero(output, capacity);
    efrp_result_t result = shape(m);
    if (result != EFRP_OK || !output) return result == EFRP_OK ? EFRP_INVALID_ARGUMENT : result;
    size_t required = 249u + m->proxy_name_length;
    if (capacity < required) return EFRP_CAPACITY_EXCEEDED;
    efrp_crypto_span_t spans[11]; uint8_t proxy_length = 0, times[16];
    size_t count = make_spans(m, &proxy_length, times, spans), offset = 0;
    for (size_t i = 0; i < count; ++i) {
        memcpy(output + offset, spans[i].bytes, spans[i].length); offset += spans[i].length;
    }
    *length = offset;
    return EFRP_OK;
}
efrp_result_t efrp_xtcp_binding_decode(const uint8_t *wire, size_t length, uint64_t now,
                                      efrp_xtcp_binding_manifest_t *m)
{
    if (!m) return EFRP_INVALID_ARGUMENT;
    memset(m, 0, sizeof *m);
    if (!wire || length < 250u || length > EFRP_XTCP_BINDING_MANIFEST_MAX_BYTES ||
        !equal(wire, manifest_magic, sizeof manifest_magic) || !wire[8] ||
        wire[8] > EFRP_XTCP_BINDING_PROXY_MAX_BYTES || length != 249u + wire[8]) return EFRP_PROTOCOL_ERROR;
    m->proxy_name = wire + 9; m->proxy_name_length = wire[8]; size_t offset = 9u + wire[8];
    uint8_t *fields[] = {m->sid, m->provider_control_id, m->visitor_control_id, m->provider_nonce,
        m->visitor_nonce, m->provider_spki_sha256, m->visitor_spki_sha256};
    for (size_t i = 0; i < 7; ++i) { memcpy(fields[i], wire + offset, 32); offset += 32; }
    m->issued_at_seconds = load_u64(wire + offset); m->expires_at_seconds = load_u64(wire + offset + 8);
    efrp_result_t result = efrp_xtcp_binding_validate(m, now);
    if (result != EFRP_OK) memset(m, 0, sizeof *m);
    return result == EFRP_INVALID_ARGUMENT ? EFRP_PROTOCOL_ERROR : result;
}
efrp_result_t efrp_xtcp_binding_hash(const efrp_xtcp_binding_manifest_t *m, uint8_t output[32])
{
    if (!output) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(output, 32);
    efrp_result_t result = shape(m);
    if (result != EFRP_OK) return result;
    efrp_crypto_span_t spans[11]; uint8_t proxy_length = 0, times[16];
    size_t count = make_spans(m, &proxy_length, times, spans);
    result = efrp_crypto_hash(spans, count, output);
    if (result != EFRP_OK) efrp_crypto_zero(output, 32);
    return result;
}
efrp_result_t efrp_xtcp_binding_check_local(const efrp_xtcp_binding_manifest_t *m,
                                           efrp_xtcp_role_t role, const uint8_t control_id[32],
                                           const uint8_t nonce[32], const uint8_t spki[32])
{
    efrp_result_t result = shape(m);
    if (result != EFRP_OK || !role_valid(role) || !control_id || !nonce || !spki)
        return result != EFRP_OK ? result : EFRP_INVALID_ARGUMENT;
    const uint8_t *expected_control = role == EFRP_XTCP_PROVIDER ? m->provider_control_id : m->visitor_control_id;
    const uint8_t *expected_nonce = role == EFRP_XTCP_PROVIDER ? m->provider_nonce : m->visitor_nonce;
    const uint8_t *expected_spki = role == EFRP_XTCP_PROVIDER ? m->provider_spki_sha256 : m->visitor_spki_sha256;
    bool valid = equal(control_id, expected_control, 32);
    valid = equal(nonce, expected_nonce, 32) && valid;
    valid = equal(spki, expected_spki, 32) && valid;
    return valid ? EFRP_OK : EFRP_AUTHENTICATION_FAILED;
}
/* Standard HMAC-SHA256 using the existing production hash primitive. */
efrp_result_t efrp_xtcp_binding_hmac(const uint8_t *key, size_t key_length,
                                const efrp_crypto_span_t *parts, size_t count, uint8_t output[32])
{
    if (!output) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(output, 32);
    if (!key || !key_length || key_length > 128 || !parts || count > 8) return EFRP_INVALID_ARGUMENT;
    uint8_t pad[64], inner[32], shortened[32] = {0};
    efrp_result_t result = EFRP_OK;
    if (key_length > sizeof pad) {
        efrp_crypto_span_t key_span = {key, key_length};
        result = efrp_crypto_hash(&key_span, 1, shortened);
        key = shortened; key_length = sizeof shortened;
    }
    if (result == EFRP_OK) {
        for (size_t i = 0; i < sizeof pad; ++i) pad[i] = (uint8_t)((i < key_length ? key[i] : 0) ^ 0x36);
        efrp_crypto_span_t spans[9]; spans[0] = (efrp_crypto_span_t){pad, sizeof pad};
        for (size_t i = 0; i < count; ++i) spans[i + 1] = parts[i];
        result = efrp_crypto_hash(spans, count + 1, inner);
    }
    if (result == EFRP_OK) {
        for (size_t i = 0; i < sizeof pad; ++i) pad[i] = (uint8_t)((i < key_length ? key[i] : 0) ^ 0x5c);
        efrp_crypto_span_t outer[] = {{pad, sizeof pad}, {inner, sizeof inner}};
        result = efrp_crypto_hash(outer, 2, output);
    }
    efrp_crypto_zero(pad, sizeof pad); efrp_crypto_zero(inner, sizeof inner); efrp_crypto_zero(shortened, sizeof shortened);
    if (result != EFRP_OK) efrp_crypto_zero(output, 32);
    return result;
}
static efrp_result_t proof_mac(const uint8_t exporter[32], uint8_t role,
                               const uint8_t digest[32], uint8_t output[32])
{
    efrp_crypto_span_t parts[] = {{(const uint8_t *)proof_domain, sizeof proof_domain - 1}, {&role, 1}, {digest, 32}};
    return efrp_xtcp_binding_hmac(exporter, 32, parts, 3, output);
}
efrp_result_t efrp_xtcp_binding_signal_proof(const uint8_t *secret, size_t secret_length,
                                            efrp_xtcp_role_t role, const uint8_t *proxy, size_t proxy_length,
                                            const uint8_t control[32], const uint8_t nonce[32],
                                            const uint8_t spki[32], int64_t timestamp, uint8_t output[32])
{
    if (!output) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(output, 32);
    if (!secret || !secret_length || secret_length > 128 || !role_valid(role) || !proxy || !proxy_length ||
        proxy_length > EFRP_XTCP_BINDING_PROXY_MAX_BYTES || !efrp_json_utf8(proxy, proxy_length) ||
        !control || !nonce || !spki || !nonzero(control) || !nonzero(nonce) || !nonzero(spki) || timestamp <= 0)
        return EFRP_INVALID_ARGUMENT;
    static const char domain[] = "esp-frp-xtcp-signal-v1";
    uint8_t identity[2] = {(uint8_t)role, (uint8_t)proxy_length}, stamp[8];
    store_u64(stamp, (uint64_t)timestamp);
    efrp_crypto_span_t parts[] = {{(const uint8_t *)domain, sizeof domain - 1}, {identity, sizeof identity},
        {proxy, proxy_length}, {control, 32}, {nonce, 32}, {spki, 32}, {stamp, sizeof stamp}};
    return efrp_xtcp_binding_hmac(secret, secret_length, parts, 7, output);
}

efrp_result_t efrp_xtcp_binding_make_proof(const efrp_xtcp_binding_manifest_t *m,
                                          efrp_xtcp_role_t role, const uint8_t exporter[32], uint8_t output[69])
{
    if (!output) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(output, EFRP_XTCP_BINDING_PROOF_BYTES);
    if (!role_valid(role) || !exporter || !nonzero(exporter)) return EFRP_INVALID_ARGUMENT;
    efrp_result_t result = efrp_xtcp_binding_hash(m, output + 5);
    if (result == EFRP_OK) result = proof_mac(exporter, (uint8_t)role, output + 5, output + 37);
    if (result == EFRP_OK) { memcpy(output, proof_magic, 4); output[4] = (uint8_t)role; }
    else efrp_crypto_zero(output, EFRP_XTCP_BINDING_PROOF_BYTES);
    return result;
}
efrp_result_t efrp_xtcp_binding_verify_proof(const efrp_xtcp_binding_manifest_t *m,
                                            efrp_xtcp_role_t role, const uint8_t exporter[32],
                                            const uint8_t *proof, size_t length)
{
    if (!role_valid(role) || !exporter || !proof) return EFRP_INVALID_ARGUMENT;
    if (length != EFRP_XTCP_BINDING_PROOF_BYTES || !equal(proof, proof_magic, 4) || proof[4] != (uint8_t)role)
        return EFRP_PROTOCOL_ERROR;
    uint8_t expected[EFRP_XTCP_BINDING_PROOF_BYTES];
    efrp_result_t result = efrp_xtcp_binding_make_proof(m, role, exporter, expected);
    if (result == EFRP_OK && !equal(proof, expected, sizeof expected)) result = EFRP_AUTHENTICATION_FAILED;
    efrp_crypto_zero(expected, sizeof expected);
    return result;
}
