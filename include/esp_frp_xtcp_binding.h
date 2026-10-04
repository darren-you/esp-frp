// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_frp_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Candidate protocol; original FRP v0.71.0 peers do not implement this ALPN. */
#define EFRP_XTCP_BINDING_ALPN "esp-frp-xtcp/1"
#define EFRP_XTCP_EXPORTER_LABEL "EXPORTER-esp-frp-xtcp-peer-v1"
#define EFRP_XTCP_BINDING_PROXY_MAX_BYTES 128u
#define EFRP_XTCP_BINDING_DIGEST_BYTES 32u
#define EFRP_XTCP_BINDING_MANIFEST_MAX_BYTES 377u
#define EFRP_XTCP_BINDING_PROOF_BYTES 69u
#define EFRP_XTCP_BINDING_MAX_LIFETIME_SECONDS 60u
typedef enum { EFRP_XTCP_PROVIDER = 1, EFRP_XTCP_VISITOR = 2 } efrp_xtcp_role_t;

/* Proxy bytes are borrowed. Decode borrows them from its complete wire buffer.
 * Control IDs come from the authenticated server's current control objects,
 * never from caller supplied user/run_id fields. The issuer distributes this
 * one-use RAM manifest through the two strict TLS/Token control channels. */
typedef struct {
    const uint8_t *proxy_name;
    size_t proxy_name_length;
    uint8_t sid[32];
    uint8_t provider_control_id[32], visitor_control_id[32];
    uint8_t provider_nonce[32], visitor_nonce[32];
    uint8_t provider_spki_sha256[32], visitor_spki_sha256[32];
    uint64_t issued_at_seconds, expires_at_seconds;
} efrp_xtcp_binding_manifest_t;

/* Output objects/buffers must not overlap any input object/buffer. Encode
 * clears the entire output capacity before validation. Decode clears its
 * output manifest and borrows proxy bytes from wire until the caller is done
 * with that manifest; keep wire alive and unchanged throughout that use. */
efrp_result_t efrp_xtcp_binding_validate(const efrp_xtcp_binding_manifest_t *manifest,
                                        uint64_t trusted_utc_seconds);
efrp_result_t efrp_xtcp_binding_encode(const efrp_xtcp_binding_manifest_t *manifest,
                                      uint8_t *output, size_t capacity, size_t *length);
efrp_result_t efrp_xtcp_binding_decode(const uint8_t *wire, size_t length,
                                      uint64_t trusted_utc_seconds,
                                      efrp_xtcp_binding_manifest_t *manifest);
efrp_result_t efrp_xtcp_binding_hash(const efrp_xtcp_binding_manifest_t *manifest,
                                    uint8_t output[32]);
efrp_result_t efrp_xtcp_binding_check_local(const efrp_xtcp_binding_manifest_t *manifest,
                                           efrp_xtcp_role_t role,
                                           const uint8_t control_id[32],
                                           const uint8_t nonce[32],
                                           const uint8_t spki_sha256[32]);
/* Capability proof for a signal request sent over the current strict TLS/Token
 * control. The issuer separately checks actual control ownership and user.
 * Timestamp is positive Unix UTC seconds; issuer accepts at most +/-5 seconds. */
efrp_result_t efrp_xtcp_binding_signal_proof(const uint8_t *secret, size_t secret_length,
                                            efrp_xtcp_role_t role,
                                            const uint8_t *proxy_name, size_t proxy_name_length,
                                            const uint8_t control_id[32], const uint8_t nonce[32],
                                            const uint8_t spki_sha256[32], int64_t timestamp_seconds,
                                            uint8_t output[32]);
/* Exporter is TLS1.3, non-early, exactly 32 bytes, with the label above and
 * context=SHA256(canonical manifest). Mutual TLS must verify both SPKI pins
 * before this reserved first-stream proof. Backend bytes remain forbidden
 * until both roles have verified their opposite role on the same TLS channel. */
efrp_result_t efrp_xtcp_binding_make_proof(const efrp_xtcp_binding_manifest_t *manifest,
                                          efrp_xtcp_role_t sender_role,
                                          const uint8_t exporter[32],
                                          uint8_t output[EFRP_XTCP_BINDING_PROOF_BYTES]);
efrp_result_t efrp_xtcp_binding_verify_proof(const efrp_xtcp_binding_manifest_t *manifest,
                                            efrp_xtcp_role_t expected_sender_role,
                                            const uint8_t exporter[32],
                                            const uint8_t *proof, size_t length);
#ifdef __cplusplus
}
#endif
