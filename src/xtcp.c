// SPDX-License-Identifier: Apache-2.0
#include "xtcp_internal.h"
#include "xtcp_nat.h"
#include "tcp_listener.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "memory_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    efrp_stream_id_t stream;
    efrp_wire_reader_t reader;
    uint8_t json[4096], output[512];
    size_t output_length, output_offset;
    uint64_t deadline;
    bool started, sid_received, partial, closing;
    char sid[65];
    efrp_result_t error;
} efrp_xtcp_work_admission_t;
typedef struct {
    efrp_quic_peer_identity_t *identity;
    efrp_xtcp_nat_t *nat;
    efrp_transport_t *peer;
    efrp_xtcp_binding_manifest_t manifest;
    uint8_t decode[4096], nonce[32], spki[32], exporter[32];
    uint8_t local_proof[69], remote_proof[70];
    char transaction_id[65], sid[65];
    efrp_stream_id_t proof_stream;
    size_t proof_written, proof_read;
    uint64_t deadline;
    bool remote_verified, local_fin;
} efrp_xtcp_attempt_t;
struct efrp_xtcp {
    efrp_xtcp_config_t config;
    char proxy_name[129], secret_key[129];
    uint8_t control_id[32];
    efrp_xtcp_status_t status;
    efrp_work_set_t work;
    efrp_xtcp_work_admission_t *admission;
    efrp_xtcp_attempt_t *attempt;
    efrp_tcp_listener_t *listener;
    efrp_connect_t *local;
    uint8_t *output;
    size_t output_length, output_offset;
    char report_sid[65];
    unsigned pending_requests;
    bool authenticated, started, cancelled, report_pending, report_success;
};
static bool unicast(const uint8_t address[4])
{ return address[0] && address[0] < 224; }
static bool nonzero(const uint8_t *bytes, size_t length)
{ uint8_t any = 0; for (size_t i = 0; i < length; ++i) any |= bytes[i]; return any != 0; }
static void hex_encode(const uint8_t input[32], char output[65])
{
    const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) { output[2*i] = alphabet[input[i] >> 4]; output[2*i+1] = alphabet[input[i] & 15]; }
    output[64] = 0;
}
static bool hex_sid(const char *text, const uint8_t expected[32])
{
    if (!text || strlen(text) != 64) return false;
    char canonical[65]; hex_encode(expected, canonical);
    return memcmp(text, canonical, sizeof canonical) == 0;
}
efrp_result_t efrp_xtcp_create(const efrp_xtcp_config_t *config, efrp_xtcp_t **out)
{
    if (!out || !config) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if ((config->role != EFRP_XTCP_PROVIDER && config->role != EFRP_XTCP_VISITOR) ||
        !config->time_is_trusted || config->options.peer_profile != EFRP_QUIC_PROFILE_P256_AES128_X25519 ||
        !config->options.stun_server_count || config->options.stun_server_count > 2 ||
        !config->local_port || !unicast(config->local_ipv4)) return EFRP_INVALID_ARGUMENT;
    if (nonzero(config->options.udp_bind_ipv4, 4) && !unicast(config->options.udp_bind_ipv4)) return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < config->options.stun_server_count; ++i)
        if (!unicast(config->options.stun_servers[i].ipv4) || !config->options.stun_servers[i].port) return EFRP_INVALID_ARGUMENT;
    efrp_result_t result = efrp_stcp_visitor_validate(config->proxy_name, config->secret_key, config->local_ipv4, config->local_port);
    if (result != EFRP_OK) return result;
    for (const unsigned char *p = (const unsigned char *)config->proxy_name; *p; ++p)
        if (*p < 32 || *p == 127) return EFRP_INVALID_ARGUMENT;
    efrp_xtcp_t *x = efrp_heap_calloc(sizeof *x); if (!x) return EFRP_NO_MEMORY;
    x->config = *config;
    memcpy(x->proxy_name, config->proxy_name, strlen(config->proxy_name) + 1);
    memcpy(x->secret_key, config->secret_key, strlen(config->secret_key) + 1);
    x->config.proxy_name = x->proxy_name; x->config.secret_key = x->secret_key;
    result = efrp_work_peer_init(&x->work, config->role, config->role == EFRP_XTCP_PROVIDER ? config->local_ipv4 : NULL,
        config->role == EFRP_XTCP_PROVIDER ? config->local_port : 0);
    if (result != EFRP_OK) { efrp_crypto_zero(x, sizeof *x); free(x); return result; }
    *out = x; return EFRP_OK;
}
efrp_result_t efrp_xtcp_set_control_id(efrp_xtcp_t *x, const uint8_t control_id[32])
{
    if (!x || !control_id || !nonzero(control_id, 32)) return EFRP_INVALID_ARGUMENT;
    if (x->authenticated || x->cancelled) return EFRP_INVALID_STATE;
    memcpy(x->control_id, control_id, 32); x->authenticated = true; return EFRP_OK;
}
efrp_result_t efrp_xtcp_start(efrp_xtcp_t *x)
{
    if (!x || !x->authenticated || x->started || x->cancelled) return EFRP_INVALID_STATE;
    efrp_result_t result = EFRP_OK;
    if (x->config.role == EFRP_XTCP_VISITOR)
        result = efrp_tcp_listener_create(x->config.local_ipv4, x->config.local_port, &x->listener);
    if (result == EFRP_OK) x->started = true;
    return result;
}
void efrp_xtcp_request(efrp_xtcp_t *x)
{
    if (!x) return;
    if (x->config.role != EFRP_XTCP_PROVIDER || x->pending_requests || x->admission) { ++x->status.rejected; return; }
    x->pending_requests = 1;
}
static void report(efrp_xtcp_t *x, const char *sid, bool success)
{
    if (!sid || !sid[0]) return;
    if (x->report_pending) { ++x->status.rejected; return; }
    memcpy(x->report_sid, sid, 65); x->report_success = success; x->report_pending = true;
}
static void fail_attempt(efrp_xtcp_t *x, efrp_result_t result)
{
    if (x->status.phase == EFRP_XTCP_DRAINING) return;
    x->status.error = result; x->status.phase = EFRP_XTCP_DRAINING;
    ++x->status.failed;
    if (x->attempt) report(x, x->attempt->sid, false);
    (void)efrp_work_cancel(&x->work);
    if (x->attempt && x->attempt->peer) (void)efrp_transport_cancel(x->attempt->peer);
    if (x->attempt && x->attempt->nat) (void)efrp_xtcp_nat_cancel(x->attempt->nat);
    if (x->local) (void)efrp_connect_cancel(x->local);
}
static efrp_result_t drain_attempt(efrp_xtcp_t *x, uint64_t now)
{
    if (x->attempt && x->attempt->peer) (void)efrp_transport_step(x->attempt->peer, now);
    if (!efrp_work_cancel(&x->work)) return EFRP_WOULD_BLOCK;
    if (efrp_connect_destroy(&x->local) != EFRP_OK) return EFRP_WOULD_BLOCK;
    if (x->attempt) {
        efrp_xtcp_attempt_t *a = x->attempt;
        if (efrp_transport_destroy(&a->peer) != EFRP_OK) return EFRP_WOULD_BLOCK;
        if (efrp_xtcp_nat_destroy(&a->nat) != EFRP_OK) return EFRP_WOULD_BLOCK;
        efrp_quic_peer_identity_destroy(&a->identity);
        efrp_crypto_zero(a, sizeof *a); free(a); x->attempt = NULL;
    }
    x->status.phase = x->cancelled ? EFRP_XTCP_STOPPED : EFRP_XTCP_IDLE;
    return EFRP_OK;
}
static efrp_result_t begin_attempt(efrp_xtcp_t *x, const char *sid, uint64_t now)
{
    if (x->attempt || x->status.phase != EFRP_XTCP_IDLE || x->output_length || x->report_pending) return EFRP_WOULD_BLOCK;
    efrp_xtcp_attempt_t *a = efrp_heap_calloc(sizeof *a); if (!a) return EFRP_NO_MEMORY;
    x->attempt = a; a->proof_stream = EFRP_STREAM_NONE;
    if (sid) memcpy(a->sid, sid, 65);
    uint8_t transaction[32];
    efrp_result_t result = efrp_crypto_random(a->nonce, 32);
    if (result == EFRP_OK) result = efrp_crypto_random(transaction, sizeof transaction);
    if (result == EFRP_OK) hex_encode(transaction, a->transaction_id);
    efrp_crypto_zero(transaction, sizeof transaction);
    if (result == EFRP_OK) result = efrp_quic_peer_identity_create(x->config.role,
        x->config.time_is_trusted, x->config.context, &a->identity);
    efrp_xtcp_nat_config_t config = {.stun_server_count = x->config.options.stun_server_count,
        .bind_port = x->config.options.udp_bind_port,
        .secret = (const uint8_t *)x->secret_key, .secret_length = strlen(x->secret_key)};
    memcpy(config.bind_ipv4, x->config.options.udp_bind_ipv4, 4);
    for (size_t i = 0; i < config.stun_server_count; ++i) {
        memcpy(config.stun_servers[i].ipv4, x->config.options.stun_servers[i].ipv4, 4);
        config.stun_servers[i].port = x->config.options.stun_servers[i].port;
    }
    if (result == EFRP_OK) result = efrp_xtcp_nat_create(&config, now, &a->nat);
    ++x->status.attempts; x->status.error = EFRP_OK; x->status.phase = EFRP_XTCP_DISCOVERING;
    if (result != EFRP_OK) fail_attempt(x, result);
    return EFRP_OK;
}
static efrp_result_t allocate_output(efrp_xtcp_t *x)
{
    if (x->output_length) return EFRP_WOULD_BLOCK;
    if (!x->output) x->output = efrp_heap_calloc(EFRP_XTCP_SIGNAL_MAX_BYTES);
    return x->output ? EFRP_OK : EFRP_NO_MEMORY;
}
static efrp_result_t signal_request(efrp_xtcp_t *x, const efrp_xtcp_nat_status_t *status, int64_t seconds)
{
    efrp_xtcp_attempt_t *a = x->attempt;
    efrp_result_t result = allocate_output(x); if (result != EFRP_OK) return result;
    const uint8_t *certificate = NULL; size_t certificate_length = 0;
    result = efrp_quic_peer_identity_certificate(a->identity, &certificate, &certificate_length, a->spki);
    efrp_xtcp_signal_request_t request = {.role = x->config.role, .transaction_id = a->transaction_id,
        .proxy_name = x->proxy_name, .sid = x->config.role == EFRP_XTCP_PROVIDER ? a->sid : NULL,
        .secret = (const uint8_t *)x->secret_key,
        .secret_length = strlen(x->secret_key), .control_id = x->control_id, .nonce = a->nonce,
        .spki_sha256 = a->spki, .certificate = certificate, .certificate_length = certificate_length,
        .timestamp_seconds = seconds, .mapped_addresses = status->mapped_addresses,
        .mapped_address_count = status->mapped_address_count,
        .assisted_addresses = unicast(status->local.ipv4) ? &status->local : NULL,
        .assisted_address_count = unicast(status->local.ipv4) ? 1u : 0u};
    if (result == EFRP_OK) result = efrp_xtcp_codec_request(&request, x->output, EFRP_XTCP_SIGNAL_MAX_BYTES, &x->output_length);
    if (result == EFRP_OK) { x->output_offset = 0; x->status.phase = EFRP_XTCP_SIGNALING; }
    return result;
}
efrp_result_t efrp_xtcp_output(efrp_xtcp_t *x, const uint8_t **bytes, size_t *length)
{
    if (!x || !bytes || !length) return EFRP_INVALID_ARGUMENT;
    *bytes = NULL; *length = 0;
    if (x->cancelled) return EFRP_CANCELLED;
    if (!x->output_length && x->report_pending) {
        efrp_result_t result = allocate_output(x); if (result != EFRP_OK) return result;
        result = efrp_xtcp_codec_report(x->report_sid, x->report_success, x->output,
            EFRP_XTCP_SIGNAL_MAX_BYTES, &x->output_length);
        if (result != EFRP_OK) return result;
        x->report_pending = false; efrp_crypto_zero(x->report_sid, sizeof x->report_sid);
    }
    if (!x->output_length) return EFRP_WOULD_BLOCK;
    *bytes = x->output + x->output_offset; *length = x->output_length - x->output_offset; return EFRP_OK;
}
efrp_result_t efrp_xtcp_consume_output(efrp_xtcp_t *x, size_t length)
{
    if (!x || !length || length > x->output_length - x->output_offset) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(x->output + x->output_offset, length); x->output_offset += length;
    if (x->output_offset == x->output_length) {
        efrp_crypto_zero(x->output, EFRP_XTCP_SIGNAL_MAX_BYTES); free(x->output); x->output = NULL;
        x->output_length = x->output_offset = 0;
    }
    return EFRP_OK;
}
efrp_result_t efrp_xtcp_response(efrp_xtcp_t *x, efrp_frame_kind_t kind,
    const uint8_t *payload, size_t length, uint64_t now, int64_t seconds)
{
    if (!x || !x->attempt || x->status.phase != EFRP_XTCP_SIGNALING || seconds <= 0) return EFRP_PROTOCOL_ERROR;
    efrp_xtcp_attempt_t *a = x->attempt;
    efrp_xtcp_signal_response_t response; size_t used;
    efrp_result_t result = efrp_xtcp_codec_response(kind, payload, length, a->decode, sizeof a->decode, &used, &response);
    if ((result != EFRP_OK && result != EFRP_WORK_REJECTED) ||
        !response.transaction_id || strcmp(response.transaction_id, a->transaction_id)) return EFRP_PROTOCOL_ERROR;
    if (result == EFRP_OK && !x->config.time_is_trusted(x->config.context)) result = EFRP_TIME_UNTRUSTED;
    if (result == EFRP_OK) result = efrp_xtcp_binding_decode(response.manifest, response.manifest_length,
        (uint64_t)seconds, &a->manifest);
    if (result == EFRP_OK && (a->manifest.proxy_name_length != strlen(x->proxy_name) ||
        memcmp(a->manifest.proxy_name, x->proxy_name, a->manifest.proxy_name_length) ||
        !hex_sid(response.sid, a->manifest.sid) || (a->sid[0] && strcmp(a->sid, response.sid)))) result = EFRP_AUTHENTICATION_FAILED;
    if (result == EFRP_OK) result = efrp_xtcp_binding_check_local(&a->manifest, x->config.role, x->control_id, a->nonce, a->spki);
    efrp_xtcp_role_t peer_role = x->config.role == EFRP_XTCP_PROVIDER ? EFRP_XTCP_VISITOR : EFRP_XTCP_PROVIDER;
    const uint8_t *pin = peer_role == EFRP_XTCP_PROVIDER ? a->manifest.provider_spki_sha256 : a->manifest.visitor_spki_sha256;
    if (result == EFRP_OK) result = efrp_quic_peer_certificate_check(response.peer_certificate,
        response.peer_certificate_length, peer_role, pin, x->config.time_is_trusted, x->config.context);
    if (result == EFRP_OK) {
        memcpy(a->sid, response.sid, 65);
        result = efrp_xtcp_nat_start_detect(a->nat, a->sid, &response, now);
    }
    if (result != EFRP_OK) { fail_attempt(x, result); return EFRP_OK; }
    x->status.phase = EFRP_XTCP_PUNCHING; return EFRP_OK;
}
static bool admit_frame(void *context, efrp_frame_kind_t kind, const uint8_t *payload, size_t length)
{
    efrp_xtcp_t *x = context; efrp_xtcp_work_admission_t *w = x->admission;
    w->error = EFRP_PROTOCOL_ERROR;
    if (w->started) {
        if (w->sid_received) return false;
        w->error = efrp_xtcp_codec_work_sid(kind, payload, length, w->sid);
        w->sid_received = w->error == EFRP_OK; return w->sid_received;
    }
    if (kind != EFRP_MESSAGE || length < 2 || payload[0] || payload[1] != 8) return false;
    cJSON *root = efrp_json_parse(payload + 2, length - 2, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    const char *const fields[] = {"proxy_name", "src_addr", "dst_addr", "src_port", "dst_port", "error"};
    const char *error = efrp_json_string(root, "error"), *src = efrp_json_string(root, "src_addr"), *dst = efrp_json_string(root, "dst_addr");
    bool valid = efrp_json_shape(root, fields, 6) && error && src && dst && strlen(src) <= 128 && strlen(dst) <= 128 &&
        efrp_json_equals(root, "proxy_name", x->proxy_name);
    const char *const ports[] = {"src_port", "dst_port"};
    for (size_t i = 0; valid && i < 2; ++i) {
        const cJSON *port = efrp_json_field(root, ports[i]);
        valid = !port || (cJSON_IsNumber(port) && port->valuedouble >= 0 && port->valuedouble <= 65535 &&
            port->valuedouble == (double)(uint16_t)port->valuedouble);
    }
    if (valid) { w->error = *error ? EFRP_WORK_REJECTED : EFRP_OK; w->started = w->error == EFRP_OK; }
    cJSON_Delete(root); return w->started;
}
static efrp_result_t open_admission(efrp_xtcp_t *x, efrp_transport_t *control, uint64_t now,
    int64_t seconds, const char *run_id, const uint8_t *token, size_t token_length)
{
    if (!x->pending_requests || x->admission) return EFRP_OK;
    efrp_xtcp_work_admission_t *w = efrp_heap_calloc(sizeof *w); if (!w) return EFRP_NO_MEMORY;
    w->stream = EFRP_STREAM_NONE;
    efrp_result_t result = efrp_stream_open(control, &w->stream);
    if (result != EFRP_OK) { free(w); return result == EFRP_WOULD_BLOCK ? EFRP_OK : result; }
    x->admission = w; --x->pending_requests;
    char signature[33] = {0}, stamp[21];
    result = efrp_token_auth(token, token_length, seconds, signature);
    snprintf(stamp, sizeof stamp, "%" PRId64, seconds);
    cJSON *root = cJSON_CreateObject();
    bool built = root && result == EFRP_OK && cJSON_AddStringToObject(root, "run_id", run_id) &&
        cJSON_AddStringToObject(root, "privilege_key", signature) && cJSON_AddRawToObject(root, "timestamp", stamp);
    efrp_crypto_zero(signature, sizeof signature);
    if (result == EFRP_OK && !built) result = EFRP_NO_MEMORY;
    if (result == EFRP_OK && !cJSON_PrintPreallocated(root, (char *)w->output + 17, (int)sizeof w->output - 17, 0)) result = EFRP_CAPACITY_EXCEEDED;
    cJSON *auth = cJSON_GetObjectItemCaseSensitive(root, "privilege_key");
    if (auth && auth->valuestring) efrp_crypto_zero(auth->valuestring, strlen(auth->valuestring));
    cJSON_Delete(root);
    if (result != EFRP_OK) { w->closing = true; w->error = result; return result; }
    size_t length = strlen((char *)w->output + 17);
    memcpy(w->output, efrp_wire_magic, 7);
    result = efrp_wire_header(EFRP_MESSAGE, length + 2, w->output + 7);
    w->output[15] = 0; w->output[16] = 6; w->output_length = length + 17;
    w->deadline = now + EFRP_SESSION_RESPONSE_MS;
    if (result == EFRP_OK) result = efrp_wire_init(&w->reader, w->json, sizeof w->json, false, admit_frame, x);
    return result;
}
static efrp_result_t step_admission(efrp_xtcp_t *x, efrp_transport_t *control, uint64_t now)
{
    efrp_xtcp_work_admission_t *w = x->admission; if (!w) return EFRP_OK;
    if (w->closing) {
        efrp_result_t result = efrp_stream_reset(control, w->stream);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) return result;
        result = efrp_stream_release(control, w->stream);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) return result;
        efrp_crypto_zero(w, sizeof *w); free(w); x->admission = NULL; return EFRP_OK;
    }
    if ((w->output_length || w->partial) && now >= w->deadline) { w->error = EFRP_TIMEOUT; w->closing = true; ++x->status.rejected; return EFRP_OK; }
    size_t used; efrp_result_t result;
    if (w->output_offset < w->output_length) {
        result = efrp_stream_write(control, w->stream, w->output + w->output_offset, w->output_length - w->output_offset, &used);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) { w->closing = true; return EFRP_OK; }
        efrp_crypto_zero(w->output + w->output_offset, used); w->output_offset += used;
        if (w->output_offset == w->output_length) w->output_length = w->output_offset = 0;
        return EFRP_OK;
    }
    uint8_t input[1024];
    result = efrp_stream_read(control, w->stream, input, sizeof input, &used);
    if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
    if (result == EFRP_EOF) {
        result = efrp_wire_finish(&w->reader);
        if (result == EFRP_OK && w->sid_received) {
            if (!x->attempt && x->status.phase == EFRP_XTCP_IDLE && !x->output_length && !x->report_pending)
                result = begin_attempt(x, w->sid, now);
            else { report(x, w->sid, false); ++x->status.rejected; }
        } else ++x->status.rejected;
        w->closing = true; return result;
    }
    if (result != EFRP_OK) { w->closing = true; ++x->status.rejected; return EFRP_OK; }
    if (!w->partial) { w->partial = true; w->deadline = now + EFRP_SESSION_RESPONSE_MS; }
    size_t consumed; result = efrp_wire_feed(&w->reader, input, used, &consumed);
    efrp_crypto_zero(input, sizeof input);
    if (result != EFRP_OK) { w->closing = true; ++x->status.rejected; }
    return EFRP_OK;
}
static efrp_result_t proof_step(efrp_xtcp_t *x, uint64_t now)
{
    efrp_xtcp_attempt_t *a = x->attempt;
    if (now >= a->deadline) return EFRP_TIMEOUT;
    efrp_result_t result;
    if (a->proof_stream == EFRP_STREAM_NONE) {
        result = x->config.role == EFRP_XTCP_VISITOR ? efrp_stream_open(a->peer, &a->proof_stream) : efrp_stream_accept(a->peer, &a->proof_stream);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) return result;
        if (a->proof_stream != 0) return EFRP_AUTHENTICATION_FAILED;
    }
    if (!a->remote_verified) {
        size_t read; result = efrp_stream_read(a->peer, a->proof_stream,
            a->remote_proof + a->proof_read, sizeof a->remote_proof - a->proof_read, &read);
        if (result == EFRP_OK) {
            a->proof_read += read; if (a->proof_read > 69) return EFRP_AUTHENTICATION_FAILED;
        } else if (result == EFRP_EOF) {
            result = efrp_xtcp_binding_verify_proof(&a->manifest,
                x->config.role == EFRP_XTCP_PROVIDER ? EFRP_XTCP_VISITOR : EFRP_XTCP_PROVIDER,
                a->exporter, a->remote_proof, a->proof_read);
            if (result != EFRP_OK) return result;
            a->remote_verified = true;
        } else if (result != EFRP_WOULD_BLOCK) return result;
    }
    if (x->config.role == EFRP_XTCP_VISITOR || a->remote_verified) {
        if (a->proof_written < 69) {
            size_t written; result = efrp_stream_write(a->peer, a->proof_stream,
                a->local_proof + a->proof_written, 69 - a->proof_written, &written);
            if (result == EFRP_OK) a->proof_written += written;
            else if (result != EFRP_WOULD_BLOCK) return result;
        } else if (!a->local_fin) {
            result = efrp_stream_close_write(a->peer, a->proof_stream);
            if (result == EFRP_OK) a->local_fin = true;
            else if (result != EFRP_WOULD_BLOCK) return result;
        }
    }
    if (a->remote_verified && a->local_fin) {
        result = efrp_stream_release(a->peer, a->proof_stream);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) return result;
        a->proof_stream = EFRP_STREAM_NONE;
        efrp_crypto_zero(a->exporter, sizeof a->exporter);
        efrp_crypto_zero(a->local_proof, sizeof a->local_proof); efrp_crypto_zero(a->remote_proof, sizeof a->remote_proof);
        x->status.phase = EFRP_XTCP_READY; ++x->status.established; report(x, a->sid, true);
    }
    return EFRP_OK;
}
static efrp_result_t step_attempt(efrp_xtcp_t *x, uint64_t now, int64_t seconds)
{
    efrp_xtcp_attempt_t *a = x->attempt; if (!a) return EFRP_OK;
    if (x->status.phase == EFRP_XTCP_DISCOVERING || x->status.phase == EFRP_XTCP_SIGNALING || x->status.phase == EFRP_XTCP_PUNCHING) {
        efrp_result_t result = efrp_xtcp_nat_step(a->nat, now);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
        efrp_xtcp_nat_status_t status; result = efrp_xtcp_nat_status(a->nat, &status); if (result != EFRP_OK) return result;
        if (status.state == EFRP_XTCP_NAT_MAPPED && x->status.phase == EFRP_XTCP_DISCOVERING) return signal_request(x, &status, seconds);
        if (status.state != EFRP_XTCP_NAT_PUNCHED) return EFRP_OK;
        result = efrp_xtcp_binding_validate(&a->manifest, (uint64_t)seconds);
        if (result != EFRP_OK) return result;
        efrp_quic_peer_config_t config = {.role = x->config.role, .profile = x->config.options.peer_profile,
            .identity = a->identity, .time_is_trusted = x->config.time_is_trusted, .context = x->config.context};
        memcpy(config.local.ipv4, status.local.ipv4, 4); config.local.port = status.local.port;
        memcpy(config.remote.ipv4, status.remote.ipv4, 4); config.remote.port = status.remote.port;
        memcpy(config.peer_spki_sha256, x->config.role == EFRP_XTCP_PROVIDER ? a->manifest.visitor_spki_sha256 : a->manifest.provider_spki_sha256, 32);
        result = efrp_xtcp_binding_hash(&a->manifest, config.manifest_sha256);
        if (result == EFRP_OK) result = efrp_xtcp_nat_handoff(a->nat, &config, now, &a->peer);
        if (result != EFRP_OK) return result;
        a->deadline = now + 10000; x->status.phase = EFRP_XTCP_HANDSHAKING;
    }
    efrp_result_t result = efrp_transport_step(a->peer, now);
    if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
    efrp_transport_status_t status; result = efrp_transport_status(a->peer, &status); if (result != EFRP_OK) return result;
    if (x->status.phase == EFRP_XTCP_HANDSHAKING) {
        if (now >= a->deadline) return EFRP_TIMEOUT;
        if (status.state != EFRP_TRANSPORT_OPEN) return EFRP_OK;
        result = efrp_quic_peer_exporter(a->peer, a->exporter);
        if (result == EFRP_OK) result = efrp_xtcp_binding_make_proof(&a->manifest, x->config.role, a->exporter, a->local_proof);
        if (result != EFRP_OK) return result;
        x->status.phase = EFRP_XTCP_PROVING;
    }
    if (x->status.phase == EFRP_XTCP_PROVING) return proof_step(x, now);
    if (x->status.phase == EFRP_XTCP_READY) {
        if (x->local) {
            result = efrp_work_peer_adopt(&x->work, &x->local, now);
            if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
        }
        return efrp_work_peer_step(&x->work, a->peer, now);
    }
    return EFRP_OK;
}
efrp_result_t efrp_xtcp_step(efrp_xtcp_t *x, efrp_transport_t *control, uint64_t now,
    int64_t seconds, const char *run_id, const uint8_t *token, size_t token_length)
{
    if (!x || !control || !run_id || !token || !token_length || seconds <= 0 || now > UINT64_MAX - 60000) return EFRP_INVALID_ARGUMENT;
    if (x->cancelled) { (void)drain_attempt(x, now); return EFRP_CANCELLED; }
    if (!x->authenticated || !x->started) return EFRP_INVALID_STATE;
    if (x->status.phase == EFRP_XTCP_DRAINING) { (void)drain_attempt(x, now); return EFRP_OK; }
    efrp_result_t result = open_admission(x, control, now, seconds, run_id, token, token_length);
    if (result == EFRP_OK) result = step_admission(x, control, now);
    if (result != EFRP_OK) return result;
    if (x->config.role == EFRP_XTCP_VISITOR && !x->local &&
        (x->status.phase == EFRP_XTCP_IDLE || x->status.phase == EFRP_XTCP_READY)) {
        efrp_work_status_t work; efrp_work_status(&x->work, &work);
        if (work.active + work.cleaning < 2) {
            result = efrp_tcp_listener_ready(x->listener);
            if (result == EFRP_OK) result = efrp_tcp_listener_accept(x->listener, now, &x->local);
            if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
            if (x->local && x->status.phase == EFRP_XTCP_IDLE) {
                result = begin_attempt(x, NULL, now);
                if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) fail_attempt(x, result);
            }
        }
    }
    /* A local accepted while a previous report was pending starts only after
     * that contiguous control frame has been consumed. */
    if (x->local && x->status.phase == EFRP_XTCP_IDLE) {
        result = begin_attempt(x, NULL, now);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) fail_attempt(x, result);
    }
    result = step_attempt(x, now, seconds);
    if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) fail_attempt(x, result);
    return EFRP_OK;
}
void efrp_xtcp_status(const efrp_xtcp_t *x, efrp_xtcp_status_t *status, efrp_work_status_t *work)
{
    if (!x) return;
    if (status) *status = x->status;
    if (work) { efrp_work_status(&x->work, work); if (x->local) ++work->pending; if (x->admission) ++work->waiting; }
}
efrp_result_t efrp_xtcp_cancel(efrp_xtcp_t *x, uint64_t now)
{
    if (!x) return EFRP_INVALID_ARGUMENT;
    if (!x->cancelled) {
        x->cancelled = true; x->status.phase = EFRP_XTCP_DRAINING; x->status.error = EFRP_CANCELLED;
        efrp_crypto_zero(x->secret_key, sizeof x->secret_key); efrp_crypto_zero(x->control_id, sizeof x->control_id);
        if (x->output) { efrp_crypto_zero(x->output, EFRP_XTCP_SIGNAL_MAX_BYTES); free(x->output); x->output = NULL; }
        x->output_length = x->output_offset = 0; x->pending_requests = 0; x->report_pending = false;
        efrp_crypto_zero(x->report_sid, sizeof x->report_sid);
        if (x->admission) {
            efrp_crypto_zero(x->admission->output, sizeof x->admission->output);
            efrp_crypto_zero(x->admission->json, sizeof x->admission->json);
        }
        if (x->attempt && x->attempt->peer) (void)efrp_transport_cancel(x->attempt->peer);
        if (x->attempt && x->attempt->nat) (void)efrp_xtcp_nat_cancel(x->attempt->nat);
    }
    if (efrp_tcp_listener_destroy(&x->listener) != EFRP_OK) return EFRP_WOULD_BLOCK;
    return drain_attempt(x, now);
}
efrp_result_t efrp_xtcp_destroy(efrp_xtcp_t **out, uint64_t now)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (!*out) return EFRP_OK;
    efrp_xtcp_t *x = *out;
    efrp_result_t result = efrp_xtcp_cancel(x, now); if (result != EFRP_OK) return result;
    /* Parent transport was cancelled and retains all native stream ownership;
     * these are only caller parser/output buffers, never borrowed by backend. */
    if (x->admission) { efrp_crypto_zero(x->admission, sizeof *x->admission); free(x->admission); }
    efrp_crypto_zero(x, sizeof *x); free(x); *out = NULL; return EFRP_OK;
}
