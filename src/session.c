// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_session.h"
#include "esp_frp_yamux.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "work_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(EFRP_TLS_TX_BYTES >= EFRP_YAMUX_HEADER_BYTES + EFRP_YAMUX_RING_BYTES,
    "session TLS staging must hold one complete Yamux output frame");

struct efrp_session {
    efrp_tls_t *tls;
    efrp_yamux_t *mux;
    /* Login and authenticated control never overlap. take_result releases
     * handshake storage before the control parser/writer borrow this union. */
    union {
        efrp_handshake_t handshake;
        struct {
            /* control_tx is at most 1024 plaintext bytes; AEAD adds 32. */
            uint8_t aead_tx[1024 + 32], json_rx[EFRP_JSON_MAX_BYTES];
        } control;
    } storage;
    efrp_aead_reader_t reader;
    efrp_aead_writer_t writer;
    efrp_wire_reader_t frames;
    efrp_session_status_t status;
    efrp_work_set_t work;
    /* Login borrows this 4 KiB block. Authenticated records instead allocate
     * actual-sized AEAD chunks only after their length header is validated. */
    uint8_t *handshake_rx;
    /* All readers retain and resume partial input. Match the work transfer
     * chunk without reducing any TLS, Yamux, AEAD or JSON frame limit. */
    uint8_t transport_rx[1024], control_rx[1024], control_tx[1024];
    uint8_t token[EFRP_AEAD_MAX_TOKEN_BYTES];
    char proxy_name[129];
    size_t token_length, transport_used, transport_offset, control_used, control_offset;
    size_t tx_used, tx_offset, tls_staged;
    uint32_t control_stream;
    uint16_t remote_port;
    uint64_t now, registration_deadline, ping_deadline, next_ping;
    efrp_result_t frame_error;
    bool proxy_queued, ping_pending, tls_eof, control_ready;
};
static void clear(efrp_session_t *s)
{
    (void)efrp_work_cancel(&s->work);
    if (!s->control_ready) efrp_handshake_destroy(&s->storage.handshake);
    efrp_aead_reader_destroy(&s->reader); efrp_aead_writer_destroy(&s->writer);
    efrp_crypto_zero(s->token, sizeof s->token);
    if (s->handshake_rx) {
        efrp_crypto_zero(s->handshake_rx, EFRP_HANDSHAKE_RX_BYTES);
        free(s->handshake_rx); s->handshake_rx = NULL;
    }
    efrp_crypto_zero(&s->storage, sizeof s->storage);
    efrp_crypto_zero(s->control_rx, sizeof s->control_rx); efrp_crypto_zero(s->control_tx, sizeof s->control_tx);
    efrp_crypto_zero(s->transport_rx, sizeof s->transport_rx);
    if (s->mux) efrp_crypto_zero(s->mux, sizeof *s->mux);
    s->transport_used = s->transport_offset = s->control_used = s->control_offset = 0;
    s->tx_used = s->tx_offset = s->tls_staged = s->token_length = 0;
    s->ping_pending = false;
}
static efrp_result_t fail(efrp_session_t *s, efrp_result_t result)
{
    if (s->status.result != EFRP_OK) { (void)efrp_work_cancel(&s->work); return s->status.result; }
    s->status.result = result;
    s->status.phase = result == EFRP_CANCELLED ? EFRP_SESSION_STOPPED : EFRP_SESSION_FAILED;
    if (s->tls) efrp_tls_cancel(s->tls);
    clear(s); return result;
}
static bool accept_control(void *context, efrp_frame_kind_t kind, const uint8_t *p, size_t n)
{
    efrp_session_t *s = context;
    efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (kind != EFRP_MESSAGE || n < 2 || p[0]) { s->frame_error = result; return false; }
    cJSON *root = efrp_json_parse(p + 2, n - 2);
    if (p[1] == 4 && s->status.phase == EFRP_SESSION_REGISTERING && s->proxy_queued) {
        const char *const fields[] = {"proxy_name", "remote_addr", "error"};
        const char *error = efrp_json_string(root, "error"), *remote = efrp_json_string(root, "remote_addr");
        if (!efrp_json_shape(root, fields, 3) || !efrp_json_equals(root, "proxy_name", s->proxy_name) ||
            !error || !remote) goto done;
        if (*error) { result = EFRP_PROXY_REJECTED; goto done; }
        size_t length = strlen(remote);
        if (!length || length >= sizeof s->status.remote_address) goto done;
        memcpy(s->status.remote_address, remote, length + 1);
        s->status.phase = EFRP_SESSION_REGISTERED; s->next_ping = s->now;
        result = EFRP_OK;
    } else if (p[1] == 12 && s->status.phase == EFRP_SESSION_REGISTERED && s->ping_pending) {
        const char *const fields[] = {"error"};
        const char *error = efrp_json_string(root, "error");
        if (!efrp_json_shape(root, fields, 1) || !error) goto done;
        if (*error) { result = EFRP_AUTHENTICATION_FAILED; goto done; }
        s->ping_pending = false; ++s->status.pongs; result = EFRP_OK;
    } else if (p[1] == 7 && (s->status.phase == EFRP_SESSION_REGISTERING || s->status.phase == EFRP_SESSION_REGISTERED)) {
        if (!efrp_json_shape(root, NULL, 0)) goto done;
        efrp_work_request(&s->work); result = EFRP_OK;
    }
done:
    cJSON_Delete(root); s->frame_error = result; return result == EFRP_OK;
}
efrp_result_t efrp_session_create(const efrp_session_config_t *c, efrp_tls_t *tls,
                                  uint64_t now, efrp_session_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if (!c || !c->proxy_name || !tls || !c->local_port || !c->local_ipv4[0] || c->local_ipv4[0] >= 224 ||
        now > UINT64_MAX - EFRP_WORK_IDLE_MS) return EFRP_INVALID_ARGUMENT;
    size_t name_length = 0; while (name_length <= 128 && c->proxy_name[name_length]) ++name_length;
    if (!name_length || name_length > 128 || !efrp_json_utf8((const uint8_t *)c->proxy_name, name_length))
        return EFRP_INVALID_ARGUMENT;
    efrp_tls_status_t status;
    if (efrp_tls_status(tls, &status) != EFRP_OK || status.state != EFRP_TLS_OPEN || status.pending_bytes)
        return EFRP_INVALID_STATE;
    efrp_session_t *s = calloc(1, sizeof *s); if (!s) return EFRP_NO_MEMORY;
    s->handshake_rx = calloc(1, EFRP_HANDSHAKE_RX_BYTES);
    if (!s->handshake_rx) { efrp_crypto_zero(s, sizeof *s); free(s); return EFRP_NO_MEMORY; }
    s->mux = calloc(1, sizeof *s->mux);
    if (!s->mux) { clear(s); efrp_crypto_zero(s, sizeof *s); free(s); return EFRP_NO_MEMORY; }
    efrp_result_t result = efrp_handshake_init(&s->storage.handshake, &c->login, s->handshake_rx, EFRP_HANDSHAKE_RX_BYTES, now);
    if (result != EFRP_OK) { clear(s); free(s->mux); efrp_crypto_zero(s, sizeof *s); free(s); return result; }
    s->token_length = c->login.token_length; memcpy(s->token, c->login.token, s->token_length);
    memcpy(s->proxy_name, c->proxy_name, name_length + 1); s->remote_port = c->remote_port; s->now = now;
    efrp_work_init(&s->work, c, s->proxy_name);
    efrp_yamux_init(s->mux, now); result = efrp_yamux_open(s->mux, &s->control_stream);
    if (result != EFRP_OK) { clear(s); free(s->mux); efrp_crypto_zero(s, sizeof *s); free(s); return result; }
    s->tls = tls; s->status.phase = EFRP_SESSION_AUTHENTICATING; *out = s; return EFRP_OK;
}
static efrp_result_t finish_login(efrp_session_t *s)
{
    efrp_aead_keys_t keys;
    efrp_result_t result = efrp_handshake_take_result(&s->storage.handshake, &keys, s->status.run_id);
    if (result != EFRP_OK) return result;
    efrp_handshake_destroy(&s->storage.handshake);
    efrp_crypto_zero(s->handshake_rx, EFRP_HANDSHAKE_RX_BYTES);
    free(s->handshake_rx); s->handshake_rx = NULL;
    s->control_ready = true;
    result = efrp_aead_reader_init_chunked(&s->reader, keys.server_to_client, calloc, free);
    if (result == EFRP_OK) result = efrp_aead_writer_init(&s->writer, keys.client_to_server, s->storage.control.aead_tx, sizeof s->storage.control.aead_tx);
    efrp_aead_clear_keys(&keys);
    if (result == EFRP_OK)
        result = efrp_wire_init(&s->frames, s->storage.control.json_rx, sizeof s->storage.control.json_rx, false, accept_control, s);
    if (result != EFRP_OK) return result;
    s->status.phase = EFRP_SESSION_REGISTERING; s->registration_deadline = s->now + EFRP_SESSION_RESPONSE_MS;
    return EFRP_OK;
}
static efrp_result_t prepare_control(efrp_session_t *s, int64_t seconds)
{
    if (s->tx_used || s->status.phase == EFRP_SESSION_AUTHENTICATING) return EFRP_OK;
    bool proxy = s->status.phase == EFRP_SESSION_REGISTERING && !s->proxy_queued;
    bool ping = s->status.phase == EFRP_SESSION_REGISTERED && !s->ping_pending && s->now >= s->next_ping;
    if (!proxy && !ping) return EFRP_OK;
    cJSON *root = cJSON_CreateObject(); bool built = root != NULL;
    char auth[33] = {0}, timestamp[21];
    efrp_result_t result = EFRP_OK;
    if (proxy) {
        built = built && cJSON_AddStringToObject(root, "proxy_name", s->proxy_name) &&
            cJSON_AddStringToObject(root, "proxy_type", "tcp") &&
            cJSON_AddNumberToObject(root, "remote_port", s->remote_port) &&
            cJSON_AddBoolToObject(root, "use_encryption", false) && cJSON_AddBoolToObject(root, "use_compression", false);
    } else {
        result = efrp_token_auth(s->token, s->token_length, seconds, auth);
        snprintf(timestamp, sizeof timestamp, "%" PRId64, seconds);
        built = built && result == EFRP_OK && cJSON_AddStringToObject(root, "privilege_key", auth) &&
            cJSON_AddRawToObject(root, "timestamp", timestamp);
    }
    efrp_crypto_zero(auth, sizeof auth);
    if (result == EFRP_OK && !built) result = EFRP_NO_MEMORY;
    if (result == EFRP_OK && !cJSON_PrintPreallocated(root, (char *)s->control_tx + 10, (int)sizeof s->control_tx - 10, 0))
        result = EFRP_CAPACITY_EXCEEDED;
    cJSON *signature = cJSON_GetObjectItemCaseSensitive(root, "privilege_key");
    if (signature && signature->valuestring) efrp_crypto_zero(signature->valuestring, strlen(signature->valuestring));
    cJSON_Delete(root);
    if (result != EFRP_OK) return result;
    size_t length = strlen((char *)s->control_tx + 10);
    result = efrp_wire_header(EFRP_MESSAGE, length + 2, s->control_tx);
    if (result != EFRP_OK) return result;
    s->control_tx[8] = 0; s->control_tx[9] = proxy ? 3 : 11;
    s->tx_used = length + 10; s->tx_offset = 0;
    if (proxy) s->proxy_queued = true;
    else { s->ping_pending = true; s->ping_deadline = s->now + EFRP_SESSION_RESPONSE_MS; s->next_ping = s->now + EFRP_SESSION_HEARTBEAT_MS; }
    return EFRP_OK;
}
static efrp_result_t control_output(efrp_session_t *s)
{
    const uint8_t *bytes; size_t length, used;
    efrp_result_t result;
    if (s->status.phase == EFRP_SESSION_AUTHENTICATING) {
        result = efrp_handshake_output(&s->storage.handshake, &bytes, &length);
        if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
        result = efrp_yamux_write(s->mux, s->control_stream, bytes, length, &used);
        if (result == EFRP_OK) return efrp_handshake_consume_output(&s->storage.handshake, used);
        return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
    }
    result = efrp_aead_output(&s->writer, &bytes, &length);
    if (result == EFRP_OK) {
        result = efrp_yamux_write(s->mux, s->control_stream, bytes, length, &used);
        if (result == EFRP_OK) return efrp_aead_consume_output(&s->writer, used);
        return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
    }
    if (result != EFRP_WOULD_BLOCK) return result;
    if (s->tx_used) {
        result = efrp_aead_write(&s->writer, s->control_tx + s->tx_offset, s->tx_used - s->tx_offset, &used);
        if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
        efrp_crypto_zero(s->control_tx + s->tx_offset, used); s->tx_offset += used;
        if (s->tx_offset == s->tx_used) s->tx_used = s->tx_offset = 0;
    }
    return EFRP_OK;
}
static efrp_result_t control_finish(efrp_session_t *s)
{
    efrp_result_t result = s->status.phase == EFRP_SESSION_AUTHENTICATING ?
        efrp_handshake_finish(&s->storage.handshake) : efrp_aead_finish(&s->reader);
    if (result == EFRP_OK && s->status.phase != EFRP_SESSION_AUTHENTICATING)
        result = efrp_wire_finish(&s->frames);
    return result == EFRP_OK ? EFRP_SESSION_CLOSED : result;
}
static efrp_result_t control_input(efrp_session_t *s)
{
    efrp_result_t result; size_t used;
    if (s->status.phase != EFRP_SESSION_AUTHENTICATING) {
        const uint8_t *plain; size_t length;
        result = efrp_aead_plaintext(&s->reader, &plain, &length);
        if (result == EFRP_OK) {
            if (length > 4096) length = 4096;
            result = efrp_wire_feed(&s->frames, plain, length, &used);
            if (result != EFRP_OK) return s->frame_error != EFRP_OK ? s->frame_error : result;
            return efrp_aead_consume_plaintext(&s->reader, used);
        }
        if (result != EFRP_WOULD_BLOCK) return result;
    }
    if (!s->control_used) {
        result = efrp_yamux_read(s->mux, s->control_stream, s->control_rx, sizeof s->control_rx, &used);
        if (result == EFRP_EOF) return control_finish(s);
        if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
        s->control_used = used; s->control_offset = 0;
    }
    const uint8_t *bytes = s->control_rx + s->control_offset;
    size_t length = s->control_used - s->control_offset;
    if (s->status.phase == EFRP_SESSION_AUTHENTICATING) {
        result = efrp_handshake_feed(&s->storage.handshake, bytes, length, &used);
        if (result != EFRP_OK) return result;
        s->control_offset += used;
        if (s->storage.handshake.state == EFRP_HANDSHAKE_DONE) {
            result = finish_login(s); if (result != EFRP_OK) return result;
        }
    } else {
        result = efrp_aead_feed(&s->reader, bytes, length, &used);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
        s->control_offset += used;
    }
    if (s->control_offset == s->control_used) {
        efrp_crypto_zero(s->control_rx, s->control_used); s->control_used = s->control_offset = 0;
    }
    return EFRP_OK;
}
static efrp_result_t transport_input(efrp_session_t *s)
{
    efrp_result_t result; size_t used;
    if (!s->transport_used && !s->tls_eof) {
        result = efrp_tls_read(s->tls, s->now, s->transport_rx, sizeof s->transport_rx, &used);
        if (result == EFRP_EOF) { s->tls_eof = true; return EFRP_OK; }
        if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
        s->transport_used = used; s->transport_offset = 0;
    }
    result = efrp_yamux_feed(s->mux, s->transport_rx + s->transport_offset,
                            s->transport_used - s->transport_offset, &used);
    if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
    s->transport_offset += used;
    if (s->transport_offset == s->transport_used) s->transport_offset = s->transport_used = 0;
    return EFRP_OK;
}
static efrp_result_t transport_output(efrp_session_t *s)
{
    if (s->tls_staged || s->tls_eof) return EFRP_OK;
    const uint8_t *bytes; size_t length, accepted;
    efrp_result_t result = efrp_yamux_output(s->mux, &bytes, &length);
    if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
    result = efrp_tls_write(s->tls, s->now, bytes, length, &accepted);
    if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
    s->tls_staged = accepted; return EFRP_OK;
}
static efrp_result_t check_eof(efrp_session_t *s)
{
    if (!s->tls_eof || s->transport_used || s->control_used) return EFRP_OK;
    efrp_yamux_stream_info_t info;
    efrp_result_t result = efrp_yamux_info(s->mux, s->control_stream, &info);
    if (result != EFRP_OK) return result;
    if (info.readable_bytes) return EFRP_OK;
    if (s->status.phase != EFRP_SESSION_AUTHENTICATING) {
        const uint8_t *plain; size_t length;
        if (efrp_aead_plaintext(&s->reader, &plain, &length) == EFRP_OK) return EFRP_OK;
    }
    result = efrp_yamux_finish(s->mux);
    return result == EFRP_OK ? control_finish(s) : result;
}
efrp_result_t efrp_session_step(efrp_session_t *s, uint64_t now, int64_t seconds)
{
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->status.result != EFRP_OK) { (void)efrp_work_cancel(&s->work); return s->status.result; }
    if (now < s->now || now > UINT64_MAX - EFRP_WORK_IDLE_MS || seconds <= 0) return EFRP_INVALID_ARGUMENT;
    s->now = now;
    efrp_result_t result = EFRP_OK;
    if (!s->tls_eof) {
        result = efrp_tls_step(s->tls, now);
        if (result == EFRP_EOF) s->tls_eof = true;
        else if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return fail(s, result);
    }
    efrp_tls_status_t tls_status;
    result = efrp_tls_status(s->tls, &tls_status); if (result != EFRP_OK) return fail(s, result);
    if (s->tls_staged && !tls_status.pending_bytes && tls_status.state == EFRP_TLS_OPEN) {
        result = efrp_yamux_consume_output(s->mux, s->tls_staged);
        if (result != EFRP_OK) return fail(s, result);
        s->tls_staged = 0;
    }
    result = efrp_yamux_tick(s->mux, now);
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    s->status.mux_timeout_source = (unsigned)s->mux->timeout_source;
    s->status.mux_timeout_stream_id = s->mux->timeout_stream_id;
    s->status.mux_timeout_age_ms = s->mux->timeout_age_ms;
    s->status.mux_timeout_pending_bytes = s->mux->timeout_pending_bytes;
#endif
    if (result != EFRP_OK) return fail(s, result);
    if (s->status.phase == EFRP_SESSION_AUTHENTICATING) {
        result = efrp_handshake_tick(&s->storage.handshake, now); if (result != EFRP_OK) return fail(s, result);
    }
    if (s->status.phase == EFRP_SESSION_REGISTERING && now >= s->registration_deadline) {
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        s->status.control_timeout_source = 1;
#endif
        return fail(s, EFRP_TIMEOUT);
    }
    if (s->ping_pending && now >= s->ping_deadline) {
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        s->status.control_timeout_source = 2;
#endif
        return fail(s, EFRP_TIMEOUT);
    }
    for (unsigned turn = 0; turn < 8; ++turn) {
        result = control_input(s); if (result != EFRP_OK) return fail(s, result);
        result = transport_input(s); if (result != EFRP_OK) return fail(s, result);
        if (!s->tls_eof) {
            result = prepare_control(s, seconds); if (result != EFRP_OK) return fail(s, result);
            result = control_output(s); if (result != EFRP_OK) return fail(s, result);
            if (s->status.phase != EFRP_SESSION_AUTHENTICATING) {
                result = efrp_work_step(&s->work, s->mux, now, s->status.run_id, s->token, s->token_length, seconds);
                if (result != EFRP_OK) return fail(s, result);
            }
            result = transport_output(s); if (result != EFRP_OK) return fail(s, result);
        }
    }
    result = check_eof(s); if (result != EFRP_OK) return fail(s, result);
    return EFRP_OK;
}
efrp_result_t efrp_session_status(const efrp_session_t *s, efrp_session_status_t *status)
{
    if (!s || !status) return EFRP_INVALID_ARGUMENT;
    *status = s->status; efrp_work_status(&s->work, &status->work); return EFRP_OK;
}
efrp_result_t efrp_session_cancel(efrp_session_t *s) { return s ? fail(s, EFRP_CANCELLED) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_session_destroy(efrp_session_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (!*out) return EFRP_OK;
    efrp_session_t *s = *out; efrp_session_cancel(s);
    if (!efrp_work_cancel(&s->work)) return EFRP_WOULD_BLOCK;
    free(s->mux);
    efrp_crypto_zero(s, sizeof *s); free(s); *out = NULL; return EFRP_OK;
}
