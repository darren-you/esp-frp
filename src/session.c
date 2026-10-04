// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_session.h"
#include "session_internal.h"
#include "stream_internal.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "proxy_internal.h"
#include "memory_internal.h"
#include "work_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct efrp_session {
    efrp_transport_t *transport;
    efrp_proxy_type_t proxy_type;
    efrp_proxy_owned_t *proxy_options;
    efrp_stcp_visitor_owned_t *visitor;
    efrp_xtcp_t *xtcp;
    char *remote_address;
    /* Login and authenticated control never overlap. take_result releases
     * handshake storage before the reader/parser/writer borrow this union. */
    union {
        efrp_handshake_t handshake;
        struct {
            /* control_tx is at most 1024 plaintext bytes; AEAD adds 32. */
            uint8_t aead_tx[1024 + 32], json_rx[EFRP_JSON_MAX_BYTES];
            uint8_t flash_window[EFRP_AEAD_RX_CHUNK_BYTES];
        } control;
    } storage;
    efrp_aead_flash_reader_t reader;
    efrp_aead_flash_store_t flash_store;
    efrp_aead_writer_t writer;
    efrp_wire_reader_t frames;
    efrp_session_status_t status;
    efrp_work_set_t work;
    /* Login receives into handshake.output after its bytes enter Yamux.
     * Authenticated control keeps a separate Flash reader window alongside
     * json_rx, which the wire parser borrows concurrently. */
    uint8_t control_rx[1024], control_tx[1024];
    uint8_t token[EFRP_AEAD_MAX_TOKEN_BYTES];
    char proxy_name[129];
    size_t token_length, control_used, control_offset;
    size_t tx_used, tx_offset;
    efrp_stream_id_t control_stream;
    uint16_t remote_port;
    uint64_t now, registration_deadline, ping_deadline, next_ping;
    efrp_result_t frame_error;
    bool proxy_queued, ping_pending, transport_eof, control_ready, other_cleared, visitor_role;
    int64_t unix_seconds;
};

static efrp_result_t clear(efrp_session_t *s)
{
    efrp_result_t store_result = efrp_aead_flash_reader_close(&s->reader);
    if (s->xtcp) {
        (void)efrp_xtcp_cancel(s->xtcp, s->now);
        efrp_xtcp_status(s->xtcp, &s->status.xtcp, &s->status.work);
    }
    if (!s->other_cleared) {
        (void)efrp_work_cancel(&s->work);
        if (!s->control_ready) efrp_handshake_destroy(&s->storage.handshake);
        efrp_aead_writer_destroy(&s->writer);
        efrp_proxy_owned_destroy(&s->proxy_options);
        efrp_stcp_visitor_owned_clear_secret(s->visitor);
        if (s->remote_address) { efrp_crypto_zero(s->remote_address, s->status.remote_address_length + 1); free(s->remote_address); s->remote_address = NULL; }
        s->status.remote_address_length = 0;
        efrp_crypto_zero(s->token, sizeof s->token);
        efrp_crypto_zero(&s->storage, sizeof s->storage);
        efrp_crypto_zero(s->control_rx, sizeof s->control_rx);
        efrp_crypto_zero(s->control_tx, sizeof s->control_tx);
        s->control_used = s->control_offset = 0;
        s->tx_used = s->tx_offset = s->token_length = 0;
        s->ping_pending = false;
        s->other_cleared = true;
    }
    if (s->xtcp) {
        efrp_result_t result = efrp_xtcp_destroy(&s->xtcp, s->now);
        if (result != EFRP_OK) return result;
    }
    return store_result;
}
static efrp_result_t fail(efrp_session_t *s, efrp_result_t result)
{
    if (s->status.result != EFRP_OK) { (void)efrp_work_cancel(&s->work); return s->status.result; }
    s->status.result = result;
    s->status.phase = result == EFRP_CANCELLED ? EFRP_SESSION_STOPPED : EFRP_SESSION_FAILED;
    if (s->transport) (void)efrp_transport_cancel(s->transport);
    efrp_result_t cleanup = clear(s);
    if (cleanup != EFRP_OK && cleanup != EFRP_WOULD_BLOCK) s->status.result = cleanup;
    return s->status.result;
}
static bool accept_control(void *context, efrp_frame_kind_t kind, const uint8_t *p, size_t n)
{
    efrp_session_t *s = context;
    efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (kind != EFRP_MESSAGE || n < 2 || p[0]) { s->frame_error = result; return false; }
    if (p[1] == 22 && s->xtcp && s->status.phase == EFRP_SESSION_REGISTERED) {
        result = efrp_xtcp_response(s->xtcp, kind, p, n, s->now, s->unix_seconds);
        s->frame_error = result; return result == EFRP_OK;
    }
    cJSON *root = efrp_json_parse(p + 2, n - 2, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    if (p[1] == 4 && s->status.phase == EFRP_SESSION_REGISTERING && s->proxy_queued) {
        const char *const fields[] = {"proxy_name", "remote_addr", "error"};
        const char *error = efrp_json_string(root, "error"), *remote = efrp_json_string(root, "remote_addr");
        if (!efrp_json_shape(root, fields, 3) || !efrp_json_equals(root, "proxy_name", s->proxy_name) ||
            !error || !remote) goto done;
        if (*error) { result = EFRP_PROXY_REJECTED; goto done; }
        size_t length = strlen(remote);
        if (!length && s->proxy_type != EFRP_PROXY_STCP && s->proxy_type != EFRP_PROXY_XTCP) goto done;
        if (length) {
            s->remote_address = malloc(length + 1);
            if (!s->remote_address) { result = EFRP_NO_MEMORY; goto done; }
            memcpy(s->remote_address, remote, length + 1);
        }
        s->status.remote_address_length = length;
        s->status.phase = EFRP_SESSION_REGISTERED; s->next_ping = s->now;
        result = EFRP_OK;
    } else if (p[1] == 12 && s->status.phase == EFRP_SESSION_REGISTERED && s->ping_pending) {
        const char *const fields[] = {"error"};
        const char *error = efrp_json_string(root, "error");
        if (!efrp_json_shape(root, fields, 1) || !error) goto done;
        if (*error) { result = EFRP_AUTHENTICATION_FAILED; goto done; }
        if (s->visitor && !s->status.pongs) {
            result = efrp_work_visit_start(&s->work);
            if (result != EFRP_OK) goto done;
        }
        if (s->xtcp && !s->status.pongs) {
            result = efrp_xtcp_start(s->xtcp);
            if (result != EFRP_OK) goto done;
        }
        s->ping_pending = false; ++s->status.pongs; result = EFRP_OK;
    } else if (p[1] == 7 && !s->visitor_role && (s->status.phase == EFRP_SESSION_REGISTERING || s->status.phase == EFRP_SESSION_REGISTERED)) {
        if (!efrp_json_shape(root, NULL, 0)) goto done;
        if (s->xtcp) efrp_xtcp_request(s->xtcp); else efrp_work_request(&s->work);
        result = EFRP_OK;
    }
done:
    cJSON_Delete(root); s->frame_error = result; return result == EFRP_OK;
}
static efrp_result_t create_session(const efrp_session_config_t *c,
    const efrp_session_visitor_config_t *visitor, const efrp_session_xtcp_config_t *xtcp_visitor,
    efrp_transport_t *transport, uint64_t now, efrp_session_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if ((!c && !visitor && !xtcp_visitor) || !transport) return EFRP_INVALID_ARGUMENT;
    const efrp_aead_flash_store_t *store = visitor ? visitor->flash_store : xtcp_visitor ? xtcp_visitor->flash_store : c->flash_store;
    const char *name = visitor ? visitor->visitor.server_proxy_name : xtcp_visitor ? xtcp_visitor->xtcp.proxy_name : c->proxy_name;
    if (!name || !store || !store->recover || !store->begin || !store->write || !store->read || !store->clear ||
        now > UINT64_MAX - EFRP_WORK_IDLE_MS) return EFRP_INVALID_ARGUMENT;
    size_t name_length = 0; while (name_length <= 128 && name[name_length]) ++name_length;
    if (!name_length || name_length > 128 || !efrp_json_utf8((const uint8_t *)name, name_length))
        return EFRP_INVALID_ARGUMENT;
    if (visitor) {
        efrp_result_t checked = efrp_stcp_visitor_validate(name, visitor->visitor.secret_key,
            visitor->visitor.bind_ipv4, visitor->visitor.bind_port);
        if (checked != EFRP_OK) return checked;
    } else if (!xtcp_visitor) {
        if (!c->local_port || !c->local_ipv4[0] || c->local_ipv4[0] >= 224) return EFRP_INVALID_ARGUMENT;
        efrp_result_t checked = efrp_proxy_validate(c->proxy_type, c->proxy_options, name, c->remote_port);
        if (checked != EFRP_OK) return checked;
        if (c->proxy_type == EFRP_PROXY_UDP ? (!c->udp_packet_size || c->udp_packet_size > 65507U)
                                         : c->udp_packet_size != 0) return EFRP_INVALID_ARGUMENT;
        if ((c->proxy_type == EFRP_PROXY_XTCP) != (c->xtcp_options != NULL)) return EFRP_INVALID_ARGUMENT;
    }
    if (xtcp_visitor && xtcp_visitor->xtcp.role != EFRP_XTCP_VISITOR) return EFRP_INVALID_ARGUMENT;
    efrp_transport_status_t status;
    if (efrp_transport_status(transport, &status) != EFRP_OK || status.state != EFRP_TRANSPORT_OPEN || status.result != EFRP_OK)
        return EFRP_INVALID_STATE;
    efrp_session_t *s = efrp_heap_calloc(sizeof *s); if (!s) return EFRP_NO_MEMORY;
    s->control_stream = EFRP_STREAM_NONE;
    s->visitor_role = visitor || xtcp_visitor;
    efrp_handshake_config_t login = visitor ? visitor->login : xtcp_visitor ? xtcp_visitor->login : c->login;
    login.quic = status.kind == EFRP_TRANSPORT_QUIC;
    login.udp_binary = !s->visitor_role && c->proxy_type == EFRP_PROXY_UDP;
    login.xtcp_binding = xtcp_visitor || (!s->visitor_role && c->proxy_type == EFRP_PROXY_XTCP);
    efrp_result_t result = visitor
        ? efrp_stcp_visitor_owned_clone(name, visitor->visitor.secret_key, &s->visitor)
        : xtcp_visitor ? efrp_xtcp_create(&xtcp_visitor->xtcp, &s->xtcp)
        : efrp_proxy_owned_clone(c->proxy_type, c->proxy_options, &s->proxy_options);
    if (result == EFRP_OK && !s->visitor_role && c->proxy_type == EFRP_PROXY_XTCP) {
        efrp_xtcp_config_t config = {.role = EFRP_XTCP_PROVIDER, .proxy_name = name,
            .secret_key = efrp_proxy_owned_options(s->proxy_options)->secret_key,
            .options = *c->xtcp_options, .local_port = c->local_port,
            .time_is_trusted = c->time_is_trusted, .context = c->context};
        memcpy(config.local_ipv4, c->local_ipv4, 4);
        result = efrp_xtcp_create(&config, &s->xtcp);
    }
    if (result == EFRP_OK) result = efrp_handshake_init(&s->storage.handshake, &login,
        s->storage.handshake.output, sizeof s->storage.handshake.output, now);
    if (result != EFRP_OK) { clear(s); efrp_stcp_visitor_owned_destroy(&s->visitor); efrp_crypto_zero(s, sizeof *s); free(s); return result; }
    s->flash_store = *store;
    s->token_length = login.token_length; memcpy(s->token, login.token, s->token_length); s->now = now;
    if (visitor) {
        efrp_stcp_visitor_settings_t settings = visitor->visitor;
        settings.server_proxy_name = efrp_stcp_visitor_owned_proxy_name(s->visitor);
        settings.secret_key = efrp_stcp_visitor_owned_secret_key(s->visitor);
        result = efrp_work_visit_init(&s->work, &settings);
    } else if (!xtcp_visitor) {
        memcpy(s->proxy_name, name, name_length + 1); s->remote_port = c->remote_port; s->proxy_type = c->proxy_type;
        efrp_work_init(&s->work, c, s->proxy_name);
    }
    if (xtcp_visitor) memcpy(s->proxy_name, name, name_length + 1);
    if (result != EFRP_OK) { clear(s); efrp_stcp_visitor_owned_destroy(&s->visitor); efrp_crypto_zero(s, sizeof *s); free(s); return result; }
    result = efrp_stream_open(transport, &s->control_stream);
    if (result != EFRP_OK) { clear(s); efrp_stcp_visitor_owned_destroy(&s->visitor); efrp_crypto_zero(s, sizeof *s); free(s); return result; }
    s->transport = transport; s->status.phase = EFRP_SESSION_AUTHENTICATING; *out = s; return EFRP_OK;
}
efrp_result_t efrp_session_create(const efrp_session_config_t *config, efrp_transport_t *transport,
    uint64_t now, efrp_session_t **out)
{
    return create_session(config, NULL, NULL, transport, now, out);
}
efrp_result_t efrp_session_visitor_create(const efrp_session_visitor_config_t *config,
    efrp_transport_t *transport, uint64_t now, efrp_session_t **out)
{
    return create_session(NULL, config, NULL, transport, now, out);
}
efrp_result_t efrp_session_xtcp_create(const efrp_session_xtcp_config_t *config,
    efrp_transport_t *transport, uint64_t now, efrp_session_t **out)
{ return create_session(NULL, NULL, config, transport, now, out); }
static efrp_result_t finish_login(efrp_session_t *s)
{
    efrp_aead_keys_t keys;
    efrp_result_t result = EFRP_OK;
    if (s->xtcp) {
        uint8_t control_id[32];
        result = efrp_handshake_xtcp_control_id(&s->storage.handshake, control_id);
        if (result == EFRP_OK) result = efrp_xtcp_set_control_id(s->xtcp, control_id);
        efrp_crypto_zero(control_id, sizeof control_id);
    }
    if (result == EFRP_OK) result = efrp_handshake_take_result(&s->storage.handshake, &keys, s->status.run_id);
    if (result != EFRP_OK) return result;
    efrp_handshake_destroy(&s->storage.handshake);
    s->control_ready = true;
    result = efrp_aead_flash_reader_init(&s->reader, keys.server_to_client,
                                         &s->flash_store, s->storage.control.flash_window,
                                         sizeof s->storage.control.flash_window);
    if (result == EFRP_OK) result = efrp_aead_writer_init(&s->writer, keys.client_to_server, s->storage.control.aead_tx, sizeof s->storage.control.aead_tx);
    efrp_aead_clear_keys(&keys);
    if (result == EFRP_OK)
        result = efrp_wire_init(&s->frames, s->storage.control.json_rx, sizeof s->storage.control.json_rx, false, accept_control, s);
    if (result != EFRP_OK) return result;
    if (s->visitor_role) { s->status.phase = EFRP_SESSION_REGISTERED; s->next_ping = s->now; }
    else { s->status.phase = EFRP_SESSION_REGISTERING; s->registration_deadline = s->now + EFRP_SESSION_RESPONSE_MS; }
    return EFRP_OK;
}
static efrp_result_t prepare_control(efrp_session_t *s, int64_t seconds)
{
    if (s->tx_used || s->status.phase == EFRP_SESSION_AUTHENTICATING) return EFRP_OK;
    if (s->xtcp && s->status.phase == EFRP_SESSION_REGISTERED) {
        const uint8_t *bytes; size_t length;
        efrp_result_t result = efrp_xtcp_output(s->xtcp, &bytes, &length);
        if (result == EFRP_OK) return EFRP_OK; /* finish that contiguous frame first */
        if (result != EFRP_WOULD_BLOCK) return result;
    }
    bool proxy = s->status.phase == EFRP_SESSION_REGISTERING && !s->proxy_queued;
    bool ping = s->status.phase == EFRP_SESSION_REGISTERED && !s->ping_pending && s->now >= s->next_ping;
    if (!proxy && !ping) return EFRP_OK;
    if (proxy) {
        efrp_result_t result = efrp_proxy_encode(s->proxy_type, efrp_proxy_owned_options(s->proxy_options),
            s->proxy_name, s->remote_port, s->control_tx, sizeof s->control_tx, &s->tx_used);
        if (result == EFRP_OK) {
            s->tx_offset = 0; s->proxy_queued = true;
            efrp_proxy_owned_destroy(&s->proxy_options);
        }
        return result;
    }
    cJSON *root = cJSON_CreateObject(); bool built = root != NULL;
    char auth[33] = {0}, timestamp[21];
    efrp_result_t result = efrp_token_auth(s->token, s->token_length, seconds, auth);
    snprintf(timestamp, sizeof timestamp, "%" PRId64, seconds);
    built = built && result == EFRP_OK && cJSON_AddStringToObject(root, "privilege_key", auth) &&
        cJSON_AddRawToObject(root, "timestamp", timestamp);
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
    s->control_tx[8] = 0; s->control_tx[9] = 11;
    s->tx_used = length + 10; s->tx_offset = 0;
    s->ping_pending = true; s->ping_deadline = s->now + EFRP_SESSION_RESPONSE_MS;
    s->next_ping = s->now + EFRP_SESSION_HEARTBEAT_MS;
    return EFRP_OK;
}
static efrp_result_t control_output(efrp_session_t *s)
{
    const uint8_t *bytes; size_t length, used;
    efrp_result_t result;
    if (s->status.phase == EFRP_SESSION_AUTHENTICATING) {
        result = efrp_handshake_output(&s->storage.handshake, &bytes, &length);
        if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
        result = efrp_stream_write(s->transport, s->control_stream, bytes, length, &used);
        if (result == EFRP_OK) return efrp_handshake_consume_output(&s->storage.handshake, used);
        return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
    }
    result = efrp_aead_output(&s->writer, &bytes, &length);
    if (result == EFRP_OK) {
        result = efrp_stream_write(s->transport, s->control_stream, bytes, length, &used);
        if (result == EFRP_OK) return efrp_aead_consume_output(&s->writer, used);
        return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
    }
    if (result != EFRP_WOULD_BLOCK) return result;
    if (s->tx_used) {
        result = efrp_aead_write(&s->writer, s->control_tx + s->tx_offset, s->tx_used - s->tx_offset, &used);
        if (result != EFRP_OK) return result == EFRP_WOULD_BLOCK ? EFRP_OK : result;
        efrp_crypto_zero(s->control_tx + s->tx_offset, used); s->tx_offset += used;
        if (s->tx_offset == s->tx_used) s->tx_used = s->tx_offset = 0;
    } else if (s->xtcp && s->status.phase == EFRP_SESSION_REGISTERED) {
        result = efrp_xtcp_output(s->xtcp, &bytes, &length);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) return result;
        if (length > 1024) length = 1024;
        result = efrp_aead_write(&s->writer, bytes, length, &used);
        if (result == EFRP_OK) return efrp_xtcp_consume_output(s->xtcp, used);
        if (result != EFRP_WOULD_BLOCK) return result;
    }
    return EFRP_OK;
}
static efrp_result_t control_finish(efrp_session_t *s)
{
    efrp_result_t result = s->status.phase == EFRP_SESSION_AUTHENTICATING ?
        efrp_handshake_finish(&s->storage.handshake) : efrp_aead_flash_finish(&s->reader);
    if (result == EFRP_OK && s->status.phase != EFRP_SESSION_AUTHENTICATING)
        result = efrp_wire_finish(&s->frames);
    return result == EFRP_OK ? EFRP_SESSION_CLOSED : result;
}
static efrp_result_t control_input(efrp_session_t *s)
{
    efrp_result_t result; size_t used;
    if (s->status.phase != EFRP_SESSION_AUTHENTICATING) {
        const uint8_t *plain; size_t length;
        result = efrp_aead_flash_plaintext(&s->reader, &plain, &length);
        if (result == EFRP_OK) {
            result = efrp_wire_feed(&s->frames, plain, length, &used);
            if (result != EFRP_OK) return s->frame_error != EFRP_OK ? s->frame_error : result;
            return efrp_aead_flash_consume_plaintext(&s->reader, used);
        }
        if (result != EFRP_WOULD_BLOCK) return result;
    }
    if (!s->control_used) {
        result = efrp_stream_read(s->transport, s->control_stream, s->control_rx, sizeof s->control_rx, &used);
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
        result = efrp_aead_flash_feed(&s->reader, bytes, length, &used);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
        s->control_offset += used;
    }
    if (s->control_offset == s->control_used) {
        efrp_crypto_zero(s->control_rx, s->control_used); s->control_used = s->control_offset = 0;
    }
    return EFRP_OK;
}
static efrp_result_t check_eof(efrp_session_t *s)
{
    if (!s->transport_eof || s->control_used) return EFRP_OK;
    efrp_stream_info_t info;
    efrp_result_t result = efrp_stream_info(s->transport, s->control_stream, &info);
    if (result != EFRP_OK) return result;
    if (info.readable_bytes) return EFRP_OK;
    if (s->status.phase != EFRP_SESSION_AUTHENTICATING) {
        const uint8_t *plain; size_t length;
        efrp_result_t plain_result = efrp_aead_flash_plaintext(&s->reader, &plain, &length);
        if (plain_result == EFRP_OK) return EFRP_OK;
        if (plain_result != EFRP_WOULD_BLOCK) return plain_result;
    }
    result = efrp_stream_finish(s->transport);
    if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
    return result == EFRP_OK ? control_finish(s) : result;
}
efrp_result_t efrp_session_step(efrp_session_t *s, uint64_t now, int64_t seconds)
{
    if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->status.result != EFRP_OK) { (void)efrp_work_cancel(&s->work); return s->status.result; }
    if (now < s->now || now > UINT64_MAX - EFRP_WORK_IDLE_MS || seconds <= 0) return EFRP_INVALID_ARGUMENT;
    s->now = now; s->unix_seconds = seconds;
    efrp_result_t result = efrp_transport_step(s->transport, now);
    if (result == EFRP_EOF) s->transport_eof = true;
    else if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return fail(s, result);
    efrp_transport_status_t transport_status;
    result = efrp_transport_status(s->transport, &transport_status);
    if (result != EFRP_OK) return fail(s, result);
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    s->status.mux_timeout_source = transport_status.timeout_source;
    s->status.mux_timeout_stream_id = transport_status.timeout_stream_id;
    s->status.mux_timeout_age_ms = transport_status.timeout_age_ms;
    s->status.mux_timeout_pending_bytes = transport_status.timeout_pending_bytes;
#endif
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
        if (!s->transport_eof) {
            result = prepare_control(s, seconds); if (result != EFRP_OK) return fail(s, result);
            result = control_output(s); if (result != EFRP_OK) return fail(s, result);
            if (s->status.phase != EFRP_SESSION_AUTHENTICATING) {
                result = s->xtcp
                    ? (s->status.pongs ? efrp_xtcp_step(s->xtcp, s->transport, now, seconds, s->status.run_id, s->token, s->token_length) : EFRP_OK)
                    : s->visitor
                    ? (s->status.pongs ? efrp_work_visit_step(&s->work, s->transport, now, s->status.run_id, seconds) : EFRP_OK)
                    : efrp_work_step(&s->work, s->transport, now, s->status.run_id, s->token, s->token_length, seconds);
                if (result != EFRP_OK) return fail(s, result);
            }
            result = efrp_transport_step(s->transport, now);
            if (result == EFRP_EOF) s->transport_eof = true;
            else if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return fail(s, result);
        }
    }
    result = check_eof(s); if (result != EFRP_OK) return fail(s, result);
    return EFRP_OK;
}
efrp_result_t efrp_session_status(const efrp_session_t *s, efrp_session_status_t *status)
{
    if (!s || !status) return EFRP_INVALID_ARGUMENT;
    *status = s->status;
    if (s->xtcp) efrp_xtcp_status(s->xtcp, &status->xtcp, &status->work);
    else if (s->proxy_type != EFRP_PROXY_XTCP && !s->visitor_role) efrp_work_status(&s->work, &status->work);
    else if (s->visitor) efrp_work_status(&s->work, &status->work);
    return EFRP_OK;
}
efrp_result_t efrp_session_remote_address(const efrp_session_t *s, char *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (output && capacity) output[0] = 0;
    if (!s || !length || (!output && capacity)) return EFRP_INVALID_ARGUMENT;
    *length = s->status.remote_address_length;
    if (capacity <= *length) return EFRP_CAPACITY_EXCEEDED;
    if (*length) memcpy(output, s->remote_address, *length);
    output[*length] = 0; return EFRP_OK;
}
efrp_result_t efrp_session_cancel(efrp_session_t *s) { return s ? fail(s, EFRP_CANCELLED) : EFRP_INVALID_ARGUMENT; }
void efrp_session_drain(efrp_session_t *s, uint64_t now)
{
    if (!s || s->status.result == EFRP_OK || now < s->now) return;
    s->now = now;
    if (s->xtcp) (void)efrp_xtcp_cancel(s->xtcp, now);
}
efrp_result_t efrp_session_destroy(efrp_session_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (!*out) return EFRP_OK;
    efrp_session_t *s = *out; (void)efrp_session_cancel(s);
    if (!efrp_work_cancel(&s->work)) return EFRP_WOULD_BLOCK;
    efrp_result_t cleanup = clear(s);
    if (cleanup != EFRP_OK) return cleanup;
    efrp_stcp_visitor_owned_destroy(&s->visitor);
    efrp_crypto_zero(s, sizeof *s); free(s); *out = NULL; return EFRP_OK;
}
