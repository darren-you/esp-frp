// SPDX-License-Identifier: Apache-2.0
#include "work_internal.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void efrp_work_status(const efrp_work_set_t *set, efrp_work_status_t *status)
{
    *status = set->status; status->waiting = status->active = status->cleaning = 0;
    for (unsigned i = 0; i < 3; ++i) switch (set->streams[i].phase) {
        case EFRP_WORK_SENDING: case EFRP_WORK_WAITING: ++status->waiting; break;
        case EFRP_WORK_CONNECTING: case EFRP_WORK_ACTIVE: ++status->active; break;
        case EFRP_WORK_CLOSING: ++status->cleaning; break;
        default: break;
    }
}
void efrp_work_init(efrp_work_set_t *set, const efrp_session_config_t *config, const char *proxy_name)
{
    memset(set, 0, sizeof *set); memcpy(set->address, config->local_ipv4, 4);
    set->port = config->local_port; set->proxy_name = proxy_name;
}
void efrp_work_request(efrp_work_set_t *set)
{
    ++set->status.requests;
    if (set->status.pending == 3) { ++set->status.rejected_requests; return; }
    ++set->status.pending;
}
static void close_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_result_t reason)
{
    if (w->phase == EFRP_WORK_CLOSING) return;
    if (w->phase == EFRP_WORK_SENDING || w->phase == EFRP_WORK_WAITING)
        efrp_crypto_zero(set->handshake_json, sizeof set->handshake_json);
    w->phase = EFRP_WORK_CLOSING; w->result = reason;
    if (reason != EFRP_OK) { ++set->status.failed; set->status.last_error = reason; }
}
static bool port_value(const cJSON *root, const char *key)
{
    const cJSON *p = efrp_json_field(root, key);
    return !p || (cJSON_IsNumber(p) && p->valuedouble >= 0 && p->valuedouble <= 65535 &&
        p->valuedouble == (double)(uint16_t)p->valuedouble);
}
static bool start_work(void *context, efrp_frame_kind_t kind, const uint8_t *p, size_t n)
{
    efrp_work_stream_t *w = context; w->result = EFRP_PROTOCOL_ERROR;
    if (kind != EFRP_MESSAGE || n < 2 || p[0] || p[1] != 8) return false;
    cJSON *root = efrp_json_parse(p + 2, n - 2);
    const char *const fields[] = {"proxy_name", "src_addr", "dst_addr", "src_port", "dst_port", "error"};
    const char *error = efrp_json_string(root, "error"), *src = efrp_json_string(root, "src_addr"), *dst = efrp_json_string(root, "dst_addr");
    if (!efrp_json_shape(root, fields, 6) || !error || !src || !dst || strlen(src) > 128 || strlen(dst) > 128 ||
        !port_value(root, "src_port") || !port_value(root, "dst_port")) goto done;
    if (*error) { w->result = EFRP_WORK_REJECTED; goto done; }
    if (!efrp_json_equals(root, "proxy_name", w->proxy_name)) goto done;
    w->started = true; w->result = EFRP_OK;
done:
    cJSON_Delete(root); return w->result == EFRP_OK;
}
static efrp_result_t new_work(efrp_work_stream_t *w, const char *run_id,
    const uint8_t *token, size_t token_length, int64_t seconds)
{
    char signature[33] = {0}, stamp[21];
    efrp_result_t result = efrp_token_auth(token, token_length, seconds, signature);
    if (result != EFRP_OK) return result;
    snprintf(stamp, sizeof stamp, "%" PRId64, seconds);
    cJSON *root = cJSON_CreateObject();
    bool built = root && cJSON_AddStringToObject(root, "run_id", run_id) &&
        cJSON_AddStringToObject(root, "privilege_key", signature) && cJSON_AddRawToObject(root, "timestamp", stamp);
    efrp_crypto_zero(signature, sizeof signature);
    if (!built) result = EFRP_NO_MEMORY;
    else if (!cJSON_PrintPreallocated(root, (char *)w->outgoing + 17, (int)sizeof w->outgoing - 17, 0))
        result = EFRP_CAPACITY_EXCEEDED;
    cJSON *auth = cJSON_GetObjectItemCaseSensitive(root, "privilege_key");
    if (auth && auth->valuestring) efrp_crypto_zero(auth->valuestring, strlen(auth->valuestring));
    cJSON_Delete(root); if (result != EFRP_OK) return result;
    size_t length = strlen((char *)w->outgoing + 17);
    memcpy(w->outgoing, efrp_wire_magic, EFRP_WIRE_MAGIC_SIZE);
    result = efrp_wire_header(EFRP_MESSAGE, length + 2, w->outgoing + 7);
    w->outgoing[15] = 0; w->outgoing[16] = 6; w->outgoing_used = length + 17;
    return result;
}
static efrp_result_t cleanup_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_yamux_t *mux)
{
    if (w->stream_id) {
        efrp_result_t r = w->result == EFRP_OK ? EFRP_OK : efrp_yamux_reset(mux, w->stream_id);
        if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (r != EFRP_OK) return r;
        r = efrp_yamux_release(mux, w->stream_id); if (r != EFRP_OK) return r;
        w->stream_id = 0;
    }
    if (w->local) {
        if (w->result == EFRP_OK) {
            efrp_result_t r = efrp_connect_finish(w->local);
            if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
            if (r != EFRP_OK) { w->result = r; ++set->status.failed; set->status.last_error = r; }
        }
        if (efrp_connect_destroy(&w->local) == EFRP_WOULD_BLOCK) return EFRP_OK;
    }
    if (w->result == EFRP_OK) ++set->status.completed;
    efrp_crypto_zero(w, sizeof *w); return EFRP_OK;
}
static efrp_result_t handshake_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_yamux_t *mux, uint64_t now)
{
    efrp_result_t r; size_t used;
    if (w->phase == EFRP_WORK_SENDING) {
        if (now >= w->deadline) { close_work(set, w, EFRP_TIMEOUT); return EFRP_OK; }
        r = efrp_yamux_write(mux, w->stream_id, w->outgoing + w->outgoing_offset,
            w->outgoing_used - w->outgoing_offset, &used);
        if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
        efrp_crypto_zero(w->outgoing + w->outgoing_offset, used); w->outgoing_offset += used;
        if (w->outgoing_offset < w->outgoing_used) return EFRP_OK;
        w->outgoing_used = w->outgoing_offset = 0; w->phase = EFRP_WORK_WAITING;
    }
    /* A pooled spare may wait indefinitely without a local socket. Only a
     * started wire frame has a deadline: expiring a healthy spare leaves a dead
     * entry in the official pool and would break the next user connection. */
    if (w->partial_header && now >= w->deadline) { close_work(set, w, EFRP_TIMEOUT); return EFRP_OK; }
    r = efrp_yamux_read(mux, w->stream_id, w->incoming, sizeof w->incoming, &used);
    if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
    if (r != EFRP_OK) { close_work(set, w, r == EFRP_EOF ? EFRP_TRUNCATED : r); return EFRP_OK; }
    if (!w->partial_header) { w->partial_header = true; w->deadline = now + EFRP_SESSION_RESPONSE_MS; }
    w->incoming_used = used;
    r = efrp_wire_feed_one(&w->reader, w->incoming, used, &w->incoming_offset);
    if (r != EFRP_OK) { close_work(set, w, w->result != EFRP_OK ? w->result : r); return EFRP_OK; }
    if (!w->started) { efrp_crypto_zero(w->incoming, w->incoming_used); w->incoming_used = w->incoming_offset = 0; return EFRP_OK; }
    efrp_crypto_zero(set->handshake_json, sizeof set->handshake_json);
    efrp_work_status_t status; efrp_work_status(set, &status);
    unsigned closing_sockets = 0;
    for (unsigned i = 0; i < 3; ++i)
        if (set->streams[i].phase == EFRP_WORK_CLOSING && set->streams[i].local) ++closing_sockets;
    if (status.active + closing_sockets >= 2) { close_work(set, w, EFRP_CAPACITY_EXCEEDED); return EFRP_OK; }
    r = efrp_connect_create_ipv4(set->address, set->port, now, &w->local);
    if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
    w->phase = EFRP_WORK_CONNECTING; w->last_activity = w->incoming_progress = now;
    return EFRP_OK;
}
static efrp_result_t forward_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_yamux_t *mux, uint64_t now)
{
    efrp_result_t r; size_t count;
    if (w->phase == EFRP_WORK_CONNECTING) {
        r = efrp_connect_step(w->local, now);
        if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
        w->phase = EFRP_WORK_ACTIVE; w->last_activity = now;
    }
    if (now - w->last_activity >= EFRP_WORK_IDLE_MS ||
        (w->incoming_used > w->incoming_offset && now - w->incoming_progress >= EFRP_YAMUX_STALL_MS) ||
        (w->outgoing_used > w->outgoing_offset && now - w->outgoing_progress >= EFRP_YAMUX_STALL_MS)) {
        close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
    }
    if (w->incoming_used == w->incoming_offset) {
        w->incoming_used = w->incoming_offset = 0;
        if (!w->remote_eof) {
            r = efrp_yamux_read(mux, w->stream_id, w->incoming, sizeof w->incoming, &count);
            if (r == EFRP_EOF) { w->remote_eof = true; w->fin_progress = now; }
            else if (r == EFRP_OK) { w->incoming_used = count; w->incoming_progress = now; }
            else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
        }
    }
    if (w->incoming_used > w->incoming_offset) {
        r = efrp_connect_send(w->local, w->incoming + w->incoming_offset, w->incoming_used - w->incoming_offset, &count);
        if (r == EFRP_OK) {
            efrp_crypto_zero(w->incoming + w->incoming_offset, count); w->incoming_offset += count;
            set->status.local_sent += count; w->incoming_progress = w->last_activity = now;
        } else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (w->remote_eof && !w->local_fin) {
        r = efrp_connect_close_write(w->local);
        if (r == EFRP_OK) w->local_fin = true;
        else if (r != EFRP_WOULD_BLOCK || now - w->fin_progress >= EFRP_YAMUX_STALL_MS) {
            close_work(set, w, r == EFRP_WOULD_BLOCK ? EFRP_TIMEOUT : r); return EFRP_OK;
        }
    }
    if (w->outgoing_used == w->outgoing_offset) {
        w->outgoing_used = w->outgoing_offset = 0;
        if (!w->local_eof) {
            r = efrp_connect_recv(w->local, w->outgoing, sizeof w->outgoing, &count);
            if (r == EFRP_EOF) w->local_eof = true;
            else if (r == EFRP_OK) { w->outgoing_used = count; w->outgoing_progress = w->last_activity = now; set->status.local_received += count; }
            else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
        }
    }
    if (w->outgoing_used > w->outgoing_offset) {
        r = efrp_yamux_write(mux, w->stream_id, w->outgoing + w->outgoing_offset, w->outgoing_used - w->outgoing_offset, &count);
        if (r == EFRP_OK) {
            efrp_crypto_zero(w->outgoing + w->outgoing_offset, count); w->outgoing_offset += count;
            w->outgoing_progress = w->last_activity = now;
        } else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (w->local_eof && !w->mux_fin) {
        r = efrp_yamux_close_write(mux, w->stream_id);
        if (r == EFRP_OK) w->mux_fin = true;
        else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (w->remote_eof && w->local_fin && w->local_eof && w->mux_fin) {
        close_work(set, w, EFRP_OK);
    }
    return EFRP_OK;
}
efrp_result_t efrp_work_step(efrp_work_set_t *set, efrp_yamux_t *mux, uint64_t now,
    const char *run_id, const uint8_t *token, size_t token_length, int64_t seconds)
{
    efrp_work_status_t status; efrp_work_status(set, &status);
    if (set->status.pending && !status.waiting) {
        for (unsigned i = 0; i < 3; ++i) if (set->streams[i].phase == EFRP_WORK_UNUSED) {
            efrp_work_stream_t *w = &set->streams[i];
            efrp_result_t r = efrp_yamux_open(mux, &w->stream_id);
            if (r == EFRP_WOULD_BLOCK) break;
            if (r != EFRP_OK) return r;
            --set->status.pending; w->proxy_name = set->proxy_name;
            w->phase = EFRP_WORK_SENDING; w->deadline = now + EFRP_SESSION_RESPONSE_MS;
            r = efrp_wire_init(&w->reader, set->handshake_json, sizeof set->handshake_json, false, start_work, w);
            if (r == EFRP_OK) r = new_work(w, run_id, token, token_length, seconds);
            if (r != EFRP_OK) close_work(set, w, r);
            break;
        }
    }
    for (unsigned offset = 0; offset < 3; ++offset) {
        efrp_work_stream_t *w = &set->streams[(set->cursor + offset) % 3];
        if (w->phase == EFRP_WORK_UNUSED) continue;
        efrp_result_t r = EFRP_OK;
        if (w->stream_id && w->phase != EFRP_WORK_CLOSING) {
            efrp_yamux_stream_info_t info;
            r = efrp_yamux_info(mux, w->stream_id, &info);
            if (r != EFRP_OK) return r;
            if (info.reset) close_work(set, w, EFRP_STREAM_RESET);
        }
        if (w->phase == EFRP_WORK_SENDING || w->phase == EFRP_WORK_WAITING) r = handshake_work(set, w, mux, now);
        if (r == EFRP_OK && (w->phase == EFRP_WORK_CONNECTING || w->phase == EFRP_WORK_ACTIVE)) r = forward_work(set, w, mux, now);
        if (r == EFRP_OK && w->phase == EFRP_WORK_CLOSING) r = cleanup_work(set, w, mux);
        if (r != EFRP_OK) return r;
    }
    set->cursor = (set->cursor + 1) % 3; return EFRP_OK;
}
bool efrp_work_cancel(efrp_work_set_t *set)
{
    bool done = true; set->status.pending = 0;
    efrp_crypto_zero(set->handshake_json, sizeof set->handshake_json);
    for (unsigned i = 0; i < 3; ++i) {
        efrp_work_stream_t *w = &set->streams[i];
        if (w->local && efrp_connect_destroy(&w->local) == EFRP_WOULD_BLOCK) {
            efrp_crypto_zero(w->incoming, sizeof w->incoming);
            efrp_crypto_zero(w->outgoing, sizeof w->outgoing); w->phase = EFRP_WORK_CLOSING; done = false;
        } else efrp_crypto_zero(w, sizeof *w);
    }
    return done;
}
