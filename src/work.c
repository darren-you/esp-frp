// SPDX-License-Identifier: Apache-2.0
#include "work_internal.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "memory_internal.h"
#include "udp_local.h"
#include "tcp_listener.h"
#include "esp_frp_udp.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EFRP_UDP_REMOTE_LIMIT 4U
#define EFRP_UDP_IDLE_MS UINT64_C(30000)
#define EFRP_UDP_HEARTBEAT_MS UINT64_C(30000)
typedef struct {
    efrp_udp_local_t *local;
    efrp_udp_address_t address;
    uint8_t zone[255];
    uint64_t last_activity;
    bool closing;
} efrp_udp_remote_t;
struct efrp_udp_work {
    efrp_udp_remote_t remotes[EFRP_UDP_REMOTE_LIMIT];
    uint8_t *incoming, *outgoing, *datagram;
    size_t capacity, datagram_capacity, outgoing_used, outgoing_offset;
    uint8_t header[8];
    size_t header_used, payload_used, payload_expected;
    efrp_udp_packet_t packet;
    uint64_t ping_at, incoming_at, outgoing_at;
    unsigned cursor;
    bool pending, discard, header_validated, outgoing_datagram;
};

struct efrp_visit_work {
    efrp_tcp_listener_t *listener;
    const char *secret_key;
    uint8_t bind_ipv4[4];
    uint16_t bind_port;
    bool started;
};

static bool udp_cleanup(efrp_udp_work_t **handle)
{
    efrp_udp_work_t *udp = *handle; if (!udp) return true;
    bool done = true;
    for (unsigned i = 0; i < EFRP_UDP_REMOTE_LIMIT; ++i)
        if (efrp_udp_local_destroy(&udp->remotes[i].local) != EFRP_OK) done = false;
    /* UDP send never borrows an application buffer after returning. Cancel
     * clears pending business bytes even when IDF must retry socket close. */
    if (udp->incoming) efrp_crypto_zero(udp->incoming, udp->capacity);
    if (udp->outgoing) efrp_crypto_zero(udp->outgoing, udp->capacity + 8U);
    if (udp->datagram) efrp_crypto_zero(udp->datagram, udp->datagram_capacity);
    efrp_crypto_zero(&udp->packet, sizeof udp->packet);
    udp->pending = false; udp->outgoing_used = udp->outgoing_offset = 0;
    if (!done) return false;
    free(udp->incoming); free(udp->outgoing); free(udp->datagram);
    efrp_crypto_zero(udp, sizeof *udp); free(udp); *handle = NULL; return true;
}

static efrp_result_t udp_create(efrp_udp_work_t **out, uint16_t packet_size, uint64_t now)
{
    efrp_udp_work_t *udp = efrp_heap_calloc(sizeof *udp);
    if (!udp) return EFRP_NO_MEMORY;
    size_t capacity = (size_t)packet_size + 555U;
    if (capacity > EFRP_WIRE_MAX_PAYLOAD) capacity = EFRP_WIRE_MAX_PAYLOAD;
    udp->capacity = capacity; udp->datagram_capacity = (size_t)packet_size + 1U;
    udp->ping_at = now + EFRP_UDP_HEARTBEAT_MS;
    udp->incoming = efrp_heap_calloc(capacity);
    udp->outgoing = efrp_heap_calloc(capacity + 8U);
    udp->datagram = efrp_heap_calloc(udp->datagram_capacity);
    if (!udp->incoming || !udp->outgoing || !udp->datagram) { (void)udp_cleanup(&udp); return EFRP_NO_MEMORY; }
    *out = udp; return EFRP_OK;
}

static bool udp_address_equal(const efrp_udp_address_t *a, const efrp_udp_address_t *b)
{
    return a->family == b->family && a->port == b->port && a->zone_length == b->zone_length &&
        !memcmp(a->ip, b->ip, a->family == 4 ? 4U : 16U) &&
        (!a->zone_length || !memcmp(a->zone, b->zone, a->zone_length));
}

static void udp_forget(efrp_udp_remote_t *remote)
{
    if (efrp_udp_local_destroy(&remote->local) == EFRP_OK) efrp_crypto_zero(remote, sizeof *remote);
    else remote->closing = true;
}

static void udp_expire(efrp_work_set_t *set, efrp_udp_work_t *udp, uint64_t now)
{
    for (unsigned i = 0; i < EFRP_UDP_REMOTE_LIMIT; ++i) {
        efrp_udp_remote_t *remote = &udp->remotes[i];
        if (!remote->local) continue;
        if (remote->closing) udp_forget(remote);
        else if (now - remote->last_activity >= EFRP_UDP_IDLE_MS) {
            ++set->status.udp_expired_remotes; udp_forget(remote);
        }
    }
}

static efrp_result_t udp_deliver(efrp_work_set_t *set, efrp_udp_work_t *udp, uint64_t now)
{
    efrp_udp_remote_t *remote = NULL, *empty = NULL;
    for (unsigned i = 0; i < EFRP_UDP_REMOTE_LIMIT; ++i) {
        efrp_udp_remote_t *candidate = &udp->remotes[i];
        if (!candidate->local) { if (!empty) empty = candidate; continue; }
        if (udp_address_equal(&candidate->address, &udp->packet.remote_address)) {
            if (candidate->closing) return EFRP_WOULD_BLOCK;
            remote = candidate; break;
        }
    }
    if (!remote) {
        if (!empty) return EFRP_CAPACITY_EXCEEDED;
        remote = empty;
        efrp_result_t result = efrp_udp_local_create(set->address, set->port, &remote->local);
        if (result != EFRP_OK) return result;
        remote->address = udp->packet.remote_address;
        if (remote->address.zone_length) memcpy(remote->zone, remote->address.zone, remote->address.zone_length);
        remote->address.zone = remote->zone; remote->last_activity = now;
    }
    efrp_result_t result = efrp_udp_local_step(remote->local);
    if (result == EFRP_OK) result = efrp_udp_local_send(remote->local, udp->packet.payload, udp->packet.payload_length);
    if (result == EFRP_OK) {
        remote->last_activity = now; set->status.local_sent += udp->packet.payload_length;
        ++set->status.udp_received_datagrams;
    } else if (result != EFRP_WOULD_BLOCK) udp_forget(remote);
    return result;
}

static void release_handshake(efrp_work_set_t *set)
{
    if (!set->handshake_json) return;
    efrp_crypto_zero(set->handshake_json, EFRP_JSON_MAX_BYTES);
    free(set->handshake_json);
    set->handshake_json = NULL;
}

void efrp_work_status(const efrp_work_set_t *set, efrp_work_status_t *status)
{
    *status = set->status; status->waiting = status->active = status->cleaning = 0;
    status->udp_active_remotes = 0;
    for (unsigned i = 0; i < 3; ++i) {
        const efrp_work_stream_t *w = set->streams[i];
        if (!w) continue;
        switch (w->phase) {
        case EFRP_WORK_SENDING: case EFRP_WORK_WAITING:
            if (set->visitor) ++status->active; else ++status->waiting;
            break;
        case EFRP_WORK_CONNECTING: case EFRP_WORK_ACTIVE: case EFRP_WORK_PEER_OPENING:
            ++status->active; break;
        case EFRP_WORK_CLOSING: ++status->cleaning; break;
        default: break;
        }
        if (w->udp) for (unsigned j = 0; j < EFRP_UDP_REMOTE_LIMIT; ++j)
            if (w->udp->remotes[j].local) ++status->udp_active_remotes;
    }
    if (set->visitor && efrp_tcp_listener_pending(set->visitor->listener)) ++status->cleaning;
}
void efrp_work_init(efrp_work_set_t *set, const efrp_session_config_t *config, const char *proxy_name)
{
    memset(set, 0, sizeof *set); memcpy(set->address, config->local_ipv4, 4);
    set->port = config->local_port; set->proxy_name = proxy_name;
    set->proxy_type = config->proxy_type; set->udp_packet_size = config->udp_packet_size;
}
efrp_result_t efrp_work_visit_init(efrp_work_set_t *set, const efrp_stcp_visitor_settings_t *settings)
{
    if (!set || !settings) return EFRP_INVALID_ARGUMENT;
    efrp_result_t result = efrp_stcp_visitor_validate(settings->server_proxy_name,
        settings->secret_key, settings->bind_ipv4, settings->bind_port);
    if (result != EFRP_OK) return result;
    memset(set, 0, sizeof *set);
    efrp_visit_work_t *visitor = efrp_heap_calloc(sizeof *visitor);
    if (!visitor) return EFRP_NO_MEMORY;
    visitor->secret_key = settings->secret_key;
    memcpy(visitor->bind_ipv4, settings->bind_ipv4, sizeof visitor->bind_ipv4);
    visitor->bind_port = settings->bind_port;
    set->visitor = visitor; set->proxy_type = EFRP_PROXY_STCP;
    set->proxy_name = settings->server_proxy_name; return EFRP_OK;
}
efrp_result_t efrp_work_visit_start(efrp_work_set_t *set)
{
    if (!set || !set->visitor || set->visitor->started || set->visitor->listener) return EFRP_INVALID_STATE;
    efrp_result_t result = efrp_tcp_listener_create(set->visitor->bind_ipv4,
        set->visitor->bind_port, &set->visitor->listener);
    if (result == EFRP_OK) set->visitor->started = true;
    return result;
}
void efrp_work_request(efrp_work_set_t *set)
{
    ++set->status.requests;
    if (set->visitor || set->peer_role) { ++set->status.rejected_requests; return; }
    if (set->status.pending == 3) { ++set->status.rejected_requests; return; }
    ++set->status.pending;
}
static void close_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_result_t reason)
{
    if (w->phase == EFRP_WORK_CLOSING) return;
    if (w->phase == EFRP_WORK_SENDING || w->phase == EFRP_WORK_WAITING) {
        release_handshake(set);
        efrp_crypto_zero(&w->reader, sizeof w->reader);
    }
    w->phase = EFRP_WORK_CLOSING; w->result = reason;
    /* A backend may retain its copied transmit data until protocol release.
     * Work-owned bytes are no longer needed after logical close. */
    efrp_crypto_zero(w->incoming, sizeof w->incoming);
    efrp_crypto_zero(w->outgoing, sizeof w->outgoing);
    w->incoming_used = w->incoming_offset = w->outgoing_used = w->outgoing_offset = 0;
    if (reason != EFRP_OK) { ++set->status.failed; set->status.last_error = reason; }
}
#if defined(EFRP_LAB_TIMEOUT_TRACE)
static void trace_timeout(efrp_work_set_t *set, const efrp_work_stream_t *w,
    efrp_work_timeout_source_t source, uint64_t age)
{
    set->status.timeout_source = source;
    set->status.timeout_stream_id = w->stream_id;
    set->status.timeout_age_ms = age > UINT32_MAX ? UINT32_MAX : (uint32_t)age;
    set->status.timeout_incoming_bytes = (uint16_t)(w->incoming_used - w->incoming_offset);
    set->status.timeout_outgoing_bytes = (uint16_t)(w->outgoing_used - w->outgoing_offset);
}
#define TRACE_TIMEOUT(set, w, source, age) trace_timeout((set), (w), (source), (age))
#else
#define TRACE_TIMEOUT(set, w, source, age) ((void)0)
#endif
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
    cJSON *root = efrp_json_parse(p + 2, n - 2, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
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
static bool start_visitor(void *context, efrp_frame_kind_t kind, const uint8_t *p, size_t n)
{
    efrp_work_stream_t *w = context;
    w->result = efrp_stcp_visitor_accept_response(kind, p, n, w->proxy_name);
    w->started = w->result == EFRP_OK; return w->started;
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
static void release_stream(efrp_work_stream_t **slot)
{
    efrp_work_stream_t *w = *slot;
    efrp_crypto_zero(w, sizeof *w);
    free(w); *slot = NULL;
}
static efrp_result_t cleanup_work(efrp_work_set_t *set, efrp_work_stream_t **slot, efrp_transport_t *transport, uint64_t now)
{
    efrp_work_stream_t *w = *slot;
    bool stream_done = w->stream_id == EFRP_STREAM_NONE;
    if (!stream_done) {
        efrp_result_t r = w->result == EFRP_OK ? EFRP_OK : efrp_stream_reset(transport, w->stream_id);
        if (r != EFRP_OK && r != EFRP_WOULD_BLOCK) return r;
        if (r == EFRP_OK) r = efrp_stream_release(transport, w->stream_id);
        if (r != EFRP_OK && r != EFRP_WOULD_BLOCK) return r;
        if (r == EFRP_OK) { w->stream_id = EFRP_STREAM_NONE; stream_done = true; }
    }
    /* Native stream release may wait for QUIC ACK/stream_close. Keep the work
     * owner and ID, but release local fds independently of that peer wait. */
    if (w->local) {
        if (w->result == EFRP_OK) {
            efrp_result_t r = efrp_connect_finish(w->local);
            if (r == EFRP_WOULD_BLOCK) {
                if (now < w->deadline) return EFRP_OK;
                TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_CLEANUP,
                    now - (w->deadline - EFRP_WORK_CLEANUP_MS));
                w->result = EFRP_TIMEOUT; ++set->status.failed; set->status.last_error = EFRP_TIMEOUT;
                (void)efrp_connect_cancel(w->local);
            }
            else if (r != EFRP_OK) { w->result = r; ++set->status.failed; set->status.last_error = r; }
        }
        if (efrp_connect_destroy(&w->local) == EFRP_WOULD_BLOCK) return EFRP_OK;
    }
    if (!udp_cleanup(&w->udp) || !stream_done) return EFRP_OK;
    if (w->result == EFRP_OK) ++set->status.completed;
    release_stream(slot); return EFRP_OK;
}
static efrp_result_t handshake_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_transport_t *transport, uint64_t now)
{
    efrp_result_t r; size_t used;
    if (set->visitor && w->stream_id == EFRP_STREAM_NONE) {
        if (now >= w->deadline) { close_work(set, w, EFRP_TIMEOUT); return EFRP_OK; }
        r = efrp_stream_open(transport, &w->stream_id);
        if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (w->phase == EFRP_WORK_SENDING) {
        if (now >= w->deadline) {
            TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_HANDSHAKE_SEND,
                now - (w->deadline - EFRP_SESSION_RESPONSE_MS));
            close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
        }
        r = efrp_stream_write(transport, w->stream_id, w->outgoing + w->outgoing_offset,
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
    if ((set->visitor || w->partial_header) && now >= w->deadline) {
        TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_HANDSHAKE_FRAME,
            now - (w->deadline - EFRP_SESSION_RESPONSE_MS));
        close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
    }
    r = efrp_stream_read(transport, w->stream_id, w->incoming, sizeof w->incoming, &used);
    if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
    if (r != EFRP_OK) { close_work(set, w, r == EFRP_EOF ? EFRP_TRUNCATED : r); return EFRP_OK; }
    if (!set->handshake_json) {
        set->handshake_json = efrp_heap_calloc(EFRP_JSON_MAX_BYTES);
        if (!set->handshake_json) { close_work(set, w, EFRP_NO_MEMORY); return EFRP_OK; }
        r = efrp_wire_init(&w->reader, set->handshake_json, EFRP_JSON_MAX_BYTES, false, set->visitor ? start_visitor : start_work, w);
        if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (!w->partial_header) { w->partial_header = true; if (!set->visitor) w->deadline = now + EFRP_SESSION_RESPONSE_MS; }
    w->incoming_used = used;
    r = efrp_wire_feed_one(&w->reader, w->incoming, used, &w->incoming_offset);
    if (r != EFRP_OK) { close_work(set, w, w->result != EFRP_OK ? w->result : r); return EFRP_OK; }
    if (!w->started) { efrp_crypto_zero(w->incoming, w->incoming_used); w->incoming_used = w->incoming_offset = 0; return EFRP_OK; }
    release_handshake(set);
    efrp_crypto_zero(&w->reader, sizeof w->reader);
    if (set->visitor) {
        /* The accepted local socket already exists. Retain any response tail
         * for raw forwarding; NewVisitorConn is the only framed admission. */
        w->phase = EFRP_WORK_ACTIVE;
        w->last_activity = w->incoming_progress = w->outgoing_progress = now;
        return EFRP_OK;
    }
    efrp_work_status_t status; efrp_work_status(set, &status);
    unsigned closing_sockets = 0;
    for (unsigned i = 0; i < 3; ++i) {
        const efrp_work_stream_t *closing = set->streams[i];
        if (closing && closing->phase == EFRP_WORK_CLOSING && closing->local) ++closing_sockets;
    }
    if (set->proxy_type == EFRP_PROXY_UDP) {
        /* Official UDP owns one work connection. A replacement invalidates
         * every old source socket and queued response before accepting data. */
        for (unsigned i = 0; i < 3; ++i) {
            efrp_work_stream_t *old = set->streams[i];
            if (old && old != w && (old->phase == EFRP_WORK_ACTIVE || old->phase == EFRP_WORK_CONNECTING))
                close_work(set, old, EFRP_STREAM_RESET);
        }
        w->phase = EFRP_WORK_CONNECTING; w->deadline = now + EFRP_SESSION_RESPONSE_MS;
        w->last_activity = now; return EFRP_OK;
    }
    if (status.active + closing_sockets >= 2) { close_work(set, w, EFRP_CAPACITY_EXCEEDED); return EFRP_OK; }
    r = efrp_connect_create_ipv4(set->address, set->port, now, &w->local);
    if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
    w->phase = EFRP_WORK_CONNECTING; w->last_activity = w->incoming_progress = now;
    return EFRP_OK;
}
static efrp_result_t udp_feed(efrp_work_set_t *set, efrp_udp_work_t *udp,
    const uint8_t *bytes, size_t length, size_t *used, uint64_t now)
{
    *used = 0;
    if (udp->pending) return EFRP_WOULD_BLOCK;
    while (*used < length) {
        if (udp->header_used < 8U) {
            if (!udp->header_used) udp->incoming_at = now;
            udp->header[udp->header_used++] = bytes[(*used)++]; udp->incoming_at = now;
            if (udp->header_used < 8U) continue;
            const uint8_t *h = udp->header;
            if (h[0] || h[1] != EFRP_MESSAGE || h[2] || h[3]) return EFRP_PROTOCOL_ERROR;
            udp->payload_expected = ((size_t)h[4] << 24) | ((size_t)h[5] << 16) | ((size_t)h[6] << 8) | h[7];
            if (udp->payload_expected < 2U) return EFRP_PROTOCOL_ERROR;
            if (udp->payload_expected > EFRP_WIRE_MAX_PAYLOAD) return EFRP_CAPACITY_EXCEEDED;
            udp->discard = udp->payload_expected > udp->capacity;
        }
        size_t take = udp->payload_expected - udp->payload_used;
        if (take > length - *used) take = length - *used;
        size_t copy = udp->payload_used < udp->capacity ? udp->capacity - udp->payload_used : 0;
        if (copy > take) copy = take;
        if (copy) memcpy(udp->incoming + udp->payload_used, bytes + *used, copy);
        udp->payload_used += take; *used += take; udp->incoming_at = now;
        if (!udp->header_validated) {
            size_t prefix = udp->payload_used < udp->capacity ? udp->payload_used : udp->capacity, offset = 0;
            efrp_result_t result = efrp_udp_packet_header_decode(udp->incoming, prefix,
                udp->payload_expected, &udp->packet, &offset);
            if (result == EFRP_OK) {
                udp->header_validated = true;
                if (udp->packet.payload_length > set->udp_packet_size) udp->discard = true;
            } else if (result != EFRP_WOULD_BLOCK) return result;
        }
        if (udp->payload_used == udp->payload_expected) {
            if (!udp->header_validated) return EFRP_TRUNCATED;
            if (udp->discard) {
                ++set->status.udp_dropped_datagrams;
                efrp_crypto_zero(udp->incoming, udp->capacity);
            } else {
                efrp_result_t result = efrp_udp_packet_decode(udp->incoming, udp->payload_expected, &udp->packet);
                if (result != EFRP_OK) return result;
                udp->pending = true; udp->incoming_at = now;
            }
            udp->header_used = udp->payload_used = udp->payload_expected = 0;
            udp->header_validated = udp->discard = false;
            return EFRP_OK;
        }
    }
    return EFRP_OK;
}

static efrp_result_t udp_output(efrp_work_set_t *set, efrp_udp_work_t *udp,
    efrp_transport_t *transport, efrp_stream_id_t stream_id, uint64_t now)
{
    if (udp->outgoing_used > udp->outgoing_offset) {
        if (now - udp->outgoing_at >= EFRP_WORK_IO_STALL_MS) return EFRP_TIMEOUT;
        size_t used = 0;
        efrp_result_t result = efrp_stream_write(transport, stream_id, udp->outgoing + udp->outgoing_offset,
            udp->outgoing_used - udp->outgoing_offset, &used);
        if (result == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (result != EFRP_OK) return result;
        efrp_crypto_zero(udp->outgoing + udp->outgoing_offset, used);
        udp->outgoing_offset += used; udp->outgoing_at = now;
        if (udp->outgoing_offset == udp->outgoing_used) {
            if (udp->outgoing_datagram) ++set->status.udp_sent_datagrams;
            udp->outgoing_offset = udp->outgoing_used = 0; udp->outgoing_datagram = false;
        }
        return EFRP_OK;
    }
    if (now >= udp->ping_at) {
        efrp_result_t result = efrp_wire_header(EFRP_MESSAGE, 4, udp->outgoing);
        if (result != EFRP_OK) return result;
        udp->outgoing[8] = 0; udp->outgoing[9] = 11;
        udp->outgoing[10] = '{'; udp->outgoing[11] = '}';
        udp->outgoing_used = 12; udp->outgoing_at = now;
        udp->ping_at = now + EFRP_UDP_HEARTBEAT_MS; return EFRP_OK;
    }
    for (unsigned offset = 0; offset < EFRP_UDP_REMOTE_LIMIT; ++offset) {
        unsigned index = (udp->cursor + offset) % EFRP_UDP_REMOTE_LIMIT;
        efrp_udp_remote_t *remote = &udp->remotes[index];
        if (!remote->local || remote->closing) continue;
        size_t length = 0;
        efrp_result_t result = efrp_udp_local_recv(remote->local, udp->datagram, set->udp_packet_size, &length);
        if (result == EFRP_WOULD_BLOCK) continue;
        udp->cursor = (index + 1U) % EFRP_UDP_REMOTE_LIMIT;
        if (result == EFRP_CAPACITY_EXCEEDED) { ++set->status.udp_dropped_datagrams; continue; }
        if (result != EFRP_OK) { udp_forget(remote); ++set->status.udp_dropped_datagrams; continue; }
        remote->last_activity = now; set->status.local_received += length;
        efrp_udp_packet_t packet = {.remote_address = remote->address, .payload = udp->datagram, .payload_length = length};
        size_t encoded = 0;
        result = efrp_udp_packet_encode(&packet, udp->outgoing + 8, udp->capacity, &encoded);
        efrp_crypto_zero(udp->datagram, udp->datagram_capacity);
        if (result != EFRP_OK) { ++set->status.udp_dropped_datagrams; continue; }
        result = efrp_wire_header(EFRP_MESSAGE, encoded, udp->outgoing);
        if (result != EFRP_OK) return result;
        udp->outgoing_used = encoded + 8U; udp->outgoing_at = now; udp->outgoing_datagram = true;
        break;
    }
    return EFRP_OK;
}

static efrp_result_t forward_udp(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_transport_t *transport, uint64_t now)
{
    if (w->phase == EFRP_WORK_CONNECTING) {
        for (unsigned i = 0; i < 3; ++i) {
            const efrp_work_stream_t *old = set->streams[i];
            if (old && old != w && old->phase == EFRP_WORK_CLOSING) {
                if (now >= w->deadline) close_work(set, w, EFRP_TIMEOUT);
                return EFRP_OK;
            }
        }
        efrp_result_t result = udp_create(&w->udp, set->udp_packet_size, now);
        if (result != EFRP_OK) { close_work(set, w, result); return EFRP_OK; }
        w->phase = EFRP_WORK_ACTIVE;
    }
    efrp_udp_work_t *udp = w->udp;
    udp_expire(set, udp, now);
    if (udp->pending) {
        efrp_result_t result = udp_deliver(set, udp, now);
        if (result == EFRP_WOULD_BLOCK && now - udp->incoming_at < EFRP_WORK_IO_STALL_MS) return EFRP_OK;
        if (result != EFRP_OK) ++set->status.udp_dropped_datagrams;
        udp->pending = false; efrp_crypto_zero(udp->incoming, udp->capacity);
        efrp_crypto_zero(&udp->packet, sizeof udp->packet);
    }
    if (udp->header_used && now - udp->incoming_at >= EFRP_WORK_IO_STALL_MS) {
        close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
    }
    if (w->incoming_used == w->incoming_offset) {
        w->incoming_used = w->incoming_offset = 0; size_t used = 0;
        efrp_result_t result = efrp_stream_read(transport, w->stream_id, w->incoming, sizeof w->incoming, &used);
        if (result == EFRP_EOF) {
            close_work(set, w, udp->header_used ? EFRP_TRUNCATED : EFRP_STREAM_RESET); return EFRP_OK;
        }
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) { close_work(set, w, result); return EFRP_OK; }
        if (result == EFRP_OK) w->incoming_used = used;
    }
    if (w->incoming_used > w->incoming_offset) {
        size_t used = 0;
        efrp_result_t result = udp_feed(set, udp, w->incoming + w->incoming_offset,
            w->incoming_used - w->incoming_offset, &used, now);
        efrp_crypto_zero(w->incoming + w->incoming_offset, used); w->incoming_offset += used;
        if (result != EFRP_OK) { close_work(set, w, result); return EFRP_OK; }
    }
    efrp_result_t result = udp_output(set, udp, transport, w->stream_id, now);
    if (result != EFRP_OK) close_work(set, w, result);
    return EFRP_OK;
}

static efrp_result_t forward_work(efrp_work_set_t *set, efrp_work_stream_t *w, efrp_transport_t *transport, uint64_t now)
{
    efrp_result_t r; size_t count;
    if (w->phase == EFRP_WORK_CONNECTING) {
        r = efrp_connect_step(w->local, now);
        if (r == EFRP_WOULD_BLOCK) return EFRP_OK;
        if (r != EFRP_OK) { close_work(set, w, r); return EFRP_OK; }
        w->phase = EFRP_WORK_ACTIVE; w->last_activity = now;
    }
    if (now - w->last_activity >= EFRP_WORK_IDLE_MS) {
        TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_IDLE, now - w->last_activity);
        close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
    }
    if (w->incoming_used > w->incoming_offset && now - w->incoming_progress >= EFRP_WORK_IO_STALL_MS) {
        TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_INCOMING_LOCAL, now - w->incoming_progress);
        close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
    }
    if (w->outgoing_used > w->outgoing_offset && now - w->outgoing_progress >= EFRP_WORK_IO_STALL_MS) {
        TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_OUTGOING_STREAM, now - w->outgoing_progress);
        close_work(set, w, EFRP_TIMEOUT); return EFRP_OK;
    }
    if (w->incoming_used == w->incoming_offset) {
        w->incoming_used = w->incoming_offset = 0;
        if (!w->remote_eof) {
            r = efrp_stream_read(transport, w->stream_id, w->incoming, sizeof w->incoming, &count);
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
        else if (r != EFRP_WOULD_BLOCK || now - w->fin_progress >= EFRP_WORK_IO_STALL_MS) {
            if (r == EFRP_WOULD_BLOCK)
                TRACE_TIMEOUT(set, w, EFRP_WORK_TIMEOUT_LOCAL_FIN, now - w->fin_progress);
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
        r = efrp_stream_write(transport, w->stream_id, w->outgoing + w->outgoing_offset, w->outgoing_used - w->outgoing_offset, &count);
        if (r == EFRP_OK) {
            efrp_crypto_zero(w->outgoing + w->outgoing_offset, count); w->outgoing_offset += count;
            w->outgoing_progress = w->last_activity = now;
        } else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (w->local_eof && !w->stream_fin) {
        r = efrp_stream_close_write(transport, w->stream_id);
        if (r == EFRP_OK) w->stream_fin = true;
        else if (r != EFRP_WOULD_BLOCK) { close_work(set, w, r); return EFRP_OK; }
    }
    if (w->remote_eof && w->local_fin && w->local_eof && w->stream_fin) {
        w->deadline = now + EFRP_WORK_CLEANUP_MS;
        close_work(set, w, EFRP_OK);
    }
    return EFRP_OK;
}
static efrp_result_t step_streams(efrp_work_set_t *set, efrp_transport_t *transport, uint64_t now)
{
    for (unsigned offset = 0; offset < 3; ++offset) {
        efrp_work_stream_t **slot = &set->streams[(set->cursor + offset) % 3];
        efrp_work_stream_t *w = *slot;
        if (!w) continue;
        efrp_result_t r = EFRP_OK;
        if (w->phase == EFRP_WORK_PEER_OPENING) {
            if (now >= w->deadline) close_work(set, w, EFRP_TIMEOUT);
            else {
                r = efrp_stream_open(transport, &w->stream_id);
                if (r == EFRP_WOULD_BLOCK) r = EFRP_OK;
                else if (r != EFRP_OK) { close_work(set, w, r); r = EFRP_OK; }
                else if (w->stream_id < 4u || (w->stream_id & 3u)) close_work(set, w, EFRP_PROTOCOL_ERROR);
                else { w->phase = EFRP_WORK_ACTIVE; w->last_activity = now; }
            }
        }
        if (w->stream_id != EFRP_STREAM_NONE && w->phase != EFRP_WORK_CLOSING) {
            efrp_stream_info_t info;
            r = efrp_stream_info(transport, w->stream_id, &info);
            if (r != EFRP_OK) return r;
            if (info.reset) close_work(set, w, EFRP_STREAM_RESET);
        }
        if (w->phase == EFRP_WORK_SENDING || w->phase == EFRP_WORK_WAITING) r = handshake_work(set, w, transport, now);
        if (r == EFRP_OK && (w->phase == EFRP_WORK_CONNECTING || w->phase == EFRP_WORK_ACTIVE))
            r = set->proxy_type == EFRP_PROXY_UDP ? forward_udp(set, w, transport, now) : forward_work(set, w, transport, now);
        if (r == EFRP_OK && w->phase == EFRP_WORK_CLOSING) r = cleanup_work(set, slot, transport, now);
        if (r != EFRP_OK) return r;
    }
    set->cursor = (set->cursor + 1) % 3; return EFRP_OK;
}
efrp_result_t efrp_work_step(efrp_work_set_t *set, efrp_transport_t *transport, uint64_t now,
    const char *run_id, const uint8_t *token, size_t token_length, int64_t seconds)
{
    if (set->visitor || set->peer_role) return EFRP_INVALID_STATE;
    efrp_work_status_t status; efrp_work_status(set, &status);
    if (set->status.pending && !status.waiting) {
        for (unsigned i = 0; i < 3; ++i) if (!set->streams[i]) {
            efrp_work_stream_t *w = efrp_heap_calloc(sizeof *w);
            if (!w) return EFRP_NO_MEMORY;
            w->stream_id = EFRP_STREAM_NONE;
            efrp_result_t r = efrp_stream_open(transport, &w->stream_id);
            if (r != EFRP_OK) {
                release_stream(&w);
                if (r == EFRP_WOULD_BLOCK) break;
                return r;
            }
            set->streams[i] = w;
            --set->status.pending; w->proxy_name = set->proxy_name;
            w->phase = EFRP_WORK_SENDING; w->deadline = now + EFRP_SESSION_RESPONSE_MS;
            r = new_work(w, run_id, token, token_length, seconds);
            if (r != EFRP_OK) close_work(set, w, r);
            break;
        }
    }
    return step_streams(set, transport, now);
}
efrp_result_t efrp_work_visit_step(efrp_work_set_t *set, efrp_transport_t *transport, uint64_t now,
    const char *run_id, int64_t seconds)
{
    if (!set || !set->visitor || !set->visitor->started || set->peer_role) return EFRP_INVALID_STATE;
    /* Count closing business sockets and failed-adoption raw fds toward the
     * same two-socket bound. Only one admission may own the shared parser. */
    unsigned sockets = efrp_tcp_listener_pending(set->visitor->listener) ? 1U : 0U;
    bool admitting = false; unsigned empty = 3;
    for (unsigned i = 0; i < 3; ++i) {
        efrp_work_stream_t *w = set->streams[i];
        if (!w) { if (empty == 3) empty = i; continue; }
        ++sockets; /* Closing protocol references reserve the same slot. */
        if (w->phase == EFRP_WORK_SENDING || w->phase == EFRP_WORK_WAITING) admitting = true;
    }
    /* Retry orphan cleanup even when its retained fd fills the last slot. */
    efrp_result_t ready = efrp_tcp_listener_ready(set->visitor->listener);
    if (ready != EFRP_OK && ready != EFRP_WOULD_BLOCK) return ready;
    if (!admitting && sockets < 2 && empty < 3 && ready == EFRP_OK) {
        efrp_work_stream_t *w = efrp_heap_calloc(sizeof *w);
        if (!w) return EFRP_NO_MEMORY;
        w->stream_id = EFRP_STREAM_NONE;
        efrp_result_t result = efrp_tcp_listener_accept(set->visitor->listener, now, &w->local);
        if (result != EFRP_OK) {
            release_stream(&w);
            if (result != EFRP_WOULD_BLOCK) { ++set->status.failed; set->status.last_error = result; }
        } else {
            ++set->status.requests; set->streams[empty] = w;
            w->proxy_name = set->proxy_name; w->phase = EFRP_WORK_SENDING;
            w->deadline = now + EFRP_SESSION_RESPONSE_MS;
            result = efrp_stcp_visitor_encode_request(run_id, set->proxy_name,
                set->visitor->secret_key, seconds, w->outgoing, sizeof w->outgoing, &w->outgoing_used);
            if (result != EFRP_OK) close_work(set, w, result);
        }
    }
    return step_streams(set, transport, now);
}

efrp_result_t efrp_work_peer_init(efrp_work_set_t *set, efrp_xtcp_role_t role,
    const uint8_t address[4], uint16_t port)
{
    if (!set || (role != EFRP_XTCP_PROVIDER && role != EFRP_XTCP_VISITOR) ||
        (role == EFRP_XTCP_PROVIDER && (!address || !address[0] || address[0] >= 224 || !port)))
        return EFRP_INVALID_ARGUMENT;
    memset(set, 0, sizeof *set); set->peer_role = role;
    if (role == EFRP_XTCP_PROVIDER) { memcpy(set->address, address, 4); set->port = port; }
    return EFRP_OK;
}
static unsigned peer_capacity(const efrp_work_set_t *set, unsigned *empty)
{
    unsigned occupied = 0; *empty = 3;
    for (unsigned i = 0; i < 3; ++i) {
        if (set->streams[i]) ++occupied;
        else if (*empty == 3) *empty = i;
    }
    return occupied;
}
efrp_result_t efrp_work_peer_adopt(efrp_work_set_t *set, efrp_connect_t **local, uint64_t now)
{
    if (!set || !local || !*local || now > UINT64_MAX - EFRP_SESSION_RESPONSE_MS) return EFRP_INVALID_ARGUMENT;
    if (set->peer_role != EFRP_XTCP_VISITOR) return EFRP_INVALID_STATE;
    efrp_connect_status_t status;
    if (efrp_connect_status(*local, &status) != EFRP_OK || status.state != EFRP_CONNECT_OPEN || status.result != EFRP_OK)
        return EFRP_INVALID_STATE;
    unsigned empty;
    if (peer_capacity(set, &empty) >= 2 || empty == 3) return EFRP_CAPACITY_EXCEEDED;
    efrp_work_stream_t *w = efrp_heap_calloc(sizeof *w);
    if (!w) return EFRP_NO_MEMORY;
    w->stream_id = EFRP_STREAM_NONE; w->phase = EFRP_WORK_PEER_OPENING;
    w->deadline = now + EFRP_SESSION_RESPONSE_MS;
    w->last_activity = w->incoming_progress = w->outgoing_progress = now;
    w->local = *local; *local = NULL; set->streams[empty] = w;
    ++set->status.requests; return EFRP_OK;
}
efrp_result_t efrp_work_peer_step(efrp_work_set_t *set, efrp_transport_t *transport, uint64_t now)
{
    if (!set || !transport || now > UINT64_MAX - EFRP_WORK_IDLE_MS) return EFRP_INVALID_ARGUMENT;
    if (set->peer_role != EFRP_XTCP_PROVIDER && set->peer_role != EFRP_XTCP_VISITOR) return EFRP_INVALID_STATE;
    efrp_transport_status_t status;
    if (efrp_transport_status(transport, &status) != EFRP_OK || status.kind != EFRP_TRANSPORT_QUIC ||
        status.state != EFRP_TRANSPORT_OPEN || status.result != EFRP_OK) return EFRP_INVALID_STATE;
    unsigned empty;
    if (set->peer_role == EFRP_XTCP_PROVIDER && peer_capacity(set, &empty) < 2 && empty < 3) {
        /* Allocate before accepting so OOM cannot lose a native owner. */
        efrp_work_stream_t *w = efrp_heap_calloc(sizeof *w);
        if (!w) return EFRP_NO_MEMORY;
        w->stream_id = EFRP_STREAM_NONE;
        efrp_result_t result = efrp_stream_accept(transport, &w->stream_id);
        if (result != EFRP_OK) {
            release_stream(&w);
            if (result != EFRP_WOULD_BLOCK) return result;
        } else {
            set->streams[empty] = w; ++set->status.requests;
            w->phase = EFRP_WORK_CONNECTING; w->deadline = now + EFRP_SESSION_RESPONSE_MS;
            w->last_activity = w->incoming_progress = w->outgoing_progress = now;
            if (w->stream_id < 4u || (w->stream_id & 3u)) result = EFRP_PROTOCOL_ERROR;
            else result = efrp_connect_create_ipv4(set->address, set->port, now, &w->local);
            if (result != EFRP_OK) close_work(set, w, result);
        }
    }
    return step_streams(set, transport, now);
}

bool efrp_work_cancel(efrp_work_set_t *set)
{
    bool done = true; set->status.pending = 0;
    if (set->visitor) {
        set->visitor->started = false;
        if (efrp_tcp_listener_destroy(&set->visitor->listener) != EFRP_OK) done = false;
    }
    release_handshake(set);
    for (unsigned i = 0; i < 3; ++i) {
        efrp_work_stream_t *w = set->streams[i];
        if (!w) continue;
        bool udp_done = udp_cleanup(&w->udp);
        if (!udp_done || (w->local && efrp_connect_destroy(&w->local) == EFRP_WOULD_BLOCK)) {
            efrp_crypto_zero(w->incoming, sizeof w->incoming);
            efrp_crypto_zero(w->outgoing, sizeof w->outgoing); w->phase = EFRP_WORK_CLOSING; done = false;
        } else release_stream(&set->streams[i]);
    }
    if (done && set->visitor) {
        efrp_crypto_zero(set->visitor, sizeof *set->visitor); free(set->visitor); set->visitor = NULL;
    }
    return done;
}
