// SPDX-License-Identifier: Apache-2.0
#include "esp_frp.h"
#include "esp_frp_connect.h"
#include "client_port.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "proxy_internal.h"
#include "session_internal.h"
#include "memory_internal.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    efrp_stcp_visitor_owned_t *owner;
    efrp_stcp_visitor_settings_t settings;
} efrp_client_visitor_t;
typedef struct {
    efrp_xtcp_config_t settings;
    char secret_key[129];
} efrp_client_xtcp_visitor_t;
struct efrp_client {
    efrp_port_t *port;
    efrp_config_t config;
    efrp_proxy_owned_t *proxy_options;
    efrp_client_visitor_t *visitor;
    efrp_client_xtcp_visitor_t *xtcp_visitor;
    efrp_xtcp_options_t xtcp_options;
    char *remote_address;
    size_t remote_address_length; /* owned under the status lock */
    efrp_aead_flash_store_t flash_store;
    char server[254], hostname[129], user[129], client_id[129], proxy[129];
    char requested_run_id[EFRP_RUN_ID_BYTES];
    uint8_t token[EFRP_AEAD_MAX_TOKEN_BYTES];
    uint8_t *ca;
    /* API lock owns these fields, status lock owns completed_ticket/snapshot. */
    bool requested;
    uint64_t next_ticket, stop_ticket, completed_ticket;
    efrp_status_t snapshot;
    /* Everything below is worker-owned. No other task accesses these handles. */
    efrp_connect_t *connection;
    efrp_tls_t *tls;
    efrp_transport_t *transport;
    efrp_session_t *session;
    efrp_status_t current;
    efrp_work_status_t totals;
    uint64_t pong_total, ready_at, worker_stop_ticket;
    unsigned failure_streak;
    bool running, retryable;
};
static void publish(efrp_client_t *c, bool event)
{
    efrp_port_status_lock(c->port); c->snapshot = c->current; efrp_port_status_unlock(c->port);
    if (event && c->config.on_event) c->config.on_event(c->config.context, &c->current);
}
static void phase(efrp_client_t *c, efrp_phase_t value)
{
    bool changed = c->current.phase != value;
    c->current.phase = value; publish(c, changed);
}
static efrp_result_t session_status(efrp_client_t *c)
{
    efrp_session_status_t s;
    if (!c->session || efrp_session_status(c->session, &s) != EFRP_OK) return EFRP_INVALID_STATE;
    c->current.work = s.work;
    c->current.xtcp = s.xtcp;
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    c->current.mux_timeout_source = s.mux_timeout_source;
    c->current.control_timeout_source = s.control_timeout_source;
    c->current.mux_timeout_stream_id = s.mux_timeout_stream_id;
    c->current.mux_timeout_age_ms = s.mux_timeout_age_ms;
    c->current.mux_timeout_pending_bytes = s.mux_timeout_pending_bytes;
#endif
#define ADD_COUNTER(field) c->current.work.field += c->totals.field
    ADD_COUNTER(requests); ADD_COUNTER(completed); ADD_COUNTER(failed);
    ADD_COUNTER(rejected_requests); ADD_COUNTER(local_sent); ADD_COUNTER(local_received);
    ADD_COUNTER(udp_received_datagrams); ADD_COUNTER(udp_sent_datagrams);
    ADD_COUNTER(udp_dropped_datagrams); ADD_COUNTER(udp_expired_remotes);
#undef ADD_COUNTER
    c->current.pongs = c->pong_total + s.pongs;
    if (s.run_id[0]) memcpy(c->current.run_id, s.run_id, sizeof s.run_id);
    if (s.remote_address_length && !c->remote_address) {
        char *address = malloc(s.remote_address_length + 1);
        if (!address) return EFRP_NO_MEMORY;
        size_t length;
        efrp_result_t result = efrp_session_remote_address(c->session, address, s.remote_address_length + 1, &length);
        if (result != EFRP_OK) { free(address); return result; }
        efrp_port_status_lock(c->port); c->remote_address = address; c->remote_address_length = length;
        efrp_port_status_unlock(c->port);
    }
    c->current.remote_address_length = s.remote_address_length; return EFRP_OK;
}
static void drain(efrp_client_t *c, efrp_result_t error)
{
    if (c->current.phase != EFRP_PHASE_DRAINING) {
        c->current.failure_phase = c->current.phase;
        (void)session_status(c); c->totals = c->current.work; c->pong_total = c->current.pongs;
        c->retryable = error == EFRP_NETWORK_ERROR || error == EFRP_DNS_ERROR ||
            error == EFRP_TIMEOUT || error == EFRP_SESSION_CLOSED || error == EFRP_EOF;
        if (c->tls) {
            efrp_tls_status_t t; (void)efrp_tls_status(c->tls, &t);
            c->current.tls_error = t.library_error; c->current.tls_verify_flags = t.verify_flags;
            /* A bare TCP EOF is a transport interruption. An authenticated but
             * truncated FRP frame remains a fatal protocol error. */
            if (error == EFRP_TRUNCATED && t.state == EFRP_TLS_FAILED && t.result == EFRP_TRUNCATED)
                c->retryable = true;
        }
        if (c->transport && c->config.transport == EFRP_TRANSPORT_QUIC) {
            efrp_transport_status_t t; (void)efrp_transport_status(c->transport, &t);
            c->current.system_error = t.system_error;
            c->current.tls_error = t.tls_error; c->current.tls_verify_flags = t.verify_flags;
        }
        if (c->connection) {
            efrp_connect_status_t s; (void)efrp_connect_status(c->connection, &s);
            c->current.system_error = s.system_error;
        }
        if (c->session) {
            (void)efrp_session_cancel(c->session);
            efrp_session_status_t status;
            if (efrp_session_status(c->session, &status) == EFRP_OK) c->current.xtcp = status.xtcp;
        }
        if (c->transport) (void)efrp_transport_cancel(c->transport);
        if (c->tls) (void)efrp_tls_cancel(c->tls);
        if (c->connection) (void)efrp_connect_cancel(c->connection);
    }
    c->current.error = error; c->current.retry_at_ms = 0; c->current.retry_delay_ms = 0;
    phase(c, EFRP_PHASE_DRAINING);
}
static bool cleanup(efrp_client_t *c)
{
    if (efrp_session_destroy(&c->session) != EFRP_OK) return false;
    if (efrp_transport_destroy(&c->transport) != EFRP_OK) return false;
    if (c->tls) { efrp_tls_destroy(c->tls); c->tls = NULL; }
    if (efrp_connect_destroy(&c->connection) != EFRP_OK) return false;
    c->current.work.active = c->current.work.waiting = c->current.work.pending = c->current.work.cleaning = 0;
    c->current.work.udp_active_remotes = 0;
    efrp_port_status_lock(c->port);
    if (c->remote_address) { efrp_crypto_zero(c->remote_address, c->remote_address_length + 1); free(c->remote_address); }
    c->remote_address = NULL; c->remote_address_length = 0;
    efrp_port_status_unlock(c->port);
    c->current.remote_address_length = 0;
    if (c->config.proxy_type == EFRP_PROXY_XTCP) c->current.xtcp.phase = EFRP_XTCP_STOPPED;
    return true;
}
static void backoff(efrp_client_t *c, uint64_t now)
{
    /* Equal jitter in [ceiling/2, ceiling], ceiling 1,2,4,8,16,30 seconds.
     * A short successful login does not reset repeated-failure backoff. */
    if (c->ready_at && now - c->ready_at >= UINT64_C(60000)) c->failure_streak = 0;
    uint32_t ceiling = c->failure_streak < 5 ? 1000u << c->failure_streak : 30000u;
    if (c->failure_streak < 5) ++c->failure_streak;
    uint32_t random;
    efrp_result_t result = efrp_crypto_random((uint8_t *)&random, sizeof random);
    if (result != EFRP_OK) { c->current.error = result; c->running = false; phase(c, EFRP_PHASE_FAILED); return; }
    c->current.retry_delay_ms = ceiling / 2u + random % (ceiling / 2u + 1u);
    c->current.retry_at_ms = now + c->current.retry_delay_ms;
    phase(c, EFRP_PHASE_BACKOFF);
}
static void begin(efrp_client_t *c, uint64_t now)
{
    c->ready_at = 0; c->current.retry_at_ms = 0; c->current.retry_delay_ms = 0;
    c->current.system_error = c->current.tls_error = 0; c->current.tls_verify_flags = UINT32_MAX;
    ++c->current.attempts; phase(c, EFRP_PHASE_CONNECTING);
    if (!c->config.time_is_trusted(c->config.context) || time(NULL) < (time_t)1704067200) {
        drain(c, EFRP_TIME_UNTRUSTED); return;
    }
    efrp_result_t result;
    if (c->config.transport == EFRP_TRANSPORT_QUIC) {
        efrp_quic_config_t config = {.hostname = c->server, .port = c->config.server_port,
            .ca_pem = c->ca, .ca_length = c->config.ca_length, .profile = c->config.quic_profile,
            .time_is_trusted = c->config.time_is_trusted, .context = c->config.context};
        result = efrp_transport_quic_create(&config, now, &c->transport);
    } else result = efrp_connect_create(c->server, c->config.server_port, now, &c->connection);
    if (result != EFRP_OK) drain(c, result);
}
static efrp_result_t authenticate(efrp_client_t *c, uint64_t now)
{
    efrp_result_t result;
    efrp_session_config_t config = {.login = {.token = c->token, .token_length = c->config.token_length,
        .hostname = c->hostname, .user = c->user, .client_id = c->client_id,
        .run_id = c->current.run_id[0] ? c->current.run_id : c->requested_run_id,
        .unix_seconds = (int64_t)time(NULL)},
        .proxy_name = c->proxy, .remote_port = c->config.remote_port, .local_port = c->config.local_port,
        .proxy_type = c->config.proxy_type, .proxy_options = c->config.proxy_options,
        .xtcp_options = c->config.xtcp_options, .time_is_trusted = c->config.time_is_trusted, .context = c->config.context,
        .udp_packet_size = c->config.udp_packet_size,
        .flash_store = &c->flash_store};
    memcpy(config.local_ipv4, c->config.local_ipv4, sizeof config.local_ipv4);
    if (c->xtcp_visitor) {
        efrp_session_xtcp_config_t visitor = {.login = config.login,
            .xtcp = c->xtcp_visitor->settings, .flash_store = &c->flash_store};
        result = efrp_session_xtcp_create(&visitor, c->transport, now, &c->session);
    } else if (c->visitor) {
        efrp_session_visitor_config_t visitor = {.login = config.login,
        .visitor = c->visitor->settings, .flash_store = &c->flash_store};
        result = efrp_session_visitor_create(&visitor, c->transport, now, &c->session);
    } else result = efrp_session_create(&config, c->transport, now, &c->session);
    if (result != EFRP_OK) return result;
    phase(c, EFRP_PHASE_AUTHENTICATING); return EFRP_OK;
}
static void step(efrp_client_t *c, uint64_t now)
{
    if (c->current.phase == EFRP_PHASE_DRAINING) {
        /* Cancellation may retain a single QUIC CONNECTION_CLOSE datagram on
         * EAGAIN. Advance its existing deadline without resuming session I/O. */
        if (c->session) {
            efrp_session_drain(c->session, now);
            efrp_session_status_t status;
            if (efrp_session_status(c->session, &status) == EFRP_OK) c->current.xtcp = status.xtcp;
        }
        if (c->transport) (void)efrp_transport_step(c->transport, now);
        if (!cleanup(c)) { publish(c, false); return; }
        if (!c->running) {
            phase(c, EFRP_PHASE_STOPPED); /* callback must return before stop can succeed */
            efrp_port_status_lock(c->port); c->completed_ticket = c->worker_stop_ticket;
            efrp_port_status_unlock(c->port); efrp_port_signal(c->port);
        } else if (c->retryable) backoff(c, now);
        else { c->running = false; phase(c, EFRP_PHASE_FAILED); }
        return;
    }
    if (!c->running) return;
    if (c->current.phase == EFRP_PHASE_BACKOFF) {
        if (now >= c->current.retry_at_ms) { ++c->current.retries; begin(c, now); }
        return;
    }
    if (!c->config.time_is_trusted(c->config.context) || time(NULL) < (time_t)1704067200) {
        drain(c, EFRP_TIME_UNTRUSTED); return;
    }
    efrp_result_t result;
    if (c->config.transport == EFRP_TRANSPORT_QUIC &&
        (c->current.phase == EFRP_PHASE_CONNECTING || c->current.phase == EFRP_PHASE_TLS_HANDSHAKING)) {
        result = efrp_transport_step(c->transport, now);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) { drain(c, result); return; }
        efrp_transport_status_t status;
        result = efrp_transport_status(c->transport, &status);
        if (result != EFRP_OK) { drain(c, result); return; }
        c->current.tls_verify_flags = status.verify_flags;
        if (status.state == EFRP_TRANSPORT_OPEN) {
            result = authenticate(c, now);
            if (result != EFRP_OK) drain(c, result);
        } else if (status.state == EFRP_TRANSPORT_HANDSHAKING) phase(c, EFRP_PHASE_TLS_HANDSHAKING);
    } else if (c->current.phase == EFRP_PHASE_CONNECTING) {
        result = efrp_connect_step(c->connection, now);
        if (result == EFRP_WOULD_BLOCK) return;
        if (result != EFRP_OK) { drain(c, result); return; }
        efrp_tls_config_t config = {.hostname = c->server, .ca_pem = c->ca, .ca_length = c->config.ca_length,
            .time_is_trusted = true, .send = efrp_connect_send, .recv = efrp_connect_recv, .io_context = c->connection};
        result = efrp_tls_create(&config, now, &c->tls);
        if (result != EFRP_OK) { drain(c, result); return; }
        phase(c, EFRP_PHASE_TLS_HANDSHAKING);
    } else if (c->current.phase == EFRP_PHASE_TLS_HANDSHAKING) {
        result = efrp_tls_step(c->tls, now);
        if (result == EFRP_WOULD_BLOCK) return;
        if (result != EFRP_OK) { drain(c, result); return; }
        efrp_tls_status_t tls_status;
        (void)efrp_tls_status(c->tls, &tls_status);
        c->current.tls_verify_flags = tls_status.verify_flags;
        result = efrp_transport_yamux_create(c->tls, now, &c->transport);
        if (result == EFRP_OK) result = authenticate(c, now);
        if (result != EFRP_OK) { drain(c, result); return; }
    } else {
        result = efrp_session_step(c->session, now, (int64_t)time(NULL));
        if (result != EFRP_OK) { drain(c, result); return; }
        efrp_session_status_t status; (void)efrp_session_status(c->session, &status);
        result = session_status(c); if (result != EFRP_OK) { drain(c, result); return; }
        if (status.phase == EFRP_SESSION_REGISTERED && status.pongs) {
            if (c->current.phase != EFRP_PHASE_READY) {
                ++c->current.ready_sessions; c->ready_at = now; c->current.error = EFRP_OK;
            }
            phase(c, EFRP_PHASE_READY);
        } else if (status.phase == EFRP_SESSION_REGISTERING || status.phase == EFRP_SESSION_REGISTERED)
            phase(c, EFRP_PHASE_REGISTERING);
        else publish(c, false);
    }
}
static void worker(void *context)
{
    efrp_client_t *c = context;
    for (;;) {
        uint64_t now = efrp_port_now_ms();
        uint32_t wait_ms = 1;
        if (!c->running && c->current.phase != EFRP_PHASE_DRAINING) wait_ms = UINT32_MAX;
        else if (c->current.phase == EFRP_PHASE_BACKOFF)
            wait_ms = now < c->current.retry_at_ms ? (uint32_t)(c->current.retry_at_ms - now) : 0;
        efrp_command_t command;
        if (efrp_port_receive(c->port, &command, wait_ms)) {
            if (command.kind == EFRP_COMMAND_EXIT) return; /* API only sends after stop */
            if (command.kind == EFRP_COMMAND_START) {
                c->running = true; c->failure_streak = 0; c->current.error = EFRP_OK;
                begin(c, efrp_port_now_ms());
            } else {
                c->running = false; c->worker_stop_ticket = command.ticket; drain(c, EFRP_CANCELLED);
            }
        }
        step(c, efrp_port_now_ms());
    }
}
static bool copy_string(char *out, const char *input, size_t max, bool ascii, bool required)
{
    if (!input) input = "";
    size_t n = 0; while (n <= max && input[n]) ++n;
    if (n > max || (required && !n) || !efrp_json_utf8((const uint8_t *)input, n)) return false;
    if (ascii) for (size_t i = 0; i < n; ++i) {
        unsigned char b = (unsigned char)input[i];
        if (b <= 32 || b >= 127 || b == '/' || b == '\\' || b == '*' || b == '@') return false;
    }
    memcpy(out, input, n + 1); return true;
}
static void destroy_visitor(efrp_client_visitor_t **visitor)
{
    if (!*visitor) return;
    efrp_stcp_visitor_owned_destroy(&(*visitor)->owner);
    efrp_crypto_zero(*visitor, sizeof **visitor); free(*visitor); *visitor = NULL;
}
static void destroy_xtcp_visitor(efrp_client_xtcp_visitor_t **visitor)
{
    if (!*visitor) return;
    efrp_crypto_zero(*visitor, sizeof **visitor); free(*visitor); *visitor = NULL;
}
static efrp_result_t validate_xtcp(const efrp_xtcp_config_t *config)
{
    efrp_xtcp_t *idle = NULL;
    efrp_result_t result = efrp_xtcp_create(config, &idle);
    if (result == EFRP_OK) result = efrp_xtcp_destroy(&idle, 0);
    return result;
}
static efrp_result_t create_client(const efrp_config_t *config,
    const efrp_stcp_visitor_config_t *visitor, const efrp_xtcp_visitor_config_t *xtcp_visitor, efrp_client_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if (!config ||
        (config->transport != EFRP_TRANSPORT_YAMUX_TLS && config->transport != EFRP_TRANSPORT_QUIC) ||
        (config->transport == EFRP_TRANSPORT_QUIC
            ? config->quic_profile != EFRP_QUIC_PROFILE_P256_AES128_X25519
            : config->quic_profile != 0) || !config->server_port || !config->ca_pem || !config->ca_length ||
        config->ca_length > EFRP_TLS_MAX_CA_BYTES || memchr(config->ca_pem, 0, config->ca_length) ||
        !config->token || !config->token_length || config->token_length > EFRP_AEAD_MAX_TOKEN_BYTES ||
        !config->time_is_trusted ||
        !config->flash_store || !config->flash_store->recover || !config->flash_store->begin ||
        !config->flash_store->write || !config->flash_store->read || !config->flash_store->clear)
        return EFRP_INVALID_ARGUMENT;
    if ((visitor && xtcp_visitor) || (config->proxy_type != EFRP_PROXY_XTCP && config->xtcp_options)) return EFRP_INVALID_ARGUMENT;
    efrp_result_t checked;
    if (xtcp_visitor) {
        efrp_xtcp_config_t settings = {.role = EFRP_XTCP_VISITOR,
            .proxy_name = xtcp_visitor->server_proxy_name, .secret_key = xtcp_visitor->secret_key,
            .options = xtcp_visitor->options, .local_port = xtcp_visitor->bind_port,
            .time_is_trusted = config->time_is_trusted, .context = config->context};
        memcpy(settings.local_ipv4, xtcp_visitor->bind_ipv4, 4);
        checked = validate_xtcp(&settings);
    } else if (visitor) checked = efrp_stcp_visitor_validate(visitor->server_proxy_name,
        visitor->secret_key, visitor->bind_ipv4, visitor->bind_port);
    else {
        if (!config->local_port || !config->local_ipv4[0] || config->local_ipv4[0] >= 224)
            return EFRP_INVALID_ARGUMENT;
        checked = efrp_proxy_validate(config->proxy_type, config->proxy_options, config->proxy_name, config->remote_port);
        if (config->proxy_type == EFRP_PROXY_UDP ? (!config->udp_packet_size || config->udp_packet_size > 65507U)
                                              : config->udp_packet_size != 0) return EFRP_INVALID_ARGUMENT;
        if (checked == EFRP_OK && config->proxy_type == EFRP_PROXY_XTCP) {
            if (!config->xtcp_options) return EFRP_INVALID_ARGUMENT;
            efrp_xtcp_config_t settings = {.role = EFRP_XTCP_PROVIDER,
                .proxy_name = config->proxy_name, .secret_key = config->proxy_options->secret_key,
                .options = *config->xtcp_options, .local_port = config->local_port,
                .time_is_trusted = config->time_is_trusted, .context = config->context};
            memcpy(settings.local_ipv4, config->local_ipv4, 4);
            checked = validate_xtcp(&settings);
        }
    }
    if (checked != EFRP_OK) return checked;
    efrp_client_t *c = efrp_heap_calloc(sizeof *c); if (!c) return EFRP_NO_MEMORY;
    if (!copy_string(c->server, config->server_hostname, 253, true, true) ||
        !copy_string(c->hostname, config->hostname, 128, false, false) ||
        !copy_string(c->user, config->user, 128, false, false) ||
        !copy_string(c->client_id, config->client_id, 128, false, false) ||
        !copy_string(c->requested_run_id, config->run_id, EFRP_RUN_ID_BYTES - 1U, false, false) ||
        !copy_string(c->proxy, config->proxy_name, 128, false, true)) { free(c); return EFRP_INVALID_ARGUMENT; }
    c->ca = malloc(config->ca_length);
    if (!c->ca) { free(c); return EFRP_NO_MEMORY; }
    if (xtcp_visitor) {
        c->xtcp_visitor = efrp_heap_calloc(sizeof *c->xtcp_visitor);
        checked = c->xtcp_visitor ? EFRP_OK : EFRP_NO_MEMORY;
        if (checked == EFRP_OK) {
            efrp_xtcp_config_t *settings = &c->xtcp_visitor->settings;
            settings->role = EFRP_XTCP_VISITOR; settings->proxy_name = c->proxy;
            if (!copy_string(c->xtcp_visitor->secret_key, xtcp_visitor->secret_key, 128, false, true)) checked = EFRP_INVALID_ARGUMENT;
            settings->secret_key = c->xtcp_visitor->secret_key;
            settings->options = xtcp_visitor->options;
            memcpy(settings->local_ipv4, xtcp_visitor->bind_ipv4, 4); settings->local_port = xtcp_visitor->bind_port;
            settings->time_is_trusted = config->time_is_trusted; settings->context = config->context;
        }
    } else if (visitor) {
        c->visitor = efrp_heap_calloc(sizeof *c->visitor);
        checked = c->visitor ? efrp_stcp_visitor_owned_clone(visitor->server_proxy_name,
            visitor->secret_key, &c->visitor->owner) : EFRP_NO_MEMORY;
        if (checked == EFRP_OK) {
            c->visitor->settings.server_proxy_name = efrp_stcp_visitor_owned_proxy_name(c->visitor->owner);
            c->visitor->settings.secret_key = efrp_stcp_visitor_owned_secret_key(c->visitor->owner);
            memcpy(c->visitor->settings.bind_ipv4, visitor->bind_ipv4, sizeof visitor->bind_ipv4);
            c->visitor->settings.bind_port = visitor->bind_port;
        }
    } else checked = efrp_proxy_owned_clone(config->proxy_type, config->proxy_options, &c->proxy_options);
    if (checked != EFRP_OK) { destroy_xtcp_visitor(&c->xtcp_visitor); destroy_visitor(&c->visitor); efrp_crypto_zero(c->ca, config->ca_length); free(c->ca); efrp_crypto_zero(c, sizeof *c); free(c); return checked; }
    memcpy(c->ca, config->ca_pem, config->ca_length); memcpy(c->token, config->token, config->token_length);
    c->config = *config;
    c->flash_store = *config->flash_store;
    c->config.server_hostname = c->server; c->config.hostname = c->hostname; c->config.user = c->user;
    c->config.client_id = c->client_id; c->config.proxy_name = c->proxy; c->config.token = c->token; c->config.ca_pem = c->ca;
    c->config.run_id = c->requested_run_id;
    c->config.flash_store = &c->flash_store;
    c->config.proxy_options = efrp_proxy_owned_options(c->proxy_options);
    if (xtcp_visitor) c->config.xtcp_options = &c->xtcp_visitor->settings.options;
    else if (config->proxy_type == EFRP_PROXY_XTCP) { c->xtcp_options = *config->xtcp_options; c->config.xtcp_options = &c->xtcp_options; }
    else c->config.xtcp_options = NULL;
    c->current.phase = EFRP_PHASE_STOPPED; c->current.tls_verify_flags = UINT32_MAX; c->snapshot = c->current;
    efrp_result_t result = efrp_port_create(&c->port);
    if (result == EFRP_OK) result = efrp_port_launch(c->port, worker, c);
    if (result != EFRP_OK) {
        efrp_port_destroy(c->port); efrp_crypto_zero(c->ca, config->ca_length); free(c->ca);
        efrp_proxy_owned_destroy(&c->proxy_options);
        destroy_visitor(&c->visitor);
        destroy_xtcp_visitor(&c->xtcp_visitor);
        efrp_crypto_zero(c, sizeof *c); free(c); return result;
    }
    *out = c; return EFRP_OK;
}
efrp_result_t efrp_create(const efrp_config_t *config, efrp_client_t **out)
{
    return create_client(config, NULL, NULL, out);
}
efrp_result_t efrp_stcp_visitor_create(const efrp_stcp_visitor_config_t *visitor, efrp_client_t **out)
{
    if (!visitor) return create_client(NULL, NULL, NULL, out);
    /* Only common login/transport fields cross this explicit assembly. The
     * role's bind/target/secret remain in its separate typed settings. */
    efrp_config_t common = {.server_hostname = visitor->server_hostname, .server_port = visitor->server_port,
        .transport = visitor->transport, .quic_profile = visitor->quic_profile,
        .ca_pem = visitor->ca_pem, .ca_length = visitor->ca_length,
        .token = visitor->token, .token_length = visitor->token_length,
        .hostname = visitor->hostname, .user = visitor->user, .client_id = visitor->client_id, .run_id = visitor->run_id,
        .proxy_name = visitor->server_proxy_name, .time_is_trusted = visitor->time_is_trusted,
        .flash_store = visitor->flash_store, .on_event = visitor->on_event, .context = visitor->context};
    return create_client(&common, visitor, NULL, out);
}
efrp_result_t efrp_xtcp_visitor_create(const efrp_xtcp_visitor_config_t *visitor, efrp_client_t **out)
{
    if (!visitor) return create_client(NULL, NULL, NULL, out);
    efrp_config_t common = {.server_hostname = visitor->server_hostname, .server_port = visitor->server_port,
        .transport = visitor->transport, .quic_profile = visitor->quic_profile,
        .ca_pem = visitor->ca_pem, .ca_length = visitor->ca_length,
        .token = visitor->token, .token_length = visitor->token_length,
        .hostname = visitor->hostname, .user = visitor->user, .client_id = visitor->client_id, .run_id = visitor->run_id,
        .proxy_name = visitor->server_proxy_name, .proxy_type = EFRP_PROXY_XTCP, .xtcp_options = &visitor->options,
        .time_is_trusted = visitor->time_is_trusted, .flash_store = visitor->flash_store,
        .on_event = visitor->on_event, .context = visitor->context};
    return create_client(&common, NULL, visitor, out);
}
efrp_result_t efrp_start(efrp_client_t *c)
{
    if (!c) return EFRP_INVALID_ARGUMENT;
    if (efrp_port_is_worker(c->port)) return EFRP_INVALID_STATE;
    if (!efrp_port_api_lock(c->port)) return EFRP_WOULD_BLOCK;
    efrp_result_t result = EFRP_INVALID_STATE;
    if (!c->requested && !c->stop_ticket) {
        result = efrp_port_send(c->port, (efrp_command_t){EFRP_COMMAND_START, 0}) ? EFRP_OK : EFRP_CAPACITY_EXCEEDED;
        if (result == EFRP_OK) c->requested = true;
    }
    efrp_port_api_unlock(c->port); return result;
}
static efrp_result_t stop_locked(efrp_client_t *c, uint32_t timeout)
{
    if (!c->requested && !c->stop_ticket) return EFRP_OK;
    if (!c->stop_ticket) {
        if (c->next_ticket == UINT64_MAX) return EFRP_COUNTER_EXHAUSTED;
        uint64_t ticket = c->next_ticket + 1;
        if (!efrp_port_send(c->port, (efrp_command_t){EFRP_COMMAND_STOP, ticket})) return EFRP_CAPACITY_EXCEEDED;
        c->stop_ticket = c->next_ticket = ticket; c->requested = false;
    }
    uint64_t end = efrp_port_now_ms() + timeout;
    for (;;) {
        efrp_port_status_lock(c->port); bool done = c->completed_ticket == c->stop_ticket;
        efrp_port_status_unlock(c->port);
        if (done) { c->stop_ticket = 0; return EFRP_OK; }
        if (!timeout) return EFRP_WOULD_BLOCK;
        uint64_t now = efrp_port_now_ms(); if (now >= end) return EFRP_TIMEOUT;
        efrp_port_wait(c->port, (uint32_t)(end - now));
    }
}
efrp_result_t efrp_stop(efrp_client_t *c, uint32_t timeout)
{
    if (!c) return EFRP_INVALID_ARGUMENT;
    if (efrp_port_is_worker(c->port)) return EFRP_INVALID_STATE;
    if (!efrp_port_api_lock(c->port)) return EFRP_WOULD_BLOCK;
    efrp_result_t result = stop_locked(c, timeout); efrp_port_api_unlock(c->port); return result;
}
efrp_result_t efrp_destroy(efrp_client_t **out, uint32_t timeout)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (!*out) return EFRP_OK;
    efrp_client_t *c = *out;
    if (efrp_port_is_worker(c->port)) return EFRP_INVALID_STATE;
    if (!efrp_port_api_lock(c->port)) return EFRP_WOULD_BLOCK;
    efrp_result_t result = stop_locked(c, timeout);
    if (result == EFRP_OK && !efrp_port_send(c->port, (efrp_command_t){EFRP_COMMAND_EXIT, 0})) result = EFRP_CAPACITY_EXCEEDED;
    efrp_port_api_unlock(c->port);
    if (result != EFRP_OK) return result;
    efrp_port_destroy(c->port); efrp_crypto_zero(c->ca, c->config.ca_length); free(c->ca);
    efrp_proxy_owned_destroy(&c->proxy_options);
    destroy_visitor(&c->visitor);
    destroy_xtcp_visitor(&c->xtcp_visitor);
    efrp_crypto_zero(c, sizeof *c); free(c); *out = NULL; return EFRP_OK;
}
efrp_result_t efrp_get_status(efrp_client_t *c, efrp_status_t *status)
{
    if (!c || !status) return EFRP_INVALID_ARGUMENT;
    efrp_port_status_lock(c->port); *status = c->snapshot; efrp_port_status_unlock(c->port); return EFRP_OK;
}

efrp_result_t efrp_get_remote_address(efrp_client_t *c, char *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (output && capacity) output[0] = 0;
    if (!c || !length || (!output && capacity)) return EFRP_INVALID_ARGUMENT;
    efrp_port_status_lock(c->port);
    *length = c->remote_address_length;
    efrp_result_t result = EFRP_CAPACITY_EXCEEDED;
    if (capacity > *length) {
        if (*length) memcpy(output, c->remote_address, *length);
        output[*length] = 0; result = EFRP_OK;
    }
    efrp_port_status_unlock(c->port); return result;
}
