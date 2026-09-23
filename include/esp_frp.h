// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_session.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct efrp_client efrp_client_t;
typedef enum {
    EFRP_PHASE_STOPPED, EFRP_PHASE_CONNECTING, EFRP_PHASE_TLS_HANDSHAKING,
    EFRP_PHASE_AUTHENTICATING, EFRP_PHASE_REGISTERING, EFRP_PHASE_READY,
    EFRP_PHASE_DRAINING, EFRP_PHASE_BACKOFF, EFRP_PHASE_FAILED
} efrp_phase_t;
typedef struct {
    efrp_phase_t phase, failure_phase;
    efrp_result_t error;
    uint64_t attempts, ready_sessions, retries, pongs;
    uint64_t retry_at_ms; /* monotonic deadline, zero outside BACKOFF */
    uint32_t retry_delay_ms;
    int system_error, tls_error;
    uint32_t tls_verify_flags;
    efrp_work_status_t work; /* counters across attempts, gauges for this attempt */
    char run_id[EFRP_RUN_ID_BYTES], remote_address[257];
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    unsigned mux_timeout_source, control_timeout_source;
    uint32_t mux_timeout_stream_id, mux_timeout_age_ms, mux_timeout_pending_bytes;
#endif
} efrp_status_t;
/* Called on the sole worker, outside the status lock. Payload is borrowed only
 * during the callback. Keep callbacks short; get_status is allowed, lifecycle
 * APIs return INVALID_STATE here. Context remains borrowed until destroy. */
typedef void (*efrp_event_t)(void *context, const efrp_status_t *status);
/* Must report whether the actual system wall clock remains synchronized.
 * Called by the worker; no blocking, mutation of the client or lifecycle calls. */
typedef bool (*efrp_time_trusted_t)(void *context);
typedef struct {
    const char *server_hostname; /* one DNS/TLS identity, <=253 ASCII bytes */
    uint16_t server_port;
    const uint8_t *ca_pem; size_t ca_length;
    const uint8_t *token; size_t token_length;
    const char *hostname, *user, *client_id; /* optional UTF-8, <=128 bytes each */
    /* Optional previously verified status.run_id, copied at create. Lets an
     * owner explicitly replace its instance without racing server retirement.
     * This is not a credential: strict TLS and Token login always run again. */
    const char *previous_run_id;
    const char *proxy_name; /* required, exact wire identity, <=128 UTF-8 bytes */
    uint16_t remote_port;
    uint8_t local_ipv4[4]; uint16_t local_port; /* sole fixed allowlist entry */
    efrp_time_trusted_t time_is_trusted;
    efrp_event_t on_event;
    void *context;
} efrp_config_t;
/* Deep-copies every byte/string; creates one idle worker and a bounded command
 * queue, no network I/O yet. Initialize esp_netif/lwIP before start. CA parsing
 * and actual trust are checked by the worker before sending FRP credentials. */
efrp_result_t efrp_create(const efrp_config_t *config, efrp_client_t **out);
/* Accepted is not READY. A started/failed client must be stopped before start.
 * Lifecycle calls are serialized internally; a concurrent call returns
 * WOULD_BLOCK. Destruction/lifetime must still be externally serialized with
 * every caller, including get_status. No config mutation API: stop/destroy/create. */
efrp_result_t efrp_start(efrp_client_t *client);
/* Requests cancellation and waits for all I/O and callbacks to finish. Zero
 * timeout polls (WOULD_BLOCK); a positive timeout returns TIMEOUT if unfinished.
 * The request remains in force and the handle must be retained on timeout.
 * Repeated stop resumes waiting. Only OK proves STOPPED; no callback follows
 * until another start. The single idle worker remains until destroy. */
efrp_result_t efrp_stop(efrp_client_t *client, uint32_t timeout_ms);
/* On OK joins the worker, clears copied secrets, frees and nulls *client.
 * On any other result retains it; never abandons SDK DNS or socket cleanup. */
efrp_result_t efrp_destroy(efrp_client_t **client, uint32_t timeout_ms);
efrp_result_t efrp_get_status(efrp_client_t *client, efrp_status_t *status);
#ifdef __cplusplus
}
#endif
