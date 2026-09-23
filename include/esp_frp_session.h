// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_handshake.h"
#include "esp_frp_tls.h"
#ifdef __cplusplus
extern "C" {
#endif
#define EFRP_SESSION_HEARTBEAT_MS UINT64_C(15000)
#define EFRP_SESSION_RESPONSE_MS UINT64_C(10000)
#define EFRP_WORK_IDLE_MS UINT64_C(60000)
typedef struct efrp_session efrp_session_t;
typedef enum { EFRP_SESSION_AUTHENTICATING, EFRP_SESSION_REGISTERING,
    EFRP_SESSION_REGISTERED, EFRP_SESSION_FAILED, EFRP_SESSION_STOPPED } efrp_session_phase_t;
typedef struct {
    efrp_handshake_config_t login;
    const char *proxy_name; /* exact wire identity; caller supplies any user prefix */
    uint16_t remote_port; /* zero requests a server-allocated port */
    /* The single proxy's exact local allowlist entry; never taken from FRPS
     * StartWorkConn address metadata. IPv4 bytes and nonzero port are copied. */
    uint8_t local_ipv4[4];
    uint16_t local_port;
} efrp_session_config_t;
#if defined(EFRP_LAB_TIMEOUT_TRACE)
typedef enum {
    EFRP_WORK_TIMEOUT_NONE = 0, EFRP_WORK_TIMEOUT_HANDSHAKE_SEND,
    EFRP_WORK_TIMEOUT_HANDSHAKE_FRAME, EFRP_WORK_TIMEOUT_INCOMING_LOCAL,
    EFRP_WORK_TIMEOUT_OUTGOING_YAMUX, EFRP_WORK_TIMEOUT_LOCAL_FIN,
    EFRP_WORK_TIMEOUT_CLEANUP, EFRP_WORK_TIMEOUT_IDLE
} efrp_work_timeout_source_t;
#endif
typedef struct {
    uint64_t requests, completed, failed, rejected_requests;
    uint64_t local_sent, local_received;
    unsigned pending, waiting, active, cleaning;
    efrp_result_t last_error;
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    /* Lab-only snapshot of the last work timeout. No endpoint or payload. */
    efrp_work_timeout_source_t timeout_source;
    uint32_t timeout_stream_id, timeout_age_ms;
    uint16_t timeout_incoming_bytes, timeout_outgoing_bytes;
#endif
} efrp_work_status_t;
typedef struct {
    efrp_session_phase_t phase;
    efrp_result_t result;
    uint64_t pongs;
    efrp_work_status_t work;
    char run_id[EFRP_RUN_ID_BYTES];
    char remote_address[257];
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    /* Yamux source IDs match efrp_yamux_timeout_source_t. Control: 1 registration, 2 Pong. */
    unsigned mux_timeout_source, control_timeout_source;
    uint32_t mux_timeout_stream_id, mux_timeout_age_ms, mux_timeout_pending_bytes;
#endif
} efrp_session_status_t;
/* Composes Yamux + Hello/Login + control AEAD over an already OPEN strict TLS
 * handle. Inputs are copied; TLS is borrowed until destroy and is cancelled on
 * failure/stop. Destroy session before TLS. Creates no task/timer, owns at most
 * two local sockets plus one waiting work stream. REGISTERED means registration;
 * complete worker, reconnect and hardware verification remain separate. */
efrp_result_t efrp_session_create(const efrp_session_config_t *config, efrp_tls_t *tls,
                                  uint64_t now_ms, efrp_session_t **out);
/* Single owner; bounded I/O turns. Wall clock must remain trusted.
 * Heartbeats are always Token-authenticated, including when server scopes
 * do not require it. EOF/failure ends the session, never silently reconnects. */
efrp_result_t efrp_session_step(efrp_session_t *session, uint64_t now_ms, int64_t unix_seconds);
efrp_result_t efrp_session_status(const efrp_session_t *session, efrp_session_status_t *status);
efrp_result_t efrp_session_cancel(efrp_session_t *session);
/* WOULD_BLOCK retains *session while local socket cleanup must retry. Keep
 * stepping/destroying; only OK frees and nulls the handle. */
efrp_result_t efrp_session_destroy(efrp_session_t **session);
#ifdef __cplusplus
}
#endif
