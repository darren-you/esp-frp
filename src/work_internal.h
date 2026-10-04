// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_session.h"
#include "esp_frp_connect.h"
#include "stream_internal.h"
#include "stcp_visitor_internal.h"
#include "esp_frp_xtcp_binding.h"

#define EFRP_WORK_IO_STALL_MS UINT64_C(2500)
#define EFRP_WORK_CLEANUP_MS UINT64_C(5000)

typedef struct efrp_udp_work efrp_udp_work_t;
typedef struct efrp_visit_work efrp_visit_work_t;

typedef enum { EFRP_WORK_UNUSED, EFRP_WORK_SENDING, EFRP_WORK_WAITING,
    EFRP_WORK_CONNECTING, EFRP_WORK_ACTIVE, EFRP_WORK_CLOSING, EFRP_WORK_PEER_OPENING } efrp_work_phase_t;
typedef struct {
    efrp_work_phase_t phase;
    efrp_stream_id_t stream_id;
    efrp_connect_t *local;
    efrp_udp_work_t *udp;
    efrp_wire_reader_t reader;
    const char *proxy_name;
    uint8_t incoming[1024], outgoing[1024];
    size_t incoming_used, incoming_offset, outgoing_used, outgoing_offset;
    uint64_t deadline, last_activity, incoming_progress, outgoing_progress, fin_progress;
    efrp_result_t result;
    bool started, partial_header, remote_eof, local_eof, local_fin, stream_fin;
} efrp_work_stream_t;
typedef struct {
    /* A work stream owns two 1 KiB transfer buffers. Keep each of the three
     * slots empty until a ReqWorkConn actually opens that stream. */
    efrp_work_stream_t *streams[3];
    /* Only one stream can be SENDING/WAITING. Allocate its full 4 KiB parser
     * workspace on first input, then release it after StartWorkConn or abort.
     * A healthy pooled spare does not retain an unused parser buffer. */
    uint8_t *handshake_json;
    efrp_work_status_t status;
    unsigned cursor;
    uint8_t address[4];
    uint16_t port;
    efrp_proxy_type_t proxy_type;
    uint16_t udp_packet_size;
    const char *proxy_name;
    /* Visitor-only state; provider groups retain no listener allocation. */
    efrp_visit_work_t *visitor;
    efrp_xtcp_role_t peer_role; /* zero for ordinary FRPS work/visitor groups */
} efrp_work_set_t;
void efrp_work_init(efrp_work_set_t *work, const efrp_session_config_t *config, const char *proxy_name);
efrp_result_t efrp_work_visit_init(efrp_work_set_t *work, const efrp_stcp_visitor_settings_t *settings);
efrp_result_t efrp_work_visit_start(efrp_work_set_t *work);
efrp_result_t efrp_work_visit_step(efrp_work_set_t *work, efrp_transport_t *transport, uint64_t now,
    const char *run_id, int64_t seconds);
void efrp_work_request(efrp_work_set_t *work);
efrp_result_t efrp_work_step(efrp_work_set_t *work, efrp_transport_t *transport, uint64_t now,
    const char *run_id, const uint8_t *token, size_t token_length, int64_t seconds);
bool efrp_work_cancel(efrp_work_set_t *work);
void efrp_work_status(const efrp_work_set_t *work, efrp_work_status_t *status);
/* Private XTCP data assembly, invoked only after mutual TLS and both reserved
 * stream proofs pass. No FRP framing/Token/secret is sent on peer business
 * streams. Provider connects its fixed target; visitor takes an already
 * accepted local socket, retaining it if native stream credit blocks. */
efrp_result_t efrp_work_peer_init(efrp_work_set_t *work, efrp_xtcp_role_t role,
    const uint8_t local_ipv4[4], uint16_t local_port);
efrp_result_t efrp_work_peer_adopt(efrp_work_set_t *work, efrp_connect_t **local,
    uint64_t now_ms);
efrp_result_t efrp_work_peer_step(efrp_work_set_t *work, efrp_transport_t *transport,
    uint64_t now_ms);
