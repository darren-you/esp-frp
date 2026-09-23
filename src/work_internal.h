// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_session.h"
#include "esp_frp_connect.h"
#include "esp_frp_yamux.h"

typedef enum { EFRP_WORK_UNUSED, EFRP_WORK_SENDING, EFRP_WORK_WAITING,
    EFRP_WORK_CONNECTING, EFRP_WORK_ACTIVE, EFRP_WORK_CLOSING } efrp_work_phase_t;
typedef struct {
    efrp_work_phase_t phase;
    uint32_t stream_id;
    efrp_connect_t *local;
    efrp_wire_reader_t reader;
    const char *proxy_name;
    uint8_t incoming[1024], outgoing[1024];
    size_t incoming_used, incoming_offset, outgoing_used, outgoing_offset;
    uint64_t deadline, last_activity, incoming_progress, outgoing_progress, fin_progress;
    efrp_result_t result;
    bool started, partial_header, remote_eof, local_eof, local_fin, mux_fin;
} efrp_work_stream_t;
typedef struct {
    efrp_work_stream_t streams[3];
    /* Only one stream can be SENDING/WAITING. Allocate its full 4 KiB parser
     * workspace on first input, then release it after StartWorkConn or abort.
     * A healthy pooled spare does not retain an unused parser buffer. */
    uint8_t *handshake_json;
    efrp_work_status_t status;
    unsigned cursor;
    uint8_t address[4];
    uint16_t port;
    const char *proxy_name;
} efrp_work_set_t;
void efrp_work_init(efrp_work_set_t *work, const efrp_session_config_t *config, const char *proxy_name);
void efrp_work_request(efrp_work_set_t *work);
efrp_result_t efrp_work_step(efrp_work_set_t *work, efrp_yamux_t *mux, uint64_t now,
    const char *run_id, const uint8_t *token, size_t token_length, int64_t seconds);
bool efrp_work_cancel(efrp_work_set_t *work);
void efrp_work_status(const efrp_work_set_t *work, efrp_work_status_t *status);
