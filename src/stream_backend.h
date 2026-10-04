// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "stream_internal.h"
typedef struct {
    efrp_result_t (*step)(efrp_transport_t *, uint64_t);
    efrp_result_t (*status)(const efrp_transport_t *, efrp_transport_status_t *);
    efrp_result_t (*open)(efrp_transport_t *, efrp_stream_id_t *);
    efrp_result_t (*accept)(efrp_transport_t *, efrp_stream_id_t *);
    efrp_result_t (*info)(const efrp_transport_t *, efrp_stream_id_t, efrp_stream_info_t *);
    efrp_result_t (*write)(efrp_transport_t *, efrp_stream_id_t, const uint8_t *, size_t, size_t *);
    efrp_result_t (*read)(efrp_transport_t *, efrp_stream_id_t, uint8_t *, size_t, size_t *);
    efrp_result_t (*close_write)(efrp_transport_t *, efrp_stream_id_t);
    efrp_result_t (*reset)(efrp_transport_t *, efrp_stream_id_t);
    efrp_result_t (*release)(efrp_transport_t *, efrp_stream_id_t);
    efrp_result_t (*finish)(const efrp_transport_t *);
    efrp_result_t (*cancel)(efrp_transport_t *);
    efrp_result_t (*destroy)(efrp_transport_t **);
} efrp_stream_operations_t;
struct efrp_transport { const efrp_stream_operations_t *operations; };
