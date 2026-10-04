// SPDX-License-Identifier: Apache-2.0
#include "stream_backend.h"
#include <string.h>
efrp_result_t efrp_transport_step(efrp_transport_t *t, uint64_t now)
{ return t ? t->operations->step(t, now) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_transport_status(const efrp_transport_t *t, efrp_transport_status_t *status)
{ if (status) memset(status, 0, sizeof *status); return t && status ? t->operations->status(t, status) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_transport_cancel(efrp_transport_t *t)
{ return t ? t->operations->cancel(t) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_transport_destroy(efrp_transport_t **t)
{ return !t ? EFRP_INVALID_ARGUMENT : !*t ? EFRP_OK : (*t)->operations->destroy(t); }
efrp_result_t efrp_stream_open(efrp_transport_t *t, efrp_stream_id_t *id)
{ if (id) *id = EFRP_STREAM_NONE; return t && id ? t->operations->open(t, id) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_accept(efrp_transport_t *t, efrp_stream_id_t *id)
{ if (id) *id = EFRP_STREAM_NONE; return !t || !id ? EFRP_INVALID_ARGUMENT :
    t->operations->accept ? t->operations->accept(t, id) : EFRP_INVALID_STATE; }
efrp_result_t efrp_stream_info(const efrp_transport_t *t, efrp_stream_id_t id, efrp_stream_info_t *info)
{ if (info) memset(info, 0, sizeof *info); return t && info && id != EFRP_STREAM_NONE ? t->operations->info(t, id, info) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_write(efrp_transport_t *t, efrp_stream_id_t id, const uint8_t *p, size_t n, size_t *used)
{ if (used) *used = 0; return t && id != EFRP_STREAM_NONE && p && n && used ? t->operations->write(t, id, p, n, used) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_read(efrp_transport_t *t, efrp_stream_id_t id, uint8_t *p, size_t n, size_t *used)
{ if (used) *used = 0; return t && id != EFRP_STREAM_NONE && p && n && used ? t->operations->read(t, id, p, n, used) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_close_write(efrp_transport_t *t, efrp_stream_id_t id)
{ return t && id != EFRP_STREAM_NONE ? t->operations->close_write(t, id) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_reset(efrp_transport_t *t, efrp_stream_id_t id)
{ return t && id != EFRP_STREAM_NONE ? t->operations->reset(t, id) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_release(efrp_transport_t *t, efrp_stream_id_t id)
{ return t && id != EFRP_STREAM_NONE ? t->operations->release(t, id) : EFRP_INVALID_ARGUMENT; }
efrp_result_t efrp_stream_finish(const efrp_transport_t *t)
{ return t ? t->operations->finish(t) : EFRP_INVALID_ARGUMENT; }
