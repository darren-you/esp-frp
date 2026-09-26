// SPDX-License-Identifier: Apache-2.0
#include "work_internal.h"
#include <assert.h>
#include <string.h>

void *fixture_work_calloc(size_t count, size_t size);
void fixture_work_fail_next_stream(void);
void fixture_work_released(void);

int main(void)
{
    efrp_work_set_t work;
    efrp_session_config_t config = {.local_ipv4 = {127, 0, 0, 1}, .local_port = 1};
    efrp_work_init(&work, &config, "allocation-fixture");
    efrp_work_request(&work);
    efrp_yamux_t mux;
    efrp_yamux_init(&mux, 0);

    fixture_work_fail_next_stream();
    assert(efrp_work_step(&work, &mux, 1, "run", (const uint8_t *)"token", 5, 1) == EFRP_NO_MEMORY);
    assert(work.status.requests == 1 && work.status.pending == 1);
    for (unsigned i = 0; i < 3; ++i) assert(!work.streams[i]);

    for (unsigned i = 0; i < 3; ++i) {
        work.streams[i] = fixture_work_calloc(1, sizeof *work.streams[i]);
        assert(work.streams[i]);
        memset(work.streams[i]->incoming, 0xa5, sizeof work.streams[i]->incoming);
        memset(work.streams[i]->outgoing, 0x5a, sizeof work.streams[i]->outgoing);
    }
    assert(efrp_work_cancel(&work));
    assert(work.status.pending == 0);
    for (unsigned i = 0; i < 3; ++i) assert(!work.streams[i]);
    assert(efrp_work_cancel(&work));
    fixture_work_released();
    return 0;
}
