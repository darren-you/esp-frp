// SPDX-License-Identifier: Apache-2.0
#include "json_internal.h"
#include "work_internal.h"
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct { void *pointer; size_t size; } allocation_t;
static allocation_t live[4];
static unsigned allocations, releases;
static bool fail_next_stream;

void fixture_work_fail_next_stream(void) { fail_next_stream = true; }

void *fixture_work_calloc(size_t count, size_t size)
{
    assert(count == 1 && (size == EFRP_JSON_MAX_BYTES || size == sizeof(efrp_work_stream_t)));
    if (fail_next_stream && size == sizeof(efrp_work_stream_t)) {
        fail_next_stream = false; return NULL;
    }
    for (unsigned i = 0; i < 4; ++i) if (!live[i].pointer) {
        void *pointer = calloc(count, size);
        assert(pointer); live[i] = (allocation_t){pointer, size};
        ++allocations; return pointer;
    }
    assert(false); return NULL;
}

void fixture_work_free(void *pointer)
{
    assert(pointer);
    for (unsigned slot = 0; slot < 4; ++slot) if (live[slot].pointer == pointer) {
        for (size_t i = 0; i < live[slot].size; ++i)
            assert(((const uint8_t *)pointer)[i] == 0);
        live[slot] = (allocation_t){0};
        ++releases; free(pointer); return;
    }
    assert(false);
}

void fixture_work_released(void)
{
    for (unsigned i = 0; i < 4; ++i) assert(!live[i].pointer);
    assert(!fail_next_stream && allocations && allocations == releases);
}
