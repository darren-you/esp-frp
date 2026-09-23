// SPDX-License-Identifier: Apache-2.0
#include "json_internal.h"
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

static void *handshake_buffer;
static unsigned allocations, releases;

void *fixture_work_calloc(size_t count, size_t size)
{
    assert(!handshake_buffer && count == 1 && size == EFRP_JSON_MAX_BYTES);
    handshake_buffer = calloc(count, size);
    assert(handshake_buffer);
    ++allocations;
    return handshake_buffer;
}

void fixture_work_free(void *pointer)
{
    assert(pointer && pointer == handshake_buffer);
    for (size_t i = 0; i < EFRP_JSON_MAX_BYTES; ++i)
        assert(((const uint8_t *)pointer)[i] == 0);
    handshake_buffer = NULL;
    ++releases;
    free(pointer);
}

void fixture_work_released(void)
{
    assert(!handshake_buffer && allocations && allocations == releases);
}
