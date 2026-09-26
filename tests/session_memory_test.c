// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_session.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
/* session.c passes this allocator to the chunked reader. TLS and crypto remain real. */
static struct { void *pointer; size_t bytes; } blocks[3 + EFRP_AEAD_RX_MAX_CHUNKS];
static unsigned calls, fail_at, live;
void *fixture_session_calloc(size_t count, size_t bytes)
{
    assert(!count || bytes <= SIZE_MAX / count);
    assert(count * bytes != EFRP_AEAD_RX_BYTES);
    if (++calls == fail_at) return NULL;
    void *pointer = calloc(count, bytes); assert(pointer);
    for (unsigned i=0;i<3 + EFRP_AEAD_RX_MAX_CHUNKS;++i) if (!blocks[i].pointer) {
        blocks[i].pointer=pointer; blocks[i].bytes=count*bytes; ++live; return pointer;
    }
    abort();
}
void fixture_session_free(void *pointer)
{
    if (!pointer) return;
    for (unsigned i=0;i<3 + EFRP_AEAD_RX_MAX_CHUNKS;++i) if (blocks[i].pointer == pointer) {
        for (size_t j=0;j<blocks[i].bytes;++j) assert(((const uint8_t *)pointer)[j] == 0);
        blocks[i].pointer=NULL; --live; free(pointer); return;
    }
    abort();
}
void fixture_session_check(const efrp_session_config_t *config, efrp_tls_t *tls, uint64_t now)
{
    assert(!live);
    for (unsigned i=1;i<=3;++i) {
        calls=0; fail_at=i; efrp_session_t *session=NULL;
        assert(efrp_session_create(config,tls,now,&session) == EFRP_NO_MEMORY && !session);
        assert(calls==i && !live);
    }
    calls=fail_at=0;
    efrp_session_config_t bad=*config; bad.login.token_length=0;
    efrp_session_t *session=NULL;
    assert(efrp_session_create(&bad,tls,now,&session) == EFRP_INVALID_ARGUMENT && !session);
    assert(calls==3 && !live);
}
void fixture_session_released(void) { assert(!live); }
