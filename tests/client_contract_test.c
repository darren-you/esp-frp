// SPDX-License-Identifier: Apache-2.0
#include "esp_frp.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { void *p; size_t n; unsigned call; } block_t;
static block_t blocks[4];
static unsigned calls, fail_at, live;
static bool verify_zero;
void *fixture_client_malloc(size_t n)
{
    if (++calls == fail_at) return NULL;
    void *p = malloc(n); assert(p);
    for (unsigned i = 0; i < 4; ++i) if (!blocks[i].p) { blocks[i] = (block_t){p, n, calls}; ++live; return p; }
    abort();
}
void *fixture_client_calloc(size_t count, size_t n)
{
    assert(!count || n <= SIZE_MAX / count);
    void *p = fixture_client_malloc(count * n); if (p) memset(p, 0, count * n); return p;
}
void fixture_client_free(void *p)
{
    if (!p) return;
    for (unsigned i = 0; i < 4; ++i) if (blocks[i].p == p) {
        if (verify_zero && calls >= 3 && blocks[i].call <= 2)
            for (size_t j = 0; j < blocks[i].n; ++j) assert(((uint8_t *)p)[j] == 0);
        blocks[i].p = NULL; --live; free(p); return;
    }
    abort();
}
static bool trusted(void *context) { (void)context; return true; }
int main(void)
{
    const uint8_t ca[] = "public placeholder PEM parsed only on start", token[] = "public-test-token";
    efrp_config_t good = {.server_hostname = "frp.fixture.invalid", .server_port = 1234,
        .ca_pem = ca, .ca_length = sizeof ca - 1, .token = token, .token_length = sizeof token - 1,
        .proxy_name = "fixture-contract", .local_ipv4 = {127, 0, 0, 1}, .local_port = 1, .time_is_trusted = trusted};
    efrp_client_t *c = NULL;
    assert(efrp_create(NULL, &c) == EFRP_INVALID_ARGUMENT && !c);
    assert(efrp_create(&good, NULL) == EFRP_INVALID_ARGUMENT);
    char long_name[255]; memset(long_name, 'x', sizeof long_name - 1); long_name[254] = 0;
    for (unsigned test = 0; test < 16; ++test) {
        efrp_config_t bad = good;
        switch (test) {
        case 0: bad.server_hostname = long_name; break;
        case 1: bad.server_hostname = "https://fixture.invalid"; break;
        case 2: bad.server_port = 0; break;
        case 3: bad.ca_length = 0; break;
        case 4: bad.ca_length = EFRP_TLS_MAX_CA_BYTES + 1; break;
        case 5: bad.ca_length = sizeof ca; break;
        case 6: bad.token_length = 0; break;
        case 7: bad.token_length = EFRP_AEAD_MAX_TOKEN_BYTES + 1; break;
        case 8: bad.proxy_name = ""; break;
        case 9: bad.proxy_name = "\xc0\xaf"; break;
        case 10: bad.hostname = long_name; break;
        case 11: bad.local_ipv4[0] = 224; break;
        case 12: bad.local_port = 0; break;
        case 13: bad.time_is_trusted = NULL; break;
        case 14: bad.previous_run_id = long_name; break;
        case 15: bad.previous_run_id = "\xc0\xaf"; break;
        }
        assert(efrp_create(&bad, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
    }
    verify_zero = true;
    for (unsigned index = 1; index <= 4; ++index) {
        calls = 0; fail_at = index;
        efrp_result_t result = efrp_create(&good, &c);
        if (index <= 3) assert(result == EFRP_NO_MEMORY && !c);
        else { assert(result == EFRP_OK && c); assert(efrp_destroy(&c, 1000) == EFRP_OK && !c); }
        assert(!live);
    }
    puts("Client config boundaries, three allocation failures, rollback and copied-secret zeroization passed");
}
