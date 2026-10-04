// SPDX-License-Identifier: Apache-2.0
/* Test-only deterministic loopback DNS; no production network lookup. */
#include "dns_backend.h"
#include "quic_dns_fixture.h"
#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <string.h>
struct efrp_dns_request { bool done, cancelled; };
static bool wait_for_completion;
static efrp_dns_request_t *active;
void quic_fixture_dns_pending(bool pending) { assert(!active); wait_for_completion = pending; }
void quic_fixture_dns_complete(void) { assert(active); active->done = true; }
unsigned quic_fixture_dns_active(void) { return active ? 1u : 0u; }
efrp_result_t efrp_dns_start(const char *hostname, efrp_dns_request_t **out)
{
    assert(out && !*out && !active);
    assert(!strcmp(hostname, "quic.example.test") || !strcmp(hostname, "different.example.test"));
    active = calloc(1, sizeof *active); if (!active) return EFRP_NO_MEMORY;
    active->done = !wait_for_completion; *out = active; return EFRP_OK;
}
efrp_result_t efrp_dns_poll(efrp_dns_request_t *request, uint8_t address[4], int *error)
{
    assert(request == active); *error = 0;
    if (!request->done) return EFRP_WOULD_BLOCK;
    if (request->cancelled) return EFRP_CANCELLED;
    const uint8_t loopback[] = {127, 0, 0, 1}; memcpy(address, loopback, sizeof loopback); return EFRP_OK;
}
void efrp_dns_cancel(efrp_dns_request_t *request) { assert(request == active); request->cancelled = true; }
efrp_result_t efrp_dns_destroy(efrp_dns_request_t **request)
{
    if (!*request) return EFRP_OK;
    assert(*request == active); if (!active->done) return EFRP_WOULD_BLOCK;
    free(active); active = NULL; *request = NULL; return EFRP_OK;
}
