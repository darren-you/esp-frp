// SPDX-License-Identifier: Apache-2.0
/* Host test resolver only: no host DNS, production address or fallback. */
#include "dns_backend.h"
#include "dns_fixture.h"
#include <assert.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
struct efrp_dns_request { bool done, cancelled, success; };
static atomic_flag fixture_lock = ATOMIC_FLAG_INIT;
static void lock(void) { while (atomic_flag_test_and_set_explicit(&fixture_lock, memory_order_acquire)) {} }
static void unlock(void) { atomic_flag_clear_explicit(&fixture_lock, memory_order_release); }
static fixture_dns_mode_t mode;
static efrp_dns_request_t *pending;
void fixture_dns_mode(fixture_dns_mode_t value) { lock(); assert(!pending); mode = value; unlock(); }
void fixture_dns_complete(bool success) { lock(); assert(pending); pending->done = true; pending->success = success; unlock(); }
unsigned fixture_dns_active(void) { lock(); unsigned n = pending ? 1u : 0u; unlock(); return n; }
efrp_result_t efrp_dns_start(const char *host, efrp_dns_request_t **out)
{
    lock(); assert(out && !*out && !pending);
    assert(!strcmp(host, "frp.fixture.invalid") || !strcmp(host, "wrong.fixture.invalid"));
    if (mode == FIXTURE_DNS_NO_MEMORY) { unlock(); return EFRP_NO_MEMORY; }
    pending = calloc(1, sizeof *pending); if (!pending) { unlock(); return EFRP_NO_MEMORY; }
    pending->done = mode != FIXTURE_DNS_PENDING; pending->success = mode != FIXTURE_DNS_FAIL;
    *out = pending; unlock(); return EFRP_OK;
}
efrp_result_t efrp_dns_poll(efrp_dns_request_t *r, uint8_t address[4], int *error)
{
    lock(); assert(r == pending); *error = 0;
    if (!r->done) { unlock(); return EFRP_WOULD_BLOCK; }
    if (r->cancelled) { unlock(); return EFRP_CANCELLED; }
    if (!r->success) { *error = -1; unlock(); return EFRP_DNS_ERROR; }
    const uint8_t loopback[] = {127, 0, 0, 1}; memcpy(address, loopback, sizeof loopback); unlock(); return EFRP_OK;
}
void efrp_dns_cancel(efrp_dns_request_t *r) { lock(); assert(r == pending); r->cancelled = true; unlock(); }
efrp_result_t efrp_dns_destroy(efrp_dns_request_t **out)
{
    if (!*out) return EFRP_OK;
    lock();
    assert(*out == pending);
    if (!pending->done) { unlock(); return EFRP_WOULD_BLOCK; }
    free(pending); pending = NULL; *out = NULL; unlock(); return EFRP_OK;
}
