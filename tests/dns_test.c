// SPDX-License-Identifier: Apache-2.0
#include "dns_backend.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

static tcpip_callback_fn queued;
static void *queued_context;
static dns_found_callback completion;
static void *completion_context;
static err_t post_result, resolve_result;
static unsigned dispatches;
static ip_addr_t answer;
err_t tcpip_try_callback(tcpip_callback_fn function, void *context)
{
    if (post_result != ERR_OK) return post_result;
    assert(!queued); queued = function; queued_context = context; return ERR_OK;
}
err_t dns_gethostbyname_addrtype(const char *hostname, ip_addr_t *address,
    dns_found_callback callback, void *context, unsigned char family)
{
    assert(!strcmp(hostname, "frp.fixture.invalid") && family == LWIP_DNS_ADDRTYPE_IPV4);
    ++dispatches;
    if (resolve_result == ERR_OK) *address = answer;
    else if (resolve_result == ERR_INPROGRESS) { completion = callback; completion_context = context; }
    return resolve_result;
}
static void dispatch_one(void)
{
    assert(queued); tcpip_callback_fn function = queued; void *context = queued_context;
    queued = NULL; queued_context = NULL; function(context);
}
static void complete_one(const ip_addr_t *value)
{
    assert(completion); dns_found_callback function = completion; void *context = completion_context;
    completion = NULL; completion_context = NULL; function("frp.fixture.invalid", value, context);
}
static void *complete_thread(void *unused) { (void)unused; complete_one(&answer); return NULL; }
int main(void)
{
    const unsigned char expected[] = {127, 0, 0, 1}; memcpy(&answer.addr, expected, 4); answer.type = 4;
    uint8_t address[4] = {0}; int error; efrp_dns_request_t *r = NULL;
    post_result = ERR_MEM;
    assert(efrp_dns_start("frp.fixture.invalid", &r) == EFRP_NO_MEMORY && !r && !queued);
    post_result = ERR_OK; resolve_result = ERR_OK;
    assert(efrp_dns_start("frp.fixture.invalid", &r) == EFRP_OK);
    assert(efrp_dns_poll(r, address, &error) == EFRP_WOULD_BLOCK);
    assert(efrp_dns_destroy(&r) == EFRP_WOULD_BLOCK);
    efrp_dns_cancel(r); dispatch_one();
    assert(!dispatches && efrp_dns_poll(r, address, &error) == EFRP_CANCELLED);
    assert(efrp_dns_destroy(&r) == EFRP_OK && !r);
    char hostname[] = "frp.fixture.invalid";
    assert(efrp_dns_start(hostname, &r) == EFRP_OK); memset(hostname, 'x', sizeof hostname - 1); dispatch_one();
    assert(efrp_dns_poll(r, address, &error) == EFRP_OK && !memcmp(address, expected, 4));
    assert(efrp_dns_destroy(&r) == EFRP_OK);
    resolve_result = ERR_MEM;
    assert(efrp_dns_start("frp.fixture.invalid", &r) == EFRP_OK); dispatch_one();
    assert(efrp_dns_poll(r, address, &error) == EFRP_DNS_ERROR && error == ERR_MEM);
    assert(efrp_dns_destroy(&r) == EFRP_OK);
    resolve_result = ERR_INPROGRESS;
    for (unsigned variant = 0; variant < 4; ++variant) {
        assert(efrp_dns_start("frp.fixture.invalid", &r) == EFRP_OK); dispatch_one();
        assert(efrp_dns_poll(r, address, &error) == EFRP_WOULD_BLOCK);
        if (variant == 0) efrp_dns_cancel(r);
        assert(efrp_dns_destroy(&r) == EFRP_WOULD_BLOCK);
        ip_addr_t bad = answer;
        if (variant == 2) bad.type = 6;
        if (variant == 3) bad.addr = 0;
        complete_one(variant == 1 ? NULL : &bad);
        assert(efrp_dns_poll(r, address, &error) == (variant == 0 ? EFRP_CANCELLED : EFRP_DNS_ERROR));
        assert(efrp_dns_destroy(&r) == EFRP_OK && !r);
    }
    for (unsigned i = 0; i < 1000; ++i) {
        assert(efrp_dns_start("frp.fixture.invalid", &r) == EFRP_OK); dispatch_one();
        pthread_t thread; assert(pthread_create(&thread, NULL, complete_thread, NULL) == 0);
        efrp_dns_cancel(r);
        while (efrp_dns_poll(r, address, &error) == EFRP_WOULD_BLOCK) sched_yield();
        assert(efrp_dns_poll(r, address, &error) == EFRP_CANCELLED);
        /* Free before joining to exercise completion's last-access guarantee. */
        assert(efrp_dns_destroy(&r) == EFRP_OK && !r);
        assert(pthread_join(thread, NULL) == 0);
    }
    assert(efrp_dns_destroy(&r) == EFRP_OK && !queued && !completion);
    puts("lwIP DNS adapter: dispatch/cache/error/late result and 1000 cancel-completion races passed (API fixture)");
    return 0;
}
