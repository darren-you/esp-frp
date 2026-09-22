// SPDX-License-Identifier: Apache-2.0
#include "dns_backend.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct efrp_dns_request {
    atomic_bool cancelled, done;
    efrp_result_t result;
    int error;
    uint8_t ipv4[4];
    char hostname[254];
};
static void complete(efrp_dns_request_t *r, const ip_addr_t *address, int error)
{
    r->error = error; r->result = EFRP_DNS_ERROR;
    if (address && IP_IS_V4(address) && !ip_addr_isany(address)) {
        uint32_t value = ip4_addr_get_u32(ip_2_ip4(address));
        memcpy(r->ipv4, &value, sizeof value); r->result = EFRP_OK;
    }
    /* Last access to r. The owner may free it after acquiring this flag. */
    atomic_store_explicit(&r->done, true, memory_order_release);
}
static void found(const char *name, const ip_addr_t *address, void *context)
{
    (void)name; complete(context, address, address ? ERR_OK : ERR_VAL);
}
static void dispatch(void *context)
{
    efrp_dns_request_t *r = context;
    if (atomic_load_explicit(&r->cancelled, memory_order_acquire)) {
        complete(r, NULL, ERR_ABRT); return;
    }
    ip_addr_t address;
    err_t result = dns_gethostbyname_addrtype(r->hostname, &address, found, r, LWIP_DNS_ADDRTYPE_IPV4);
    if (result == ERR_OK) complete(r, &address, 0);
    else if (result != ERR_INPROGRESS) complete(r, NULL, result);
}
efrp_result_t efrp_dns_start(const char *hostname, efrp_dns_request_t **out)
{
    if (!out || !hostname) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    size_t n = 0; while (n < 254 && hostname[n]) ++n;
    if (!n || n >= 254) return EFRP_INVALID_ARGUMENT;
    efrp_dns_request_t *r = calloc(1, sizeof *r); if (!r) return EFRP_NO_MEMORY;
    atomic_init(&r->cancelled, false); atomic_init(&r->done, false);
    memcpy(r->hostname, hostname, n + 1);
    err_t result = tcpip_try_callback(dispatch, r);
    if (result != ERR_OK) { free(r); return result == ERR_MEM ? EFRP_NO_MEMORY : EFRP_DNS_ERROR; }
    *out = r; return EFRP_OK;
}
efrp_result_t efrp_dns_poll(efrp_dns_request_t *r, uint8_t ipv4[4], int *error)
{
    if (!r || !ipv4 || !error) return EFRP_INVALID_ARGUMENT;
    *error = 0;
    if (!atomic_load_explicit(&r->done, memory_order_acquire)) return EFRP_WOULD_BLOCK;
    *error = r->error;
    if (atomic_load_explicit(&r->cancelled, memory_order_relaxed)) return EFRP_CANCELLED;
    if (r->result == EFRP_OK) memcpy(ipv4, r->ipv4, sizeof r->ipv4);
    return r->result;
}
void efrp_dns_cancel(efrp_dns_request_t *r)
{
    if (r) atomic_store_explicit(&r->cancelled, true, memory_order_release);
}
efrp_result_t efrp_dns_destroy(efrp_dns_request_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (!*out) return EFRP_OK;
    efrp_dns_request_t *r = *out;
    if (!atomic_load_explicit(&r->done, memory_order_acquire)) return EFRP_WOULD_BLOCK;
    free(r); *out = NULL; return EFRP_OK;
}
