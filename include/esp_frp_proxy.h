// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    EFRP_PROXY_TCP = 0, EFRP_PROXY_UDP = 1, EFRP_PROXY_STCP,
    EFRP_PROXY_HTTP, EFRP_PROXY_HTTPS, EFRP_PROXY_XTCP
} efrp_proxy_type_t;
#define EFRP_PROXY_SECRET_MAX_BYTES 128u
#define EFRP_PROXY_DOMAIN_MAX_BYTES 253u
#define EFRP_PROXY_DOMAIN_MAX_COUNT 4u
#define EFRP_PROXY_SUBDOMAIN_MAX_BYTES 63u
#define EFRP_PROXY_REGISTRATION_MAX_BYTES 1024u
/* Only STCP/XTCP accept secret_key; their visitor authorization uses the FRPS
 * default of the authenticated provider's user. Only HTTP/HTTPS accept domains
 * and subdomain. A domain is an ASCII DNS name (including A-labels), optionally
 * prefixed by "*."; subdomain is one DNS label. Inputs are borrowed here and
 * copied by client/session create. Empty strings mean no optional value.
 * Registration is bounded to 1024 bytes, including the wire v2 header and
 * cJSON printing headroom. Individually valid fields can exceed that combined
 * bound and are rejected before opening a connection. */
typedef struct {
    const char *secret_key;
    const char *const *custom_domains;
    size_t custom_domain_count;
    const char *subdomain;
} efrp_proxy_options_t;
#ifdef __cplusplus
}
#endif
