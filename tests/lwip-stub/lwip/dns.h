// SPDX-License-Identifier: Apache-2.0
/* Test-only API fixture; not an lwIP implementation or firmware dependency. */
#pragma once
#include <stdint.h>
typedef int err_t;
enum { ERR_OK = 0, ERR_MEM = -1, ERR_VAL = -6, ERR_ABRT = -13, ERR_INPROGRESS = -5 };
typedef struct { uint32_t addr; unsigned type; } ip_addr_t;
#define IP_IS_V4(p) ((p)->type == 4)
#define ip_addr_isany(p) ((p)->addr == 0)
#define ip_2_ip4(p) (p)
#define ip4_addr_get_u32(p) ((p)->addr)
#define LWIP_DNS_ADDRTYPE_IPV4 0
typedef void (*dns_found_callback)(const char *, const ip_addr_t *, void *);
err_t dns_gethostbyname_addrtype(const char *, ip_addr_t *, dns_found_callback, void *, unsigned char);
