// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef enum { FIXTURE_DNS_READY, FIXTURE_DNS_PENDING, FIXTURE_DNS_FAIL, FIXTURE_DNS_NO_MEMORY } fixture_dns_mode_t;
void fixture_dns_mode(fixture_dns_mode_t mode);
/* Explicit test-network input; set before starting any DNS request. */
void fixture_dns_address(const uint8_t address[4]);
void fixture_dns_complete(bool success);
unsigned fixture_dns_active(void);
