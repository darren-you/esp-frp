// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
void quic_fixture_dns_pending(bool pending);
void quic_fixture_dns_complete(void);
unsigned quic_fixture_dns_active(void);
