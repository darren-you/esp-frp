// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "dns.h"
typedef void (*tcpip_callback_fn)(void *);
err_t tcpip_try_callback(tcpip_callback_fn, void *);
