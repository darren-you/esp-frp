// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_connect.h"
/* Accept ownership only after verifying a connected IPv4 TCP socket and
 * configuring nonblocking, NODELAY and bounded cancellation. On failure the
 * caller still owns fd (socket options may have changed) and must close it.
 * Successful adoption performs no DNS or connect attempt. */
efrp_result_t efrp_connect_adopt_fd(int fd, uint64_t now_ms, efrp_connect_t **out);
