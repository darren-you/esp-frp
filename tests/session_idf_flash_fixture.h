// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "esp_frp_idf_flash_store.h"

/* Host-only ESP partition shim. The composed session still uses the real
 * IDF scratch provider and the official TLS/FRPS protocol fixtures. */
const efrp_aead_flash_store_t *efrp_session_idf_flash_prepare(void);
void efrp_session_idf_flash_check(const char *mode);
