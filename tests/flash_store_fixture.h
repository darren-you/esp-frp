// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_flash_reader.h"

typedef struct {
    uint8_t bytes[EFRP_AEAD_MAX_PLAINTEXT];
    uint64_t generation, lease;
    unsigned begins, clears;
    bool recovered, busy, quarantined, fail_clear;
} efrp_test_flash_t;

/* Host-only fake Flash. Each executable owns its instance; never shipped as an
 * ESP component or sample provider. Caller must recover before a session. */
efrp_aead_flash_store_t efrp_test_flash_store(efrp_test_flash_t *flash);
