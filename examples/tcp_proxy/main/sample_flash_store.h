// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_flash_reader.h"
efrp_result_t sample_flash_store_init(void);
const efrp_aead_flash_store_t *sample_flash_store_callbacks(void);
