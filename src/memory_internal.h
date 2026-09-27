// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>
#include <stdlib.h>

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#if defined(CONFIG_IDF_TARGET_ESP32) && defined(CONFIG_ESP32_IRAM_AS_8BIT_ACCESSIBLE_MEMORY)
#include "esp_heap_caps.h"
#define EFRP_HAS_IRAM_8BIT 1
#endif
#endif

/* Reserve ordinary DRAM for TLS internals, sockets and the product runtime.
 * IDF's free() accepts pointers returned by heap_caps_calloc(). */
static inline void *efrp_heap_calloc(size_t size)
{
#ifdef EFRP_HAS_IRAM_8BIT
    return heap_caps_calloc(1, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_IRAM_8BIT);
#else
    return calloc(1, size);
#endif
}
