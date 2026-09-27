// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef uint8_t esp_partition_type_t;
typedef uint8_t esp_partition_subtype_t;
#define ESP_PARTITION_TYPE_DATA ((esp_partition_type_t)0x01)
#define ESP_PARTITION_SUBTYPE_DATA_UNDEFINED ((esp_partition_subtype_t)0x06)
typedef struct {
    esp_partition_type_t type;
    esp_partition_subtype_t subtype;
    uint32_t address, size;
    char label[17];
    bool encrypted, readonly;
    uint32_t erase_size;
} esp_partition_t;
const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
    esp_partition_subtype_t subtype, const char *label);
esp_err_t esp_partition_erase_range(const esp_partition_t *partition,
    size_t offset, size_t size);
esp_err_t esp_partition_write(const esp_partition_t *partition,
    size_t offset, const void *source, size_t size);
esp_err_t esp_partition_read(const esp_partition_t *partition,
    size_t offset, void *destination, size_t size);
