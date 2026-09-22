// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef ESP_PLATFORM
#include "cJSON.h"
#else
#include <cjson/cJSON.h>
#endif
#define EFRP_JSON_MAX_BYTES 4096u
bool efrp_json_utf8(const uint8_t *bytes, size_t length);
cJSON *efrp_json_parse(const uint8_t *bytes, size_t length);
bool efrp_json_shape(const cJSON *object, const char *const *allowed, size_t count);
const cJSON *efrp_json_field(const cJSON *object, const char *name);
const char *efrp_json_string(const cJSON *object, const char *name);
bool efrp_json_equals(const cJSON *object, const char *name, const char *expected);
