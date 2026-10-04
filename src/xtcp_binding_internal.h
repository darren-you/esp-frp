// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "crypto_backend.h"
efrp_result_t efrp_xtcp_binding_hmac(const uint8_t *key, size_t key_length,
                                     const efrp_crypto_span_t *parts, size_t count,
                                     uint8_t output[32]);
