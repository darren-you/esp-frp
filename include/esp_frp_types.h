// SPDX-License-Identifier: Apache-2.0
#pragma once

typedef enum {
    EFRP_OK = 0,
    EFRP_WOULD_BLOCK = 1,
    EFRP_EOF = 2,
    EFRP_INVALID_ARGUMENT = -1,
    EFRP_PROTOCOL_ERROR = -2,
    EFRP_CAPACITY_EXCEEDED = -3,
    EFRP_CALLBACK_REJECTED = -4,
    EFRP_TRUNCATED = -5,
    EFRP_INVALID_STATE = -6,
    EFRP_SESSION_CLOSED = -7,
    EFRP_STREAM_RESET = -8,
    EFRP_TIMEOUT = -9
} efrp_result_t;
