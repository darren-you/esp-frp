// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EFRP_WIRE_MAX_PAYLOAD 65536u
#define EFRP_WIRE_HEADER_SIZE 8u
#define EFRP_WIRE_MAGIC_SIZE 7u

typedef enum {
    EFRP_OK = 0,
    EFRP_INVALID_ARGUMENT = -1,
    EFRP_PROTOCOL_ERROR = -2,
    EFRP_CAPACITY_EXCEEDED = -3,
    EFRP_CALLBACK_REJECTED = -4,
    EFRP_TRUNCATED = -5
} efrp_result_t;

typedef enum {
    EFRP_CLIENT_HELLO = 1,
    EFRP_SERVER_HELLO = 2,
    EFRP_MESSAGE = 16
} efrp_frame_kind_t;

/* Payload belongs to the caller-provided parser buffer and is valid only during
 * this synchronous callback. Copy before returning if it must outlive it.
 * Returning false permanently fails this parser; reconnect and reinitialize. */
typedef bool (*efrp_frame_handler_t)(void *context, efrp_frame_kind_t kind,
                                     const uint8_t *payload, size_t length);

typedef struct {
    uint8_t header[EFRP_WIRE_HEADER_SIZE];
    uint8_t *payload;
    size_t capacity;
    size_t header_used;
    size_t payload_used;
    size_t payload_expected;
    size_t magic_used;
    bool expect_magic;
    efrp_result_t failure;
    efrp_frame_kind_t kind;
    efrp_frame_handler_t handler;
    void *context;
} efrp_wire_reader_t;

extern const uint8_t efrp_wire_magic[EFRP_WIRE_MAGIC_SIZE];

/* All storage is borrowed for the lifetime of the reader. No allocation and no
 * retained input pointer. One owner/task only; callbacks must not re-enter it. */
efrp_result_t efrp_wire_init(efrp_wire_reader_t *reader, uint8_t *storage,
                            size_t capacity, bool expect_magic,
                            efrp_frame_handler_t handler, void *context);
efrp_result_t efrp_wire_feed(efrp_wire_reader_t *reader, const uint8_t *bytes,
                            size_t length, size_t *consumed);
efrp_result_t efrp_wire_finish(const efrp_wire_reader_t *reader);
efrp_result_t efrp_wire_header(efrp_frame_kind_t kind, size_t payload_length,
                              uint8_t output[EFRP_WIRE_HEADER_SIZE]);

#ifdef __cplusplus
}
#endif
