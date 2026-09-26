// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>
#include <stdint.h>

/* The backing pointer may permit only aligned 32-bit loads and stores. Keep
 * every access volatile so the compiler cannot narrow it to a byte access.
 * Byte order here is logical; no byte view of the backing memory is used. */
static inline void efrp_words_zero(void *storage, size_t length)
{
    volatile uint32_t *words = storage;
    for (size_t i = 0; i < (length + 3u) / 4u; ++i) words[i] = 0;
}

static inline void efrp_words_store(void *storage, size_t offset, const uint8_t *bytes, size_t length)
{
    volatile uint32_t *words = storage;
    for (size_t i = 0; i < length; ++i, ++offset) {
        const size_t index = offset / 4u;
        const unsigned shift = (unsigned)(offset % 4u) * 8u;
        uint32_t word = words[index];
        word = (word & ~(UINT32_C(0xff) << shift)) | ((uint32_t)bytes[i] << shift);
        words[index] = word;
    }
}

static inline void efrp_words_load(const void *storage, size_t offset, uint8_t *bytes, size_t length)
{
    const volatile uint32_t *words = storage;
    for (size_t i = 0; i < length; ++i, ++offset)
        bytes[i] = (uint8_t)(words[offset / 4u] >> ((unsigned)(offset % 4u) * 8u));
}

static inline void efrp_words_clear(void *storage, size_t offset, size_t length)
{
    volatile uint32_t *words = storage;
    for (size_t i = 0; i < length; ++i, ++offset) {
        const size_t index = offset / 4u;
        const unsigned shift = (unsigned)(offset % 4u) * 8u;
        words[index] = words[index] & ~(UINT32_C(0xff) << shift);
    }
}
