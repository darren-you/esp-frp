// SPDX-License-Identifier: Apache-2.0
// Lab-only, linked into a copied five-component Base image.
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_memory_utils.h"
#include "esp_frp_aead.h"

static const char *const TAG = "frp-iram-aead";
static const uint8_t s_key[EFRP_AEAD_KEY_BYTES] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};
static struct { void *pointer; size_t size; } s_blocks[EFRP_AEAD_RX_MAX_CHUNKS];
static unsigned s_allocated, s_released, s_rejected, s_wipe_errors, s_region_errors;
static unsigned s_before_8bit, s_min_8bit;

static unsigned heap_free(uint32_t caps) { return (unsigned)heap_caps_get_free_size(caps); }
static unsigned heap_largest(uint32_t caps) { return (unsigned)heap_caps_get_largest_free_block(caps); }
static unsigned free_8bit(void) { return heap_free(MALLOC_CAP_8BIT); }
static void *word_allocate(size_t count, size_t size)
{
    if (count != 1 || !size || size > EFRP_AEAD_RX_CHUNK_BYTES || size % 4u) return NULL;
    void *pointer = heap_caps_malloc(size, MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
    if (!pointer) { ++s_rejected; return NULL; }
    const uint8_t *last = (const uint8_t *)pointer + size - 1u;
    bool pure = esp_ptr_in_iram(pointer) && esp_ptr_in_iram(last) &&
        !esp_ptr_in_diram_iram(pointer) && !esp_ptr_in_diram_iram(last);
    bool byte_accessible = esp_ptr_byte_accessible(pointer) || esp_ptr_byte_accessible(last);
    unsigned current_8bit = free_8bit();
    if (current_8bit < s_min_8bit) s_min_8bit = current_8bit;
    ESP_LOGI(TAG, "alloc index=%u size=%u pointer=%p pure_iram=%d byte_accessible=%d free8=%u/%u exec32=%u/%u",
             s_allocated + 1u, (unsigned)size, pointer, pure, byte_accessible,
             current_8bit, heap_largest(MALLOC_CAP_8BIT),
             heap_free(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT),
             heap_largest(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT));
    if (!pure || byte_accessible || (uintptr_t)pointer % 4u || current_8bit != s_before_8bit) {
        ++s_region_errors; ++s_rejected; heap_caps_free(pointer); return NULL;
    }
    for (size_t i = 0; i < EFRP_AEAD_RX_MAX_CHUNKS; ++i) if (!s_blocks[i].pointer) {
        s_blocks[i].pointer = pointer; s_blocks[i].size = size;
        ++s_allocated; return pointer;
    }
    ++s_rejected; heap_caps_free(pointer); return NULL;
}
static void word_release(void *pointer)
{
    for (size_t i = 0; i < EFRP_AEAD_RX_MAX_CHUNKS; ++i) if (s_blocks[i].pointer == pointer) {
        const volatile uint32_t *words = pointer;
        for (size_t w = 0; w < s_blocks[i].size / 4u; ++w)
            if (words[w]) { ++s_wipe_errors; break; }
        s_blocks[i].pointer = NULL; ++s_released;
        heap_caps_free(pointer); return;
    }
    ++s_region_errors;
}
static uint8_t expected_byte(size_t offset) { return (uint8_t)(offset * 37u + 11u); }
static unsigned s_failures;

static void run_record(const char *label, const uint8_t *wire, size_t wire_length,
                       size_t plain_length, bool bad_tag)
{
    memset(s_blocks, 0, sizeof s_blocks);
    s_allocated = s_released = s_rejected = s_wipe_errors = s_region_errors = 0;
    s_before_8bit = s_min_8bit = free_8bit();
    const unsigned before_exec = heap_free(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
    const unsigned before_largest8 = heap_largest(MALLOC_CAP_8BIT);
    efrp_aead_reader_t reader = {0};
    efrp_result_t result = efrp_aead_reader_init_words(&reader, s_key, word_allocate, word_release);
    size_t fed = 0, compared = 0;
    if (result == EFRP_OK) while (fed < wire_length) {
        uint8_t last = wire[fed];
        const uint8_t *input = wire + fed;
        size_t take = wire_length - fed, consumed = 0;
        if (take > 1024u) take = 1024u;
        if (bad_tag && fed + take == wire_length) {
            take = wire_length - fed - 1u;
            if (!take) { last ^= 1u; input = &last; take = 1; }
        }
        result = efrp_aead_feed(&reader, input, take, &consumed);
        fed += consumed;
        if (result != EFRP_OK || consumed != take) break;
    }
    const unsigned after_feed_8bit = free_8bit();
    const unsigned after_feed_exec = heap_free(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
    if (result == EFRP_OK && fed == wire_length) while (compared < plain_length) {
        uint8_t output[256]; size_t copied = 0;
        result = efrp_aead_copy_plaintext(&reader, output, sizeof output, &copied);
        if (result != EFRP_OK || !copied) break;
        for (size_t i = 0; i < copied; ++i) if (output[i] != expected_byte(compared + i)) {
            result = EFRP_PROTOCOL_ERROR; break;
        }
        if (result == EFRP_OK) result = efrp_aead_consume_plaintext(&reader, copied);
        memset(output, 0, sizeof output);
        if (result != EFRP_OK) break;
        compared += copied;
    }
    const uint64_t records = reader.records;
    efrp_aead_reader_destroy(&reader);
    const unsigned after_8bit = free_8bit();
    const unsigned after_exec = heap_free(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
    bool pass = bad_tag ? result == EFRP_AUTHENTICATION_FAILED && !compared :
        result == EFRP_OK && fed == wire_length && records == 1 && compared == plain_length;
    pass = pass && s_allocated == s_released && !s_wipe_errors && !s_region_errors &&
        after_8bit == s_before_8bit && after_exec == before_exec;
    if (!pass) ++s_failures;
    ESP_LOGI(TAG, "record label=%s plain=%u feed=%d fed=%u records=%u compared=%u alloc=%u release=%u reject=%u wipe_errors=%u region_errors=%u heap8_before=%u/%u heap8_min_alloc=%u heap8_after_feed=%u heap8_after=%u exec_before=%u exec_after_feed=%u exec_after=%u pass=%d",
             label, (unsigned)plain_length, (int)result, (unsigned)fed, (unsigned)records,
             (unsigned)compared, s_allocated, s_released, s_rejected, s_wipe_errors, s_region_errors,
             s_before_8bit, before_largest8, s_min_8bit, after_feed_8bit, after_8bit,
             before_exec, after_feed_exec, after_exec, pass);
}
void capacity_word_probe(const uint8_t *wire_4k, size_t length_4k,
                         const uint8_t *wire_max, size_t length_max)
{
    ESP_LOGI(TAG, "start 8bit=%u/%u exec32=%u/%u", free_8bit(), heap_largest(MALLOC_CAP_8BIT),
             heap_free(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT),
             heap_largest(MALLOC_CAP_EXEC | MALLOC_CAP_32BIT));
    run_record("4k", wire_4k, length_4k, 4096, false);
    run_record("4k_bad_tag", wire_4k, length_4k, 4096, true);
    run_record("64k", wire_max, length_max, 65536, false);
    run_record("64k_bad_tag", wire_max, length_max, 65536, true);
    ESP_LOGI(TAG, "summary failures=%u", s_failures);
}
