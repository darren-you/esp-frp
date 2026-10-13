// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_flash_reader.h"
#include "esp_frp_idf_flash_store.h"
#include "esp_heap_caps.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { RECORD_BYTES = 65568, CIPHER_BYTES = 65536, IO_BYTES = 1024 };

static const uint8_t full_record[] = {
#include "full-record.inc"
};
_Static_assert(sizeof full_record == RECORD_BYTES, "full AEAD fixture required");

static efrp_idf_flash_store_t flash_store;
static atomic_flag flash_owner = ATOMIC_FLAG_INIT;
static uint8_t window[EFRP_AEAD_RX_CHUNK_BYTES];
static size_t minimum_free = SIZE_MAX, minimum_largest = SIZE_MAX;
static unsigned owner_calls;
static uint64_t flash_operation_us, maximum_flash_operation_us;
static struct {
    bool active, runtime_begin, acquired, operation_running;
    bool waiting_for_poll, contender_finished;
    unsigned handoff_ticks, claims, claims_at_acquire;
    uint64_t wait_us;
    TaskHandle_t frp_task, ota_task, observer;
} contention;

static void fail(const char *stage, int result)
{
    printf("EFRP_C3_FLASH fail stage=%s result=%d\n", stage, result);
    abort();
}

#define REQUIRE(condition, stage) do { if (!(condition)) fail((stage), -1); } while (0)
#define REQUIRE_OK(expression, stage) do { \
    efrp_result_t checked_result = (expression); \
    if (checked_result != EFRP_OK) fail((stage), checked_result); \
} while (0)

static void require_partition(const esp_partition_t *partition, bool expect_erased,
                              const char *stage);

static void sample_heap(void)
{
    size_t free_bytes = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest_bytes = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    if (free_bytes < minimum_free) minimum_free = free_bytes;
    if (largest_bytes < minimum_largest) minimum_largest = largest_bytes;
}

static efrp_result_t with_owner(void *context, efrp_idf_flash_operation_t operation,
                                void *operation_context)
{
    atomic_flag *owner = context;
    if (atomic_flag_test_and_set_explicit(owner, memory_order_acquire))
        return EFRP_STORAGE_ERROR;
    ++owner_calls;
    if (contention.active) {
        ++contention.claims;
        if (contention.claims == 1U) xTaskNotifyGive(contention.ota_task);
    }
    int64_t started_us = esp_timer_get_time();
    if (contention.active) contention.operation_running = true;
    efrp_result_t result = operation(operation_context);
    if (contention.active) contention.operation_running = false;
    uint64_t elapsed_us = (uint64_t)(esp_timer_get_time() - started_us);
    flash_operation_us += elapsed_us;
    if (elapsed_us > maximum_flash_operation_us)
        maximum_flash_operation_us = elapsed_us;
    atomic_flag_clear_explicit(owner, memory_order_release);
    return result;
}

/* These wrappers exist only in this QEMU probe. Real partition I/O still
 * runs; fixed synthetic latency makes priority starvation reproducible
 * without pretending QEMU implements the board's physical Flash latency. */
esp_err_t __real_esp_partition_erase_range(const esp_partition_t *partition,
                                         size_t offset, size_t size);
void __real_vTaskDelay(TickType_t ticks);

esp_err_t __wrap_esp_partition_erase_range(const esp_partition_t *partition,
                                         size_t offset, size_t size)
{
    const esp_err_t result = __real_esp_partition_erase_range(partition, offset, size);
    if (contention.active && xTaskGetCurrentTaskHandle() == contention.frp_task) {
        REQUIRE(size == partition->erase_size, "one_sector_per_claim");
        __real_vTaskDelay(pdMS_TO_TICKS(40));
        /* Select the legal worst alignment: the lower-priority contender has
         * already failed in this tick before the owner is released. Its
         * notification wakes priority 5 before it calls vTaskDelay(1). */
        if (!contention.contender_finished) {
            contention.waiting_for_poll = true;
            REQUIRE(ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(100)) == 1U,
                    "align_failed_poll_before_release");
            contention.waiting_for_poll = false;
        }
    }
    return result;
}

void __wrap_vTaskDelay(TickType_t ticks)
{
    if (contention.active && !contention.operation_running &&
        xTaskGetCurrentTaskHandle() == contention.frp_task) {
        REQUIRE(ticks == 2, "provider_two_tick_handoff");
        ticks = (TickType_t)contention.handoff_ticks;
    }
    __real_vTaskDelay(ticks);
}

static void contender_task(void *unused)
{
    (void)unused;
    REQUIRE(ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(2000)) == 1U, "contender_start");
    const int64_t started_us = esp_timer_get_time();
    do {
        if (!atomic_flag_test_and_set_explicit(&flash_owner, memory_order_acquire)) {
            contention.acquired = true;
            contention.claims_at_acquire = contention.claims;
            atomic_flag_clear_explicit(&flash_owner, memory_order_release);
            break;
        }
        if (contention.waiting_for_poll) xTaskNotifyGive(contention.frp_task);
        if (esp_timer_get_time() - started_us >= INT64_C(500000)) break;
        vTaskDelay(1);
    } while (true);
    contention.wait_us = (uint64_t)(esp_timer_get_time() - started_us);
    contention.contender_finished = true;
    xTaskNotifyGive(contention.observer);
    vTaskDelete(NULL);
}

static void eraser_task(void *unused)
{
    (void)unused;
    /* Set the handle before the first wrapped Flash operation. */
    contention.frp_task = xTaskGetCurrentTaskHandle();
    const efrp_aead_flash_store_t *store = efrp_idf_flash_store_callbacks(&flash_store);
    uint64_t lease = 0U;
    if (contention.runtime_begin) {
        REQUIRE_OK(store->begin(store->context, &lease), "contention_begin");
        REQUIRE(lease != 0U, "contention_lease");
        REQUIRE_OK(store->clear(store->context, lease), "contention_clear");
    } else {
        REQUIRE_OK(store->recover(store->context), "contention_recover");
    }
    xTaskNotifyGive(contention.observer);
    vTaskDelete(NULL);
}

static void test_owner_contention(const esp_partition_t *partition)
{
    /* The negative controls change only the handoff delay: immediate and
     * one-tick reacquisition lose the lower-priority task's 500 ms budget.
     * Two-tick controls execute the production provider unchanged. */
    for (unsigned scenario = 0U; scenario < 4U; ++scenario) {
        memset(&contention, 0, sizeof contention);
        contention.active = true;
        contention.handoff_ticks = scenario < 2U ? scenario : 2U;
        contention.runtime_begin = scenario == 3U;
        contention.observer = xTaskGetCurrentTaskHandle();
        REQUIRE(xTaskCreate(contender_task, "ota_poll", 4096, NULL, 4,
                            &contention.ota_task) == pdPASS, "create_contender");
        REQUIRE(xTaskCreate(eraser_task, "frp_erase", 8192, NULL, 5,
                            NULL) == pdPASS, "create_eraser");
        unsigned finished = 0U;
        while (finished < 2U) {
            const uint32_t count = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(3000));
            REQUIRE(count != 0U && count <= 2U - finished, "contention_join");
            finished += count;
        }
        contention.active = false;
        REQUIRE(contention.claims == 16U, "contention_sector_count");
        REQUIRE(contention.acquired == (scenario >= 2U), "contention_expected_result");
        if (scenario >= 2U) {
            REQUIRE(contention.claims_at_acquire < 16U && contention.wait_us < 500000U,
                    "lower_priority_acquired_between_sectors");
        } else {
            REQUIRE(contention.wait_us >= 500000U, "negative_original_budget_exhausted");
        }
        printf("EFRP_C3_FLASH contention mode=%s handoff_ticks=%u frp_priority=5"
               " ota_priority=4 poll_ticks=1 budget_us=500000 sector_claims=%u"
               " acquired=%u claims_at_acquire=%u wait_us=%" PRIu64
               " latency=synthetic_40ms_per_sector\n",
               contention.runtime_begin ? "begin" : "recover", contention.handoff_ticks,
               contention.claims, (unsigned)contention.acquired, contention.claims_at_acquire,
               contention.wait_us);
        require_partition(partition, true, "contention_erased");
    }
    owner_calls = 0U;
    flash_operation_us = maximum_flash_operation_us = 0U;
    puts("EFRP_C3_FLASH CONTENTION_PASS negative=0,1 positive=2 recovery_and_begin=verified");
}

static const esp_partition_t *bind_store(void)
{
    const esp_partition_t *partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        EFRP_IDF_FLASH_STORE_LABEL);
    REQUIRE(partition != NULL, "partition_find");
    printf("EFRP_C3_FLASH partition label=%s type=%u subtype=%u offset=0x%" PRIx32
           " size=%" PRIu32 " erase=%" PRIu32 " readonly=%d encrypted=%d\n",
           partition->label, partition->type, partition->subtype,
           partition->address, partition->size, partition->erase_size,
           partition->readonly, partition->encrypted);
    const efrp_idf_flash_store_config_t config = {
        .partition_label = EFRP_IDF_FLASH_STORE_LABEL,
        .partition_type = ESP_PARTITION_TYPE_DATA,
        .partition_subtype = ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        .partition_offset_bytes = UINT32_C(0x110000),
        .partition_size_bytes = EFRP_IDF_FLASH_STORE_BYTES,
        .owner_context = &flash_owner,
        .with_owner = with_owner,
    };
    REQUIRE(efrp_idf_flash_store_bind(&flash_store, &config), "provider_bind");
    REQUIRE(efrp_idf_flash_store_callbacks(&flash_store) != NULL, "callbacks");
    return partition;
}

static void inspect_partition(const esp_partition_t *partition, bool *erased,
                              bool *ciphertext)
{
    uint8_t observed[256];
    *erased = true;
    *ciphertext = true;
    for (size_t offset = 0; offset < CIPHER_BYTES; offset += sizeof observed) {
        if (esp_partition_read(partition, offset, observed, sizeof observed) != ESP_OK)
            fail("partition_read", -1);
        for (size_t i = 0; i < sizeof observed; ++i) {
            if (observed[i] != UINT8_MAX) *erased = false;
            if (observed[i] != full_record[16 + offset + i]) *ciphertext = false;
        }
    }
    memset(observed, 0, sizeof observed);
}

static void require_partition(const esp_partition_t *partition, bool expect_erased,
                              const char *stage)
{
    bool erased, ciphertext;
    inspect_partition(partition, &erased, &ciphertext);
    REQUIRE(expect_erased ? erased : ciphertext, stage);
}

static void make_key(uint8_t key[32])
{
    for (size_t i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 17U + 3U);
}

static void feed_valid_record(efrp_aead_flash_reader_t *reader)
{
    size_t offset = 0;
    while (offset < RECORD_BYTES - 1) {
        size_t count = RECORD_BYTES - 1 - offset;
        if (count > IO_BYTES) count = IO_BYTES;
        size_t consumed = 0;
        REQUIRE_OK(efrp_aead_flash_feed(reader, full_record + offset, count, &consumed),
                   "valid_feed");
        REQUIRE(consumed == count, "valid_consumed");
        offset += count;
        sample_heap();
    }
    const uint8_t *plaintext = NULL;
    size_t length = 0;
    REQUIRE(efrp_aead_flash_plaintext(reader, &plaintext, &length) == EFRP_WOULD_BLOCK &&
            plaintext == NULL && length == 0 && reader->flash_passes == 0,
            "no_plaintext_before_tag");
    size_t consumed = 0;
    REQUIRE_OK(efrp_aead_flash_feed(reader, full_record + offset, 1, &consumed),
               "valid_tag");
    REQUIRE(consumed == 1 && reader->records == 1 && reader->flash_records == 1 &&
            reader->flash_passes == 1 && reader->leased && reader->ready,
            "full_record_authenticated");
    sample_heap();
}

static int64_t verify_windows(efrp_aead_flash_reader_t *reader)
{
    int64_t max_window_us = 0;
    for (size_t offset = 0; offset < CIPHER_BYTES; offset += sizeof window) {
        const uint8_t *plaintext = NULL;
        size_t length = 0;
        int64_t started_us = esp_timer_get_time();
        REQUIRE_OK(efrp_aead_flash_plaintext(reader, &plaintext, &length),
                   "plaintext_window");
        int64_t elapsed_us = esp_timer_get_time() - started_us;
        if (elapsed_us > max_window_us) max_window_us = elapsed_us;
        REQUIRE(plaintext != NULL && length == sizeof window, "window_length");
        for (size_t i = 0; i < length; ++i)
            REQUIRE(plaintext[i] == (uint8_t)((offset + i) * 29U + 7U),
                    "window_content");
        REQUIRE_OK(efrp_aead_flash_consume_plaintext(reader, length), "window_consume");
        sample_heap();
    }
    REQUIRE(reader->flash_records == 1 && reader->flash_passes == 17 &&
            reader->flash_read_bytes == UINT64_C(17) * CIPHER_BYTES &&
            !reader->leased && !reader->ready && flash_store.state == EFRP_IDF_FLASH_IDLE,
            "full_window_reverification");
    REQUIRE_OK(efrp_aead_flash_finish(reader), "valid_finish");
    return max_window_us;
}

static void reject_bad_tag(const uint8_t key[32])
{
    efrp_aead_flash_reader_t reader = {0};
    const efrp_aead_flash_store_t *store = efrp_idf_flash_store_callbacks(&flash_store);
    REQUIRE_OK(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window),
               "bad_reader_init");
    for (size_t offset = 0; offset < RECORD_BYTES;) {
        uint8_t input[IO_BYTES];
        size_t count = RECORD_BYTES - offset;
        if (count > sizeof input) count = sizeof input;
        memcpy(input, full_record + offset, count);
        if (offset + count == RECORD_BYTES) input[count - 1] ^= 1U;
        size_t consumed = 0;
        efrp_result_t result = efrp_aead_flash_feed(&reader, input, count, &consumed);
        REQUIRE(consumed == count, "bad_consumed");
        if (offset + count == RECORD_BYTES)
            REQUIRE(result == EFRP_AUTHENTICATION_FAILED, "bad_tag_rejected");
        else REQUIRE(result == EFRP_OK, "bad_feed");
        offset += count;
        sample_heap();
    }
    const uint8_t *plaintext = NULL;
    size_t length = 0;
    REQUIRE(efrp_aead_flash_plaintext(&reader, &plaintext, &length) ==
            EFRP_AUTHENTICATION_FAILED && plaintext == NULL && length == 0 &&
            reader.records == 0 && reader.flash_records == 0 &&
            flash_store.state == EFRP_IDF_FLASH_IDLE, "bad_tag_no_delivery");
    for (size_t i = 0; i < sizeof window; ++i)
        REQUIRE(window[i] == 0, "bad_tag_window_zero");
    REQUIRE_OK(efrp_aead_flash_reader_close(&reader), "bad_reader_close");
}

static void first_boot(const esp_partition_t *partition)
{
    test_owner_contention(partition);
    const efrp_aead_flash_store_t *store = efrp_idf_flash_store_callbacks(&flash_store);
    int64_t started_us = esp_timer_get_time();
    REQUIRE_OK(efrp_aead_flash_store_recover(store), "initial_recover");
    int64_t recover_us = esp_timer_get_time() - started_us;
    require_partition(partition, true, "initial_erase_readback");
    sample_heap();
    size_t baseline_free = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t baseline_largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    uint8_t key[32];
    make_key(key);
    efrp_aead_flash_reader_t reader = {0};
    REQUIRE_OK(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window),
               "valid_reader_init");
    uint64_t flash_before_feed_us = flash_operation_us;
    started_us = esp_timer_get_time();
    feed_valid_record(&reader);
    int64_t feed_auth_us = esp_timer_get_time() - started_us;
    uint64_t flash_feed_us = flash_operation_us - flash_before_feed_us;
    require_partition(partition, false, "ciphertext_write_readback");
    uint64_t flash_before_windows_us = flash_operation_us;
    started_us = esp_timer_get_time();
    int64_t max_window_us = verify_windows(&reader);
    int64_t windows_us = esp_timer_get_time() - started_us;
    uint64_t flash_windows_us = flash_operation_us - flash_before_windows_us;
    const uint64_t flash_read_bytes = reader.flash_read_bytes;
    const uint64_t flash_passes = reader.flash_passes;
    REQUIRE_OK(efrp_aead_flash_reader_close(&reader), "valid_reader_close");
    require_partition(partition, false, "clear_preserves_ciphertext_until_recover");
    uint64_t flash_before_bad_tag_us = flash_operation_us;
    started_us = esp_timer_get_time();
    reject_bad_tag(key);
    int64_t bad_tag_us = esp_timer_get_time() - started_us;
    uint64_t flash_bad_tag_us = flash_operation_us - flash_before_bad_tag_us;
    require_partition(partition, false, "bad_tag_ciphertext_readback");
    memset(key, 0, sizeof key);
    printf("EFRP_C3_FLASH metrics recover_us=%" PRId64 " feed_auth_us=%" PRId64
           " flash_feed_us=%" PRIu64 " windows_us=%" PRId64
           " flash_windows_us=%" PRIu64 " max_window_us=%" PRId64
           " bad_tag_us=%" PRId64 " flash_bad_tag_us=%" PRIu64
           " flash_operation_us=%" PRIu64 " max_flash_operation_us=%" PRIu64
           " flash_passes=%" PRIu64
           " flash_read_bytes=%" PRIu64 " owner_calls=%u baseline_free=%zu"
           " baseline_largest=%zu minimum_free=%zu minimum_largest=%zu"
           " final_free=%zu final_largest=%zu\n",
           recover_us, feed_auth_us, flash_feed_us, windows_us,
           flash_windows_us, max_window_us, bad_tag_us, flash_bad_tag_us,
           flash_operation_us, maximum_flash_operation_us,
           flash_passes, flash_read_bytes, owner_calls, baseline_free,
           baseline_largest, minimum_free, minimum_largest,
           heap_caps_get_free_size(MALLOC_CAP_8BIT),
           heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    puts("EFRP_C3_FLASH PHASE1_PASS full_record=65536 bad_tag=rejected flash=persistent");
}

static void second_boot(const esp_partition_t *partition)
{
    sample_heap();
    int64_t started_us = esp_timer_get_time();
    REQUIRE_OK(efrp_aead_flash_store_recover(efrp_idf_flash_store_callbacks(&flash_store)),
               "boot_recover");
    int64_t recover_us = esp_timer_get_time() - started_us;
    require_partition(partition, true, "boot_recover_erase_readback");
    REQUIRE(flash_store.state == EFRP_IDF_FLASH_IDLE && flash_store.active_lease == 0,
            "boot_recover_idle");
    sample_heap();
    printf("EFRP_C3_FLASH recovery recover_us=%" PRId64
           " flash_operation_us=%" PRIu64 " max_flash_operation_us=%" PRIu64
           " owner_calls=%u"
           " minimum_free=%zu minimum_largest=%zu final_free=%zu"
           " final_largest=%zu\n", recover_us, flash_operation_us,
           maximum_flash_operation_us, owner_calls, minimum_free,
           minimum_largest, heap_caps_get_free_size(MALLOC_CAP_8BIT),
           heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    puts("EFRP_C3_FLASH PHASE2_PASS persisted_ciphertext=65536 recovered_erased=65536");
}

void app_main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ESP_FRP_LAB_ONLY C3_FLASH_SCRATCH sdk=6.1 target=esp32c3");
    const esp_partition_t *partition = bind_store();
    bool erased, ciphertext;
    inspect_partition(partition, &erased, &ciphertext);
    REQUIRE(erased != ciphertext, "boot_partition_state");
    if (erased) first_boot(partition);
    else second_boot(partition);
}
