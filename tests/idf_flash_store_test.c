// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_idf_flash_store.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { SCRATCH_OFFSET = 0x3e6000 };
typedef struct {
    bool busy, fail_release, skip_operation, repeat_operation, swallow_error;
    unsigned claims, releases;
} owner_t;
static esp_partition_t partition;
static uint8_t flash[EFRP_IDF_FLASH_STORE_BYTES];
static bool fail_erase, short_write_success, fail_read;
static unsigned erase_calls, write_calls, read_calls;
static uint8_t plaintext[EFRP_AEAD_MAX_PLAINTEXT], wire[EFRP_AEAD_TX_MAX_BYTES];
static uint8_t window[EFRP_AEAD_RX_CHUNK_BYTES];
static const uint8_t key[32] = {2, 3, 5, 7};

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
    esp_partition_subtype_t subtype, const char *label)
{
    (void)type; (void)subtype; (void)label; return &partition;
}
esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t offset,
                                     size_t size)
{
    assert(p == &partition && offset == 0U && size == sizeof flash);
    ++erase_calls;
    memset(flash, 0xff, fail_erase ? size / 2U : size);
    return fail_erase ? ESP_FAIL : ESP_OK;
}
esp_err_t esp_partition_write(const esp_partition_t *p, size_t offset,
                               const void *source, size_t size)
{
    assert(p == &partition && offset <= sizeof flash && size <= sizeof flash - offset);
    ++write_calls;
    memcpy(flash + offset, source, short_write_success ? size / 2U : size);
    return ESP_OK;
}
esp_err_t esp_partition_read(const esp_partition_t *p, size_t offset,
                              void *destination, size_t size)
{
    assert(p == &partition && offset <= sizeof flash && size <= sizeof flash - offset);
    ++read_calls;
    if (fail_read) { memcpy(destination, flash + offset, size / 2U); return ESP_FAIL; }
    memcpy(destination, flash + offset, size);
    return ESP_OK;
}
static efrp_result_t with_owner(void *context, efrp_idf_flash_operation_t operation,
                                void *operation_context)
{
    owner_t *owner = context;
    if (owner->busy) return EFRP_STORAGE_ERROR;
    owner->busy = true; ++owner->claims;
    efrp_result_t result = owner->skip_operation ? EFRP_OK : operation(operation_context);
    if (owner->repeat_operation) { (void)operation(operation_context); result = EFRP_OK; }
    if (owner->swallow_error) result = EFRP_OK;
    owner->busy = false; ++owner->releases;
    return owner->fail_release ? EFRP_STORAGE_ERROR : result;
}
static void reset_flash(void)
{
    partition = (esp_partition_t){.type = ESP_PARTITION_TYPE_DATA,
        .subtype = ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        .address = SCRATCH_OFFSET, .size = sizeof flash,
        .label = "frp_scratch", .erase_size = 4096U};
    memset(flash, 0x35, sizeof flash);
    fail_erase = short_write_success = fail_read = false;
    erase_calls = write_calls = read_calls = 0U;
}
static efrp_idf_flash_store_config_t config_for(owner_t *owner)
{
    return (efrp_idf_flash_store_config_t){.partition_label = "frp_scratch",
        .partition_type = ESP_PARTITION_TYPE_DATA,
        .partition_subtype = ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        .partition_offset_bytes = SCRATCH_OFFSET,
        .partition_size_bytes = EFRP_IDF_FLASH_STORE_BYTES,
        .owner_context = owner, .with_owner = with_owner};
}
static const efrp_aead_flash_store_t *bind(efrp_idf_flash_store_t *provider,
                                           owner_t *owner)
{
    efrp_idf_flash_store_config_t config = config_for(owner);
    assert(efrp_idf_flash_store_bind(provider, &config));
    const efrp_aead_flash_store_t *store = efrp_idf_flash_store_callbacks(provider);
    assert(store && store->context == provider);
    return store;
}
static void test_exact_binding(void)
{
    reset_flash(); owner_t owner = {0}; efrp_idf_flash_store_t provider = {0};
    efrp_idf_flash_store_config_t config = config_for(&owner);
    assert(efrp_idf_flash_store_bind(&provider, &config));
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    provider = (efrp_idf_flash_store_t){0};
    config.partition_offset_bytes += 4096U;
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    config = config_for(&owner); config.partition_size_bytes -= 4096U;
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    config = config_for(&owner); config.partition_label = "product_pkgs";
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    config = config_for(&owner); config.with_owner = NULL;
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    config = config_for(&owner); partition.readonly = true;
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    partition.readonly = false; partition.encrypted = true;
    assert(!efrp_idf_flash_store_bind(&provider, &config));
    partition.encrypted = false; partition.erase_size = 8192U;
    assert(!efrp_idf_flash_store_bind(&provider, &config));
}
static size_t make_record(size_t length)
{
    static uint8_t output[EFRP_AEAD_TX_MAX_BYTES];
    efrp_aead_writer_t writer = {0};
    size_t written, used; const uint8_t *bytes;
    for (size_t i = 0; i < length; ++i) plaintext[i] = (uint8_t)(i * 29U + 7U);
    assert(efrp_aead_writer_init(&writer, key, output, sizeof output) == EFRP_OK);
    assert(efrp_aead_write(&writer, plaintext, length, &written) == EFRP_OK && written == length);
    assert(efrp_aead_output(&writer, &bytes, &used) == EFRP_OK);
    memcpy(wire, bytes, used);
    efrp_aead_writer_destroy(&writer);
    return used;
}
static void feed_record(efrp_aead_flash_reader_t *reader, size_t length)
{
    for (size_t offset = 0; offset < length;) {
        size_t count = length - offset, consumed = 0;
        if (count > 1009U) count = 1009U;
        assert(efrp_aead_flash_feed(reader, wire + offset, count, &consumed) == EFRP_OK);
        assert(consumed == count); offset += count;
    }
}
static void test_owner_and_reader(void)
{
    reset_flash(); owner_t owner = {0}; efrp_idf_flash_store_t provider = {0};
    const efrp_aead_flash_store_t *store = bind(&provider, &owner);
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK && erase_calls == 1U);
    efrp_aead_flash_reader_t reader = {0};
    assert(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window) == EFRP_OK);
    size_t small = make_record(4096U);
    owner.busy = true; /* OTA owns Flash across an ordinary control record. */
    unsigned claims = owner.claims;
    feed_record(&reader, small);
    assert(owner.busy && owner.claims == claims && erase_calls == 1U && !reader.leased);
    const uint8_t *decoded; size_t decoded_length;
    assert(efrp_aead_flash_plaintext(&reader, &decoded, &decoded_length) == EFRP_OK);
    assert(decoded_length == 4096U && memcmp(decoded, plaintext, decoded_length) == 0);
    assert(efrp_aead_flash_consume_plaintext(&reader, decoded_length) == EFRP_OK);
    assert(efrp_aead_flash_reader_close(&reader) == EFRP_OK && owner.busy);
    owner.busy = false;

    size_t large = make_record(65536U);
    assert(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window) == EFRP_OK);
    owner.busy = true;
    size_t consumed = 0;
    assert(efrp_aead_flash_feed(&reader, wire, 16U, &consumed) == EFRP_STORAGE_ERROR);
    assert(consumed == 16U && owner.busy && !reader.leased);
    owner.busy = false;
    assert(efrp_aead_flash_reader_close(&reader) == EFRP_OK);

    assert(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window) == EFRP_OK);
    consumed = 0;
    assert(efrp_aead_flash_feed(&reader, wire, 17U, &consumed) == EFRP_OK);
    assert(reader.leased && erase_calls == 2U);
    owner.busy = true;
    assert(efrp_aead_flash_feed(&reader, wire + 17U, large - 17U, &consumed) == EFRP_STORAGE_ERROR);
    assert(!reader.leased && owner.busy && provider.state == EFRP_IDF_FLASH_IDLE);
    assert(efrp_aead_flash_reader_close(&reader) == EFRP_OK && !reader.active && owner.busy);
    owner.busy = false;
    assert(provider.state == EFRP_IDF_FLASH_IDLE && owner.claims == owner.releases);
    uint64_t lease = 0U;
    assert(store->begin(store->context, &lease) == EFRP_OK && lease);
    assert(store->clear(store->context, lease) == EFRP_OK);
    assert(store->read(store->context, lease, 0U, window, 1U) == EFRP_STORAGE_ERROR);
}
static void test_full_record_and_owner_interrupt(void)
{
    reset_flash(); owner_t owner = {0}; efrp_idf_flash_store_t provider = {0};
    const efrp_aead_flash_store_t *store = bind(&provider, &owner);
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK && erase_calls == 1U);
    const size_t wire_length = make_record(EFRP_AEAD_MAX_PLAINTEXT);
    efrp_aead_flash_reader_t reader = {0};
    assert(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window) == EFRP_OK);
    feed_record(&reader, wire_length);
    assert(reader.ready && reader.leased && erase_calls == 2U);
    const uint64_t stale_lease = reader.lease;
    for (size_t offset = 0; offset < EFRP_AEAD_MAX_PLAINTEXT; offset += sizeof window) {
        const uint8_t *decoded = NULL; size_t decoded_length = 0U;
        assert(efrp_aead_flash_plaintext(&reader, &decoded, &decoded_length) == EFRP_OK);
        assert(decoded_length == sizeof window);
        assert(memcmp(decoded, plaintext + offset, decoded_length) == 0);
        if (offset + decoded_length == EFRP_AEAD_MAX_PLAINTEXT) {
            assert(reader.flash_passes == 17U);
            assert(reader.flash_read_bytes == 17U * EFRP_AEAD_MAX_PLAINTEXT);
        }
        assert(efrp_aead_flash_consume_plaintext(&reader, decoded_length) == EFRP_OK);
    }
    assert(!reader.leased && provider.state == EFRP_IDF_FLASH_IDLE);
    assert(store->read(store->context, stale_lease, 0U, window, 1U) == EFRP_STORAGE_ERROR);
    assert(efrp_aead_flash_reader_close(&reader) == EFRP_OK);

    assert(efrp_aead_flash_reader_init(&reader, key, store, window, sizeof window) == EFRP_OK);
    feed_record(&reader, wire_length);
    assert(reader.ready && reader.leased && erase_calls == 3U);
    const uint8_t *decoded = NULL; size_t decoded_length = 0U;
    assert(efrp_aead_flash_plaintext(&reader, &decoded, &decoded_length) == EFRP_OK);
    assert(efrp_aead_flash_consume_plaintext(&reader, decoded_length) == EFRP_OK);
    owner.busy = true; /* OTA takes the owner between verified windows. */
    assert(efrp_aead_flash_plaintext(&reader, &decoded, &decoded_length) == EFRP_STORAGE_ERROR);
    assert(!reader.leased && provider.state == EFRP_IDF_FLASH_IDLE && owner.busy);
    assert(efrp_aead_flash_reader_close(&reader) == EFRP_OK && owner.busy);
    owner.busy = false;
    assert(owner.claims == owner.releases);
}
static void test_flash_failures_and_recovery(void)
{
    reset_flash(); owner_t owner = {0}; efrp_idf_flash_store_t provider = {0};
    const efrp_aead_flash_store_t *store = bind(&provider, &owner);
    fail_erase = true;
    assert(efrp_aead_flash_store_recover(store) == EFRP_STORAGE_ERROR);
    fail_erase = false;
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK);
    uint64_t lease = 0U;
    assert(store->begin(store->context, &lease) == EFRP_OK && lease);
    const uint8_t source[4] = {0x99, 0x88, 0x77, 0x66};
    short_write_success = true;
    assert(store->write(store->context, lease, 1U, source, sizeof source) == EFRP_STORAGE_ERROR);
    assert(provider.state == EFRP_IDF_FLASH_QUARANTINED);
    short_write_success = false;
    owner.busy = true;
    unsigned claims = owner.claims;
    assert(store->clear(store->context, lease) == EFRP_OK && owner.busy);
    assert(owner.claims == claims);
    owner.busy = false;
    assert(store->begin(store->context, &lease) == EFRP_OK);
    assert(store->write(store->context, lease, 1U, source, sizeof source) == EFRP_OK);
    uint8_t destination[4] = {1, 1, 1, 1}; fail_read = true;
    assert(store->read(store->context, lease, 1U, destination, sizeof destination) == EFRP_STORAGE_ERROR);
    assert((destination[0] | destination[1] | destination[2] | destination[3]) == 0);
    fail_read = false;
    assert(store->clear(store->context, lease) == EFRP_OK);
    assert(owner.claims == owner.releases && !owner.busy);
}
static void test_owner_callback_contract(void)
{
    reset_flash(); owner_t owner = {0}; efrp_idf_flash_store_t provider = {0};
    const efrp_aead_flash_store_t *store = bind(&provider, &owner);
    owner.skip_operation = true;
    assert(efrp_aead_flash_store_recover(store) == EFRP_STORAGE_ERROR);
    assert(provider.state == EFRP_IDF_FLASH_QUARANTINED && erase_calls == 0U);
    owner.skip_operation = false;
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK);
    owner.swallow_error = true; fail_erase = true;
    assert(store->begin(store->context, &(uint64_t){0}) == EFRP_STORAGE_ERROR);
    assert(provider.state == EFRP_IDF_FLASH_QUARANTINED);
    owner.swallow_error = false; fail_erase = false;
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK);
    owner.repeat_operation = true;
    uint64_t lease = 0U;
    assert(store->begin(store->context, &lease) == EFRP_STORAGE_ERROR && !lease);
    assert(provider.state == EFRP_IDF_FLASH_QUARANTINED);
    owner.repeat_operation = false;
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK);
    assert(store->begin(store->context, &lease) == EFRP_OK && lease);
    owner.skip_operation = true;
    const uint8_t value = 0x5aU;
    assert(store->write(store->context, lease, 0U, &value, 1U) == EFRP_STORAGE_ERROR);
    assert(provider.state == EFRP_IDF_FLASH_QUARANTINED);
    owner.skip_operation = false;
    assert(store->clear(store->context, lease) == EFRP_OK);
    assert(store->begin(store->context, &lease) == EFRP_OK);
    assert(!atomic_flag_test_and_set(&provider.guard));
    assert(store->clear(store->context, lease) == EFRP_STORAGE_ERROR);
    assert(provider.active_lease == lease);
    atomic_flag_clear(&provider.guard);
    assert(store->clear(store->context, lease) == EFRP_OK);
    assert(owner.claims == owner.releases && !owner.busy);
}
int main(void)
{
    test_exact_binding();
    test_owner_and_reader();
    test_full_record_and_owner_interrupt();
    test_flash_failures_and_recovery();
    test_owner_callback_contract();
    puts("IDF Flash store: exact partition, 64KiB record/17 rereads, OTA contention, clear retry and I/O faults passed");
    return 0;
}
