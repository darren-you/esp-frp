// SPDX-License-Identifier: Apache-2.0
#include "session_idf_flash_fixture.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { SCRATCH_OFFSET = 0x110000 };

static esp_partition_t partition;
static uint8_t scratch[EFRP_IDF_FLASH_STORE_BYTES];
static efrp_idf_flash_store_t provider;
static struct { bool held; unsigned claims, releases; } owner;
static size_t erased_bytes, written_bytes, read_bytes;

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
    esp_partition_subtype_t subtype, const char *label)
{
    return type == partition.type && subtype == partition.subtype &&
        strcmp(label, partition.label) == 0 ? &partition : NULL;
}

esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t offset,
                                    size_t length)
{
    assert(p == &partition && owner.held && offset == 0U &&
        length == sizeof scratch);
    memset(scratch, 0xff, length);
    erased_bytes += length;
    return ESP_OK;
}

esp_err_t esp_partition_write(const esp_partition_t *p, size_t offset,
                              const void *bytes, size_t length)
{
    assert(p == &partition && owner.held && bytes &&
        offset <= sizeof scratch && length <= sizeof scratch - offset);
    const uint8_t *source = bytes;
    for (size_t i = 0; i < length; ++i) {
        assert((scratch[offset + i] & source[i]) == source[i]);
        scratch[offset + i] &= source[i];
    }
    written_bytes += length;
    return ESP_OK;
}

esp_err_t esp_partition_read(const esp_partition_t *p, size_t offset,
                             void *bytes, size_t length)
{
    assert(p == &partition && owner.held && bytes &&
        offset <= sizeof scratch && length <= sizeof scratch - offset);
    memcpy(bytes, scratch + offset, length);
    read_bytes += length;
    return ESP_OK;
}

static efrp_result_t with_owner(void *context, efrp_idf_flash_operation_t operation,
                                void *operation_context)
{
    assert(context == &owner && !owner.held && operation);
    owner.held = true;
    ++owner.claims;
    efrp_result_t result = operation(operation_context);
    owner.held = false;
    ++owner.releases;
    return result;
}

const efrp_aead_flash_store_t *efrp_session_idf_flash_prepare(void)
{
    assert(!owner.held && owner.claims == owner.releases);
    memset(&owner, 0, sizeof owner);
    memset(&provider, 0, sizeof provider);
    memset(scratch, 0x5a, sizeof scratch); /* Simulate ciphertext from a prior boot. */
    erased_bytes = written_bytes = read_bytes = 0;
    partition = (esp_partition_t){.type = ESP_PARTITION_TYPE_DATA,
        .subtype = ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        .address = SCRATCH_OFFSET, .size = sizeof scratch,
        .label = EFRP_IDF_FLASH_STORE_LABEL, .erase_size = 4096U};
    efrp_idf_flash_store_config_t config = {
        .partition_label = EFRP_IDF_FLASH_STORE_LABEL,
        .partition_type = ESP_PARTITION_TYPE_DATA,
        .partition_subtype = ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        .partition_offset_bytes = SCRATCH_OFFSET,
        .partition_size_bytes = sizeof scratch,
        .owner_context = &owner, .with_owner = with_owner};
    assert(efrp_idf_flash_store_bind(&provider, &config));
    const efrp_aead_flash_store_t *store = efrp_idf_flash_store_callbacks(&provider);
    assert(store && efrp_aead_flash_store_recover(store) == EFRP_OK);
    for (size_t i = 0; i < sizeof scratch; ++i) assert(scratch[i] == 0xff);
    assert(erased_bytes == sizeof scratch);
    return store;
}

void efrp_session_idf_flash_check(const char *mode)
{
    assert(!owner.held && owner.claims == owner.releases);
    assert(provider.state == EFRP_IDF_FLASH_IDLE && provider.active_lease == 0U);
    if (strcmp(mode, "fixture-aead-max") == 0 ||
        strcmp(mode, "fixture-aead-max-tamper") == 0) {
        assert(erased_bytes == 2U * sizeof scratch);
        assert(written_bytes == sizeof scratch);
        /* Initial write verification, one full tag pass, then 16 windows. */
        if (strcmp(mode, "fixture-aead-max") == 0)
            assert(read_bytes >= 18U * sizeof scratch);
        else
            assert(read_bytes >= 2U * sizeof scratch);
    } else {
        assert(erased_bytes == sizeof scratch && !written_bytes);
    }
    fprintf(stderr, "IDF_FLASH mode=%s erased=%zu written=%zu read=%zu claims=%u releases=%u\n",
        mode, erased_bytes, written_bytes, read_bytes, owner.claims, owner.releases);
}
