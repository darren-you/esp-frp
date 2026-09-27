// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_idf_flash_store.h"

#include <limits.h>
#include <string.h>

enum { EFRP_IDF_FLASH_ERASE_BYTES = 4096, VERIFY_BYTES = 256 };

static bool enter(efrp_idf_flash_store_t *provider)
{
    if (provider == NULL || !provider->bound ||
        atomic_flag_test_and_set_explicit(&provider->guard, memory_order_acquire))
        return false;
    /* A failed concurrent clear may arrive between the previous callback's
     * final state check and its unlock. The next callback must still see the
     * quarantine before it can begin or expose old ciphertext. */
    if (atomic_exchange_explicit(&provider->quarantine_requested, false,
                                 memory_order_acq_rel))
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
    return true;
}

static efrp_result_t leave(efrp_idf_flash_store_t *provider, efrp_result_t result)
{
    if (atomic_exchange_explicit(&provider->quarantine_requested, false,
                                 memory_order_acq_rel)) {
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
        result = EFRP_STORAGE_ERROR;
    }
    atomic_flag_clear_explicit(&provider->guard, memory_order_release);
    return result;
}

typedef struct {
    efrp_idf_flash_store_t *provider;
    size_t offset, length;
    const uint8_t *source;
    uint8_t *destination;
    unsigned calls;
    efrp_result_t result;
} flash_operation_t;

static efrp_result_t erase_operation(void *context)
{
    flash_operation_t *op = context;
    if (++op->calls != 1U) return op->result = EFRP_STORAGE_ERROR;
    op->result = esp_partition_erase_range(op->provider->partition, 0U,
        EFRP_IDF_FLASH_STORE_BYTES) == ESP_OK ? EFRP_OK : EFRP_STORAGE_ERROR;
    return op->result;
}

static efrp_result_t write_operation(void *context)
{
    flash_operation_t *op = context;
    if (++op->calls != 1U) return op->result = EFRP_STORAGE_ERROR;
    bool exact = esp_partition_write(op->provider->partition, op->offset,
                                     op->source, op->length) == ESP_OK;
    uint8_t observed[VERIFY_BYTES];
    for (size_t done = 0U; exact && done < op->length;) {
        const size_t count = op->length - done < sizeof observed ?
            op->length - done : sizeof observed;
        exact = esp_partition_read(op->provider->partition, op->offset + done,
                                   observed, count) == ESP_OK &&
                memcmp(observed, op->source + done, count) == 0;
        done += count;
    }
    memset(observed, 0, sizeof observed);
    op->result = exact ? EFRP_OK : EFRP_STORAGE_ERROR;
    return op->result;
}

static efrp_result_t read_operation(void *context)
{
    flash_operation_t *op = context;
    if (++op->calls != 1U) return op->result = EFRP_STORAGE_ERROR;
    op->result = esp_partition_read(op->provider->partition, op->offset,
        op->destination, op->length) == ESP_OK ? EFRP_OK : EFRP_STORAGE_ERROR;
    return op->result;
}

static bool valid_range(size_t offset, size_t length)
{
    return length > 0U && offset < EFRP_IDF_FLASH_STORE_BYTES &&
        length <= EFRP_IDF_FLASH_STORE_BYTES - offset;
}

static efrp_result_t recover(void *context)
{
    efrp_idf_flash_store_t *provider = context;
    if (!enter(provider)) return EFRP_STORAGE_ERROR;
    /* Boot recovery belongs before sessions. An active runtime reader must
     * retain its lease for clear retry; do not erase its ciphertext here. */
    if (provider->active_lease != 0U)
        return leave(provider, EFRP_STORAGE_ERROR);
    /* Revoke even on an interrupted erase. A previous boot's RAM lease is
     * never authority for this boot's scratch bytes. */
    provider->state = EFRP_IDF_FLASH_UNRECOVERED;
    provider->active_lease = 0U;
    flash_operation_t op = {.provider = provider};
    if (provider->with_owner(provider->owner_context, erase_operation, &op) != EFRP_OK ||
        op.calls != 1U || op.result != EFRP_OK) {
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
        return leave(provider, EFRP_STORAGE_ERROR);
    }
    provider->state = EFRP_IDF_FLASH_IDLE;
    return leave(provider, EFRP_OK);
}

static efrp_result_t begin(void *context, uint64_t *lease)
{
    if (lease != NULL) *lease = 0U;
    efrp_idf_flash_store_t *provider = context;
    if (!enter(provider)) return EFRP_STORAGE_ERROR;
    if (lease == NULL) return leave(provider, EFRP_INVALID_ARGUMENT);
    if (provider->state != EFRP_IDF_FLASH_IDLE ||
        provider->next_lease == UINT64_MAX) {
        return leave(provider, EFRP_STORAGE_ERROR);
    }
    flash_operation_t op = {.provider = provider};
    efrp_result_t operation_result = provider->with_owner(provider->owner_context,
                                                            erase_operation, &op);
    if (operation_result != EFRP_OK || op.calls != 1U || op.result != EFRP_OK) {
        if (op.calls != 0U || operation_result == EFRP_OK)
            provider->state = EFRP_IDF_FLASH_QUARANTINED;
        return leave(provider, EFRP_STORAGE_ERROR);
    }
    const uint64_t issued = ++provider->next_lease;
    provider->active_lease = issued;
    provider->state = EFRP_IDF_FLASH_LEASED;
    efrp_result_t result = EFRP_OK;
    if (atomic_exchange_explicit(&provider->quarantine_requested, false,
                                 memory_order_acq_rel)) {
        /* A concurrent failed clear can request quarantine while begin is
         * issuing a lease. Revoke it before releasing the state guard. */
        provider->active_lease = 0U;
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
        result = EFRP_STORAGE_ERROR;
    } else {
        *lease = issued;
    }
    atomic_flag_clear_explicit(&provider->guard, memory_order_release);
    return result;
}

static efrp_result_t write_bytes(void *context, uint64_t lease, size_t offset,
                                 const uint8_t *bytes, size_t length)
{
    efrp_idf_flash_store_t *provider = context;
    if (!enter(provider)) return EFRP_STORAGE_ERROR;
    if (bytes == NULL || !valid_range(offset, length))
        return leave(provider, EFRP_INVALID_ARGUMENT);
    if (provider->state != EFRP_IDF_FLASH_LEASED ||
        lease == 0U || lease != provider->active_lease)
        return leave(provider, EFRP_STORAGE_ERROR);
    flash_operation_t op = {.provider = provider, .offset = offset,
                            .length = length, .source = bytes};
    efrp_result_t result = provider->with_owner(provider->owner_context,
                                                write_operation, &op);
    if (result != EFRP_OK || op.calls != 1U || op.result != EFRP_OK)
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
    return leave(provider, result == EFRP_OK && op.calls == 1U && op.result == EFRP_OK ?
        EFRP_OK : EFRP_STORAGE_ERROR);
}

static efrp_result_t read_bytes(void *context, uint64_t lease, size_t offset,
                                uint8_t *bytes, size_t length)
{
    efrp_idf_flash_store_t *provider = context;
    if (!enter(provider)) return EFRP_STORAGE_ERROR;
    if (bytes == NULL || !valid_range(offset, length))
        return leave(provider, EFRP_INVALID_ARGUMENT);
    if (provider->state != EFRP_IDF_FLASH_LEASED ||
        lease == 0U || lease != provider->active_lease)
        return leave(provider, EFRP_STORAGE_ERROR);
    flash_operation_t op = {.provider = provider, .offset = offset,
                            .length = length, .destination = bytes};
    efrp_result_t result = provider->with_owner(provider->owner_context,
                                                read_operation, &op);
    if (result != EFRP_OK || op.calls != 1U || op.result != EFRP_OK) {
        memset(bytes, 0, length);
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
    }
    return leave(provider, result == EFRP_OK && op.calls == 1U && op.result == EFRP_OK ?
        EFRP_OK : EFRP_STORAGE_ERROR);
}

static efrp_result_t clear(void *context, uint64_t lease)
{
    efrp_idf_flash_store_t *provider = context;
    if (!enter(provider)) {
        if (provider != NULL && provider->bound)
            atomic_store_explicit(&provider->quarantine_requested, true,
                                  memory_order_release);
        return EFRP_STORAGE_ERROR;
    }
    if (lease == 0U || lease != provider->active_lease ||
        (provider->state != EFRP_IDF_FLASH_LEASED &&
         provider->state != EFRP_IDF_FLASH_QUARANTINED))
        return leave(provider, EFRP_STORAGE_ERROR);
    /* No Flash I/O occurs here. Revoke the RAM lease under the provider guard;
     * the next begin erases the whole partition before publishing a lease. */
    efrp_result_t result = EFRP_OK;
    if (atomic_exchange_explicit(&provider->quarantine_requested, false,
                                 memory_order_acq_rel)) {
        provider->state = EFRP_IDF_FLASH_QUARANTINED;
        result = EFRP_STORAGE_ERROR;
    } else {
        provider->active_lease = 0U;
        provider->state = EFRP_IDF_FLASH_IDLE;
    }
    atomic_flag_clear_explicit(&provider->guard, memory_order_release);
    return result;
}

bool efrp_idf_flash_store_bind(efrp_idf_flash_store_t *provider,
                               const efrp_idf_flash_store_config_t *config)
{
    if (provider == NULL || provider->bound || config == NULL ||
        config->partition_label == NULL ||
        strcmp(config->partition_label, EFRP_IDF_FLASH_STORE_LABEL) != 0 ||
        config->partition_type != ESP_PARTITION_TYPE_DATA ||
        config->partition_subtype != ESP_PARTITION_SUBTYPE_DATA_UNDEFINED ||
        config->partition_offset_bytes == 0U ||
        config->partition_size_bytes != EFRP_IDF_FLASH_STORE_BYTES ||
        config->partition_offset_bytes % EFRP_IDF_FLASH_ERASE_BYTES != 0U ||
        config->owner_context == NULL || config->with_owner == NULL) return false;
    const esp_partition_t *partition = esp_partition_find_first(
        config->partition_type, config->partition_subtype, config->partition_label);
    if (partition == NULL || partition->type != config->partition_type ||
        partition->subtype != config->partition_subtype ||
        strcmp(partition->label, config->partition_label) != 0 ||
        partition->address != config->partition_offset_bytes ||
        partition->size != config->partition_size_bytes ||
        partition->erase_size != EFRP_IDF_FLASH_ERASE_BYTES ||
        partition->readonly || partition->encrypted) return false;
    memset(provider, 0, sizeof *provider);
    atomic_flag_clear(&provider->guard);
    atomic_init(&provider->quarantine_requested, false);
    provider->partition = partition;
    provider->owner_context = config->owner_context;
    provider->with_owner = config->with_owner;
    provider->state = EFRP_IDF_FLASH_UNRECOVERED;
    provider->callbacks = (efrp_aead_flash_store_t){
        .context = provider,
        .recover = recover,
        .begin = begin,
        .write = write_bytes,
        .read = read_bytes,
        .clear = clear,
    };
    provider->bound = true;
    return true;
}

const efrp_aead_flash_store_t *efrp_idf_flash_store_callbacks(
    const efrp_idf_flash_store_t *provider)
{
    return provider != NULL && provider->bound ? &provider->callbacks : NULL;
}
