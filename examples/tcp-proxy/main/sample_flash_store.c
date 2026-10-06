// SPDX-License-Identifier: Apache-2.0
#include "sample_flash_store.h"
#include "esp_frp_idf_flash_store.h"
#include <stdatomic.h>

/* The independent sample has no OTA or package writer. This single sample
 * owner still makes accidental concurrent Flash use fail closed. Products
 * supply their existing storage owner through with_owner instead. */
static atomic_flag sample_owner = ATOMIC_FLAG_INIT;
static efrp_idf_flash_store_t sample_store;

static efrp_result_t with_owner(void *context,
    efrp_idf_flash_operation_t operation, void *operation_context)
{
    atomic_flag *owner = context;
    if (atomic_flag_test_and_set_explicit(owner, memory_order_acquire))
        return EFRP_STORAGE_ERROR;
    efrp_result_t result = operation(operation_context);
    atomic_flag_clear_explicit(owner, memory_order_release);
    return result;
}

efrp_result_t sample_flash_store_init(void)
{
    const efrp_idf_flash_store_config_t config = {
        .partition_label = EFRP_IDF_FLASH_STORE_LABEL,
        .partition_type = ESP_PARTITION_TYPE_DATA,
        .partition_subtype = ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
        .partition_offset_bytes = UINT32_C(0x110000),
        .partition_size_bytes = EFRP_IDF_FLASH_STORE_BYTES,
        .owner_context = &sample_owner,
        .with_owner = with_owner,
    };
    if (!efrp_idf_flash_store_bind(&sample_store, &config))
        return EFRP_STORAGE_ERROR;
    return efrp_aead_flash_store_recover(efrp_idf_flash_store_callbacks(&sample_store));
}

const efrp_aead_flash_store_t *sample_flash_store_callbacks(void)
{
    return efrp_idf_flash_store_callbacks(&sample_store);
}
