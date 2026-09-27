// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "esp_partition.h"
#include "esp_frp_flash_reader.h"

#define EFRP_IDF_FLASH_STORE_BYTES UINT32_C(0x10000)
#define EFRP_IDF_FLASH_STORE_LABEL "frp_scratch"

/* Run exactly one synchronous Flash operation while holding the product's
 * existing storage owner. The adapter calls this for each erase, verified
 * write and read. clear only revokes the RAM lease under the provider guard.
 * The wrapper must call operation exactly once,
 * release ownership even when it fails, and return STORAGE_ERROR if release
 * fails. The provider checks that operation was called exactly once. */
typedef efrp_result_t (*efrp_idf_flash_operation_t)(void *operation_context);
typedef efrp_result_t (*efrp_idf_flash_with_owner_t)(
    void *owner_context, efrp_idf_flash_operation_t operation,
    void *operation_context);

typedef struct {
    const char *partition_label;
    esp_partition_type_t partition_type;
    esp_partition_subtype_t partition_subtype;
    uint32_t partition_offset_bytes;
    uint32_t partition_size_bytes;
    void *owner_context;
    efrp_idf_flash_with_owner_t with_owner;
} efrp_idf_flash_store_config_t;

typedef enum {
    EFRP_IDF_FLASH_UNRECOVERED = 0,
    EFRP_IDF_FLASH_IDLE,
    EFRP_IDF_FLASH_LEASED,
    EFRP_IDF_FLASH_QUARANTINED,
} efrp_idf_flash_store_state_t;

/* Stable-address boot object. Its callback context is retained until every
 * FRP client/session is destroyed. Fields are exposed for static allocation,
 * never for caller mutation. */
typedef struct {
    efrp_aead_flash_store_t callbacks;
    const esp_partition_t *partition;
    void *owner_context;
    efrp_idf_flash_with_owner_t with_owner;
    atomic_flag guard;
    atomic_bool quarantine_requested;
    uint64_t next_lease;
    uint64_t active_lease;
    efrp_idf_flash_store_state_t state;
    bool bound;
} efrp_idf_flash_store_t;

/* Bind verifies every approved partition fact, without erasing. Only an
 * unencrypted, writable 64 KiB data/undefined partition is accepted; arbitrary
 * byte writes are not valid for an encrypted partition. Call recover at boot
 * before FRP start, after the storage owner is initialized. */
bool efrp_idf_flash_store_bind(efrp_idf_flash_store_t *provider,
                               const efrp_idf_flash_store_config_t *config);
const efrp_aead_flash_store_t *efrp_idf_flash_store_callbacks(
    const efrp_idf_flash_store_t *provider);
