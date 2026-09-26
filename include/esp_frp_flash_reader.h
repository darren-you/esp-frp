// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_aead.h"
#ifdef __cplusplus
extern "C" {
#endif

/* The owner supplies one exclusive, eraseable 64 KiB ciphertext scratch area.
 * begin erases and leases it before returning a fresh nonzero lease; failed
 * begin must revoke access. All I/O is exact, byte addressed, and rejects a
 * stale lease. clear revokes the lease and quarantines old ciphertext; it may
 * defer physical erase to the next begin. On clear failure it keeps the area
 * quarantined until a retry or boot recovery succeeds. recover is called at
 * boot before FRP sessions, revokes old leases and erases interrupted bytes.
 * Callbacks must not reenter the reader. */
typedef struct {
    void *context;
    efrp_result_t (*recover)(void *context);
    efrp_result_t (*begin)(void *context, uint64_t *lease);
    efrp_result_t (*write)(void *context, uint64_t lease, size_t offset,
                           const uint8_t *bytes, size_t length);
    efrp_result_t (*read)(void *context, uint64_t lease, size_t offset,
                          uint8_t *bytes, size_t length);
    efrp_result_t (*clear)(void *context, uint64_t lease);
} efrp_aead_flash_store_t;

/* Boot owner calls once before creating an FRP session; the store provider
 * must reject begin until this has succeeded in the current boot. */
efrp_result_t efrp_aead_flash_store_recover(const efrp_aead_flash_store_t *store);

/* One owner and one record at a time. Fields are exposed for static allocation,
 * not mutation. The caller owns exactly 4096 bytes of exclusive, unshared
 * byte-accessible RAM. Records up to 4096 plaintext bytes authenticate there
 * and never erase Flash; larger records use exclusive ciphertext scratch.
 * Every Flash window is exposed only after a complete GCM and SHA-256 recheck
 * of the same record. No other task may inspect the window during calls: it
 * temporarily contains untrusted decrypt output before final verification.
 * The application must arbitrate a real partition. */
typedef struct {
    uint8_t key[32], stream_nonce[12], nonce[12], record_nonce[12];
    uint8_t header[4], tag[16], digest[32];
    uint8_t *window;
    efrp_aead_flash_store_t store;
    uint64_t lease, records, record_sequence;
    /* Monotonic for this reader lifetime; failed exact reads are not counted. */
    uint64_t flash_records, flash_passes, flash_read_bytes;
    size_t capacity, nonce_used, header_used, body_used, body_expected;
    size_t plain_used, plain_offset, window_used, window_offset;
    bool active, leased, ready, in_memory;
    efrp_result_t failure;
} efrp_aead_flash_reader_t;

/* Zero-initialize reader before init. recover must have succeeded in this
 * boot; init cannot prove that platform fact, so the provider and boot owner
 * must enforce it. Keep reader and exclusive window alive through a successful
 * close. If close returns STORAGE_ERROR, both remain owned by the caller and
 * must be retained for retry while the provider quarantines the lease. */
efrp_result_t efrp_aead_flash_reader_init(efrp_aead_flash_reader_t *reader,
                                          const uint8_t key[32],
                                          const efrp_aead_flash_store_t *store,
                                          uint8_t *window, size_t capacity);
efrp_result_t efrp_aead_flash_feed(efrp_aead_flash_reader_t *reader,
                                   const uint8_t *bytes, size_t length,
                                   size_t *consumed);
/* This may reread and verify the entire ciphertext before returning a window.
 * The pointer is borrowed until consume or the next reader operation. */
efrp_result_t efrp_aead_flash_plaintext(efrp_aead_flash_reader_t *reader,
                                        const uint8_t **bytes, size_t *length);
efrp_result_t efrp_aead_flash_consume_plaintext(efrp_aead_flash_reader_t *reader,
                                                size_t length);
efrp_result_t efrp_aead_flash_finish(const efrp_aead_flash_reader_t *reader);
/* A failed clear leaves the lease quarantined; keep the reader and retry. */
efrp_result_t efrp_aead_flash_reader_close(efrp_aead_flash_reader_t *reader);
#ifdef __cplusplus
}
#endif
