// SPDX-License-Identifier: Apache-2.0
#include "flash_store_fixture.h"
#include <string.h>

static efrp_result_t recover(void *context)
{
    efrp_test_flash_t *f = context;
    if (!f) return EFRP_INVALID_ARGUMENT;
    memset(f->bytes, 0xff, sizeof f->bytes);
    f->lease = 0; f->busy = false; f->quarantined = false; f->recovered = true;
    ++f->generation;
    return EFRP_OK;
}
static efrp_result_t begin(void *context, uint64_t *lease)
{
    efrp_test_flash_t *f = context;
    if (!f || !lease || !f->recovered || f->busy || f->quarantined) return EFRP_STORAGE_ERROR;
    memset(f->bytes, 0xff, sizeof f->bytes);
    f->lease = ++f->generation; f->busy = true; *lease = f->lease; ++f->begins;
    return EFRP_OK;
}
static efrp_result_t write_flash(void *context, uint64_t lease, size_t offset,
                                  const uint8_t *bytes, size_t length)
{
    efrp_test_flash_t *f = context;
    if (!f || !f->busy || f->quarantined || lease != f->lease || !bytes ||
        offset > sizeof f->bytes || length > sizeof f->bytes - offset) return EFRP_STORAGE_ERROR;
    memcpy(f->bytes + offset, bytes, length);
    return EFRP_OK;
}
static efrp_result_t read_flash(void *context, uint64_t lease, size_t offset,
                                 uint8_t *bytes, size_t length)
{
    efrp_test_flash_t *f = context;
    if (!f || !f->busy || f->quarantined || lease != f->lease || !bytes ||
        offset > sizeof f->bytes || length > sizeof f->bytes - offset) return EFRP_STORAGE_ERROR;
    memcpy(bytes, f->bytes + offset, length);
    return EFRP_OK;
}
static efrp_result_t clear(void *context, uint64_t lease)
{
    efrp_test_flash_t *f = context;
    if (!f || !f->busy || lease != f->lease) return EFRP_STORAGE_ERROR;
    if (f->fail_clear) { f->quarantined = true; return EFRP_STORAGE_ERROR; }
    f->busy = false; f->quarantined = false; f->lease = 0; ++f->clears;
    return EFRP_OK;
}
efrp_aead_flash_store_t efrp_test_flash_store(efrp_test_flash_t *flash)
{
    return (efrp_aead_flash_store_t){.context = flash, .recover = recover,
        .begin = begin, .write = write_flash, .read = read_flash, .clear = clear};
}
