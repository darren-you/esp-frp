// SPDX-License-Identifier: Apache-2.0
#include "crypto_backend.h"
#include "word_storage.h"
#include "psa/crypto.h"
#include <string.h>

static efrp_result_t outcome(psa_status_t status)
{
    if (status == PSA_SUCCESS) return EFRP_OK;
    return status == PSA_ERROR_INVALID_SIGNATURE ? EFRP_AUTHENTICATION_FAILED : EFRP_CRYPTO_ERROR;
}
static efrp_result_t digest(const efrp_crypto_span_t *spans, size_t count, uint8_t *output,
                            size_t size, psa_algorithm_t algorithm)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t status = psa_crypto_init(); size_t n = 0;
    if (status == PSA_SUCCESS) status = psa_hash_setup(&op, algorithm);
    for (size_t i = 0; i < count && status == PSA_SUCCESS; ++i)
        status = psa_hash_update(&op, spans[i].bytes, spans[i].length);
    if (status == PSA_SUCCESS) status = psa_hash_finish(&op, output, size, &n);
    psa_status_t cleanup = psa_hash_abort(&op);
    if (cleanup != PSA_SUCCESS || (status == PSA_SUCCESS && n != size)) status = PSA_ERROR_BAD_STATE;
    return outcome(status);
}
efrp_result_t efrp_crypto_hash(const efrp_crypto_span_t *spans, size_t count, uint8_t output[32])
{
    return digest(spans, count, output, 32, PSA_ALG_SHA_256);
}
efrp_result_t efrp_crypto_md5(const efrp_crypto_span_t *spans, size_t count, uint8_t output[16])
{
    return digest(spans, count, output, 16, PSA_ALG_MD5);
}
efrp_result_t efrp_crypto_hkdf(const uint8_t *token, size_t length, const uint8_t salt[32],
                              const char *info, uint8_t output[32])
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status = psa_crypto_init();
    if (status == PSA_SUCCESS) status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS) status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, 32);
    if (status == PSA_SUCCESS) status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, token, length);
    if (status == PSA_SUCCESS) status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *)info, strlen(info));
    if (status == PSA_SUCCESS) status = psa_key_derivation_output_bytes(&op, output, 32);
    if (psa_key_derivation_abort(&op) != PSA_SUCCESS) status = PSA_ERROR_BAD_STATE;
    return outcome(status);
}
efrp_result_t efrp_crypto_random(uint8_t *output, size_t length)
{
    psa_status_t status = psa_crypto_init();
    if (status == PSA_SUCCESS) status = psa_generate_random(output, length);
    return outcome(status);
}
efrp_result_t efrp_crypto_gcm(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t aad[16], uint8_t *buffer, size_t plain_length)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    uint8_t input[512], output[PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(512)], tag[16];
    _Static_assert(sizeof output <= 1024, "Review AEAD chunk workspace after SDK changes");
    size_t consumed = 0, produced = 0, n = 0, tag_length = 0;
    psa_status_t status = psa_crypto_init();
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_usage_flags(&attributes, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    if (status == PSA_SUCCESS) status = psa_import_key(&attributes, key, 32, &id);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS) status = encrypt ? psa_aead_encrypt_setup(&op, id, PSA_ALG_GCM) :
        psa_aead_decrypt_setup(&op, id, PSA_ALG_GCM);
    if (status == PSA_SUCCESS) status = psa_aead_set_nonce(&op, nonce, 12);
    if (status == PSA_SUCCESS) status = psa_aead_set_lengths(&op, 16, plain_length);
    if (status == PSA_SUCCESS) status = psa_aead_update_ad(&op, aad, 16);
    if (!encrypt) memcpy(tag, buffer + plain_length, 16);
    /* SDK exclusive-buffer mode does not promise overlapping buffers.
     * Every PSA call gets disjoint input/output; only copy verified bounds back.
     * Plaintext remains private to the record layer until final tag verification. */
    while (consumed < plain_length && status == PSA_SUCCESS) {
        size_t take = plain_length - consumed;
        if (take > sizeof input) take = sizeof input;
        memcpy(input, buffer + consumed, take);
        status = psa_aead_update(&op, input, take, output, sizeof output, &n);
        consumed += take;
        if (status == PSA_SUCCESS && n > consumed - produced) status = PSA_ERROR_BAD_STATE;
        if (status == PSA_SUCCESS) { memcpy(buffer + produced, output, n); produced += n; }
    }
    if (status == PSA_SUCCESS) {
        if (encrypt) status = psa_aead_finish(&op, output, sizeof output, &n, tag, sizeof tag, &tag_length);
        else status = psa_aead_verify(&op, output, sizeof output, &n, tag, sizeof tag);
        if (status == PSA_SUCCESS && (n != plain_length - produced || (encrypt && tag_length != 16)))
            status = PSA_ERROR_BAD_STATE;
        if (status == PSA_SUCCESS) {
            memcpy(buffer + produced, output, n);
            if (encrypt) memcpy(buffer + plain_length, tag, 16);
        }
    }
    if (psa_aead_abort(&op) != PSA_SUCCESS) status = PSA_ERROR_BAD_STATE;
    if (!mbedtls_svc_key_id_is_null(id) && psa_destroy_key(id) != PSA_SUCCESS) status = PSA_ERROR_BAD_STATE;
    efrp_crypto_zero(input, sizeof input); efrp_crypto_zero(output, sizeof output); efrp_crypto_zero(tag, sizeof tag);
    return outcome(status);
}
static void chunk_copy(uint8_t *const chunks[], const size_t sizes[], size_t count,
                       size_t offset, uint8_t *buffer, size_t length, bool write_chunks,
                       bool words_only)
{
    for (size_t i = 0; i < count && length; ++i) {
        if (offset >= sizes[i]) { offset -= sizes[i]; continue; }
        size_t n = sizes[i] - offset;
        if (n > length) n = length;
        if (words_only) {
            if (write_chunks) efrp_words_store(chunks[i], offset, buffer, n);
            else efrp_words_load(chunks[i], offset, buffer, n);
        } else if (write_chunks) memcpy(chunks[i] + offset, buffer, n);
        else memcpy(buffer, chunks[i] + offset, n);
        buffer += n; length -= n; offset = 0;
    }
}
efrp_result_t efrp_crypto_gcm_decrypt_chunks(const uint8_t key[32], const uint8_t nonce[12],
                                            const uint8_t aad[16], uint8_t *const chunks[],
                                            const size_t sizes[], size_t count, const uint8_t tag[16],
                                            bool words_only)
{
    size_t total = 0;
    if (count > EFRP_AEAD_RX_MAX_CHUNKS) return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < count; ++i) {
        if (!chunks[i] || !sizes[i] || sizes[i] > EFRP_AEAD_RX_CHUNK_BYTES ||
            total > EFRP_AEAD_MAX_PLAINTEXT - sizes[i]) return EFRP_INVALID_ARGUMENT;
        total += sizes[i];
    }
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    uint8_t input[512], output[PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(512)];
    _Static_assert(sizeof output <= 1024, "Review AEAD chunk workspace after SDK changes");
    size_t consumed = 0, produced = 0, n = 0;
    psa_status_t status = psa_crypto_init();
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    if (status == PSA_SUCCESS) status = psa_import_key(&attributes, key, 32, &id);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS) status = psa_aead_decrypt_setup(&op, id, PSA_ALG_GCM);
    if (status == PSA_SUCCESS) status = psa_aead_set_nonce(&op, nonce, 12);
    if (status == PSA_SUCCESS) status = psa_aead_set_lengths(&op, 16, total);
    if (status == PSA_SUCCESS) status = psa_aead_update_ad(&op, aad, 16);
    while (consumed < total && status == PSA_SUCCESS) {
        size_t take = total - consumed;
        if (take > sizeof input) take = sizeof input;
        chunk_copy(chunks, sizes, count, consumed, input, take, false, words_only);
        status = psa_aead_update(&op, input, take, output, sizeof output, &n);
        consumed += take;
        if (status == PSA_SUCCESS && n > consumed - produced) status = PSA_ERROR_BAD_STATE;
        if (status == PSA_SUCCESS) {
            chunk_copy(chunks, sizes, count, produced, output, n, true, words_only); produced += n;
        }
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_verify(&op, output, sizeof output, &n, tag, 16);
        if (status == PSA_SUCCESS && n != total - produced) status = PSA_ERROR_BAD_STATE;
        if (status == PSA_SUCCESS) chunk_copy(chunks, sizes, count, produced, output, n, true, words_only);
    }
    if (psa_aead_abort(&op) != PSA_SUCCESS) status = PSA_ERROR_BAD_STATE;
    if (!mbedtls_svc_key_id_is_null(id) && psa_destroy_key(id) != PSA_SUCCESS) status = PSA_ERROR_BAD_STATE;
    efrp_crypto_zero(input, sizeof input); efrp_crypto_zero(output, sizeof output);
    return outcome(status);
}
