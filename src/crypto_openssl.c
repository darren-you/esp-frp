// SPDX-License-Identifier: Apache-2.0
// Host verification backend only; ESP-IDF always builds crypto_psa.c.
#include "crypto_backend.h"
#include "word_storage.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <string.h>
#include <limits.h>

static efrp_result_t digest(const efrp_crypto_span_t *spans, size_t count, uint8_t *output,
                            unsigned size, const EVP_MD *algorithm)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); unsigned n = 0;
    if (!ctx) return EFRP_CRYPTO_ERROR;
    int ok = EVP_DigestInit_ex(ctx, algorithm, NULL);
    for (size_t i = 0; i < count && ok == 1; ++i) ok = EVP_DigestUpdate(ctx, spans[i].bytes, spans[i].length);
    if (ok == 1) ok = EVP_DigestFinal_ex(ctx, output, &n);
    EVP_MD_CTX_free(ctx);
    return ok == 1 && n == size ? EFRP_OK : EFRP_CRYPTO_ERROR;
}
efrp_result_t efrp_crypto_hash(const efrp_crypto_span_t *spans, size_t count, uint8_t output[32])
{
    return digest(spans, count, output, 32, EVP_sha256());
}
efrp_result_t efrp_crypto_md5(const efrp_crypto_span_t *spans, size_t count, uint8_t output[16])
{
    return digest(spans, count, output, 16, EVP_md5());
}
efrp_result_t efrp_crypto_hkdf(const uint8_t *token, size_t length, const uint8_t salt[32],
                              const char *info, uint8_t output[32])
{
    EVP_KDF *algorithm = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!algorithm) return EFRP_CRYPTO_ERROR;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(algorithm); EVP_KDF_free(algorithm);
    if (!ctx) return EFRP_CRYPTO_ERROR;
    char digest[] = "SHA256"; int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)token, length),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, 32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };
    int ok = EVP_KDF_derive(ctx, output, 32, params); EVP_KDF_CTX_free(ctx);
    return ok == 1 ? EFRP_OK : EFRP_CRYPTO_ERROR;
}
efrp_result_t efrp_crypto_random(uint8_t *output, size_t length)
{
    if (length > INT_MAX) return EFRP_CRYPTO_ERROR;
    return RAND_bytes(output, (int)length) == 1 ? EFRP_OK : EFRP_CRYPTO_ERROR;
}
efrp_result_t efrp_crypto_gcm(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t aad[16], uint8_t *buffer, size_t length)
{
    if (length > EFRP_AEAD_MAX_PLAINTEXT) return EFRP_INVALID_ARGUMENT;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return EFRP_CRYPTO_ERROR;
    int n = 0, tail = 0, ignore = 0;
    efrp_result_t result = EFRP_CRYPTO_ERROR;
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce, encrypt ? 1 : 0) != 1 ||
        EVP_CipherUpdate(ctx, NULL, &ignore, aad, 16) != 1) goto done;
    if (!encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, buffer + length) != 1) goto done;
    if (EVP_CipherUpdate(ctx, buffer, &n, buffer, (int)length) != 1 || n != (int)length) goto done;
    if (EVP_CipherFinal_ex(ctx, buffer + length, &tail) != 1) {
        if (!encrypt) result = EFRP_AUTHENTICATION_FAILED;
        goto done;
    }
    if (tail) goto done;
    if (encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, buffer + length) != 1) goto done;
    result = EFRP_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}
efrp_result_t efrp_crypto_gcm_decrypt_chunks(const uint8_t key[32], const uint8_t nonce[12],
                                            const uint8_t aad[16], uint8_t *const chunks[],
                                            const size_t sizes[], size_t count, const uint8_t tag[16],
                                            bool words_only)
{
    if (count > EFRP_AEAD_RX_MAX_CHUNKS) return EFRP_INVALID_ARGUMENT;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return EFRP_CRYPTO_ERROR;
    int n = 0, tail = 0; uint8_t final[16] = {0}, input[512], output[512];
    efrp_result_t result = EFRP_CRYPTO_ERROR;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &n, aad, 16) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1) goto done;
    for (size_t i = 0; i < count; ++i) {
        if (!chunks[i] || sizes[i] > EFRP_AEAD_RX_CHUNK_BYTES) goto done;
        if (!words_only) {
            if (EVP_DecryptUpdate(ctx, chunks[i], &n, chunks[i], (int)sizes[i]) != 1 || n != (int)sizes[i]) goto done;
        } else for (size_t offset = 0; offset < sizes[i];) {
            size_t take = sizes[i] - offset;
            if (take > sizeof input) take = sizeof input;
            efrp_words_load(chunks[i], offset, input, take);
            if (EVP_DecryptUpdate(ctx, output, &n, input, (int)take) != 1 || n != (int)take) goto done;
            efrp_words_store(chunks[i], offset, output, take);
            offset += take;
        }
    }
    if (EVP_DecryptFinal_ex(ctx, final, &tail) != 1) result = EFRP_AUTHENTICATION_FAILED;
    else if (!tail) result = EFRP_OK;
done:
    efrp_crypto_zero(final, sizeof final);
    efrp_crypto_zero(input, sizeof input); efrp_crypto_zero(output, sizeof output);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

static void copy_verified_window(uint8_t *window, size_t window_offset, size_t window_length,
                                 size_t produced, const uint8_t *output, size_t length)
{
    if (!window_length || !length) return;
    size_t first = produced > window_offset ? produced : window_offset;
    size_t last = produced + length < window_offset + window_length ?
        produced + length : window_offset + window_length;
    if (first < last) memcpy(window + first - window_offset, output + first - produced, last - first);
}
efrp_result_t efrp_crypto_gcm_decrypt_store(const uint8_t key[32], const uint8_t nonce[12],
                                           const uint8_t aad[16], uint64_t sequence,
                                           efrp_crypto_store_read_t read_store, void *context,
                                           size_t plain_length, const uint8_t tag[16],
                                           size_t window_offset, uint8_t *window, size_t window_length,
                                           const uint8_t expected_digest[32], uint8_t digest[32])
{
    if (!key || !nonce || !aad || !read_store || !tag || !digest ||
        plain_length > EFRP_AEAD_MAX_PLAINTEXT || window_offset > plain_length ||
        window_length > plain_length - window_offset || (window_length && !window))
        return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(digest, 32);
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    uint8_t input[512] = {0}, output[512] = {0}, final[16] = {0};
    uint8_t sequence_be[8], actual_digest[32] = {0};
    for (size_t i = 0; i < sizeof sequence_be; ++i)
        sequence_be[i] = (uint8_t)(sequence >> (56u - 8u * i));
    efrp_result_t result = EFRP_CRYPTO_ERROR;
    int n = 0, tail = 0; unsigned hash_length = 0;
    if (!cipher || !hash ||
        EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(cipher, NULL, &n, aad, 16) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1 ||
        EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(hash, aad, 16) != 1 || EVP_DigestUpdate(hash, nonce, 12) != 1 ||
        EVP_DigestUpdate(hash, sequence_be, sizeof sequence_be) != 1 ||
        EVP_DigestUpdate(hash, tag, 16) != 1) goto done;
    for (size_t offset = 0; offset < plain_length;) {
        size_t take = plain_length - offset;
        if (take > sizeof input) take = sizeof input;
        if (read_store(context, offset, input, take) != EFRP_OK) {
            result = EFRP_STORAGE_ERROR; goto done;
        }
        if (EVP_DigestUpdate(hash, input, take) != 1 ||
            EVP_DecryptUpdate(cipher, output, &n, input, (int)take) != 1 || n != (int)take)
            goto done;
        copy_verified_window(window, window_offset, window_length, offset, output, (size_t)n);
        offset += take;
    }
    if (EVP_DecryptFinal_ex(cipher, final, &tail) != 1) {
        result = EFRP_AUTHENTICATION_FAILED; goto done;
    }
    if (tail != 0 || EVP_DigestFinal_ex(hash, actual_digest, &hash_length) != 1 || hash_length != 32)
        goto done;
    if (expected_digest) {
        unsigned mismatch = 0;
        for (size_t i = 0; i < 32; ++i) mismatch |= expected_digest[i] ^ actual_digest[i];
        if (mismatch) { result = EFRP_STORAGE_ERROR; goto done; }
    }
    memcpy(digest, actual_digest, 32); result = EFRP_OK;
done:
    if (result != EFRP_OK && window && window_length) efrp_crypto_zero(window, window_length);
    efrp_crypto_zero(input, sizeof input); efrp_crypto_zero(output, sizeof output);
    efrp_crypto_zero(final, sizeof final); efrp_crypto_zero(actual_digest, sizeof actual_digest);
    efrp_crypto_zero(sequence_be, sizeof sequence_be);
    EVP_MD_CTX_free(hash); EVP_CIPHER_CTX_free(cipher);
    return result;
}
