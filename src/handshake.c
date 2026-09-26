// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_handshake.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#if defined(CONFIG_IDF_TARGET_ESP32) && CONFIG_IDF_TARGET_ESP32
#define EFRP_LOGIN_ARCH "xtensa"
#elif defined(CONFIG_IDF_TARGET_ESP32C3) && CONFIG_IDF_TARGET_ESP32C3
#define EFRP_LOGIN_ARCH "riscv32"
#elif defined(ESP_PLATFORM)
#error "ESP FRP login architecture requires an explicit supported IDF target"
#else
/* The host fixture models the C3 unless a target is selected explicitly. */
#define EFRP_LOGIN_ARCH "riscv32"
#endif

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void encode_random(const uint8_t random[32], char output[45])
{
    size_t at = 0;
    for (size_t i = 0; i < 32; i += 3) {
        uint32_t value = (uint32_t)random[i] << 16;
        if (i + 1 < 32) value |= (uint32_t)random[i + 1] << 8;
        if (i + 2 < 32) value |= random[i + 2];
        output[at++] = base64[(value >> 18) & 63]; output[at++] = base64[(value >> 12) & 63];
        output[at++] = base64[(value >> 6) & 63]; output[at++] = i + 2 < 32 ? base64[value & 63] : '=';
    }
    output[44] = 0;
}
static bool random_valid(const char *s)
{
    if (!s || strlen(s) != 44 || s[43] != '=') return false;
    for (size_t i = 0; i < 43; ++i) {
        const char *at = strchr(base64, s[i]);
        if (!at || (i == 42 && ((at - base64) & 3))) return false;
    }
    return true;
}
efrp_result_t efrp_token_auth(const uint8_t *token, size_t length, int64_t seconds, char output[33])
{
    if (!output) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(output, 33);
    if (!token || !length || length > EFRP_AEAD_MAX_TOKEN_BYTES || seconds <= 0) return EFRP_INVALID_ARGUMENT;
    char decimal[21]; int n = snprintf(decimal, sizeof decimal, "%" PRId64, seconds);
    if (n <= 0 || (size_t)n >= sizeof decimal) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_span_t parts[] = {{token, length}, {(const uint8_t *)decimal, (size_t)n}};
    uint8_t hash[16] = {0};
    efrp_result_t result = efrp_crypto_md5(parts, 2, hash);
    if (result == EFRP_OK) {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < 16; ++i) { output[2*i] = hex[hash[i] >> 4]; output[2*i+1] = hex[hash[i] & 15]; }
    }
    efrp_crypto_zero(hash, sizeof hash); return result;
}
static efrp_result_t ready(const efrp_handshake_t *h)
{
    if (!h || !h->active) return EFRP_INVALID_STATE;
    return h->failure;
}
static void clear_secret(efrp_handshake_t *h)
{
    efrp_aead_clear_keys(&h->keys); efrp_crypto_zero(h->token, sizeof h->token);
    efrp_crypto_zero(h->output, sizeof h->output); efrp_crypto_zero(h->client_hello, sizeof h->client_hello);
    if (h->storage) efrp_crypto_zero(h->storage, EFRP_HANDSHAKE_RX_BYTES);
    h->output_length = h->output_offset = h->token_length = h->hello_length = 0;
}
static efrp_result_t fail(efrp_handshake_t *h, efrp_result_t result)
{
    clear_secret(h); efrp_crypto_zero(h->run_id, sizeof h->run_id);
    h->failure = result; h->state = EFRP_HANDSHAKE_FAILED; return result;
}
static efrp_result_t accept_hello(efrp_handshake_t *h, const uint8_t *p, size_t length)
{
    cJSON *root = efrp_json_parse(p, length);
    const char *const root_fields[] = {"selected", "error"}, *const selections[] = {"message", "crypto"};
    const char *const messages[] = {"codec", "udpPacketCodec"}, *const cryptos[] = {"algorithm", "serverRandom"};
    efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (!efrp_json_shape(root, root_fields, 2)) goto done;
    const char *error = efrp_json_string(root, "error");
    if (!error) goto done;
    if (*error) { result = EFRP_NEGOTIATION_FAILED; goto done; }
    const cJSON *selected = efrp_json_field(root, "selected"), *message = efrp_json_field(selected, "message"), *crypto = efrp_json_field(selected, "crypto");
    if (!efrp_json_shape(selected, selections, 2) || !efrp_json_shape(message, messages, 2) || !efrp_json_shape(crypto, cryptos, 2)) goto done;
    if (!efrp_json_equals(message, "codec", "json") || !efrp_json_equals(message, "udpPacketCodec", "") ||
        !efrp_json_equals(crypto, "algorithm", "aes-256-gcm") || !random_valid(efrp_json_string(crypto, "serverRandom"))) {
        result = EFRP_NEGOTIATION_FAILED; goto done;
    }
    result = efrp_aead_derive(h->token, h->token_length, h->client_hello, h->hello_length, p, length, &h->keys);
    if (result == EFRP_OK) {
        efrp_crypto_zero(h->token, sizeof h->token); h->token_length = 0;
        efrp_crypto_zero(h->client_hello, sizeof h->client_hello); h->hello_length = 0;
        h->state = EFRP_HANDSHAKE_LOGIN;
    }
done:
    cJSON_Delete(root); return result;
}
static efrp_result_t accept_login(efrp_handshake_t *h, const uint8_t *p, size_t length)
{
    if (length < 2 || p[0] || p[1] != 2) return EFRP_PROTOCOL_ERROR;
    cJSON *root = efrp_json_parse(p + 2, length - 2);
    const char *const fields[] = {"version", "run_id", "error"};
    efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (!efrp_json_shape(root, fields, 3)) goto done;
    const char *error = efrp_json_string(root, "error"), *run_id = efrp_json_string(root, "run_id");
    if (!error || !run_id || !efrp_json_string(root, "version")) goto done;
    if (*error) { result = EFRP_LOGIN_REJECTED; goto done; }
    size_t n = strlen(run_id);
    if (!n || n >= sizeof h->run_id) goto done;
    memcpy(h->run_id, run_id, n + 1); h->state = EFRP_HANDSHAKE_DONE; result = EFRP_OK;
done:
    cJSON_Delete(root); return result;
}
static bool accept_frame(void *context, efrp_frame_kind_t kind, const uint8_t *p, size_t length)
{
    efrp_handshake_t *h = context; efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (h->state == EFRP_HANDSHAKE_HELLO && kind == EFRP_SERVER_HELLO) result = accept_hello(h, p, length);
    else if (h->state == EFRP_HANDSHAKE_LOGIN && kind == EFRP_MESSAGE) result = accept_login(h, p, length);
    if (result != EFRP_OK) h->failure = result;
    return result == EFRP_OK;
}
static bool config_string(const char *s)
{
    if (!s) return true;
    size_t n = 0; while (n <= 128 && s[n]) ++n;
    return n <= 128 && efrp_json_utf8((const uint8_t *)s, n);
}
static bool add_string(cJSON *object, const char *name, const char *value)
{
    return cJSON_AddStringToObject(object, name, value ? value : "") != NULL;
}
static void delete_login(cJSON *login)
{
    /* cJSON_Delete does not cleanse the copied authentication signature. */
    cJSON *auth_value = cJSON_GetObjectItemCaseSensitive(login, "privilege_key");
    if (auth_value && auth_value->valuestring) efrp_crypto_zero(auth_value->valuestring, strlen(auth_value->valuestring));
    cJSON_Delete(login);
}
efrp_result_t efrp_handshake_init(efrp_handshake_t *h, const efrp_handshake_config_t *c,
                                  uint8_t *storage, size_t capacity, uint64_t now)
{
    if (!h || !c || !storage || capacity < EFRP_HANDSHAKE_RX_BYTES || !c->token || !c->token_length ||
        c->token_length > EFRP_AEAD_MAX_TOKEN_BYTES || c->unix_seconds <= 0 ||
        now > UINT64_MAX - EFRP_HANDSHAKE_TIMEOUT_MS || !config_string(c->hostname) ||
        !config_string(c->user) || !config_string(c->client_id) || !config_string(c->previous_run_id)) return EFRP_INVALID_ARGUMENT;
    if (h->active) return EFRP_INVALID_STATE;
    *h = (efrp_handshake_t){.active = true, .storage = storage, .state = EFRP_HANDSHAKE_SEND,
        .deadline_ms = now + EFRP_HANDSHAKE_TIMEOUT_MS, .last_now_ms = now, .token_length = c->token_length};
    memset(storage, 0, EFRP_HANDSHAKE_RX_BYTES); memcpy(h->token, c->token, c->token_length);
    uint8_t random[32]; char encoded[45], auth[33];
    efrp_result_t result = efrp_crypto_random(random, sizeof random);
    if (result != EFRP_OK) return fail(h, result);
    encode_random(random, encoded); efrp_crypto_zero(random, sizeof random);
    int hello = snprintf((char *)h->client_hello, sizeof h->client_hello,
        "{\"bootstrap\":{\"transport\":\"tcp\",\"tls\":true,\"tcpMux\":true},"
        "\"capabilities\":{\"message\":{\"codecs\":[\"json\"]},\"crypto\":{"
        "\"algorithms\":[\"aes-256-gcm\"],\"clientRandom\":\"%s\"}}}", encoded);
    if (hello <= 0 || (size_t)hello >= sizeof h->client_hello) return fail(h, EFRP_CAPACITY_EXCEEDED);
    h->hello_length = (size_t)hello;
    result = efrp_token_auth(c->token, c->token_length, c->unix_seconds, auth);
    if (result != EFRP_OK) return fail(h, result);
    cJSON *login = cJSON_CreateObject();
    char timestamp[21]; snprintf(timestamp, sizeof timestamp, "%" PRId64, c->unix_seconds);
    bool built = login && add_string(login, "version", "esp-frp/0.1.0") && add_string(login, "os", "esp-idf") &&
        add_string(login, "arch", EFRP_LOGIN_ARCH) && add_string(login, "hostname", c->hostname) &&
        add_string(login, "user", c->user) && add_string(login, "client_id", c->client_id) &&
        add_string(login, "run_id", c->previous_run_id) && add_string(login, "privilege_key", auth) &&
        cJSON_AddRawToObject(login, "timestamp", timestamp) && cJSON_AddNumberToObject(login, "pool_count", 0);
    efrp_crypto_zero(auth, sizeof auth);
    size_t offset = 7 + 8 + h->hello_length;
    if (!built || !cJSON_PrintPreallocated(login, (char *)h->output + offset + 10,
                                         (int)(sizeof h->output - offset - 10), 0)) {
        delete_login(login); return fail(h, EFRP_CAPACITY_EXCEEDED);
    }
    delete_login(login);
    size_t login_length = strlen((char *)h->output + offset + 10);
    memcpy(h->output, efrp_wire_magic, 7);
    result = efrp_wire_header(EFRP_CLIENT_HELLO, h->hello_length, h->output + 7);
    if (result != EFRP_OK) return fail(h, result);
    memcpy(h->output + 15, h->client_hello, h->hello_length);
    result = efrp_wire_header(EFRP_MESSAGE, login_length + 2, h->output + offset);
    if (result != EFRP_OK) return fail(h, result);
    h->output[offset + 8] = 0; h->output[offset + 9] = 1;
    h->output_length = offset + 10 + login_length;
    result = efrp_wire_init(&h->frames, storage, EFRP_HANDSHAKE_RX_BYTES, false, accept_frame, h);
    return result == EFRP_OK ? EFRP_OK : fail(h, result);
}
efrp_result_t efrp_handshake_output(const efrp_handshake_t *h, const uint8_t **bytes, size_t *length)
{
    if (bytes) *bytes = NULL;
    if (length) *length = 0;
    if (!bytes || !length) return EFRP_INVALID_ARGUMENT;
    if (ready(h) != EFRP_OK) return ready(h);
    if (h->state != EFRP_HANDSHAKE_SEND) return EFRP_WOULD_BLOCK;
    *bytes = h->output + h->output_offset; *length = h->output_length - h->output_offset; return EFRP_OK;
}
efrp_result_t efrp_handshake_consume_output(efrp_handshake_t *h, size_t length)
{
    if (ready(h) != EFRP_OK) return ready(h);
    if (h->state != EFRP_HANDSHAKE_SEND) return EFRP_INVALID_STATE;
    if (length > h->output_length - h->output_offset) return EFRP_INVALID_ARGUMENT;
    efrp_crypto_zero(h->output + h->output_offset, length); h->output_offset += length;
    if (h->output_offset == h->output_length) {
        h->output_offset = h->output_length = 0; h->state = EFRP_HANDSHAKE_HELLO;
    }
    return EFRP_OK;
}
efrp_result_t efrp_handshake_feed(efrp_handshake_t *h, const uint8_t *bytes, size_t length, size_t *consumed)
{
    if (consumed) *consumed = 0;
    if (!consumed || (!bytes && length)) return EFRP_INVALID_ARGUMENT;
    if (ready(h) != EFRP_OK) return ready(h);
    if (h->state == EFRP_HANDSHAKE_SEND || h->state == EFRP_HANDSHAKE_DONE) return EFRP_WOULD_BLOCK;
    if (h->state != EFRP_HANDSHAKE_HELLO && h->state != EFRP_HANDSHAKE_LOGIN) return EFRP_INVALID_STATE;
    while (*consumed < length) {
        size_t used;
        efrp_result_t result = efrp_wire_feed_one(&h->frames, bytes + *consumed, length - *consumed, &used);
        *consumed += used;
        if (result != EFRP_OK) return fail(h, h->failure != EFRP_OK ? h->failure : result);
        if (h->state == EFRP_HANDSHAKE_DONE) break;
    }
    return EFRP_OK;
}
efrp_result_t efrp_handshake_tick(efrp_handshake_t *h, uint64_t now)
{
    if (ready(h) != EFRP_OK) return ready(h);
    if (now < h->last_now_ms) return EFRP_INVALID_ARGUMENT;
    h->last_now_ms = now;
    if (h->state != EFRP_HANDSHAKE_DONE && h->state != EFRP_HANDSHAKE_TAKEN && now >= h->deadline_ms)
        return fail(h, EFRP_TIMEOUT);
    return EFRP_OK;
}
efrp_result_t efrp_handshake_finish(efrp_handshake_t *h)
{
    if (ready(h) != EFRP_OK) return ready(h);
    return h->state == EFRP_HANDSHAKE_DONE || h->state == EFRP_HANDSHAKE_TAKEN ? EFRP_OK : fail(h, EFRP_TRUNCATED);
}
efrp_result_t efrp_handshake_take_result(efrp_handshake_t *h, efrp_aead_keys_t *keys, char run_id[EFRP_RUN_ID_BYTES])
{
    if (!keys || !run_id) return EFRP_INVALID_ARGUMENT;
    if (ready(h) != EFRP_OK) return ready(h);
    if (h->state != EFRP_HANDSHAKE_DONE) return EFRP_INVALID_STATE;
    *keys = h->keys; memcpy(run_id, h->run_id, sizeof h->run_id);
    clear_secret(h); efrp_crypto_zero(h->run_id, sizeof h->run_id);
    /* The caller may immediately reuse this buffer for AEAD. A later destroy
     * must not wipe storage whose ownership has already been returned. */
    h->storage = NULL; h->frames = (efrp_wire_reader_t){0};
    h->state = EFRP_HANDSHAKE_TAKEN; return EFRP_OK;
}
void efrp_handshake_destroy(efrp_handshake_t *h)
{
    if (!h) return;
    if (h->active) clear_secret(h);
    efrp_crypto_zero(h, sizeof *h);
}
