// SPDX-License-Identifier: Apache-2.0
#include "stcp_visitor_internal.h"
#include "esp_frp_handshake.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "memory_internal.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

struct efrp_stcp_visitor_owned {
    const char *proxy_name, *secret_key;
    size_t allocation_bytes, secret_bytes;
};

static bool required_text(const char *text, size_t maximum, size_t *length)
{
    *length = 0;
    if (!text) return false;
    while (*length <= maximum && text[*length]) ++*length;
    return *length && *length <= maximum && efrp_json_utf8((const uint8_t *)text, *length);
}

static efrp_result_t validate_identity(const char *target, const char *secret,
    size_t *target_length, size_t *secret_length)
{
    return required_text(target, EFRP_STCP_VISITOR_NAME_MAX_BYTES, target_length) &&
        required_text(secret, EFRP_STCP_VISITOR_SECRET_MAX_BYTES, secret_length)
        ? EFRP_OK : EFRP_INVALID_ARGUMENT;
}

efrp_result_t efrp_stcp_visitor_validate(const char *target, const char *secret,
    const uint8_t address[4], uint16_t port)
{
    size_t target_length, secret_length;
    if (!address || !address[0] || address[0] >= 224 || !port) return EFRP_INVALID_ARGUMENT;
    return validate_identity(target, secret, &target_length, &secret_length);
}

efrp_result_t efrp_stcp_visitor_owned_clone(const char *target, const char *secret,
    efrp_stcp_visitor_owned_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    size_t target_length, secret_length;
    efrp_result_t result = validate_identity(target, secret, &target_length, &secret_length);
    if (result != EFRP_OK) return result;
    size_t bytes = sizeof(efrp_stcp_visitor_owned_t) + target_length + secret_length + 2;
    efrp_stcp_visitor_owned_t *owner = efrp_heap_calloc(bytes);
    if (!owner) return EFRP_NO_MEMORY;
    owner->allocation_bytes = bytes;
    owner->secret_bytes = secret_length + 1;
    char *next = (char *)(owner + 1);
    owner->proxy_name = next; memcpy(next, target, target_length + 1); next += target_length + 1;
    owner->secret_key = next; memcpy(next, secret, secret_length + 1);
    *out = owner;
    return EFRP_OK;
}

const char *efrp_stcp_visitor_owned_proxy_name(const efrp_stcp_visitor_owned_t *owner)
{
    return owner ? owner->proxy_name : NULL;
}
const char *efrp_stcp_visitor_owned_secret_key(const efrp_stcp_visitor_owned_t *owner)
{
    return owner ? owner->secret_key : NULL;
}
void efrp_stcp_visitor_owned_clear_secret(efrp_stcp_visitor_owned_t *owner)
{
    if (owner) efrp_crypto_zero((void *)owner->secret_key, owner->secret_bytes);
}
void efrp_stcp_visitor_owned_destroy(efrp_stcp_visitor_owned_t **owner)
{
    if (!owner || !*owner) return;
    efrp_stcp_visitor_owned_t *value = *owner;
    size_t bytes = value->allocation_bytes;
    efrp_crypto_zero(value, bytes); free(value); *owner = NULL;
}

static size_t escaped_length(const char *text)
{
    size_t length = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\' || *p == '\b' || *p == '\f' ||
            *p == '\n' || *p == '\r' || *p == '\t') length += 2;
        else length += *p < 32 ? 6u : 1u;
    }
    return length;
}
static bool add_reference(cJSON *root, const char *field, const char *value)
{
    cJSON *item = cJSON_CreateStringReference(value);
    if (!item) return false;
    if (cJSON_AddItemToObject(root, field, item)) return true;
    cJSON_Delete(item); return false;
}

efrp_result_t efrp_stcp_visitor_encode_request(const char *run_id,
    const char *target, const char *secret, int64_t seconds,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (capacity > EFRP_STCP_VISITOR_REQUEST_MAX_BYTES) capacity = EFRP_STCP_VISITOR_REQUEST_MAX_BYTES;
    if (output) efrp_crypto_zero(output, capacity);
    if (!output || !length) return EFRP_INVALID_ARGUMENT;
    size_t run_length, target_length, secret_length;
    efrp_result_t result = validate_identity(target, secret, &target_length, &secret_length);
    if (result != EFRP_OK || !required_text(run_id, EFRP_RUN_ID_BYTES - 1u, &run_length) || seconds <= 0)
        return EFRP_INVALID_ARGUMENT;
    char timestamp[21], signature[33] = {0};
    int digits = snprintf(timestamp, sizeof timestamp, "%" PRId64, seconds);
    if (digits <= 0 || (size_t)digits >= sizeof timestamp) return EFRP_INVALID_ARGUMENT;
    size_t json_length = sizeof "{\"run_id\":\"\",\"proxy_name\":\"\",\"sign_key\":\"\",\"timestamp\":1,\"use_encryption\":false,\"use_compression\":false}" - 1;
    json_length += escaped_length(run_id) + escaped_length(target) + 32 + (size_t)digits - 1;
    size_t required = EFRP_WIRE_MAGIC_SIZE + 10 + json_length;
    if (required + 5 > capacity) return EFRP_CAPACITY_EXCEEDED;
    result = efrp_token_auth((const uint8_t *)secret, secret_length, seconds, signature);
    if (result != EFRP_OK) return result;
    cJSON *root = cJSON_CreateObject();
    bool built = root && add_reference(root, "run_id", run_id) && add_reference(root, "proxy_name", target) &&
        add_reference(root, "sign_key", signature) && cJSON_AddRawToObject(root, "timestamp", timestamp) &&
        cJSON_AddBoolToObject(root, "use_encryption", false) && cJSON_AddBoolToObject(root, "use_compression", false);
    if (!built) result = EFRP_NO_MEMORY;
    else if (!cJSON_PrintPreallocated(root, (char *)output + 17, (int)capacity - 17, 0))
        result = EFRP_CAPACITY_EXCEEDED;
    cJSON_Delete(root); efrp_crypto_zero(signature, sizeof signature);
    if (result == EFRP_OK && strlen((char *)output + 17) != json_length) result = EFRP_PROTOCOL_ERROR;
    if (result == EFRP_OK) result = efrp_wire_header(EFRP_MESSAGE, json_length + 2, output + EFRP_WIRE_MAGIC_SIZE);
    if (result != EFRP_OK) { efrp_crypto_zero(output, capacity); return result; }
    memcpy(output, efrp_wire_magic, EFRP_WIRE_MAGIC_SIZE);
    output[15] = 0; output[16] = 9; *length = required;
    return EFRP_OK;
}

efrp_result_t efrp_stcp_visitor_accept_response(efrp_frame_kind_t kind,
    const uint8_t *payload, size_t length, const char *target)
{
    size_t target_length;
    if (!required_text(target, EFRP_STCP_VISITOR_NAME_MAX_BYTES, &target_length)) return EFRP_INVALID_ARGUMENT;
    if (kind != EFRP_MESSAGE || !payload || length < 2 || length - 2 > EFRP_JSON_MAX_BYTES ||
        payload[0] || payload[1] != 10) return EFRP_PROTOCOL_ERROR;
    cJSON *root = efrp_json_parse(payload + 2, length - 2, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    const char *const fields[] = {"proxy_name", "error"};
    const char *error = efrp_json_string(root, "error");
    efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (efrp_json_shape(root, fields, 2) && error && efrp_json_equals(root, "proxy_name", target))
        result = *error ? EFRP_WORK_REJECTED : EFRP_OK;
    cJSON_Delete(root);
    return result;
}
