// SPDX-License-Identifier: Apache-2.0
#include "xtcp_codec.h"
#include "xtcp_binding_internal.h"
#include "json_internal.h"
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool text(const char *s, size_t minimum, size_t maximum)
{
    if (!s) return false;
    size_t n = 0; while (n <= maximum && s[n]) ++n;
    if (n < minimum || n > maximum || !efrp_json_utf8((const uint8_t *)s, n)) return false;
    for (size_t i = 0; i < n; ++i) if ((uint8_t)s[i] < 32 || (uint8_t)s[i] == 127) return false;
    return true;
}
static bool hex32(const char *s)
{
    if (!text(s, 64, 64)) return false;
    for (size_t i = 0; i < 64; ++i) if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static bool reference(cJSON *root, const char *key, const char *value)
{
    cJSON *item = cJSON_CreateStringReference(value);
    if (item && cJSON_AddItemToObject(root, key, item)) return true;
    cJSON_Delete(item); return false;
}
static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(const uint8_t *bytes, size_t n, char *output)
{
    size_t at = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t x = (uint32_t)bytes[i] << 16;
        if (i + 1 < n) x |= (uint32_t)bytes[i + 1] << 8;
        if (i + 2 < n) x |= bytes[i + 2];
        output[at++] = alphabet[(x >> 18) & 63u]; output[at++] = alphabet[(x >> 12) & 63u];
        output[at++] = i + 1 < n ? alphabet[(x >> 6) & 63u] : '=';
        output[at++] = i + 2 < n ? alphabet[x & 63u] : '=';
    }
    output[at] = 0;
}
static int base64_value(char c)
{
    const char *p = strchr(alphabet, c);
    return c && p ? (int)(p - alphabet) : -1;
}
static bool base64_decode(const char *s, uint8_t *out, size_t cap, size_t *length)
{
    *length = 0;
    if (!s) return false;
    size_t n = strlen(s);
    if (!n || n % 4 || n / 4 > (cap + 2) / 3) return false;
    for (size_t i = 0; i < n; i += 4) {
        int a = base64_value(s[i]), b = base64_value(s[i + 1]);
        bool pad2 = s[i + 2] == '=', pad3 = s[i + 3] == '=';
        int c = pad2 ? 0 : base64_value(s[i + 2]), d = pad3 ? 0 : base64_value(s[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad3) ||
            ((pad2 || pad3) && i + 4 != n) || (pad2 && (b & 15)) || (!pad2 && pad3 && (c & 3))) return false;
        uint32_t x = (uint32_t)a << 18 | (uint32_t)b << 12 | (uint32_t)c << 6 | (uint32_t)d;
        size_t count = pad2 ? 1u : pad3 ? 2u : 3u;
        if (count > cap - *length) return false;
        out[(*length)++] = (uint8_t)(x >> 16);
        if (count > 1) out[(*length)++] = (uint8_t)(x >> 8);
        if (count > 2) out[(*length)++] = (uint8_t)x;
    }
    return true;
}
static bool endpoint_valid(const efrp_xtcp_endpoint_t *e)
{
    return e && e->ipv4[0] && e->ipv4[0] < 224 && e->port;
}
static bool add_addresses(cJSON *root, const char *key, const efrp_xtcp_endpoint_t *addresses, size_t count)
{
    if (!count) return true;
    cJSON *array = cJSON_AddArrayToObject(root, key);
    if (!array) return false;
    for (size_t i = 0; i < count; ++i) {
        char address[22];
        int n = snprintf(address, sizeof address, "%u.%u.%u.%u:%u", (unsigned)addresses[i].ipv4[0],
            (unsigned)addresses[i].ipv4[1], (unsigned)addresses[i].ipv4[2], (unsigned)addresses[i].ipv4[3], (unsigned)addresses[i].port);
        if (n < 1 || (size_t)n >= sizeof address) return false;
        cJSON *item = cJSON_CreateString(address);
        if (!item || !cJSON_AddItemToArray(array, item)) { cJSON_Delete(item); return false; }
    }
    return true;
}
static efrp_result_t frame(cJSON *root, uint8_t type, uint8_t *output, size_t capacity, size_t *length)
{
    char *json = cJSON_PrintUnformatted(root);
    if (!json) return EFRP_NO_MEMORY;
    size_t n = strlen(json);
    efrp_result_t result = EFRP_CAPACITY_EXCEEDED;
    if (n <= EFRP_XTCP_SIGNAL_MAX_BYTES - 10u && capacity >= n + 10u) {
        result = efrp_wire_header(EFRP_MESSAGE, n + 2, output);
        if (result == EFRP_OK) { output[8] = 0; output[9] = type; memcpy(output + 10, json, n); *length = n + 10; }
    }
    efrp_crypto_zero(json, n); cJSON_free(json); return result;
}

efrp_result_t efrp_xtcp_codec_request(const efrp_xtcp_signal_request_t *r, uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (capacity > EFRP_XTCP_SIGNAL_MAX_BYTES) capacity = EFRP_XTCP_SIGNAL_MAX_BYTES;
    if (output) efrp_crypto_zero(output, capacity);
    if (!r || !output || !length || !text(r->transaction_id, 1, 64) || !text(r->proxy_name, 1, 128) ||
        !r->certificate || !r->certificate_length || r->certificate_length > EFRP_XTCP_CERTIFICATE_MAX_BYTES ||
        !r->mapped_addresses || r->mapped_address_count < 2 || r->mapped_address_count > EFRP_XTCP_ADDRESS_MAX_COUNT ||
        r->assisted_address_count > EFRP_XTCP_ADDRESS_MAX_COUNT || (r->assisted_address_count && !r->assisted_addresses) ||
        (r->role == EFRP_XTCP_PROVIDER ? !hex32(r->sid) : r->role != EFRP_XTCP_VISITOR || r->sid)) return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < r->mapped_address_count; ++i) if (!endpoint_valid(r->mapped_addresses + i)) return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < r->assisted_address_count; ++i) if (!endpoint_valid(r->assisted_addresses + i)) return EFRP_INVALID_ARGUMENT;
    uint8_t proof[32]; char encoded[4][45], certificate[1369], timestamp[21];
    efrp_result_t result = efrp_xtcp_binding_signal_proof(r->secret, r->secret_length, r->role,
        (const uint8_t *)r->proxy_name, strlen(r->proxy_name), r->control_id, r->nonce, r->spki_sha256, r->timestamp_seconds, proof);
    if (result != EFRP_OK) return result;
    base64_encode(r->control_id, 32, encoded[0]); base64_encode(r->nonce, 32, encoded[1]);
    base64_encode(r->spki_sha256, 32, encoded[2]); base64_encode(proof, 32, encoded[3]);
    base64_encode(r->certificate, r->certificate_length, certificate);
    int digits = snprintf(timestamp, sizeof timestamp, "%" PRId64, r->timestamp_seconds);
    cJSON *root = cJSON_CreateObject();
    bool built = digits > 0 && (size_t)digits < sizeof timestamp && root && reference(root, "transaction_id", r->transaction_id) &&
        reference(root, "proxy_name", r->proxy_name) && reference(root, "control_id", encoded[0]) && reference(root, "nonce", encoded[1]) &&
        reference(root, "spki_sha256", encoded[2]) && reference(root, "signal_proof", encoded[3]) && reference(root, "certificate", certificate) &&
        cJSON_AddRawToObject(root, "timestamp", timestamp) &&
        (r->role == EFRP_XTCP_PROVIDER ? reference(root, "sid", r->sid) : reference(root, "protocol", "quic")) &&
        add_addresses(root, "mapped_addrs", r->mapped_addresses, r->mapped_address_count) &&
        add_addresses(root, "assisted_addrs", r->assisted_addresses, r->assisted_address_count);
    result = built ? frame(root, r->role == EFRP_XTCP_PROVIDER ? 21 : 20, output, capacity, length) : EFRP_NO_MEMORY;
    cJSON_Delete(root); efrp_crypto_zero(proof, sizeof proof); efrp_crypto_zero(encoded, sizeof encoded);
    efrp_crypto_zero(certificate, sizeof certificate);
    if (result != EFRP_OK) efrp_crypto_zero(output, capacity);
    return result;
}

typedef struct { uint8_t *bytes; size_t capacity, used; bool exceeded; } arena_t;
static void *reserve(arena_t *a, size_t length, size_t alignment)
{
    uintptr_t address = (uintptr_t)a->bytes + a->used;
    size_t padding = (alignment - address % alignment) % alignment;
    if (padding > a->capacity - a->used || length > a->capacity - a->used - padding) { a->exceeded = true; return NULL; }
    void *p = a->bytes + a->used + padding; a->used += padding + length; return p;
}
static const char *copy_text(arena_t *a, const cJSON *root, const char *name, size_t minimum, size_t maximum)
{
    const char *s = efrp_json_string(root, name);
    if (!text(s, minimum, maximum)) return NULL;
    size_t n = strlen(s) + 1; char *out = reserve(a, n, 1);
    if (out) memcpy(out, s, n);
    return out;
}
static bool decimal(const char **cursor, unsigned maximum, unsigned *output)
{
    const char *s = *cursor; if (*s < '0' || *s > '9') return false;
    unsigned value = 0; const char *first = s;
    do { if (value > maximum / 10u) return false; value = value * 10u + (unsigned)(*s++ - '0'); if (value > maximum) return false; } while (*s >= '0' && *s <= '9');
    if (s - first > 1 && *first == '0') return false;
    *cursor = s; *output = value; return true;
}
static bool parse_endpoint(const char *s, efrp_xtcp_endpoint_t *e)
{
    if (!s) return false;
    for (size_t i = 0; i < 4; ++i) {
        unsigned value; if (!decimal(&s, 255, &value)) return false; e->ipv4[i] = (uint8_t)value;
        if (*s++ != (i == 3 ? ':' : '.')) return false;
    }
    unsigned port; if (!decimal(&s, 65535, &port) || *s) return false;
    e->port = (uint16_t)port; return endpoint_valid(e);
}
static bool read_addresses(arena_t *a, const cJSON *root, const char *name, bool required, const efrp_xtcp_endpoint_t **output, size_t *count)
{
    const cJSON *array = efrp_json_field(root, name);
    if (!array) return !required;
    if (!cJSON_IsArray(array)) return false;
    int n = cJSON_GetArraySize(array);
    if (n < (required ? 1 : 0) || n > (int)EFRP_XTCP_ADDRESS_MAX_COUNT) return false;
    if (!n) return true;
    efrp_xtcp_endpoint_t *addresses = reserve(a, (size_t)n * sizeof *addresses, _Alignof(efrp_xtcp_endpoint_t));
    if (!addresses) return false;
    for (int i = 0; i < n; ++i) {
        const cJSON *item = cJSON_GetArrayItem(array, i);
        if (!cJSON_IsString(item) || !parse_endpoint(item->valuestring, addresses + i)) return false;
    }
    *output = addresses; *count = (size_t)n; return true;
}
static bool number(const cJSON *root, const char *name, uint32_t maximum, bool required, uint32_t *output)
{
    const cJSON *n = efrp_json_field(root, name); *output = 0;
    if (!n) return !required;
    if (!cJSON_IsNumber(n) || !isfinite(n->valuedouble) || n->valuedouble < 0 || n->valuedouble > maximum ||
        n->valuedouble != (double)(uint32_t)n->valuedouble) return false;
    *output = (uint32_t)n->valuedouble; return true;
}
static bool read_detect(const cJSON *root, efrp_xtcp_detect_behavior_t *d)
{
    const cJSON *value = efrp_json_field(root, "detect_behavior");
    const char *const fields[] = {"role", "mode", "ttl", "send_delay_ms", "read_timeout", "candidate_ports", "send_random_ports", "listen_random_ports"};
    if (!efrp_json_shape(value, fields, 8)) return false;
    if (efrp_json_equals(value, "role", "sender")) d->role = EFRP_XTCP_DETECT_SENDER;
    else if (efrp_json_equals(value, "role", "receiver")) d->role = EFRP_XTCP_DETECT_RECEIVER;
    else return false;
    uint32_t n;
    if (!number(value, "mode", 4, false, &n)) return false;
    d->mode = (uint8_t)n;
    if (!number(value, "ttl", 255, false, &n)) return false;
    d->ttl = (uint8_t)n;
    if (!number(value, "send_delay_ms", 10000, false, &d->send_delay_ms) ||
        !number(value, "read_timeout", 60000, true, &d->read_timeout_ms) || !d->read_timeout_ms) return false;
    if (!number(value, "send_random_ports", 1000, false, &n)) return false;
    d->send_random_ports = (uint16_t)n;
    if (!number(value, "listen_random_ports", 256, false, &n)) return false;
    d->listen_random_ports = (uint16_t)n;
    const cJSON *array = efrp_json_field(value, "candidate_ports");
    if (!array) return true;
    if (!cJSON_IsArray(array)) return false;
    int count = cJSON_GetArraySize(array);
    if (count < 0 || count > (int)EFRP_XTCP_PORT_RANGE_MAX_COUNT) return false;
    const char *const range_fields[] = {"from", "to"};
    for (int i = 0; i < count; ++i) {
        const cJSON *item = cJSON_GetArrayItem(array, i); uint32_t from, to;
        if (!efrp_json_shape(item, range_fields, 2) || !number(item, "from", 65535, true, &from) ||
            !number(item, "to", 65535, true, &to) || !from || from > to) return false;
        d->port_ranges[i].from = (uint16_t)from; d->port_ranges[i].to = (uint16_t)to;
    }
    d->port_range_count = (size_t)count; return true;
}
static const uint8_t *copy_binary(arena_t *a, const cJSON *root, const char *name, size_t minimum, size_t maximum, size_t *length)
{
    const char *s = efrp_json_string(root, name);
    if (!s || !*s || strlen(s) > 4u * ((maximum + 2u) / 3u)) return NULL;
    size_t encoded = strlen(s), bytes = encoded / 4u * 3u;
    if (encoded && s[encoded - 1] == '=') --bytes;
    if (encoded > 1 && s[encoded - 2] == '=') --bytes;
    if (bytes < minimum || bytes > maximum) return NULL;
    uint8_t *out = reserve(a, bytes, 1);
    return out && base64_decode(s, out, bytes, length) && *length == bytes ? out : NULL;
}

/* Decode at its own issued instant only to check canonical shape. The real
 * trusted-clock admission check remains the controller's responsibility. */
static bool manifest_shape(const uint8_t *wire, size_t length)
{
    if (!wire || length < 250) return false;
    uint64_t issued = 0; for (size_t i = length - 16; i < length - 8; ++i) issued = (issued << 8) | wire[i];
    efrp_xtcp_binding_manifest_t value;
    bool valid = efrp_xtcp_binding_decode(wire, length, issued, &value) == EFRP_OK;
    efrp_crypto_zero(&value, sizeof value); return valid;
}
efrp_result_t efrp_xtcp_codec_response(efrp_frame_kind_t kind, const uint8_t *payload, size_t length,
    uint8_t *storage, size_t capacity, size_t *storage_used, efrp_xtcp_signal_response_t *response)
{
    if (storage_used) *storage_used = 0;
    if (response) memset(response, 0, sizeof *response);
    if (!response || !storage_used || !storage) return EFRP_INVALID_ARGUMENT;
    if (kind != EFRP_MESSAGE || !payload || length < 2 || length > EFRP_XTCP_SIGNAL_MAX_BYTES - 8 || payload[0] || payload[1] != 22) return EFRP_PROTOCOL_ERROR;
    cJSON *root = efrp_json_parse(payload + 2, length - 2, EFRP_JSON_XTCP_MAX_PUNCTUATION);
    const char *const fields[] = {"binding_manifest", "peer_certificate", "transaction_id", "sid", "protocol", "candidate_addrs", "assisted_addrs", "detect_behavior", "error"};
    arena_t a = {storage, capacity, 0, false}; efrp_xtcp_signal_response_t r = {0};
    efrp_result_t result = EFRP_PROTOCOL_ERROR;
    if (!efrp_json_shape(root, fields, 9)) goto done;
    r.transaction_id = copy_text(&a, root, "transaction_id", 1, 64);
    r.error = copy_text(&a, root, "error", 0, 256);
    if (!r.transaction_id || !r.error) goto done;
    if (*r.error) {
 const char *const errors[] = {"transaction_id", "sid", "error", "detect_behavior"};
 const char *error_sid = efrp_json_string(root, "sid");
 if (!efrp_json_shape(root, errors, 4) || !efrp_json_shape(efrp_json_field(root, "detect_behavior"), NULL, 0) || !error_sid || (*error_sid && !hex32(error_sid))) goto done;
 result = EFRP_WORK_REJECTED; goto done; }
    r.sid = copy_text(&a, root, "sid", 64, 64);
    if (!hex32(r.sid) || !efrp_json_equals(root, "protocol", "quic")) goto done;
    r.manifest = copy_binary(&a, root, "binding_manifest", 250, 377, &r.manifest_length);
    r.peer_certificate = copy_binary(&a, root, "peer_certificate", 1, EFRP_XTCP_CERTIFICATE_MAX_BYTES, &r.peer_certificate_length);
    if (!r.manifest || !manifest_shape(r.manifest, r.manifest_length) || !r.peer_certificate || !read_addresses(&a, root, "candidate_addrs", true, &r.candidate_addresses, &r.candidate_address_count) ||
        !read_addresses(&a, root, "assisted_addrs", false, &r.assisted_addresses, &r.assisted_address_count) || !read_detect(root, &r.detect)) goto done;
    result = EFRP_OK;
 done:
    cJSON_Delete(root);
    if (a.exceeded) result = EFRP_CAPACITY_EXCEEDED;
    if (result == EFRP_OK || result == EFRP_WORK_REJECTED) { *response = r; *storage_used = a.used; }
    else efrp_crypto_zero(storage, a.used);
    return result;
}

efrp_result_t efrp_xtcp_codec_work_sid(efrp_frame_kind_t kind, const uint8_t *payload, size_t length, char sid[65])
{
    if (sid) memset(sid, 0, 65);
    if (!sid) return EFRP_INVALID_ARGUMENT;
    if (kind != EFRP_MESSAGE || !payload || length < 2 || payload[0] || payload[1] != 23) return EFRP_PROTOCOL_ERROR;
    cJSON *root = efrp_json_parse(payload + 2, length - 2, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    const char *const fields[] = {"sid"}; const char *s = efrp_json_string(root, "sid");
    bool valid = efrp_json_shape(root, fields, 1) && hex32(s);
    if (valid) memcpy(sid, s, 65);
    cJSON_Delete(root); return valid ? EFRP_OK : EFRP_PROTOCOL_ERROR;
}

efrp_result_t efrp_xtcp_codec_report(const char *sid, bool success, uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (capacity > EFRP_XTCP_SIGNAL_MAX_BYTES) capacity = EFRP_XTCP_SIGNAL_MAX_BYTES;
    if (output) efrp_crypto_zero(output, capacity);
    if (!output || !length || !hex32(sid)) return EFRP_INVALID_ARGUMENT;
    cJSON *root = cJSON_CreateObject();
    bool built = root && reference(root, "sid", sid) && cJSON_AddBoolToObject(root, "success", success);
    efrp_result_t result = built ? frame(root, 24, output, capacity, length) : EFRP_NO_MEMORY;
    cJSON_Delete(root); return result;
}

static bool sid_message_valid(const efrp_xtcp_sid_message_t *m)
{
    return m && hex32(m->sid) && hex32(m->nonce) && text(m->transaction_id, 1, 64);
}
efrp_result_t efrp_xtcp_codec_sid_encode(const efrp_xtcp_sid_message_t *m, const uint8_t *secret, size_t secret_length,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (capacity > EFRP_XTCP_DATAGRAM_MAX_BYTES) capacity = EFRP_XTCP_DATAGRAM_MAX_BYTES;
    if (output) efrp_crypto_zero(output, capacity);
    if (!output || !length || !secret || !secret_length || secret_length > 128 || !sid_message_valid(m)) return EFRP_INVALID_ARGUMENT;
    cJSON *root = cJSON_CreateObject();
    bool built = root && reference(root, "transaction_id", m->transaction_id) && reference(root, "sid", m->sid) &&
        reference(root, "nonce", m->nonce) && (!m->response || cJSON_AddBoolToObject(root, "response", true));
    char *json = built ? cJSON_PrintUnformatted(root) : NULL;
    efrp_result_t result = EFRP_NO_MEMORY; size_t n = json ? strlen(json) : 0;
    if (json) {
        result = EFRP_CAPACITY_EXCEEDED;
        if (n && n <= 512 && capacity >= n + 38) {
            memcpy(output, "XHD1", 4); output[4] = (uint8_t)(n >> 8); output[5] = (uint8_t)n; memcpy(output + 6, json, n);
            efrp_crypto_span_t part = {output, n + 6};
            result = efrp_xtcp_binding_hmac(secret, secret_length, &part, 1, output + 6 + n);
            if (result == EFRP_OK) *length = n + 38;
        }
        efrp_crypto_zero(json, n); cJSON_free(json);
    }
    cJSON_Delete(root);
    if (result != EFRP_OK) efrp_crypto_zero(output, capacity);
    return result;
}
efrp_result_t efrp_xtcp_codec_sid_decode(const uint8_t *wire, size_t length, const uint8_t *secret, size_t secret_length,
    efrp_xtcp_sid_message_t *message)
{
    if (message) memset(message, 0, sizeof *message);
    if (!message || !secret || !secret_length || secret_length > 128) return EFRP_INVALID_ARGUMENT;
    if (!wire || length < 39 || length > EFRP_XTCP_DATAGRAM_MAX_BYTES || memcmp(wire, "XHD1", 4)) return EFRP_PROTOCOL_ERROR;
    size_t n = (size_t)wire[4] * 256u + wire[5];
    if (!n || n > 512 || length != n + 38) return EFRP_PROTOCOL_ERROR;
    uint8_t expected[32]; efrp_crypto_span_t part = {wire, n + 6};
    efrp_result_t result = efrp_xtcp_binding_hmac(secret, secret_length, &part, 1, expected);
    if (result != EFRP_OK) return result;
    unsigned mismatch = 0; for (size_t i = 0; i < 32; ++i) mismatch |= (unsigned)(expected[i] ^ wire[n + 6 + i]);
    efrp_crypto_zero(expected, sizeof expected);
    if (mismatch) return EFRP_AUTHENTICATION_FAILED;
    cJSON *root = efrp_json_parse(wire + 6, n, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    const char *const fields[] = {"transaction_id", "sid", "response", "nonce"};
    const char *sid = efrp_json_string(root, "sid"), *txn = efrp_json_string(root, "transaction_id"), *nonce = efrp_json_string(root, "nonce");
    const cJSON *response = efrp_json_field(root, "response");
    bool valid = efrp_json_shape(root, fields, 4) && hex32(sid) && hex32(nonce) && text(txn, 1, 64) && (!response || cJSON_IsBool(response));
    if (valid) { memcpy(message->sid, sid, 65); memcpy(message->nonce, nonce, 65); memcpy(message->transaction_id, txn, strlen(txn) + 1); message->response = cJSON_IsTrue(response); }
    cJSON_Delete(root); return valid ? EFRP_OK : EFRP_PROTOCOL_ERROR;
}
