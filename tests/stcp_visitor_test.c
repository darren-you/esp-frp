// SPDX-License-Identifier: Apache-2.0
#include "stcp_visitor_internal.h"
#include "json_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t loopback[4] = {127, 0, 0, 1};
static uint8_t output[EFRP_STCP_VISITOR_REQUEST_MAX_BYTES];
static void cleared(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i) assert(!bytes[i]);
}
static cJSON *request(const char *run_id, const char *target, const char *secret, int64_t seconds)
{
    size_t length = 123;
    memset(output, 0xa5, sizeof output);
    assert(efrp_stcp_visitor_encode_request(run_id, target, secret, seconds,
        output, sizeof output, &length) == EFRP_OK);
    assert(length > 17 && length + 5 <= sizeof output);
    assert(!memcmp(output, efrp_wire_magic, EFRP_WIRE_MAGIC_SIZE));
    assert(output[7] == 0 && output[8] == EFRP_MESSAGE && output[9] == 0 && output[10] == 0);
    size_t payload = ((size_t)output[11] << 24) | ((size_t)output[12] << 16) |
        ((size_t)output[13] << 8) | output[14];
    assert(payload + 15 == length && output[15] == 0 && output[16] == 9);
    cleared(output + length, sizeof output - length);
    uint8_t exact[EFRP_STCP_VISITOR_REQUEST_MAX_BYTES]; size_t exact_length;
    assert(efrp_stcp_visitor_encode_request(run_id, target, secret, seconds,
        exact, length + 5, &exact_length) == EFRP_OK);
    assert(exact_length == length && !memcmp(exact, output, length));
    memset(exact, 0xa5, sizeof exact); exact_length = 123;
    assert(efrp_stcp_visitor_encode_request(run_id, target, secret, seconds,
        exact, length + 4, &exact_length) == EFRP_CAPACITY_EXCEEDED);
    assert(!exact_length); cleared(exact, length + 4); assert(exact[length + 4] == 0xa5);
    cJSON *root = efrp_json_parse(output + 17, length - 17, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    assert(root && efrp_json_equals(root, "run_id", run_id) && efrp_json_equals(root, "proxy_name", target));
    const char *const fields[] = {"run_id", "proxy_name", "sign_key", "timestamp", "use_encryption", "use_compression"};
    assert(efrp_json_shape(root, fields, 6));
    assert(cJSON_IsFalse(efrp_json_field(root, "use_encryption")) && cJSON_IsFalse(efrp_json_field(root, "use_compression")));
    const cJSON *stamp = efrp_json_field(root, "timestamp");
    assert(cJSON_IsNumber(stamp) && stamp->valuedouble == (double)seconds);
    assert(!efrp_json_field(root, "privilege_key") && !efrp_json_field(root, "sk"));
    return root;
}
static void rejected(const char *run_id, const char *target, const char *secret,
    int64_t seconds, efrp_result_t expected)
{
    size_t length = 123; memset(output, 0xa5, sizeof output);
    assert(efrp_stcp_visitor_encode_request(run_id, target, secret, seconds,
        output, sizeof output, &length) == expected);
    assert(!length); cleared(output, sizeof output);
}
static void requests(void)
{
    cJSON *root = request("visitor-run", "provider.private", "public-visitor-secret", INT64_C(1700000000));
    assert(efrp_json_equals(root, "sign_key", "83f8986890edae18c625c9cc057631d0")); cJSON_Delete(root);
    root = request("visitor\"\\\n\xe4\xb8\xad", "provider\"\\\n\x01\xe4\xb8\xad",
        "public-secret\"\\\n\x01\xe4\xb8\xad", INT64_C(1700000000)); cJSON_Delete(root);
    rejected(NULL, "provider.private", "secret", 1, EFRP_INVALID_ARGUMENT);
    rejected("", "provider.private", "secret", 1, EFRP_INVALID_ARGUMENT);
    rejected("run", NULL, "secret", 1, EFRP_INVALID_ARGUMENT);
    rejected("run", "", "secret", 1, EFRP_INVALID_ARGUMENT);
    rejected("run", "provider.private", NULL, 1, EFRP_INVALID_ARGUMENT);
    rejected("run", "provider.private", "", 1, EFRP_INVALID_ARGUMENT);
    rejected("run", "provider.private", "secret", 0, EFRP_INVALID_ARGUMENT);
    rejected("run", "provider.private", "secret", -1, EFRP_INVALID_ARGUMENT);
    rejected("\xc0\x80", "provider.private", "secret", 1, EFRP_INVALID_ARGUMENT);
    rejected("run", "\xc0\x80", "secret", 1, EFRP_INVALID_ARGUMENT);
    rejected("run", "provider.private", "\xc0\x80", 1, EFRP_INVALID_ARGUMENT);
    char run[66], target[130], secret[130];
    memset(run, 'r', sizeof run - 1); run[sizeof run - 1] = 0;
    memset(target, 't', sizeof target - 1); target[sizeof target - 1] = 0;
    memset(secret, 's', sizeof secret - 1); secret[sizeof secret - 1] = 0;
    rejected(run, "provider.private", "secret", 1, EFRP_INVALID_ARGUMENT); run[64] = 0;
    rejected("run", target, "secret", 1, EFRP_INVALID_ARGUMENT); target[128] = 0;
    rejected("run", "provider.private", secret, 1, EFRP_INVALID_ARGUMENT); secret[128] = 0;
    root = request(run, target, secret, INT64_MAX); cJSON_Delete(root);
    memset(run, 1, 64); memset(target, 1, 128);
    rejected(run, target, secret, 1, EFRP_CAPACITY_EXCEEDED);
    size_t length = 123;
    assert(efrp_stcp_visitor_encode_request("run", "target", "secret", 1, NULL, 0, &length) == EFRP_INVALID_ARGUMENT && !length);
    memset(output, 0xa5, sizeof output);
    assert(efrp_stcp_visitor_encode_request("run", "target", "secret", 1, output, sizeof output, NULL) == EFRP_INVALID_ARGUMENT);
    cleared(output, sizeof output);
}
static void identities(void)
{
    assert(efrp_stcp_visitor_validate("provider.private", "secret", loopback, 1234) == EFRP_OK);
    const uint8_t lan[4] = {192, 168, 1, 2}, wildcard[4] = {0}, multicast[4] = {224, 0, 0, 1};
    assert(efrp_stcp_visitor_validate("provider.private", "secret", lan, 1234) == EFRP_OK);
    assert(efrp_stcp_visitor_validate("provider.private", "secret", NULL, 1234) == EFRP_INVALID_ARGUMENT);
    assert(efrp_stcp_visitor_validate("provider.private", "secret", wildcard, 1234) == EFRP_INVALID_ARGUMENT);
    assert(efrp_stcp_visitor_validate("provider.private", "secret", multicast, 1234) == EFRP_INVALID_ARGUMENT);
    assert(efrp_stcp_visitor_validate("provider.private", "secret", loopback, 0) == EFRP_INVALID_ARGUMENT);
    assert(efrp_stcp_visitor_validate("", "secret", loopback, 1234) == EFRP_INVALID_ARGUMENT);
    assert(efrp_stcp_visitor_validate("target", "", loopback, 1234) == EFRP_INVALID_ARGUMENT);
    efrp_stcp_visitor_owned_t *owner = NULL;
    assert(efrp_stcp_visitor_owned_clone("target", "", &owner) == EFRP_INVALID_ARGUMENT && !owner);
    assert(efrp_stcp_visitor_owned_clone("target", "secret", NULL) == EFRP_INVALID_ARGUMENT);
    assert(!efrp_stcp_visitor_owned_proxy_name(NULL) && !efrp_stcp_visitor_owned_secret_key(NULL));
    char target[] = "provider.private", secret[] = "public-secret";
    assert(efrp_stcp_visitor_owned_clone(target, secret, &owner) == EFRP_OK && owner);
    efrp_stcp_visitor_owned_t *saved = owner;
    assert(efrp_stcp_visitor_owned_clone("other", "secret", &owner) == EFRP_INVALID_STATE && owner == saved);
    target[0] = '!'; secret[0] = '!';
    assert(!strcmp(efrp_stcp_visitor_owned_proxy_name(owner), "provider.private"));
    assert(!strcmp(efrp_stcp_visitor_owned_secret_key(owner), "public-secret"));
    cJSON *root = request("run", efrp_stcp_visitor_owned_proxy_name(owner), efrp_stcp_visitor_owned_secret_key(owner), 1);
    cJSON_Delete(root);
    efrp_stcp_visitor_owned_clear_secret(owner);
    cleared((const uint8_t *)efrp_stcp_visitor_owned_secret_key(owner), strlen("public-secret") + 1);
    assert(!strcmp(efrp_stcp_visitor_owned_proxy_name(owner), "provider.private"));
    efrp_stcp_visitor_owned_clear_secret(owner); efrp_stcp_visitor_owned_clear_secret(NULL);
    efrp_stcp_visitor_owned_destroy(&owner); assert(!owner);
    efrp_stcp_visitor_owned_destroy(&owner); efrp_stcp_visitor_owned_destroy(NULL);
}
static efrp_result_t response(const char *json)
{
    uint8_t payload[EFRP_JSON_MAX_BYTES + 2]; size_t n = strlen(json);
    assert(n <= EFRP_JSON_MAX_BYTES); payload[0] = 0; payload[1] = 10;
    memcpy(payload + 2, json, n);
    return efrp_stcp_visitor_accept_response(EFRP_MESSAGE, payload, n + 2, "provider.private");
}
static void responses(void)
{
    assert(response("{\"proxy_name\":\"provider.private\"}") == EFRP_OK);
    assert(response("{\"proxy_name\":\"provider.private\",\"error\":\"\"}") == EFRP_OK);
    assert(response("{\"proxy_name\":\"provider.private\",\"error\":\"auth failed\"}") == EFRP_WORK_REJECTED);
    const char *bad[] = {"{}", "{\"proxy_name\":\"other\"}", "{\"proxy_name\":5}",
        "{\"proxy_name\":\"provider.private\",\"error\":false}", "{\"proxy_name\":\"provider.private\",\"other\":5}",
        "{\"proxy_name\":\"provider.private\",\"proxy_name\":\"provider.private\"}",
        "{\"proxy_name\":\"provider.private\",\"error\":\"\",\"error\":\"auth failed\"}",
        "{\"proxy_name\":\"provider.private\\u0000\"}", "{\"proxy_name\":\"provider.private\"", "[]", "{} trailing"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) assert(response(bad[i]) == EFRP_PROTOCOL_ERROR);
    uint8_t payload[] = {0, 10, '{', '}'};
    assert(efrp_stcp_visitor_accept_response(EFRP_MESSAGE, NULL, 0, "provider.private") == EFRP_PROTOCOL_ERROR);
    assert(efrp_stcp_visitor_accept_response(EFRP_MESSAGE, payload, 1, "provider.private") == EFRP_PROTOCOL_ERROR);
    assert(efrp_stcp_visitor_accept_response(EFRP_MESSAGE, payload, sizeof payload, NULL) == EFRP_INVALID_ARGUMENT);
    assert(efrp_stcp_visitor_accept_response(EFRP_SERVER_HELLO, payload, sizeof payload, "provider.private") == EFRP_PROTOCOL_ERROR);
    payload[0] = 1;
    assert(efrp_stcp_visitor_accept_response(EFRP_MESSAGE, payload, sizeof payload, "provider.private") == EFRP_PROTOCOL_ERROR);
    payload[0] = 0; payload[1] = 8;
    assert(efrp_stcp_visitor_accept_response(EFRP_MESSAGE, payload, sizeof payload, "provider.private") == EFRP_PROTOCOL_ERROR);
    uint8_t oversized[EFRP_JSON_MAX_BYTES + 3] = {0, 10};
    assert(efrp_stcp_visitor_accept_response(EFRP_MESSAGE, oversized, sizeof oversized, "provider.private") == EFRP_PROTOCOL_ERROR);
}
static size_t allocation_limit, allocations, outstanding;
static void *limited_malloc(size_t length)
{
    void *memory = allocations++ < allocation_limit ? malloc(length) : NULL;
    if (memory) ++outstanding;
    return memory;
}
static void limited_free(void *memory)
{
    if (memory) { assert(outstanding); --outstanding; free(memory); }
}
static void allocation_failures(void)
{
    cJSON_Hooks hooks = {.malloc_fn = limited_malloc, .free_fn = limited_free};
    bool success = false;
    for (size_t limit = 0; limit < 100; ++limit) {
        allocation_limit = limit; allocations = 0; cJSON_InitHooks(&hooks);
        size_t length = 123; memset(output, 0xa5, sizeof output);
        efrp_result_t result = efrp_stcp_visitor_encode_request("run", "provider.private", "public-secret", 1,
            output, sizeof output, &length);
        assert(!outstanding); cJSON_InitHooks(NULL);
        if (result == EFRP_OK) { success = true; break; }
        assert(result == EFRP_NO_MEMORY && !length); cleared(output, sizeof output);
    }
    assert(success); success = false;
    for (size_t limit = 0; limit < 100; ++limit) {
        allocation_limit = limit; allocations = 0; cJSON_InitHooks(&hooks);
        efrp_result_t result = response("{\"proxy_name\":\"provider.private\"}");
        assert(!outstanding); cJSON_InitHooks(NULL);
        if (result == EFRP_OK) { success = true; break; }
        assert(result == EFRP_PROTOCOL_ERROR);
    }
    assert(success);
}
int main(void)
{
    requests(); identities(); responses(); allocation_failures();
    puts("STCP visitor: v2 request/signature, strict response, bounds, ownership and allocation failures passed");
    return 0;
}
