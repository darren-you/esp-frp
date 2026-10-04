// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_handshake.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

static const uint8_t token[] = "public-handshake-token";
static const char hello[] = "{\"selected\":{\"message\":{\"codec\":\"json\"},\"crypto\":{\"algorithm\":\"aes-256-gcm\",\"serverRandom\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}}";
static const char login[] = "{\"version\":\"0.71.0\",\"run_id\":\"0123456789abcdef\"}";
static efrp_handshake_config_t config(void)
{
    return (efrp_handshake_config_t){.token = token, .token_length = sizeof token - 1,
        .hostname = "board\"\\\n", .user = "公开测试", .client_id = "fixture", .run_id = "old-id", .unix_seconds = INT64_C(1790000000)};
}
static void zero(const void *p, size_t n)
{
    const uint8_t *bytes = p; for (size_t i = 0; i < n; ++i) assert(!bytes[i]);
}
static size_t frame(uint8_t *out, efrp_frame_kind_t kind, const char *json)
{
    size_t n = strlen(json), prefix = kind == EFRP_MESSAGE ? 2 : 0;
    assert(efrp_wire_header(kind, n + prefix, out) == EFRP_OK);
    if (prefix) { out[8] = 0; out[9] = 2; }
    memcpy(out + 8 + prefix, json, n); return n + 8 + prefix;
}
static void start(efrp_handshake_t *h, uint8_t rx[EFRP_HANDSHAKE_RX_BYTES])
{
    efrp_handshake_config_t c = config();
    assert(efrp_handshake_init(h, &c, rx, EFRP_HANDSHAKE_RX_BYTES, 100) == EFRP_OK);
    assert(efrp_handshake_init(h, &c, rx, EFRP_HANDSHAKE_RX_BYTES, 100) == EFRP_INVALID_STATE);
    const uint8_t *p; size_t n, used;
    assert(efrp_handshake_feed(h, (const uint8_t *)"x", 1, &used) == EFRP_WOULD_BLOCK && !used);
    assert(efrp_handshake_output(h, &p, &n) == EFRP_OK && n > 200);
    assert(!memcmp(p, efrp_wire_magic, 7));
    const size_t login_offset = 7 + 8 + h->hello_length + 10;
    assert(login_offset < n);
    cJSON *login_body = cJSON_Parse((const char *)p + login_offset);
    assert(login_body);
    const cJSON *arch = cJSON_GetObjectItemCaseSensitive(login_body, "arch");
#if defined(CONFIG_IDF_TARGET_ESP32) && CONFIG_IDF_TARGET_ESP32
    assert(cJSON_IsString(arch) && !strcmp(arch->valuestring, "xtensa"));
#else
    assert(cJSON_IsString(arch) && !strcmp(arch->valuestring, "riscv32"));
#endif
    cJSON_Delete(login_body);
    assert(efrp_handshake_consume_output(h, n + 1) == EFRP_INVALID_ARGUMENT);
    while (efrp_handshake_output(h, &p, &n) == EFRP_OK) {
        if (n > 17) n = 17;
        assert(efrp_handshake_consume_output(h, n) == EFRP_OK);
    }
    assert(h->state == EFRP_HANDSHAKE_HELLO); zero(h->output, sizeof h->output);
}
static void split_and_tail(void)
{
    uint8_t wire[2048], rx[EFRP_HANDSHAKE_RX_BYTES];
    size_t hello_n = frame(wire, EFRP_SERVER_HELLO, hello);
    size_t count = hello_n + frame(wire + hello_n, EFRP_MESSAGE, login);
    memset(wire + count, 0xa5, 50);
    for (size_t split = 1; split <= count + 50; ++split) {
        efrp_handshake_t h = {0}; start(&h, rx);
        uint8_t client[512]; size_t client_n = h.hello_length; memcpy(client, h.client_hello, client_n);
        size_t at = 0;
        while (h.state != EFRP_HANDSHAKE_DONE) {
            size_t n = count + 50 - at, used;
            if (n > split) n = split;
            assert(efrp_handshake_feed(&h, wire + at, n, &used) == EFRP_OK && used);
            at += used;
        }
        assert(at == count); size_t used;
        assert(efrp_handshake_feed(&h, wire + count, 50, &used) == EFRP_WOULD_BLOCK && !used);
        efrp_aead_keys_t expected, actual; char id[EFRP_RUN_ID_BYTES];
        assert(efrp_aead_derive(token, sizeof token - 1, client, client_n,
            (const uint8_t *)hello, sizeof hello - 1, &expected) == EFRP_OK);
        assert(efrp_handshake_take_result(&h, &actual, id) == EFRP_OK);
        assert(!memcmp(&actual, &expected, sizeof actual) && !strcmp(id, "0123456789abcdef"));
        assert(efrp_handshake_take_result(&h, &actual, id) == EFRP_INVALID_STATE);
        zero(rx, sizeof rx); zero(h.token, sizeof h.token); zero(&h.keys, sizeof h.keys);
        efrp_aead_clear_keys(&actual); efrp_aead_clear_keys(&expected);
        memset(rx, 0x5a, sizeof rx); /* Reused by the next protocol layer. */
        efrp_handshake_destroy(&h); zero(&h, sizeof h);
        for (size_t i = 0; i < sizeof rx; ++i) assert(rx[i] == 0x5a);
    }
}
static void in_place_receive(void)
{
    uint8_t wire[2048];
    size_t wire_length = frame(wire, EFRP_SERVER_HELLO, hello);
    wire_length += frame(wire + wire_length, EFRP_MESSAGE, login);
    memset(wire + wire_length, 0xa5, 8);
    for (unsigned mode = 0; mode < 3; ++mode) {
        efrp_handshake_t h = {0};
        efrp_handshake_config_t c = config();
        assert(efrp_handshake_init(&h, &c, h.output, sizeof h.output, 100) == EFRP_OK);
        const uint8_t *output; size_t length, used;
        assert(efrp_handshake_output(&h, &output, &length) == EFRP_OK);
        assert(output == h.output && length > 200);
        assert(efrp_handshake_consume_output(&h, length / 2) == EFRP_OK);
        assert(efrp_handshake_feed(&h, wire, wire_length, &used) == EFRP_WOULD_BLOCK && !used);
        if (mode == 2) {
            assert(efrp_handshake_finish(&h) == EFRP_TRUNCATED);
            zero(h.output, sizeof h.output);
            efrp_handshake_destroy(&h); zero(&h, sizeof h);
            continue;
        }
        assert(efrp_handshake_output(&h, &output, &used) == EFRP_OK && used == length - length / 2);
        assert(efrp_handshake_consume_output(&h, used) == EFRP_OK);
        assert(h.state == EFRP_HANDSHAKE_HELLO); zero(h.output, sizeof h.output);
        if (mode == 1) {
            wire[8] = 'x';
            assert(efrp_handshake_feed(&h, wire, wire_length, &used) == EFRP_PROTOCOL_ERROR);
            zero(h.output, sizeof h.output);
            wire[8] = '{';
        } else {
            assert(efrp_handshake_feed(&h, wire, wire_length + 8, &used) == EFRP_OK);
            assert(used == wire_length && h.state == EFRP_HANDSHAKE_DONE);
            efrp_aead_keys_t keys; char run_id[EFRP_RUN_ID_BYTES];
            assert(efrp_handshake_take_result(&h, &keys, run_id) == EFRP_OK);
            assert(!strcmp(run_id, "0123456789abcdef"));
            zero(h.output, sizeof h.output);
            efrp_aead_clear_keys(&keys);
        }
        efrp_handshake_destroy(&h); zero(&h, sizeof h);
    }
}
static void rejection(const char *server_json, const char *login_json, efrp_result_t expected)
{
    uint8_t wire[8192], rx[EFRP_HANDSHAKE_RX_BYTES]; efrp_handshake_t h = {0}; start(&h, rx);
    size_t n = frame(wire, EFRP_SERVER_HELLO, server_json), used;
    if (login_json) n += frame(wire + n, EFRP_MESSAGE, login_json);
    assert(efrp_handshake_feed(&h, wire, n, &used) == expected && used <= n);
    assert(h.state == EFRP_HANDSHAKE_FAILED);
    assert(efrp_handshake_feed(&h, wire, n, &used) == expected && !used);
    zero(rx, sizeof rx); zero(h.token, sizeof h.token); zero(&h.keys, sizeof h.keys); zero(h.output, sizeof h.output);
    efrp_handshake_destroy(&h);
}
static void invalid_messages(void)
{
    const char *bad[] = {"null", "[]", "{}", "{\"selected\":null}", "{\"selected\":{},\"selected\":{}}",
        "{\"error\":null}", "{\"error\":\"\\u0000hidden\"}", "{\"error\":\"\\ud800\"}",
        "{\"unknown\":1}", "{\"error\":\"\xff\"}", "{\"error\":\"\"}\v", "{\"error\":\"\"}{}",
        "{\"selected\":{\"message\":{\"codec\":\"json\",\"codec\":\"json\"}}}",
        "{\"error\":\"\",\"err\\u006fr\":\"hidden\"}", "\xef\xbb\xbf{}"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) rejection(bad[i], NULL, EFRP_PROTOCOL_ERROR);
    rejection("{\"error\":\"no algorithm\"}", NULL, EFRP_NEGOTIATION_FAILED);
    const char *bad_login[] = {"{}", "null", "{\"run_id\":null}", "{\"run_id\":\"\"}",
        "{\"run_id\":\"a\",\"run_id\":\"b\"}", "{\"run_id\":\"a\",\"error\":false}",
        "{\"run_id\":\"a\",\"version\":7}", "{\"run_id\":\"a\",\"unknown\":{}}"};
    for (size_t i = 0; i < sizeof bad_login / sizeof bad_login[0]; ++i) rejection(hello, bad_login[i], EFRP_PROTOCOL_ERROR);
    char oversized_run[EFRP_RUN_ID_BYTES + 1U];
    memset(oversized_run, 'r', sizeof oversized_run - 1U);
    oversized_run[sizeof oversized_run - 1U] = 0;
    char oversized_login[128];
    assert(snprintf(oversized_login, sizeof oversized_login,
                    "{\"run_id\":\"%s\"}", oversized_run) > 0);
    rejection(hello, oversized_login, EFRP_PROTOCOL_ERROR);
    rejection(hello, "{\"error\":\"wrong token\"}", EFRP_LOGIN_REJECTED);
    const char *target[] = {"aes-256-gcm", "json", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
    for (size_t i = 0; i < 3; ++i) {
        char changed[sizeof hello]; memcpy(changed, hello, sizeof hello);
        char *p = strstr(changed, target[i]); assert(p); p[0] = '!';
        rejection(changed, NULL, EFRP_NEGOTIATION_FAILED);
    }
    char changed[sizeof hello]; memcpy(changed, hello, sizeof hello);
    char *padding = strstr(changed, "AAA="); assert(padding); padding[2] = 'B';
    rejection(changed, NULL, EFRP_NEGOTIATION_FAILED);
    uint8_t wire[8192], rx[EFRP_HANDSHAKE_RX_BYTES]; size_t used;
    for (unsigned mode = 0; mode < 4; ++mode) {
        efrp_handshake_t h = {0}; start(&h, rx);
        size_t n = frame(wire, mode == 0 ? EFRP_MESSAGE : EFRP_SERVER_HELLO, mode == 0 ? login : hello);
        if (mode == 1) n += frame(wire + n, EFRP_SERVER_HELLO, hello);
        if (mode == 2) {
            size_t at = n; n += frame(wire + n, EFRP_MESSAGE, login); wire[at + 9] = 12;
        }
        if (mode == 3) { assert(efrp_wire_header(EFRP_SERVER_HELLO, 4097, wire) == EFRP_OK); n = 8; }
        assert(efrp_handshake_feed(&h, wire, n, &used) == (mode == 3 ? EFRP_CAPACITY_EXCEEDED : EFRP_PROTOCOL_ERROR));
        efrp_handshake_destroy(&h);
    }
}
static void deadlines_and_limits(void)
{
    uint8_t wire[2048], rx[EFRP_HANDSHAKE_RX_BYTES];
    size_t n = frame(wire, EFRP_SERVER_HELLO, hello); n += frame(wire + n, EFRP_MESSAGE, login);
    for (size_t cut = 0; cut < n; ++cut) {
        efrp_handshake_t h = {0}; start(&h, rx); size_t used;
        assert(efrp_handshake_feed(&h, wire, cut, &used) == EFRP_OK);
        assert(efrp_handshake_finish(&h) == EFRP_TRUNCATED); zero(rx, sizeof rx); efrp_handshake_destroy(&h);
    }
    efrp_handshake_t h = {0}; start(&h, rx);
    assert(efrp_handshake_tick(&h, 99) == EFRP_INVALID_ARGUMENT);
    assert(efrp_handshake_tick(&h, 10099) == EFRP_OK);
    assert(efrp_handshake_tick(&h, 10100) == EFRP_TIMEOUT); zero(rx, sizeof rx); efrp_handshake_destroy(&h);
    efrp_handshake_config_t c = config();
    assert(efrp_handshake_init(&h, &c, rx, sizeof rx - 1, 0) == EFRP_INVALID_ARGUMENT);
    assert(efrp_handshake_init(&h, &c, rx, sizeof rx, UINT64_MAX) == EFRP_INVALID_ARGUMENT);
    c.unix_seconds = 0; assert(efrp_handshake_init(&h, &c, rx, sizeof rx, 0) == EFRP_INVALID_ARGUMENT);
    c = config(); char name[130]; memset(name, 'a', 129); name[129] = 0; c.hostname = name;
    assert(efrp_handshake_init(&h, &c, rx, sizeof rx, 0) == EFRP_INVALID_ARGUMENT);
    c.hostname = "\xc0\x80"; assert(efrp_handshake_init(&h, &c, rx, sizeof rx, 0) == EFRP_INVALID_ARGUMENT);
    char auth[33];
    assert(efrp_token_auth(token, sizeof token - 1, INT64_MAX, auth) == EFRP_OK && strlen(auth) == 32);
    assert(efrp_token_auth(token, 0, 1, auth) == EFRP_INVALID_ARGUMENT); zero(auth, sizeof auth);
}
static size_t allocation_limit, allocations, outstanding;
static void *limited_malloc(size_t n)
{
    void *p = allocations++ < allocation_limit ? malloc(n) : NULL;
    if (p) ++outstanding;
    return p;
}
static void limited_free(void *p)
{
    if (p) { assert(outstanding); --outstanding; free(p); }
}
static void allocation_failures(void)
{
    cJSON_Hooks hooks = {.malloc_fn = limited_malloc, .free_fn = limited_free};
    bool success = false;
    for (size_t limit = 0; limit < 100; ++limit) {
        efrp_handshake_t h = {0}; uint8_t rx[EFRP_HANDSHAKE_RX_BYTES]; efrp_handshake_config_t c = config();
        allocation_limit = limit; allocations = 0; cJSON_InitHooks(&hooks);
        efrp_result_t result = efrp_handshake_init(&h, &c, rx, sizeof rx, 0);
        if (result != EFRP_OK) {
            assert(result == EFRP_CAPACITY_EXCEEDED); zero(h.token, sizeof h.token); zero(h.output, sizeof h.output);
        } else success = true;
        assert(!outstanding); efrp_handshake_destroy(&h); cJSON_InitHooks(NULL);
        if (success) break;
    }
    assert(success);
    /* The test is single-threaded; production never changes global cJSON hooks. */
    for (size_t limit = 0; limit < 100; ++limit) {
        efrp_handshake_t h = {0}; uint8_t rx[EFRP_HANDSHAKE_RX_BYTES], wire[1024]; start(&h, rx);
        allocation_limit = limit; allocations = 0; cJSON_InitHooks(&hooks);
        size_t n = frame(wire, EFRP_SERVER_HELLO, hello), used;
        efrp_result_t result = efrp_handshake_feed(&h, wire, n, &used);
        if (result != EFRP_OK) { assert(result == EFRP_PROTOCOL_ERROR); zero(h.token, sizeof h.token); }
        assert(!outstanding); efrp_handshake_destroy(&h); cJSON_InitHooks(NULL);
        if (result == EFRP_OK) break;
        assert(limit != 99);
    }
}
static void udp_negotiation(void)
{
    const char selected[] = "{\"selected\":{\"message\":{\"codec\":\"json\",\"udpPacketCodec\":\"binary-v1\"},\"crypto\":{\"algorithm\":\"aes-256-gcm\",\"serverRandom\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}}";
    for (unsigned mode = 0; mode < 4; ++mode) {
        efrp_handshake_t h = {0}; uint8_t rx[EFRP_HANDSHAKE_RX_BYTES], wire[2048];
        efrp_handshake_config_t c = config(); c.udp_binary = mode != 0;
        assert(efrp_handshake_init(&h, &c, rx, sizeof rx, 0) == EFRP_OK);
        assert((strstr((char *)h.client_hello, "udpPacketCodecs") != NULL) == c.udp_binary);
        const uint8_t *out; size_t length, used;
        assert(efrp_handshake_output(&h, &out, &length) == EFRP_OK);
        assert(efrp_handshake_consume_output(&h, length) == EFRP_OK);
        size_t n = frame(wire, EFRP_SERVER_HELLO, mode == 1 ? hello : selected);
        n += frame(wire + n, EFRP_MESSAGE, login); wire[n] = 0xa5;
        if (mode < 2) assert(efrp_handshake_feed(&h, wire, n, &used) == EFRP_NEGOTIATION_FAILED);
        else {
            if (mode == 3) for (size_t at = 0; at < n;) {
                assert(efrp_handshake_feed(&h, wire + at, 1, &used) == EFRP_OK && used == 1); at += used;
            }
            else assert(efrp_handshake_feed(&h, wire, n + 1, &used) == EFRP_OK && used == n);
            assert(h.state == EFRP_HANDSHAKE_DONE && h.udp_binary);
            efrp_aead_keys_t keys; char id[EFRP_RUN_ID_BYTES];
            assert(efrp_handshake_take_result(&h, &keys, id) == EFRP_OK);
            assert(!strcmp(id, "0123456789abcdef")); efrp_aead_clear_keys(&keys);
        }
        efrp_handshake_destroy(&h); zero(&h, sizeof h);
    }
}
static void xtcp_control_identity(void)
{
    const char *responses[] = {
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"ERERERERERERERERERERERERERERERERERERERERERE=\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"ERERERERERERERERERERERERERERERERERERERERERER\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"ERERERERERERERERERERERERERERERERERERERERERF=\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":17}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"ERERERERERERERERERERERERERERERERERERERERERE=\",\"xtcp_control_id\":\"ERERERERERERERERERERERERERERERERERERERERERE=\"}",
        "{\"version\":\"candidate\",\"run_id\":\"same-run-id\",\"xtcp_control_id\":\"ERERE!ERERERERERERERERERERERERERERERERERERE=\"}"
    };
    for (size_t mode = 0; mode <= sizeof responses / sizeof responses[0]; ++mode) {
        efrp_handshake_t h = {0}; uint8_t rx[EFRP_HANDSHAKE_RX_BYTES], wire[2048], control_id[32];
        efrp_handshake_config_t c = config(); c.xtcp_binding = mode != sizeof responses / sizeof responses[0];
        assert(efrp_handshake_init(&h, &c, rx, sizeof rx, 0) == EFRP_OK);
        const uint8_t *out; size_t length, used;
        assert(efrp_handshake_output(&h, &out, &length) == EFRP_OK);
        size_t login_offset = 7u + 8u + h.hello_length + 10u;
        cJSON *request = cJSON_Parse((const char *)out + login_offset); assert(request);
        const cJSON *protocol = cJSON_GetObjectItemCaseSensitive(request, "xtcp_binding_protocol");
        if (c.xtcp_binding) assert(cJSON_IsString(protocol) && !strcmp(protocol->valuestring, "esp-frp-xtcp/1"));
        else assert(!protocol);
        cJSON_Delete(request);
        memset(control_id, 0xaa, sizeof control_id);
        assert(efrp_handshake_xtcp_control_id(&h, control_id) == EFRP_INVALID_STATE); zero(control_id, sizeof control_id);
        assert(efrp_handshake_consume_output(&h, length) == EFRP_OK);
        size_t count = frame(wire, EFRP_SERVER_HELLO, hello);
        count += frame(wire + count, EFRP_MESSAGE, responses[c.xtcp_binding ? mode : 0]);
        efrp_result_t result = efrp_handshake_feed(&h, wire, count, &used);
        if (mode) {
            assert(result == EFRP_PROTOCOL_ERROR); zero(h.xtcp_control_id, sizeof h.xtcp_control_id);
            assert(efrp_handshake_xtcp_control_id(&h, control_id) == EFRP_PROTOCOL_ERROR); zero(control_id, sizeof control_id);
        } else {
            assert(result == EFRP_OK && h.state == EFRP_HANDSHAKE_DONE);
            assert(efrp_handshake_xtcp_control_id(&h, control_id) == EFRP_OK);
            for (size_t i = 0; i < sizeof control_id; ++i) assert(control_id[i] == 0x11);
            efrp_aead_keys_t keys; char id[EFRP_RUN_ID_BYTES];
            assert(efrp_handshake_take_result(&h, &keys, id) == EFRP_OK && !strcmp(id, "same-run-id"));
            zero(h.xtcp_control_id, sizeof h.xtcp_control_id); efrp_aead_clear_keys(&keys);
            assert(efrp_handshake_xtcp_control_id(&h, control_id) == EFRP_INVALID_STATE); zero(control_id, sizeof control_id);
        }
        efrp_handshake_destroy(&h); zero(&h, sizeof h);
    }
}
int main(void)
{
    xtcp_control_identity(); udp_negotiation(); split_and_tail(); in_place_receive(); invalid_messages(); deadlines_and_limits(); allocation_failures();
    puts("Handshake: framing, negotiation, JSON bounds, deadline, cleanup and allocation failures passed");
    return 0;
}
