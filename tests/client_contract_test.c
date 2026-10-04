// SPDX-License-Identifier: Apache-2.0
#include "esp_frp.h"
#include "flash_store_fixture.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { void *p; size_t n; unsigned call; } block_t;
static block_t blocks[4];
static unsigned calls, fail_at, live;
static bool verify_zero, verify_xtcp_settings;
void *fixture_client_malloc(size_t n)
{
    if (++calls == fail_at) return NULL;
    void *p = malloc(n); assert(p);
    for (unsigned i = 0; i < 4; ++i) if (!blocks[i].p) { blocks[i] = (block_t){p, n, calls}; ++live; return p; }
    abort();
}
void *fixture_client_calloc(size_t count, size_t n)
{
    assert(!count || n <= SIZE_MAX / count);
    void *p = fixture_client_malloc(count * n); if (p) memset(p, 0, count * n); return p;
}
void fixture_client_free(void *p)
{
    if (!p) return;
    for (unsigned i = 0; i < 4; ++i) if (blocks[i].p == p) {
        if (verify_zero && calls >= 3 && (blocks[i].call <= 2 || (verify_xtcp_settings && blocks[i].call == 3)))
            for (size_t j = 0; j < blocks[i].n; ++j) assert(((uint8_t *)p)[j] == 0);
        blocks[i].p = NULL; --live; free(p); return;
    }
    abort();
}
static bool trusted(void *context) { (void)context; return true; }
int main(void)
{
    const uint8_t ca[] = "public placeholder PEM parsed only on start", token[] = "public-test-token";
    static efrp_test_flash_t flash;
    efrp_aead_flash_store_t store = efrp_test_flash_store(&flash);
    assert(efrp_aead_flash_store_recover(&store) == EFRP_OK);
    efrp_config_t good = {.server_hostname = "frp.fixture.invalid", .server_port = 1234,
        .ca_pem = ca, .ca_length = sizeof ca - 1, .token = token, .token_length = sizeof token - 1,
        .proxy_name = "fixture-contract", .local_ipv4 = {127, 0, 0, 1}, .local_port = 1,
        .time_is_trusted = trusted, .flash_store = &store};
    efrp_client_t *c = NULL;
    assert(efrp_create(NULL, &c) == EFRP_INVALID_ARGUMENT && !c);
    assert(efrp_create(&good, NULL) == EFRP_INVALID_ARGUMENT);
    char long_name[255]; memset(long_name, 'x', sizeof long_name - 1); long_name[254] = 0;
    for (unsigned test = 0; test < 27; ++test) {
        efrp_config_t bad = good;
        switch (test) {
        case 0: bad.server_hostname = long_name; break;
        case 1: bad.server_hostname = "https://fixture.invalid"; break;
        case 2: bad.server_port = 0; break;
        case 3: bad.ca_length = 0; break;
        case 4: bad.ca_length = EFRP_TLS_MAX_CA_BYTES + 1; break;
        case 5: bad.ca_length = sizeof ca; break;
        case 6: bad.token_length = 0; break;
        case 7: bad.token_length = EFRP_AEAD_MAX_TOKEN_BYTES + 1; break;
        case 8: bad.proxy_name = ""; break;
        case 9: bad.proxy_name = "\xc0\xaf"; break;
        case 10: bad.hostname = long_name; break;
        case 11: bad.local_ipv4[0] = 224; break;
        case 12: bad.local_port = 0; break;
        case 13: bad.time_is_trusted = NULL; break;
        case 14: bad.run_id = long_name; break;
        case 15: bad.run_id = "\xc0\xaf"; break;
        case 16: bad.flash_store = NULL; break;
        case 18: bad.proxy_type = (efrp_proxy_type_t)99; break;
        case 19: bad.proxy_type = EFRP_PROXY_UDP; break;
        case 20: bad.proxy_type = EFRP_PROXY_UDP; bad.udp_packet_size = 65508; break;
        case 21: bad.udp_packet_size = 1; break;
        case 22: bad.proxy_type = EFRP_PROXY_STCP; break;
        case 23: bad.transport = (efrp_transport_kind_t)99; break;
        case 24: bad.transport = EFRP_TRANSPORT_QUIC; break;
        case 25: bad.transport = EFRP_TRANSPORT_QUIC; bad.quic_profile = (efrp_quic_profile_t)99; break;
        case 26: bad.quic_profile = EFRP_QUIC_PROFILE_P256_AES128_X25519; break;
        case 17: {
            efrp_aead_flash_store_t missing = store;
            missing.clear = NULL;
            bad.flash_store = &missing;
            assert(efrp_create(&bad, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
            continue;
        }
        }
        assert(efrp_create(&bad, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
    }
    char bounded_run_id[EFRP_RUN_ID_BYTES + 1U];
    memset(bounded_run_id, 'r', sizeof bounded_run_id);
    bounded_run_id[EFRP_RUN_ID_BYTES - 1U] = 0;
    efrp_config_t bounded = good;
    bounded.run_id = bounded_run_id;
    assert(efrp_create(&bounded, &c) == EFRP_OK && c);
    efrp_status_t unverified;
    assert(efrp_get_status(c, &unverified) == EFRP_OK && unverified.run_id[0] == 0);
    char address[2] = {1, 1}; size_t length = 123;
    assert(efrp_get_remote_address(c, address, sizeof address, &length) == EFRP_OK && !length && !address[0] && address[1] == 1);
    assert(efrp_get_remote_address(c, NULL, 0, &length) == EFRP_CAPACITY_EXCEEDED && !length);
    assert(efrp_get_remote_address(NULL, address, sizeof address, &length) == EFRP_INVALID_ARGUMENT && !length);

    assert(efrp_destroy(&c, 1000) == EFRP_OK && !c && !live);
    bounded_run_id[EFRP_RUN_ID_BYTES - 1U] = 'r';
    bounded_run_id[EFRP_RUN_ID_BYTES] = 0;
    assert(efrp_create(&bounded, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
    verify_zero = true;
    for (unsigned index = 1; index <= 4; ++index) {
        calls = 0; fail_at = index;
        efrp_result_t result = efrp_create(&good, &c);
        if (index <= 3) assert(result == EFRP_NO_MEMORY && !c);
        else { assert(result == EFRP_OK && c); assert(efrp_destroy(&c, 1000) == EFRP_OK && !c); }
        assert(!live);
    }
    efrp_stcp_visitor_config_t visitor = {.server_hostname = good.server_hostname, .server_port = good.server_port,
        .ca_pem = ca, .ca_length = sizeof ca - 1, .token = token, .token_length = sizeof token - 1,
        .server_proxy_name = "provider.private", .secret_key = "public-visitor-secret",
        .bind_ipv4 = {127, 0, 0, 1}, .bind_port = 8765, .time_is_trusted = trusted, .flash_store = &store};
    fail_at = 0;
    assert(efrp_stcp_visitor_create(NULL, &c) == EFRP_INVALID_ARGUMENT && !c);
    for (unsigned test = 0; test < 13; ++test) {
        efrp_stcp_visitor_config_t invalid_visitor = visitor;
        switch (test) {
        case 0: invalid_visitor.secret_key = ""; break;
        case 1: invalid_visitor.secret_key = long_name; break;
        case 2: invalid_visitor.secret_key = "\xc0\xaf"; break;
        case 3: invalid_visitor.server_proxy_name = ""; break;
        case 4: invalid_visitor.bind_ipv4[0] = 0; break;
        case 5: invalid_visitor.bind_ipv4[0] = 224; break;
        case 6: invalid_visitor.bind_port = 0; break;
        case 7: invalid_visitor.token_length = 0; break;
        case 8: invalid_visitor.time_is_trusted = NULL; break;
        case 9: invalid_visitor.transport = (efrp_transport_kind_t)99; break;
        case 10: invalid_visitor.transport = EFRP_TRANSPORT_QUIC; break;
        case 11: invalid_visitor.transport = EFRP_TRANSPORT_QUIC; invalid_visitor.quic_profile = (efrp_quic_profile_t)99; break;
        case 12: invalid_visitor.quic_profile = EFRP_QUIC_PROFILE_P256_AES128_X25519; break;
        }
        assert(efrp_stcp_visitor_create(&invalid_visitor, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
    }
    for (unsigned index = 1; index <= 5; ++index) {
        calls = 0; fail_at = index;
        efrp_result_t result = efrp_stcp_visitor_create(&visitor, &c);
        if (index <= 4) assert(result == EFRP_NO_MEMORY && !c);
        else { assert(result == EFRP_OK && c); assert(efrp_destroy(&c, 1000) == EFRP_OK && !c); }
        assert(!live);
    }
    fail_at = 0;
    efrp_xtcp_options_t xtcp_options = {.peer_profile = EFRP_QUIC_PROFILE_P256_AES128_X25519,
        .stun_servers = {{{127, 0, 0, 1}, 3478}}, .stun_server_count = 1, .udp_bind_ipv4 = {127, 0, 0, 1}};
    efrp_proxy_options_t xtcp_secret = {.secret_key = "public-provider-secret"};
    efrp_config_t xtcp_provider = good;
    xtcp_provider.proxy_type = EFRP_PROXY_XTCP; xtcp_provider.proxy_options = &xtcp_secret; xtcp_provider.xtcp_options = &xtcp_options;
    for (unsigned test = 0; test < 10; ++test) {
        efrp_config_t invalid = xtcp_provider; efrp_xtcp_options_t options = xtcp_options;
        invalid.xtcp_options = &options;
        switch (test) {
        case 0: invalid.proxy_type = EFRP_PROXY_TCP; invalid.proxy_options = NULL; break;
        case 1: invalid.xtcp_options = NULL; break;
        case 2: options.peer_profile = 0; break;
        case 3: options.stun_server_count = 0; break;
        case 4: options.stun_server_count = 3; break;
        case 5: options.stun_servers[0].ipv4[0] = 224; break;
        case 6: options.stun_servers[0].port = 0; break;
        case 7: options.udp_bind_ipv4[0] = 0; options.udp_bind_ipv4[1] = 1; break;
        case 8: invalid.proxy_name = "provider.\ninvalid"; break;
        case 9: invalid.remote_port = 7000; break;
        }
        assert(efrp_create(&invalid, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
    }
    for (unsigned index = 1; index <= 4; ++index) {
        calls = 0; fail_at = index;
        efrp_result_t result = efrp_create(&xtcp_provider, &c);
        if (index <= 3) assert(result == EFRP_NO_MEMORY && !c);
        else {
            assert(result == EFRP_OK && c);
            assert(efrp_get_status(c, &unverified) == EFRP_OK && unverified.phase == EFRP_PHASE_STOPPED && unverified.xtcp.phase == EFRP_XTCP_IDLE);
            assert(efrp_destroy(&c, 1000) == EFRP_OK && !c);
        }
        assert(!live);
    }
    fail_at = 0;
    efrp_xtcp_visitor_config_t xtcp_visitor = {.server_hostname = good.server_hostname, .server_port = good.server_port,
        .ca_pem = ca, .ca_length = sizeof ca - 1, .token = token, .token_length = sizeof token - 1,
        .server_proxy_name = "provider.bound", .secret_key = "public-visitor-secret", .bind_ipv4 = {127, 0, 0, 1}, .bind_port = 8765,
        .options = xtcp_options, .time_is_trusted = trusted, .flash_store = &store};
    assert(efrp_xtcp_visitor_create(NULL, &c) == EFRP_INVALID_ARGUMENT && !c);
    for (unsigned test = 0; test < 16; ++test) {
        efrp_xtcp_visitor_config_t invalid = xtcp_visitor;
        switch (test) {
        case 0: invalid.secret_key = ""; break;
        case 1: invalid.secret_key = long_name; break;
        case 2: invalid.secret_key = "\xc0\xaf"; break;
        case 3: invalid.server_proxy_name = ""; break;
        case 4: invalid.server_proxy_name = "provider.\ninvalid"; break;
        case 5: invalid.bind_ipv4[0] = 0; break;
        case 6: invalid.bind_ipv4[0] = 224; break;
        case 7: invalid.bind_port = 0; break;
        case 8: invalid.options.peer_profile = 0; break;
        case 9: invalid.options.stun_server_count = 0; break;
        case 10: invalid.options.stun_server_count = 3; break;
        case 11: invalid.options.stun_servers[0].ipv4[0] = 224; break;
        case 12: invalid.options.stun_servers[0].port = 0; break;
        case 13: invalid.options.udp_bind_ipv4[0] = 224; break;
        case 14: invalid.token_length = 0; break;
        case 15: invalid.time_is_trusted = NULL; break;
        }
        assert(efrp_xtcp_visitor_create(&invalid, &c) == EFRP_INVALID_ARGUMENT && !c && !live);
    }
    verify_xtcp_settings = true;
    for (unsigned index = 1; index <= 5; ++index) {
        calls = 0; fail_at = index;
        efrp_result_t result = efrp_xtcp_visitor_create(&xtcp_visitor, &c);
        if (index <= 4) assert(result == EFRP_NO_MEMORY && !c);
        else {
            assert(result == EFRP_OK && c);
            assert(efrp_get_status(c, &unverified) == EFRP_OK && unverified.phase == EFRP_PHASE_STOPPED && unverified.xtcp.phase == EFRP_XTCP_IDLE);
            assert(efrp_destroy(&c, 1000) == EFRP_OK && !c);
        }
        assert(!live);
    }
    puts("Provider/STCP/XTCP visitor config boundaries, allocation rollback and copied-secret zeroization passed");
}
