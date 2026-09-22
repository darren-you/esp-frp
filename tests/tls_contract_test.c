// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_tls.h"
#include "mbedtls/platform.h"
#include "psa/crypto.h"
#include "psa/crypto_extra.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned calls; unsigned invalid; } fixture_t;
static efrp_result_t send_fixture(void *context, const uint8_t *bytes, size_t length, size_t *used)
{
    fixture_t *f = context; (void)bytes; ++f->calls;
    *used = f->invalid == 1 ? length + 1 : f->invalid == 2 ? 1 : 0;
    return f->invalid == 1 || f->invalid == 3 ? EFRP_OK :
        f->invalid == 4 ? EFRP_EOF : f->invalid == 5 ? EFRP_NETWORK_ERROR : EFRP_WOULD_BLOCK;
}
static efrp_result_t recv_fixture(void *context, uint8_t *bytes, size_t length, size_t *used)
{
    return send_fixture(context, bytes, length, used);
}
static void rejected(const efrp_tls_config_t *config, uint64_t now, efrp_result_t expected)
{
    efrp_tls_t *t = NULL;
    assert(efrp_tls_create(config, now, &t) == expected && !t);
}
#if defined(MBEDTLS_PLATFORM_MEMORY)
static size_t allocations, outstanding, reject_at;
static void *tracked_calloc(size_t count, size_t size)
{
    if (++allocations == reject_at) return NULL;
    void *p = calloc(count, size); if (p) ++outstanding; return p;
}
static void tracked_free(void *p)
{
    if (p) { assert(outstanding); --outstanding; free(p); }
}
static void allocation_failures(const efrp_tls_config_t *config)
{
    /* Isolated host process only. Never reset shared PSA in production: MQTT
     * and other components may own keys in the same global subsystem. */
    mbedtls_psa_crypto_free();
    assert(mbedtls_platform_set_calloc_free(tracked_calloc, tracked_free) == 0);
    efrp_tls_t *t = NULL;
    assert(efrp_tls_create(config, 0, &t) == EFRP_OK);
    size_t total = allocations;
    efrp_tls_destroy(t); mbedtls_psa_crypto_free(); assert(!outstanding && total);
    size_t failures = 0;
    for (size_t nth = 1; nth <= total; ++nth) {
        t = NULL; allocations = 0; reject_at = nth;
        efrp_result_t result = efrp_tls_create(config, 0, &t);
        assert(allocations >= nth);
        if (result != EFRP_OK) { assert(!t); ++failures; }
        efrp_tls_destroy(t); mbedtls_psa_crypto_free(); assert(!outstanding);
    }
    assert(failures); reject_at = 0;
    assert(mbedtls_platform_set_calloc_free(calloc, free) == 0);
    printf("TLS contract: %zu SDK allocation positions injected, %zu create failures, no retained SDK allocations\n", total, failures);
}
#endif
void tls_contract_tests(const uint8_t *ca, size_t length)
{
    fixture_t fixture = {0};
    efrp_tls_config_t valid = {.hostname = "frp.fixture.invalid", .ca_pem = ca, .ca_length = length,
        .time_is_trusted = true, .send = send_fixture, .recv = recv_fixture, .io_context = &fixture};
    efrp_tls_config_t c = valid;
    rejected(NULL, 0, EFRP_INVALID_ARGUMENT);
    rejected(&valid, UINT64_MAX, EFRP_INVALID_ARGUMENT);
    c.time_is_trusted = false; rejected(&c, 0, EFRP_TIME_UNTRUSTED);
    const char *hosts[] = {NULL, "", "bad host", "bad/host", "*.invalid", "user@host", "bad\\host", "\xc3\xa9.invalid"};
    for (size_t i = 0; i < sizeof hosts / sizeof *hosts; ++i) {
        c = valid; c.hostname = hosts[i]; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    }
    char long_host[255]; memset(long_host, 'a', sizeof long_host); long_host[254] = 0;
    c = valid; c.hostname = long_host; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    c = valid; c.ca_length = 0; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    c.ca_length = EFRP_TLS_MAX_CA_BYTES + 1; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    c = valid; c.ca_pem = NULL; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    const uint8_t embedded[] = {'a', 0, 'b'};
    c = valid; c.ca_pem = embedded; c.ca_length = sizeof embedded; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    c.ca_pem = (const uint8_t *)"invalid CA"; c.ca_length = 10; rejected(&c, 0, EFRP_TLS_TRUST_ERROR);
    const char broken[] = "\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n";
    uint8_t *bundle = malloc(length + sizeof broken); assert(bundle);
    memcpy(bundle, ca, length); memcpy(bundle + length, broken, sizeof broken);
    c = valid; c.ca_pem = bundle; c.ca_length = length + sizeof broken - 1;
    rejected(&c, 0, EFRP_TLS_TRUST_ERROR); free(bundle);
    c = valid; c.send = NULL; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    c = valid; c.recv = NULL; rejected(&c, 0, EFRP_INVALID_ARGUMENT);
    assert(!fixture.calls);
    for (unsigned i = 0; i < 100; ++i) {
        efrp_tls_t *t = NULL; assert(efrp_tls_create(&valid, 100, &t) == EFRP_OK);
        efrp_tls_t *original = t;
        assert(efrp_tls_create(&valid, 100, &t) == EFRP_INVALID_STATE && t == original);
        assert(efrp_tls_step(t, 99) == EFRP_INVALID_ARGUMENT);
        assert(efrp_tls_step(t, UINT64_MAX) == EFRP_INVALID_ARGUMENT);
        size_t used = 99; uint8_t byte;
        assert(efrp_tls_read(t, 100, &byte, 1, &used) == EFRP_WOULD_BLOCK && !used);
        assert(efrp_tls_write(t, 100, &byte, 1, &used) == EFRP_INVALID_STATE && !used);
        assert(efrp_tls_close(t, 100) == EFRP_INVALID_STATE);
        assert(efrp_tls_cancel(t) == EFRP_CANCELLED);
        assert(efrp_tls_cancel(t) == EFRP_CANCELLED);
        assert(efrp_tls_step(t, 100) == EFRP_CANCELLED);
        efrp_tls_destroy(t);
    }
    assert(!fixture.calls);
    for (unsigned invalid = 1; invalid <= 5; ++invalid) {
        fixture.invalid = invalid; efrp_tls_t *t = NULL;
        assert(efrp_tls_create(&valid, 0, &t) == EFRP_OK);
        efrp_result_t result;
        unsigned attempts = 0;
        do { assert(++attempts <= 100); result = efrp_tls_step(t, 0); } while (result == EFRP_WOULD_BLOCK);
        assert(result == EFRP_NETWORK_ERROR);
        unsigned calls = fixture.calls;
        assert(efrp_tls_step(t, 1) == result); efrp_tls_destroy(t); assert(fixture.calls == calls);
    }
#if defined(MBEDTLS_PLATFORM_MEMORY)
    allocation_failures(&valid);
#endif
    puts("TLS contract: trust preconditions, input bounds, monotonic time, 100 cancellations and callback failures passed");
}
