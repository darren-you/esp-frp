// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_connect.h"
#include "esp_frp_session.h"
#ifdef EFRP_SESSION_IDF_FLASH_TEST
#include "session_idf_flash_fixture.h"
#else
#include "flash_store_fixture.h"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
void fixture_session_check(const efrp_session_config_t *, efrp_transport_t *, uint64_t);
void fixture_session_released(void);
void fixture_session_fail_next_allocation(void);
static uint64_t now_ms(void)
{
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static efrp_result_t expected_result(const char *mode)
{
    if (!strcmp(mode, "registration-memory")) return EFRP_NO_MEMORY;
    if (!strcmp(mode, "wrong-token")) return EFRP_LOGIN_REJECTED;
    if (!strcmp(mode, "proxy-error")) return EFRP_PROXY_REJECTED;
    if (!strcmp(mode, "fixture-login-fin") || !strcmp(mode, "fixture-frame-truncated") ||
        !strcmp(mode, "fixture-aead-truncated") || !strcmp(mode,"fixture-yamux-truncated")) return EFRP_TRUNCATED;
    if (!strcmp(mode,"fixture-yamux-reset")) return EFRP_STREAM_RESET;
    if (!strcmp(mode,"fixture-aead-oversized")) return EFRP_PROTOCOL_ERROR;
    if (!strcmp(mode,"fixture-aead-max-clear-fail")) return EFRP_STORAGE_ERROR;
    if (!strcmp(mode,"fixture-control-oversized")) return EFRP_CAPACITY_EXCEEDED;
    if (!strcmp(mode, "fixture-fin") || !strcmp(mode, "fixture-tls-fin")) return EFRP_SESSION_CLOSED;
    if (!strcmp(mode, "fixture-pong-error") || !strcmp(mode, "fixture-aead-tamper") ||
        !strcmp(mode, "fixture-aead-max-tamper")) return EFRP_AUTHENTICATION_FAILED;
    if (!strcmp(mode, "fixture-register-timeout") || !strcmp(mode, "fixture-pong-timeout")) return EFRP_TIMEOUT;
    if (!strncmp(mode, "fixture-bad-", 12)) return EFRP_PROTOCOL_ERROR;
    return EFRP_OK;
}
typedef struct { efrp_connect_t *connection; unsigned writes, reads; bool split; } io_t;
static efrp_result_t session_send(void *context, const uint8_t *p, size_t n, size_t *sent)
{
    io_t *io = context; *sent = 0;
    if (io->split) { if (++io->writes % 2) return EFRP_WOULD_BLOCK; if (n > 37) n = 37; }
    return efrp_connect_send(io->connection, p, n, sent);
}
static efrp_result_t session_recv(void *context, uint8_t *p, size_t n, size_t *received)
{
    io_t *io = context; *received = 0;
    if (io->split) { if (++io->reads % 2) return EFRP_WOULD_BLOCK; if (n > 41) n = 41; }
    return efrp_connect_recv(io->connection, p, n, received);
}
static void round_trip(unsigned port, const uint8_t *ca, size_t ca_length, const char *mode,
    unsigned round, unsigned proxy_port)
{
    efrp_connect_t *connection = NULL; efrp_tls_t *tls = NULL; efrp_transport_t *transport = NULL; efrp_session_t *session = NULL;
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, now_ms(), &connection) == EFRP_OK);
    efrp_result_t result;
    do { result = efrp_connect_step(connection, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    int fd; assert(efrp_connect_fd(connection, &fd) == EFRP_OK);
    io_t io = {.connection = connection, .split = !strcmp(mode, "split")};
    efrp_tls_config_t tls_config = {.hostname = "frp.fixture.invalid", .ca_pem = ca, .ca_length = ca_length,
        .time_is_trusted = true, .send = session_send, .recv = session_recv, .io_context = &io};
    assert(efrp_tls_create(&tls_config, now_ms(), &tls) == EFRP_OK);
    do { result = efrp_tls_step(tls, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    assert(efrp_transport_yamux_create(tls, now_ms(), &transport) == EFRP_OK);
    char proxy[100], client_id[100];
    snprintf(proxy, sizeof proxy, "fixture-control-%s-%u", mode, round);
    snprintf(client_id, sizeof client_id, "fixture-client-%s-%u", mode, round);
    const char *token = !strcmp(mode, "wrong-token") ? "wrong-public-token" : "public-session-token";
#ifdef EFRP_SESSION_IDF_FLASH_TEST
    const efrp_aead_flash_store_t *store = efrp_session_idf_flash_prepare();
#else
    static efrp_test_flash_t flash;
    memset(&flash, 0, sizeof flash);
    efrp_aead_flash_store_t store_value = efrp_test_flash_store(&flash);
    const efrp_aead_flash_store_t *store = &store_value;
    assert(efrp_aead_flash_store_recover(store) == EFRP_OK);
    flash.fail_clear = !strcmp(mode, "fixture-aead-max-clear-fail");
#endif
    efrp_session_config_t config = {.login = {.token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-control-board", .client_id = client_id, .unix_seconds = (int64_t)time(NULL)},
        .proxy_name = proxy, .remote_port = (uint16_t)proxy_port, .local_ipv4 = {127, 0, 0, 1},
        .local_port = 9, .flash_store = store};
    assert(efrp_session_create(NULL, transport, now_ms(), &session) == EFRP_INVALID_ARGUMENT && !session);
    assert(efrp_session_create(&config, NULL, now_ms(), &session) == EFRP_INVALID_ARGUMENT && !session);
    efrp_session_config_t invalid = config;
    invalid.proxy_name = "";
    assert(efrp_session_create(&invalid, transport, now_ms(), &session) == EFRP_INVALID_ARGUMENT && !session);
    if (!round) fixture_session_check(&config, transport, now_ms());
    assert(efrp_session_create(&config, transport, now_ms(), &session) == EFRP_OK);
    assert(efrp_session_create(&config, transport, now_ms(), &session) == EFRP_INVALID_STATE);
    assert(efrp_session_step(session, 0, (int64_t)time(NULL)) == EFRP_INVALID_ARGUMENT);
    assert(efrp_session_step(session, now_ms(), 0) == EFRP_INVALID_ARGUMENT);
    // The session/handshake must own their configuration after create.
    memset(proxy, 'x', strlen(proxy)); memset(client_id, 'y', strlen(client_id));
    if (!strcmp(mode, "registration-memory")) fixture_session_fail_next_allocation();
    efrp_result_t expected = expected_result(mode);
    bool announced = false; uint64_t end = now_ms() + 20000; efrp_session_status_t status = {0};
    if (!strcmp(mode, "cancel-login")) {
        assert(efrp_session_cancel(session) == EFRP_CANCELLED); expected = EFRP_CANCELLED; result = expected;
    } else for (;;) {
        assert(now_ms() < end);
        result = efrp_session_step(session, now_ms(), (int64_t)time(NULL));
        assert(efrp_session_status(session, &status) == EFRP_OK);
        if (result != EFRP_OK) break;
        if (!strcmp(mode, "cancel-register") && status.phase == EFRP_SESSION_REGISTERING) {
            result = efrp_session_cancel(session); expected = EFRP_CANCELLED; break;
        }
        if (status.phase == EFRP_SESSION_REGISTERED) {
            assert(status.run_id[0] && status.remote_address_length);
            if (!announced) {
                char address[257]; size_t length;
                assert(efrp_session_remote_address(session, address, sizeof address, &length) == EFRP_OK);
                assert(length == status.remote_address_length);
                char small[2] = {1, 1}; size_t needed = 0;
                assert(efrp_session_remote_address(session, small, sizeof small, &needed) == EFRP_CAPACITY_EXCEEDED);
                assert(needed == length && !small[0] && small[1] == 1);
                assert(efrp_session_remote_address(session, NULL, 0, &needed) == EFRP_CAPACITY_EXCEEDED && needed == length);
                printf("REGISTERED %s\n", address); fflush(stdout); announced = true;
            }
            unsigned want_pongs = !strcmp(mode, "heartbeat") ? 2 : 1;
            bool need_work = !strcmp(mode, "request") || !strcmp(mode, "fixture-tail") || !strcmp(mode, "fixture-record");
            bool need_rejection = !strcmp(mode, "fixture-work-overflow") || !strcmp(mode,"fixture-aead-max");
            if (expected == EFRP_OK && status.pongs >= want_pongs && (!need_work || status.work.requests) &&
                (!need_rejection || status.work.rejected_requests)) break;
        }
        poll(NULL, 0, 1);
    }
    if (result != expected) { fprintf(stderr, "session mode=%s result=%d expected=%d phase=%d\n", mode, result, expected, status.phase); abort(); }
    if (!strcmp(mode, "fixture-aead-max-tamper"))
        assert(status.work.requests == 0 && status.work.rejected_requests == 0);
    if (expected != EFRP_OK) assert(efrp_session_step(session, now_ms(), (int64_t)time(NULL)) == expected);
    assert(efrp_session_cancel(session) == (expected == EFRP_OK ? EFRP_CANCELLED : expected));
    assert(efrp_session_status(session, &status) == EFRP_OK);
    assert(status.work.pending == 0 && !status.work.active && !status.work.waiting && !status.work.cleaning);
    assert(status.phase == ((expected == EFRP_OK || expected == EFRP_CANCELLED) ? EFRP_SESSION_STOPPED : EFRP_SESSION_FAILED));
#ifndef EFRP_SESSION_IDF_FLASH_TEST
    if (flash.fail_clear) {
        assert(flash.busy && flash.quarantined && flash.begins == 1);
        assert(efrp_session_destroy(&session) == EFRP_STORAGE_ERROR && session);
        assert(efrp_session_cancel(session) == EFRP_STORAGE_ERROR);
        assert(flash.busy && flash.quarantined);
        flash.fail_clear = false;
    }
#endif
    assert(efrp_session_destroy(&session) == EFRP_OK && !session);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport); efrp_tls_destroy(tls);
#ifdef EFRP_SESSION_IDF_FLASH_TEST
    efrp_session_idf_flash_check(mode);
#else
    assert(!flash.busy && flash.clears == flash.begins);
    if (!strcmp(mode, "fixture-aead-max") || !strcmp(mode, "fixture-aead-max-clear-fail")) assert(flash.begins > 0);
#endif
    fixture_session_released();
    assert(efrp_connect_destroy(&connection) == EFRP_OK && !connection);
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}
int main(int argc, char **argv)
{
    assert(argc == 6);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), rounds = (unsigned)strtoul(argv[4], NULL, 10);
    unsigned proxy_port = (unsigned)strtoul(argv[5], NULL, 10);
    assert(port && port <= 65535 && rounds && rounds <= 100 && proxy_port <= 65535);
    FILE *file = fopen(argv[2], "rb"); assert(file);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t n = fread(ca, 1, sizeof ca, file);
    assert(n && n < sizeof ca && !ferror(file) && fclose(file) == 0);
    for (unsigned i = 0; i < rounds; ++i) round_trip(port, ca, n, argv[3], i, proxy_port);
    fprintf(stderr, "Control session: mode=%s rounds=%u passed\n", argv[3], rounds); return 0;
}
