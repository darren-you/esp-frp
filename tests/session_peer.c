// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_connect.h"
#include "esp_frp_session.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static uint64_t now_ms(void)
{
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static efrp_result_t expected_result(const char *mode)
{
    if (!strcmp(mode, "wrong-token")) return EFRP_LOGIN_REJECTED;
    if (!strcmp(mode, "proxy-error")) return EFRP_PROXY_REJECTED;
    if (!strcmp(mode, "fixture-login-fin") || !strcmp(mode, "fixture-frame-truncated") ||
        !strcmp(mode, "fixture-aead-truncated")) return EFRP_TRUNCATED;
    if (!strcmp(mode, "fixture-fin") || !strcmp(mode, "fixture-tls-fin")) return EFRP_SESSION_CLOSED;
    if (!strcmp(mode, "fixture-pong-error") || !strcmp(mode, "fixture-aead-tamper")) return EFRP_AUTHENTICATION_FAILED;
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
    efrp_connect_t *connection = NULL; efrp_tls_t *tls = NULL; efrp_session_t *session = NULL;
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
    char proxy[100], client_id[100];
    snprintf(proxy, sizeof proxy, "fixture-control-%s-%u", mode, round);
    snprintf(client_id, sizeof client_id, "fixture-client-%s-%u", mode, round);
    const char *token = !strcmp(mode, "wrong-token") ? "wrong-public-token" : "public-session-token";
    efrp_session_config_t config = {.login = {.token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-control-board", .client_id = client_id, .unix_seconds = (int64_t)time(NULL)},
        .proxy_name = proxy, .remote_port = (uint16_t)proxy_port, .local_ipv4 = {127, 0, 0, 1}, .local_port = 9};
    assert(efrp_session_create(NULL, tls, now_ms(), &session) == EFRP_INVALID_ARGUMENT && !session);
    assert(efrp_session_create(&config, NULL, now_ms(), &session) == EFRP_INVALID_ARGUMENT && !session);
    efrp_session_config_t invalid = config;
    invalid.proxy_name = "";
    assert(efrp_session_create(&invalid, tls, now_ms(), &session) == EFRP_INVALID_ARGUMENT && !session);
    assert(efrp_session_create(&config, tls, now_ms(), &session) == EFRP_OK);
    assert(efrp_session_create(&config, tls, now_ms(), &session) == EFRP_INVALID_STATE);
    assert(efrp_session_step(session, 0, (int64_t)time(NULL)) == EFRP_INVALID_ARGUMENT);
    assert(efrp_session_step(session, now_ms(), 0) == EFRP_INVALID_ARGUMENT);
    // The session/handshake must own their configuration after create.
    memset(proxy, 'x', strlen(proxy)); memset(client_id, 'y', strlen(client_id));
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
            assert(status.run_id[0] && status.remote_address[0]);
            if (!announced) { printf("REGISTERED %s\n", status.remote_address); fflush(stdout); announced = true; }
            unsigned want_pongs = !strcmp(mode, "heartbeat") ? 2 : 1;
            bool need_work = !strcmp(mode, "request") || !strcmp(mode, "fixture-tail") || !strcmp(mode, "fixture-record");
            bool need_rejection = !strcmp(mode, "fixture-work-overflow");
            if (expected == EFRP_OK && status.pongs >= want_pongs && (!need_work || status.work.requests) &&
                (!need_rejection || status.work.rejected_requests)) break;
        }
        poll(NULL, 0, 1);
    }
    if (result != expected) { fprintf(stderr, "session mode=%s result=%d expected=%d phase=%d\n", mode, result, expected, status.phase); abort(); }
    if (expected != EFRP_OK) assert(efrp_session_step(session, now_ms(), (int64_t)time(NULL)) == expected);
    assert(efrp_session_cancel(session) == (expected == EFRP_OK ? EFRP_CANCELLED : expected));
    assert(efrp_session_status(session, &status) == EFRP_OK);
    assert(status.work.pending == 0 && !status.work.active && !status.work.waiting && !status.work.cleaning);
    assert(status.phase == ((expected == EFRP_OK || expected == EFRP_CANCELLED) ? EFRP_SESSION_STOPPED : EFRP_SESSION_FAILED));
    assert(efrp_session_destroy(&session) == EFRP_OK && !session); efrp_tls_destroy(tls);
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
