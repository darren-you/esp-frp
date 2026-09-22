// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_connect.h"
#include "esp_frp_session.h"
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static uint64_t now_ms(void)
{
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
int main(int argc, char **argv)
{
    assert(argc == 6);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), local_port = (unsigned)strtoul(argv[3], NULL, 10);
    unsigned expected = (unsigned)strtoul(argv[5], NULL, 10);
    assert(port && port <= 65535 && local_port && local_port <= 65535);
    FILE *file = fopen(argv[2], "rb"); assert(file);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t n = fread(ca, 1, sizeof ca, file);
    assert(n && n < sizeof ca && !ferror(file) && fclose(file) == 0);
    unsigned baseline = open_fds();
    efrp_connect_t *connection = NULL; efrp_tls_t *tls = NULL; efrp_session_t *session = NULL;
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, now_ms(), &connection) == EFRP_OK);
    efrp_result_t result;
    do { result = efrp_connect_step(connection, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    efrp_tls_config_t tls_config = {.hostname = "frp.fixture.invalid", .ca_pem = ca, .ca_length = n,
        .time_is_trusted = true, .send = efrp_connect_send, .recv = efrp_connect_recv, .io_context = connection};
    assert(efrp_tls_create(&tls_config, now_ms(), &tls) == EFRP_OK);
    do { result = efrp_tls_step(tls, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    const char *token = "public-session-token";
    char proxy_name[128]; snprintf(proxy_name, sizeof proxy_name, "fixture-work-proxy-%s-%u", argv[4], local_port);
    efrp_session_config_t config = {.login = {.token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-work-board", .client_id = "fixture-work-client", .unix_seconds = (int64_t)time(NULL)},
        .proxy_name = proxy_name, .local_ipv4 = {127, 0, 0, 1}, .local_port = (uint16_t)local_port};
    assert(efrp_session_create(&config, tls, now_ms(), &session) == EFRP_OK);
    memset(config.local_ipv4, 0, sizeof config.local_ipv4); config.local_port = 0;
    assert(fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK) == 0);
    bool announced = false, stopping = false; uint64_t stop_deadline = 0, end = now_ms() + 200000, offset = 0, jump_at = 0;
    efrp_session_status_t status = {0}; unsigned peak = 0;
    for (;;) {
        uint64_t wall = now_ms(); assert(wall < end);
        if (jump_at && wall >= jump_at) { offset += EFRP_WORK_IDLE_MS + 1; jump_at = 0; }
        uint64_t now = wall + offset;
        result = efrp_session_step(session, now, (int64_t)time(NULL));
        assert(efrp_session_status(session, &status) == EFRP_OK);
        if (result != EFRP_OK) {
            fprintf(stderr, "work session failure=%d work=%d completed=%" PRIu64 " failed=%" PRIu64 "\n", result,
                status.work.last_error, status.work.completed, status.work.failed); abort();
        }
        assert(status.work.active <= 2 && status.work.waiting <= 1 && status.work.active + status.work.waiting + status.work.cleaning <= 3);
        if (status.work.active > peak) peak = status.work.active;
        if (!announced && status.phase == EFRP_SESSION_REGISTERED && status.pongs) {
            printf("READY %s\n", status.remote_address); fflush(stdout); announced = true;
        }
        char command;
        if (read(STDIN_FILENO, &command, 1) == 1) {
            if (command == 'q') { stopping = true; stop_deadline = now + 5000; }
            else if (command == 't') jump_at = wall + 100; /* fixture monotonic clock only */
            else if (command == 's') {
                printf("STATE %u %u %" PRIu64 " %" PRIu64 " %d\n", status.work.active, status.work.waiting,
                    status.work.completed, status.work.failed, status.work.last_error); fflush(stdout);
            } else assert(false);
        }
        if (stopping) {
            bool fault_mode = strcmp(argv[4], "duplex") != 0;
            if (fault_mode || (!status.work.active && !status.work.cleaning && status.work.completed == expected)) break;
            if (now >= stop_deadline) {
                fprintf(stderr, "work did not drain: active=%u waiting=%u completed=%" PRIu64 " failed=%" PRIu64 " reason=%d\n",
                    status.work.active, status.work.waiting, status.work.completed, status.work.failed, status.work.last_error); abort();
            }
        }
        poll(NULL, 0, 1);
    }
    if (!strcmp(argv[4], "duplex")) assert(peak == 2 && !status.work.failed && status.work.completed == expected);
    assert(efrp_session_cancel(session) == EFRP_CANCELLED);
    do { result = efrp_session_destroy(&session); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK && !session); efrp_tls_destroy(tls);
    assert(efrp_connect_destroy(&connection) == EFRP_OK);
    assert(open_fds() == baseline);
    fprintf(stderr, "Work peer: mode=%s completed=%" PRIu64 " failed=%" PRIu64 " peak=%u sent=%" PRIu64 " received=%" PRIu64 " fd baseline restored\n",
        argv[4], status.work.completed, status.work.failed, peak, status.work.local_sent, status.work.local_received);
    return 0;
}
