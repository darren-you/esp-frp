// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_connect.h"
#include "esp_frp_session.h"
#include "flash_store_fixture.h"
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
    struct timespec value; assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000U + (uint64_t)value.tv_nsec / 1000000U;
}
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
int main(int argc, char **argv)
{
    assert(argc == 5);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), local_port = (unsigned)strtoul(argv[3], NULL, 10);
    unsigned packet_size = (unsigned)strtoul(argv[4], NULL, 10);
    assert(port && port <= 65535 && local_port && local_port <= 65535 && packet_size && packet_size <= 65507);
    FILE *file = fopen(argv[2], "rb"); assert(file);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t ca_length = fread(ca, 1, sizeof ca, file);
    assert(ca_length && ca_length < sizeof ca && !ferror(file) && fclose(file) == 0);
    unsigned baseline = open_fds();
    efrp_connect_t *connection = NULL; efrp_tls_t *tls = NULL; efrp_session_t *session = NULL;
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, now_ms(), &connection) == EFRP_OK);
    efrp_result_t result;
    do { result = efrp_connect_step(connection, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    efrp_tls_config_t tls_config = {.hostname = "frp.fixture.invalid", .ca_pem = ca, .ca_length = ca_length,
        .time_is_trusted = true, .send = efrp_connect_send, .recv = efrp_connect_recv, .io_context = connection};
    assert(efrp_tls_create(&tls_config, now_ms(), &tls) == EFRP_OK);
    do { result = efrp_tls_step(tls, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    const char *token = "public-session-token";
    static efrp_test_flash_t flash;
    efrp_aead_flash_store_t store = efrp_test_flash_store(&flash);
    assert(efrp_aead_flash_store_recover(&store) == EFRP_OK);
    char name[128]; snprintf(name, sizeof name, "fixture-udp-proxy-%u-%u", local_port, packet_size);
    efrp_transport_t *transport = NULL;
    assert(efrp_transport_yamux_create(tls, now_ms(), &transport) == EFRP_OK);
    efrp_session_config_t config = {.login = {.token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-udp-board", .client_id = name, .unix_seconds = (int64_t)time(NULL)},
        .proxy_name = name, .proxy_type = EFRP_PROXY_UDP, .udp_packet_size = (uint16_t)packet_size,
        .local_ipv4 = {127, 0, 0, 1}, .local_port = (uint16_t)local_port, .flash_store = &store};
    assert(efrp_session_create(&config, transport, now_ms(), &session) == EFRP_OK);
    memset(config.local_ipv4, 0, sizeof config.local_ipv4); config.local_port = 0; config.udp_packet_size = 0;
    assert(fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK) == 0);
    bool announced = false; uint64_t end = now_ms() + 160000;
    efrp_session_status_t status = {0};
    for (;;) {
        uint64_t now = now_ms(); assert(now < end);
        result = efrp_session_step(session, now, (int64_t)time(NULL));
        assert(efrp_session_status(session, &status) == EFRP_OK);
        if (result != EFRP_OK) {
            fprintf(stderr, "UDP session=%d work=%d failures=%" PRIu64 "\n", result, status.work.last_error, status.work.failed); abort();
        }
        assert(status.work.active <= 1 && status.work.waiting <= 1 && status.work.udp_active_remotes <= 4);
        if (!announced && status.phase == EFRP_SESSION_REGISTERED && status.pongs) {
            char remote_address[257]; size_t remote_length = 0;
            assert(efrp_session_remote_address(session, remote_address, sizeof remote_address, &remote_length) == EFRP_OK);
            assert(remote_length == status.remote_address_length && remote_length < sizeof remote_address);
            printf("READY %s\n", remote_address); fflush(stdout); announced = true;
        }
        char command;
        if (read(STDIN_FILENO, &command, 1) == 1) {
            if (command == 'q') break;
#if defined(EFRP_UDP_RECOVERY_TEST)
            if (command == 'z') {
                assert(!status.work.active && !status.work.cleaning && !status.work.udp_active_remotes);
                assert(open_fds() == baseline + 1); /* The original control TCP socket only. */
                puts("DRAINED"); fflush(stdout); continue;
            }
#endif
            assert(command == 's');
            printf("STATE %u %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                status.work.active, status.work.udp_active_remotes, status.work.requests,
                status.work.udp_received_datagrams, status.work.udp_sent_datagrams,
                status.work.udp_dropped_datagrams, status.work.udp_expired_remotes); fflush(stdout);
        }
        poll(NULL, 0, 1);
    }
    assert(efrp_session_cancel(session) == EFRP_CANCELLED);
    do { result = efrp_session_destroy(&session); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK && !session && !flash.busy && flash.clears == flash.begins);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
    efrp_tls_destroy(tls); assert(efrp_connect_destroy(&connection) == EFRP_OK);
    assert(open_fds() == baseline);
    fprintf(stderr, "UDP peer: sent=%" PRIu64 " received=%" PRIu64 " dropped=%" PRIu64 " expired=%" PRIu64 " fd baseline restored\n",
        status.work.udp_sent_datagrams, status.work.udp_received_datagrams,
        status.work.udp_dropped_datagrams, status.work.udp_expired_remotes);
    return 0;
}
