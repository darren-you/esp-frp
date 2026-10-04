// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp.h"
#include "client_port.h"
#include "flash_store_fixture.h"
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool trusted(void *context) { (void)context; return true; }
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static void state(const char *label, const efrp_status_t *status)
{
    printf("%s %d %" PRIu64 " %" PRIu64 " %u %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
        label, status->phase, status->ready_sessions, status->attempts, status->work.active,
        status->work.udp_active_remotes, status->work.udp_received_datagrams, status->work.udp_sent_datagrams,
        status->work.udp_dropped_datagrams, status->work.udp_expired_remotes);
    fflush(stdout);
}
int main(int argc, char **argv)
{
    assert(argc == 4);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), local_port = (unsigned)strtoul(argv[3], NULL, 10);
    assert(port && port <= 65535 && local_port && local_port <= 65535);
    FILE *file = fopen(argv[2], "rb"); assert(file);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t ca_length = fread(ca, 1, sizeof ca, file);
    assert(ca_length && ca_length < sizeof ca && !ferror(file) && fclose(file) == 0);
    unsigned baseline = open_fds();
    static efrp_test_flash_t flash;
    efrp_aead_flash_store_t store = efrp_test_flash_store(&flash);
    assert(efrp_aead_flash_store_recover(&store) == EFRP_OK);
    char proxy_name[128]; snprintf(proxy_name, sizeof proxy_name, "fixture-udp-client-%u", local_port);
    const char token[] = "public-session-token";
    efrp_config_t config = {.server_hostname = "frp.fixture.invalid", .server_port = (uint16_t)port,
        .ca_pem = ca, .ca_length = ca_length, .token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-udp-worker", .client_id = proxy_name, .proxy_name = proxy_name,
        .proxy_type = EFRP_PROXY_UDP, .udp_packet_size = 1500, .local_ipv4 = {127, 0, 0, 1},
        .local_port = (uint16_t)local_port, .time_is_trusted = trusted, .flash_store = &store};
#if defined(EFRP_CLIENT_QUIC_TEST)
    config.transport = EFRP_TRANSPORT_QUIC;
    config.quic_profile = EFRP_QUIC_PROFILE_P256_AES128_X25519;
#endif
    efrp_client_t *client = NULL;
    assert(efrp_create(&config, &client) == EFRP_OK);
    memset(ca, 0, ca_length); memset(proxy_name, 0, strlen(proxy_name));
    config.udp_packet_size = 0; memset(config.local_ipv4, 0, 4);
    assert(efrp_start(client) == EFRP_OK);
    assert(fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK) == 0);
    uint64_t end = efrp_port_now_ms() + 90000, announced = 0, backoff_announced = 0;
    char run_id[EFRP_RUN_ID_BYTES] = {0};
    efrp_status_t status = {0};
    for (;;) {
        assert(efrp_port_now_ms() < end);
        assert(efrp_get_status(client, &status) == EFRP_OK);
        if (status.phase == EFRP_PHASE_FAILED) {
            fprintf(stderr, "UDP worker failed phase=%d error=%d\n", status.failure_phase, status.error); abort();
        }
        assert(status.work.active <= 1 && status.work.udp_active_remotes <= 4);
        if (status.phase == EFRP_PHASE_READY && status.ready_sessions > announced) {
            if (!run_id[0]) memcpy(run_id, status.run_id, sizeof run_id);
            assert(!strcmp(run_id, status.run_id) && status.tls_verify_flags == 0);
            char address[257]; size_t length = 0;
            assert(efrp_get_remote_address(client, address, sizeof address, &length) == EFRP_OK);
            assert(length && length == status.remote_address_length);
            printf("READY %s\n", address); fflush(stdout); announced = status.ready_sessions;
        }
        if (status.phase == EFRP_PHASE_BACKOFF && announced && backoff_announced < announced) {
            assert(!status.work.active && !status.work.waiting && !status.work.cleaning && !status.work.udp_active_remotes);
            assert(!status.remote_address_length && open_fds() == baseline);
            assert(status.work.udp_received_datagrams && status.work.udp_sent_datagrams);
            state("BACKOFF", &status); backoff_announced = announced;
        }
        char command;
        if (read(STDIN_FILENO, &command, 1) == 1) {
            if (command == 'q') break;
            if (command == 's') state("STATE", &status);
            else if (command == 'c') {
                assert(efrp_stop(client, 5000) == EFRP_OK);
                assert(efrp_get_status(client, &status) == EFRP_OK && status.phase == EFRP_PHASE_STOPPED);
                assert(!status.work.active && !status.work.waiting && !status.work.cleaning && !status.work.udp_active_remotes);
                assert(!status.remote_address_length && open_fds() == baseline);
                state("STOPPED", &status);
            } else if (command == 'r') assert(efrp_start(client) == EFRP_OK);
            else assert(false);
        }
        poll(NULL, 0, 1);
    }
    assert(efrp_stop(client, 5000) == EFRP_OK);
    assert(efrp_get_status(client, &status) == EFRP_OK && status.phase == EFRP_PHASE_STOPPED);
    assert(!status.work.active && !status.work.udp_active_remotes && open_fds() == baseline);
    assert(efrp_destroy(&client, 5000) == EFRP_OK && !client);
    assert(open_fds() == baseline && !flash.busy && flash.clears == flash.begins);
    fprintf(stderr, "UDP worker: ready=%" PRIu64 " attempts=%" PRIu64 " datagrams=%" PRIu64 "/%" PRIu64 " gauges/fd restored\n",
        status.ready_sessions, status.attempts, status.work.udp_received_datagrams, status.work.udp_sent_datagrams);
    return 0;
}
