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
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
int main(int argc, char **argv)
{
    assert(argc == 7 || argc == 10);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), local_port = (unsigned)strtoul(argv[3], NULL, 10);
    assert(port && port <= UINT16_MAX && local_port && local_port <= UINT16_MAX);
    efrp_result_t expected = (efrp_result_t)strtol(argv[6], NULL, 10);
    FILE *file = fopen(argv[2], "rb"); assert(file);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t ca_length = fread(ca, 1, sizeof ca, file);
    assert(ca_length && ca_length < sizeof ca && !ferror(file) && fclose(file) == 0);
    unsigned baseline = open_fds();
    efrp_connect_t *connection = NULL; efrp_tls_t *tls = NULL; efrp_session_t *session = NULL;
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, now_ms(), &connection) == EFRP_OK);
    efrp_result_t result;
    do { result = efrp_connect_step(connection, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); }
    while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    efrp_tls_config_t tls_config = {.hostname = "frp.fixture.invalid", .ca_pem = ca, .ca_length = ca_length,
        .time_is_trusted = true, .send = efrp_connect_send, .recv = efrp_connect_recv, .io_context = connection};
    assert(efrp_tls_create(&tls_config, now_ms(), &tls) == EFRP_OK);
    do { result = efrp_tls_step(tls, now_ms()); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); }
    while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK);
    efrp_proxy_type_t type = EFRP_PROXY_TCP;
    efrp_proxy_options_t options = {0};
    char secret[] = "public-proxy-secret";
    const char *domains[2];
    if (!strcmp(argv[4], "stcp")) { type = EFRP_PROXY_STCP; options.secret_key = secret; }
    else if (!strcmp(argv[4], "http") || !strcmp(argv[4], "https")) {
        assert(argc == 10);
        type = !strcmp(argv[4], "http") ? EFRP_PROXY_HTTP : EFRP_PROXY_HTTPS;
        domains[0] = argv[7]; domains[1] = argv[8];
        options.custom_domains = domains; options.custom_domain_count = 2; options.subdomain = argv[9];
    } else assert(!strcmp(argv[4], "tcp"));
    char name[129]; assert(strlen(argv[5]) < sizeof name); memcpy(name, argv[5], strlen(argv[5]) + 1);
    char client_id[64];
    assert(snprintf(client_id, sizeof client_id, "fixture-provider-%ld", (long)getpid()) > 0);
    const char *token = "public-session-token";
    static efrp_test_flash_t flash;
    efrp_aead_flash_store_t store = efrp_test_flash_store(&flash);
    assert(efrp_aead_flash_store_recover(&store) == EFRP_OK);
    efrp_transport_t *transport = NULL;
    assert(efrp_transport_yamux_create(tls, now_ms(), &transport) == EFRP_OK);
    efrp_session_config_t config = {.login = {.token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-provider-board", .user = "provider", .client_id = client_id, .unix_seconds = (int64_t)time(NULL)},
        .proxy_type = type, .proxy_options = &options, .proxy_name = name,
        .local_ipv4 = {127, 0, 0, 1}, .local_port = (uint16_t)local_port, .flash_store = &store};
    assert(efrp_session_create(&config, transport, now_ms(), &session) == EFRP_OK);
    /* The same borrowed inputs can be released immediately after create. */
    memset(secret, 'x', sizeof secret - 1); memset(name, 'x', strlen(name)); memset(client_id, 'x', strlen(client_id));
    if (argc == 10) { argv[7][0] = argv[8][0] = argv[9][0] = '!'; domains[0] = domains[1] = NULL; }
    memset(&options, 0, sizeof options); memset(config.local_ipv4, 0, sizeof config.local_ipv4); config.local_port = 0;
    assert(fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK) == 0);
    bool announced = false; uint64_t deadline = now_ms() + 60000;
    efrp_session_status_t status = {0};
    for (;;) {
        assert(now_ms() < deadline);
        result = efrp_session_step(session, now_ms(), (int64_t)time(NULL));
        assert(efrp_session_status(session, &status) == EFRP_OK);
        if (result != EFRP_OK) break;
        assert(status.work.active <= 2 && status.work.waiting <= 1);
        if (status.phase == EFRP_SESSION_REGISTERED && status.pongs && !announced) {
            size_t address_length;
            assert(efrp_session_remote_address(session, NULL, 0, &address_length) == EFRP_CAPACITY_EXCEEDED);
            assert(address_length == status.remote_address_length);
            char *address = malloc(address_length + 1); assert(address);
            memset(address, 'x', address_length + 1);
            assert(efrp_session_remote_address(session, address, address_length, &address_length) == EFRP_CAPACITY_EXCEEDED);
            if (address_length) assert(!address[0]);
            assert(efrp_session_remote_address(session, address, address_length + 1, &address_length) == EFRP_OK);
            assert(strlen(address) == status.remote_address_length);
            printf("READY %s\n", address); fflush(stdout); free(address); announced = true;
        }
        char command;
        if (read(STDIN_FILENO, &command, 1) == 1) {
            if (command == 'q') break;
            assert(command == 's');
            printf("STATE %u %u %" PRIu64 " %" PRIu64 " %d\n", status.work.active, status.work.waiting,
                status.work.completed, status.work.failed, status.work.last_error); fflush(stdout);
        }
        poll(NULL, 0, 1);
    }
    if (result != expected) {
        fprintf(stderr, "proxy mode=%s result=%d expected=%d phase=%d\n", argv[4], result, expected, status.phase); abort();
    }
    if (expected == EFRP_OK) assert(announced);
    else { assert(!announced); printf("REJECTED %d\n", result); fflush(stdout); }
    assert(efrp_session_cancel(session) == (expected == EFRP_OK ? EFRP_CANCELLED : expected));
    do { result = efrp_session_destroy(&session); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); }
    while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK && !session && !flash.busy && flash.clears == flash.begins);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
    efrp_tls_destroy(tls); assert(efrp_connect_destroy(&connection) == EFRP_OK && !connection);
    assert(open_fds() == baseline);
    fprintf(stderr, "Proxy peer: type=%d completed=%" PRIu64 " failed=%" PRIu64 " fd baseline restored\n",
        type, status.work.completed, status.work.failed);
    return 0;
}
