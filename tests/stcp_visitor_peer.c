// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp.h"
#include "esp_frp_stcp_visitor.h"
#include "client_port.h"
#include "dns_fixture.h"
#include "flash_store_fixture.h"
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    efrp_client_t *client;
    atomic_bool trusted;
    atomic_uint events;
    pthread_t owner;
    bool has_owner;
} visitor_events_t;
static bool trusted(void *context) { return atomic_load(&((visitor_events_t *)context)->trusted); }
static void event(void *context, const efrp_status_t *status)
{
    visitor_events_t *events = context;
    if (!events->has_owner) { events->owner = pthread_self(); events->has_owner = true; }
    assert(pthread_equal(events->owner, pthread_self()));
    efrp_status_t copy;
    assert(efrp_get_status(events->client, &copy) == EFRP_OK);
    assert(copy.phase == status->phase && copy.attempts == status->attempts);
    assert(efrp_start(events->client) == EFRP_INVALID_STATE);
    assert(efrp_stop(events->client, 1) == EFRP_INVALID_STATE);
    efrp_client_t *handle = events->client;
    assert(efrp_destroy(&handle, 1) == EFRP_INVALID_STATE && handle == events->client);
    atomic_fetch_add(&events->events, 1);
}
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static efrp_status_t wait_phase(efrp_client_t *client, efrp_phase_t phase, uint64_t ready_sessions)
{
    uint64_t deadline = efrp_port_now_ms() + 15000;
    for (;;) {
        efrp_status_t status; assert(efrp_get_status(client, &status) == EFRP_OK);
        if (status.phase == phase && status.ready_sessions >= ready_sessions) return status;
        if (efrp_port_now_ms() >= deadline) {
            fprintf(stderr, "visitor wait phase=%d got=%d reason=%d attempts=%" PRIu64 " ready=%" PRIu64 "\n",
                phase, status.phase, status.error, status.attempts, status.ready_sessions); abort();
        }
        poll(NULL, 0, 1);
    }
}
static void stopped(visitor_events_t *events)
{
    assert(efrp_stop(events->client, 5000) == EFRP_OK);
    efrp_status_t status; assert(efrp_get_status(events->client, &status) == EFRP_OK);
    assert(status.phase == EFRP_PHASE_STOPPED && !status.work.active && !status.work.waiting && !status.work.cleaning);
    assert(!status.retry_at_ms && !fixture_dns_active());
    unsigned count = atomic_load(&events->events); poll(NULL, 0, 3);
    assert(atomic_load(&events->events) == count);
    assert(efrp_stop(events->client, 0) == EFRP_OK);
}
static void ready(efrp_client_t *client, const efrp_status_t *status, const char *prefix, unsigned port)
{
    assert(status->phase == EFRP_PHASE_READY && status->pongs && status->run_id[0] && status->tls_verify_flags == 0);
    assert(!status->remote_address_length);
    char address[1] = {'x'}; size_t length = 123;
    assert(efrp_get_remote_address(client, address, sizeof address, &length) == EFRP_OK && !length && !address[0]);
    printf("%s 127.0.0.1:%u %s\n", prefix, port, status->run_id); fflush(stdout);
}
int main(int argc, char **argv)
{
    assert(argc == 9);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), bind_port = (unsigned)strtoul(argv[3], NULL, 10);
    efrp_result_t expected = (efrp_result_t)strtol(argv[8], NULL, 10);
    const char *mode = argv[4];
    assert(port && port <= UINT16_MAX && bind_port && bind_port <= UINT16_MAX);
    FILE *file = fopen(argv[2], "rb"); assert(file);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t ca_length = fread(ca, 1, sizeof ca, file);
    assert(ca_length && ca_length < sizeof ca && !ferror(file) && fclose(file) == 0);
    unsigned baseline = open_fds();
    static efrp_test_flash_t flash;
    efrp_aead_flash_store_t store = efrp_test_flash_store(&flash);
    assert(efrp_aead_flash_store_recover(&store) == EFRP_OK);
    visitor_events_t events = {.trusted = true};
    if (!strcmp(mode, "untrusted")) atomic_store(&events.trusted, false);
    char server[254] = "frp.fixture.invalid", token[] = "public-session-token", client_id[64];
    char target[129], secret[129], user[129];
    assert(strlen(argv[5]) < sizeof user && strlen(argv[6]) < sizeof target && strlen(argv[7]) < sizeof secret);
    strcpy(user, argv[5]); strcpy(target, argv[6]); strcpy(secret, argv[7]);
    assert(snprintf(client_id, sizeof client_id, "fixture-visitor-%ld", (long)getpid()) > 0);
    if (!strcmp(mode, "wrong-token")) token[0] = 'x';
    if (!strcmp(mode, "wrong-host")) strcpy(server, "wrong.fixture.invalid");
    fixture_dns_mode(FIXTURE_DNS_READY);
    efrp_stcp_visitor_config_t config = {.server_hostname = server, .server_port = (uint16_t)port,
        .ca_pem = ca, .ca_length = ca_length, .token = (const uint8_t *)token, .token_length = strlen(token),
        .hostname = "fixture-visitor-board", .user = user, .client_id = client_id,
        .server_proxy_name = target, .secret_key = secret, .bind_ipv4 = {127, 0, 0, 1}, .bind_port = (uint16_t)bind_port,
        .time_is_trusted = trusted, .on_event = event, .context = &events, .flash_store = &store};
#if defined(EFRP_CLIENT_QUIC_TEST)
    config.transport = EFRP_TRANSPORT_QUIC;
    config.quic_profile = EFRP_QUIC_PROFILE_P256_AES128_X25519;
#endif
    efrp_stcp_visitor_config_t invalid = config;
    memset(invalid.bind_ipv4, 0, sizeof invalid.bind_ipv4);
    assert(efrp_stcp_visitor_create(&invalid, &events.client) == EFRP_INVALID_ARGUMENT && !events.client);
    invalid = config; invalid.secret_key = "";
    assert(efrp_stcp_visitor_create(&invalid, &events.client) == EFRP_INVALID_ARGUMENT && !events.client);
    assert(efrp_stcp_visitor_create(&config, &events.client) == EFRP_OK && events.client);
    assert(efrp_stcp_visitor_create(&config, &events.client) == EFRP_INVALID_STATE);
    memset(ca, 0, ca_length); memset(server, 'x', strlen(server)); memset(token, 'x', strlen(token));
    memset(client_id, 'x', strlen(client_id)); memset(user, 'x', strlen(user));
    memset(target, 'x', strlen(target)); memset(secret, 'x', strlen(secret));
    memset(config.bind_ipv4, 0, sizeof config.bind_ipv4); config.bind_port = 0;
    unsigned before = atomic_load(&events.events); poll(NULL, 0, 2);
    assert(atomic_load(&events.events) == before);
    assert(efrp_start(events.client) == EFRP_OK);
    assert(efrp_start(events.client) == EFRP_INVALID_STATE);
    efrp_status_t status;
    if (expected != EFRP_OK) {
        bool bind_error = !strcmp(mode, "bind-error");
        status = wait_phase(events.client, bind_error ? EFRP_PHASE_BACKOFF : EFRP_PHASE_FAILED, 0);
        assert(status.error == expected && (bind_error || !status.retry_at_ms) && !status.work.active && !status.work.waiting);
        printf("REJECTED %d\n", expected); fflush(stdout);
    } else {
        status = wait_phase(events.client, EFRP_PHASE_READY, 1);
        ready(events.client, &status, "READY", bind_port);
    }
    char run_id[EFRP_RUN_ID_BYTES]; memcpy(run_id, status.run_id, sizeof run_id);
    uint64_t reported_ready = status.ready_sessions;
    uint64_t deadline = efrp_port_now_ms() + 100000;
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    uint64_t traced_failures = 0;
#endif
    assert(fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK) == 0);
    for (;;) {
        assert(efrp_port_now_ms() < deadline);
        assert(efrp_get_status(events.client, &status) == EFRP_OK);
        assert(status.work.active + status.work.waiting + status.work.cleaning <= 2 && status.work.waiting <= 1);
#if defined(EFRP_LAB_TIMEOUT_TRACE)
        if (status.work.failed > traced_failures) {
            fprintf(stderr, "visitor work failure: source=%u stream=%" PRIu64 " age=%" PRIu32
                " incoming=%u outgoing=%u active=%u cleaning=%u reason=%d\n",
                (unsigned)status.work.timeout_source, status.work.timeout_stream_id, status.work.timeout_age_ms,
                status.work.timeout_incoming_bytes, status.work.timeout_outgoing_bytes,
                status.work.active, status.work.cleaning, status.work.last_error);
            traced_failures = status.work.failed;
        }
#endif
        char command;
        if (read(STDIN_FILENO, &command, 1) != 1) { poll(NULL, 0, 1); continue; }
        if (command == 'q') break;
        if (command == 's') {
            printf("STATE %u %u %" PRIu64 " %" PRIu64 " %d\n", status.work.active, status.work.waiting,
                status.work.completed, status.work.failed, status.work.last_error); fflush(stdout);
        } else if (command == 'z') {
            stopped(&events); puts("STOPPED"); fflush(stdout);
        } else if (command == 'g') {
            uint64_t next = reported_ready + 1;
            assert(efrp_start(events.client) == EFRP_OK);
            status = wait_phase(events.client, EFRP_PHASE_READY, next);
            assert(!strcmp(run_id, status.run_id)); ready(events.client, &status, "RECOVERED", bind_port);
            reported_ready = status.ready_sessions;
        } else if (command == 'b') {
            status = wait_phase(events.client, EFRP_PHASE_BACKOFF, 1);
            assert(!status.work.active && !status.work.waiting && !status.work.cleaning && status.retry_at_ms);
            printf("BACKOFF %d\n", status.error); fflush(stdout);
        } else if (command == 'c') {
            uint64_t next = reported_ready + 1;
            status = wait_phase(events.client, EFRP_PHASE_READY, next);
            assert(!strcmp(run_id, status.run_id)); ready(events.client, &status, "RECOVERED", bind_port);
            reported_ready = status.ready_sessions;
        } else {
            assert(command == 't'); atomic_store(&events.trusted, false);
            status = wait_phase(events.client, EFRP_PHASE_FAILED, 1);
            assert(status.error == EFRP_TIME_UNTRUSTED && !status.work.active && !status.work.waiting && !status.work.cleaning);
            printf("FAILED %d\n", status.error); fflush(stdout);
        }
    }
    stopped(&events); before = atomic_load(&events.events);
    assert(efrp_destroy(&events.client, 5000) == EFRP_OK && !events.client);
    assert(efrp_destroy(&events.client, 0) == EFRP_OK);
    poll(NULL, 0, 3); assert(atomic_load(&events.events) == before);
    assert(!fixture_dns_active() && open_fds() == baseline && !flash.busy && flash.clears == flash.begins);
    fprintf(stderr, "STCP visitor peer: completed=%" PRIu64 " failed=%" PRIu64 " callbacks/owner/fd baseline restored\n",
        status.work.completed, status.work.failed);
    return 0;
}
