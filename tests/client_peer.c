// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp.h"
#include "client_port.h"
#include "dns_fixture.h"
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
    atomic_uint events;
    atomic_bool trusted, entered, release;
    efrp_phase_t pause_phase;
    pthread_t owner;
    bool has_owner;
} events_t;
static bool trusted(void *context) { return atomic_load(&((events_t *)context)->trusted); }
static void event(void *context, const efrp_status_t *status)
{
    events_t *e = context;
    if (!e->has_owner) { e->owner = pthread_self(); e->has_owner = true; }
    assert(pthread_equal(e->owner, pthread_self()));
    efrp_status_t copy; assert(efrp_get_status(e->client, &copy) == EFRP_OK);
    assert(copy.phase == status->phase && copy.attempts == status->attempts);
    assert(efrp_start(e->client) == EFRP_INVALID_STATE);
    assert(efrp_stop(e->client, 1) == EFRP_INVALID_STATE);
    efrp_client_t *handle = e->client;
    assert(efrp_destroy(&handle, 1) == EFRP_INVALID_STATE && handle == e->client);
    atomic_fetch_add(&e->events, 1);
    if (status->phase == e->pause_phase) {
        atomic_store(&e->entered, true);
        while (!atomic_load(&e->release)) poll(NULL, 0, 1);
    }
}
static unsigned open_fds(void)
{
    unsigned count = 0; for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count; return count;
}
static efrp_status_t wait_phase(efrp_client_t *c, efrp_phase_t phase, uint64_t attempts)
{
    uint64_t end = efrp_port_now_ms() + 15000;
    for (;;) {
        efrp_status_t s; assert(efrp_get_status(c, &s) == EFRP_OK);
        if (s.phase == phase && s.attempts >= attempts) return s;
        if (efrp_port_now_ms() >= end) {
            fprintf(stderr, "wait phase=%d got=%d error=%d attempts=%" PRIu64 "\n", phase, s.phase, s.error, s.attempts); abort();
        }
        poll(NULL, 0, 1);
    }
}
static void stopped(events_t *e)
{
    assert(efrp_stop(e->client, 5000) == EFRP_OK);
    efrp_status_t s; assert(efrp_get_status(e->client, &s) == EFRP_OK);
    assert(s.phase == EFRP_PHASE_STOPPED && !s.work.active && !s.work.waiting && !s.work.cleaning);
    assert(!s.retry_at_ms);
    unsigned n = atomic_load(&e->events); poll(NULL, 0, 3); assert(atomic_load(&e->events) == n);
    assert(efrp_stop(e->client, 0) == EFRP_OK);
}
static void command_wait(char expected)
{
    char ch = 0; assert(read(STDIN_FILENO, &ch, 1) == 1 && ch == expected);
}
int main(int argc, char **argv)
{
    assert(argc == 5);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), rounds = (unsigned)strtoul(argv[4], NULL, 10);
    const char *mode = argv[3]; assert(port && port <= 65535 && rounds);
    FILE *f = fopen(argv[2], "rb"); assert(f);
    uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t n = fread(ca, 1, sizeof ca, f); assert(n && n < sizeof ca && !ferror(f)); fclose(f);
    unsigned baseline = open_fds();
    for (unsigned i = 0; i < rounds; ++i) {
        events_t events = {.trusted = true, .release = false, .pause_phase = EFRP_PHASE_FAILED};
        /* FAILED callbacks do not block unless explicitly selected below. */
        events.pause_phase = (efrp_phase_t)-1;
        if (!strcmp(mode, "pause-tls")) events.pause_phase = EFRP_PHASE_TLS_HANDSHAKING;
        if (!strcmp(mode, "pause-login")) events.pause_phase = EFRP_PHASE_AUTHENTICATING;
        if (!strcmp(mode, "pause-register")) events.pause_phase = EFRP_PHASE_REGISTERING;
        if (!strcmp(mode, "pause-ready")) events.pause_phase = EFRP_PHASE_READY;
        char server[254] = "frp.fixture.invalid", token[] = "public-session-token", proxy[129];
        snprintf(proxy, sizeof proxy, "fixture-client-%s-%u", mode, i);
        if (!strcmp(mode, "wrong-token")) token[0] = 'x';
        if (!strcmp(mode, "wrong-host")) strcpy(server, "wrong.fixture.invalid");
        if (!strcmp(mode, "untrusted")) atomic_store(&events.trusted, false);
        fixture_dns_mode(!strcmp(mode, "dns-pending") ? FIXTURE_DNS_PENDING :
            !strcmp(mode, "dns-retry") ? FIXTURE_DNS_FAIL :
            !strcmp(mode, "no-memory") ? FIXTURE_DNS_NO_MEMORY : FIXTURE_DNS_READY);
        efrp_config_t config = {.server_hostname = server, .server_port = (uint16_t)port,
            .ca_pem = ca, .ca_length = n, .token = (const uint8_t *)token, .token_length = strlen(token),
            .proxy_name = proxy, .local_ipv4 = {127, 0, 0, 1}, .local_port = 1,
            .time_is_trusted = trusted, .on_event = event, .context = &events};
        assert(efrp_create(&config, &events.client) == EFRP_OK);
        assert(efrp_create(&config, &events.client) == EFRP_INVALID_STATE);
        /* The next attempt must use the copied inputs, not these stack buffers. */
        memset(server, 'x', sizeof server - 1); memset(token, 'x', sizeof token - 1); memset(proxy, 'x', strlen(proxy));
        unsigned before = atomic_load(&events.events); poll(NULL, 0, 2); assert(atomic_load(&events.events) == before);
        assert(efrp_start(events.client) == EFRP_OK);
        assert(efrp_start(events.client) == EFRP_INVALID_STATE);
        if (!strcmp(mode, "dns-pending")) {
            uint64_t end = efrp_port_now_ms() + 1000;
            while (!fixture_dns_active()) { assert(efrp_port_now_ms() < end); poll(NULL, 0, 1); }
            assert(efrp_stop(events.client, 0) == EFRP_WOULD_BLOCK);
            assert(efrp_destroy(&events.client, 2) == EFRP_TIMEOUT && events.client);
            assert(efrp_start(events.client) == EFRP_INVALID_STATE);
            (void)wait_phase(events.client, EFRP_PHASE_DRAINING, 1);
            assert(fixture_dns_active() == 1); fixture_dns_complete(true);
        } else if (events.pause_phase != (efrp_phase_t)-1) {
            uint64_t end = efrp_port_now_ms() + 15000;
            while (!atomic_load(&events.entered)) { assert(efrp_port_now_ms() < end); poll(NULL, 0, 1); }
            assert(efrp_stop(events.client, 20) == EFRP_TIMEOUT);
            assert(efrp_start(events.client) == EFRP_INVALID_STATE);
            atomic_store(&events.release, true);
        } else if (!strcmp(mode, "wrong-token") || !strcmp(mode, "wrong-host") ||
                   !strcmp(mode, "untrusted") || !strcmp(mode, "no-memory")) {
            efrp_status_t s = wait_phase(events.client, EFRP_PHASE_FAILED, 1);
            efrp_result_t want = !strcmp(mode, "wrong-token") ? EFRP_LOGIN_REJECTED :
                !strcmp(mode, "wrong-host") ? EFRP_TLS_TRUST_ERROR :
                !strcmp(mode, "untrusted") ? EFRP_TIME_UNTRUSTED : EFRP_NO_MEMORY;
            assert(s.error == want && !s.retry_at_ms);
            poll(NULL, 0, 1100); assert(efrp_get_status(events.client, &s) == EFRP_OK && s.attempts == 1);
        } else {
            uint64_t attempts = 1;
            if (!strcmp(mode, "dns-retry")) {
                efrp_status_t b = wait_phase(events.client, EFRP_PHASE_BACKOFF, 1);
                assert(b.error == EFRP_DNS_ERROR && b.retry_delay_ms >= 500 && b.retry_delay_ms <= 1000);
                assert(!fixture_dns_active()); fixture_dns_mode(FIXTURE_DNS_READY); attempts = 2;
            }
            efrp_status_t s = wait_phase(events.client, EFRP_PHASE_READY, attempts);
            assert(s.ready_sessions == 1 && s.pongs && s.run_id[0]);
            if (!strcmp(mode, "restart")) {
                printf("READY %s\n", s.remote_address); fflush(stdout); command_wait('r');
                efrp_status_t b = wait_phase(events.client, EFRP_PHASE_BACKOFF, 1);
                assert(b.retry_delay_ms >= 500 && b.retry_delay_ms <= 1000);
                printf("BACKOFF\n"); fflush(stdout); command_wait('c');
                s = wait_phase(events.client, EFRP_PHASE_READY, 2); assert(s.ready_sessions == 2 && s.retries >= 1);
                printf("RECOVERED %s\n", s.remote_address); fflush(stdout);
            } else if (!strcmp(mode, "stop-backoff")) {
                fixture_dns_mode(FIXTURE_DNS_FAIL);
                stopped(&events); assert(efrp_start(events.client) == EFRP_OK);
                s = wait_phase(events.client, EFRP_PHASE_BACKOFF, 2); assert(s.error == EFRP_DNS_ERROR);
            } else if (!strcmp(mode, "trust-lost")) {
                atomic_store(&events.trusted, false);
                s = wait_phase(events.client, EFRP_PHASE_FAILED, 1); assert(s.error == EFRP_TIME_UNTRUSTED);
            } else if (!strcmp(mode, "reuse")) {
                for (unsigned cycle = 0; cycle < 10; ++cycle) {
                    stopped(&events); assert(efrp_start(events.client) == EFRP_OK);
                    s = wait_phase(events.client, EFRP_PHASE_READY, cycle + 2); assert(s.ready_sessions == cycle + 2);
                }
            }
        }
        stopped(&events);
        before = atomic_load(&events.events);
        assert(efrp_destroy(&events.client, 5000) == EFRP_OK && !events.client);
        assert(efrp_destroy(&events.client, 0) == EFRP_OK);
        poll(NULL, 0, 3); assert(atomic_load(&events.events) == before);
        assert(!fixture_dns_active() && open_fds() == baseline);
        if ((i + 1) % 20 == 0) fprintf(stderr, "client %s %u/%u destroy/join/fd passed\n", mode, i + 1, rounds);
    }
    fprintf(stderr, "Client %s: %u lifecycle(s), callbacks/owner/cleanup passed\n", mode, rounds);
    return 0;
}
