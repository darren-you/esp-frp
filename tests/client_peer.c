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
    bool fast_backoff;
    atomic_uint backoffs;
} events_t;
void fixture_client_advance(uint64_t ms);
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
    if (e->fast_backoff && status->phase == EFRP_PHASE_BACKOFF) {
        static const uint32_t ceilings[] = {1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000};
        unsigned index = atomic_load(&e->backoffs); assert(index < 8);
        assert(status->error == EFRP_DNS_ERROR && !fixture_dns_active());
        assert(status->retry_delay_ms >= ceilings[index] / 2 && status->retry_delay_ms <= ceilings[index]);
        assert(status->attempts == index + 1 && status->retries == index);
        if (index < 7) fixture_client_advance(status->retry_delay_ms + 1);
        atomic_fetch_add(&e->backoffs, 1);
    }
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
typedef struct { efrp_client_t *client; efrp_result_t result; } stop_thread_t;
static void *stop_thread(void *context)
{
    stop_thread_t *t = context; t->result = efrp_stop(t->client, 5000); return NULL;
}
int main(int argc, char **argv)
{
    assert(argc == 5 || argc == 6);
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
        if (!strcmp(mode, "pause-stopped")) events.pause_phase = EFRP_PHASE_STOPPED;
        char server[254] = "frp.fixture.invalid", token[] = "public-session-token", proxy[129];
        snprintf(proxy, sizeof proxy, "fixture-client-%s-%u", mode, i);
        if (!strcmp(mode, "wrong-token")) token[0] = 'x';
        if (!strcmp(mode, "wrong-host")) strcpy(server, "wrong.fixture.invalid");
        if (!strcmp(mode, "untrusted")) atomic_store(&events.trusted, false);
        events.fast_backoff = !strcmp(mode, "backoff-matrix");
        fixture_dns_mode((!strcmp(mode, "dns-pending") || !strcmp(mode, "concurrent-stop")) ? FIXTURE_DNS_PENDING :
            (!strcmp(mode, "dns-retry") || events.fast_backoff) ? FIXTURE_DNS_FAIL :
            !strcmp(mode, "no-memory") ? FIXTURE_DNS_NO_MEMORY : FIXTURE_DNS_READY);
        uint8_t *ca_copy = malloc(n); assert(ca_copy); memcpy(ca_copy, ca, n);
        efrp_config_t config = {.server_hostname = server, .server_port = (uint16_t)port,
            .ca_pem = ca_copy, .ca_length = n, .token = (const uint8_t *)token, .token_length = strlen(token),
            .hostname = "fixture-worker-board", .client_id = proxy, .proxy_name = proxy,
            .local_ipv4 = {127, 0, 0, 1}, .local_port = argc == 6 ? (uint16_t)strtoul(argv[5], NULL, 10) : 1,
            .time_is_trusted = trusted, .on_event = event, .context = &events};
        assert(efrp_create(&config, &events.client) == EFRP_OK);
        assert(efrp_create(&config, &events.client) == EFRP_INVALID_STATE);
        memset(ca_copy, 0, n); free(ca_copy);
        /* The next attempt must use the copied inputs, not these stack buffers. */
        memset(server, 'x', sizeof server - 1); memset(token, 'x', sizeof token - 1); memset(proxy, 'x', strlen(proxy));
        unsigned before = atomic_load(&events.events); poll(NULL, 0, 2); assert(atomic_load(&events.events) == before);
        assert(efrp_start(events.client) == EFRP_OK);
        assert(efrp_start(events.client) == EFRP_INVALID_STATE);
        if (!strcmp(mode, "concurrent-stop") || !strcmp(mode, "pause-stopped")) {
            bool dns = !strcmp(mode, "concurrent-stop");
            if (dns) {
                uint64_t end = efrp_port_now_ms() + 1000;
                while (!fixture_dns_active()) { assert(efrp_port_now_ms() < end); poll(NULL, 0, 1); }
            } else (void)wait_phase(events.client, EFRP_PHASE_READY, 1);
            stop_thread_t t = {.client = events.client}; pthread_t thread;
            assert(pthread_create(&thread, NULL, stop_thread, &t) == 0);
            (void)wait_phase(events.client, dns ? EFRP_PHASE_DRAINING : EFRP_PHASE_STOPPED, 1);
            assert(efrp_start(events.client) == EFRP_WOULD_BLOCK);
            assert(efrp_stop(events.client, 0) == EFRP_WOULD_BLOCK);
            if (dns) fixture_dns_complete(true);
            else atomic_store(&events.release, true);
            assert(pthread_join(thread, NULL) == 0 && t.result == EFRP_OK);
        } else if (events.fast_backoff) {
            unsigned turns = 0;
            while (atomic_load(&events.backoffs) < 8) { assert(++turns < 5000); poll(NULL, 0, 1); }
        } else if (!strcmp(mode, "dns-pending")) {
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
            char first_run_id[EFRP_RUN_ID_BYTES]; memcpy(first_run_id, s.run_id, sizeof first_run_id);
            if (!strcmp(mode, "duplex")) {
                printf("READY %s\n", s.remote_address); fflush(stdout); command_wait('q');
                uint64_t end = efrp_port_now_ms() + 5000;
                do {
                    assert(efrp_get_status(events.client, &s) == EFRP_OK);
                    assert(efrp_port_now_ms() < end); poll(NULL, 0, 1);
                } while (s.work.completed != 6 || s.work.active != 2);
                assert(!s.work.failed && s.work.waiting <= 1);
                assert(s.work.local_sent == 6 * UINT64_C(300006) && s.work.local_received == 6 * UINT64_C(300002));
            } else if (!strcmp(mode, "restart")) {
                printf("READY %s\n", s.remote_address); fflush(stdout); command_wait('r');
                efrp_status_t b = wait_phase(events.client, EFRP_PHASE_BACKOFF, 1);
                assert(b.retry_delay_ms >= 500 && b.retry_delay_ms <= 1000);
                printf("BACKOFF\n"); fflush(stdout); command_wait('c');
                s = wait_phase(events.client, EFRP_PHASE_READY, 2); assert(s.ready_sessions == 2 && s.retries >= 1);
                assert(!strcmp(first_run_id, s.run_id));
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
                    assert(!strcmp(first_run_id, s.run_id));
                }
            } else if (!strcmp(mode, "replacement")) {
                stopped(&events);
                assert(efrp_destroy(&events.client, 5000) == EFRP_OK && !events.client);
                assert(open_fds() == baseline); events.has_owner = false;
                strcpy(server, "frp.fixture.invalid"); strcpy(token, "public-session-token");
                snprintf(proxy, sizeof proxy, "fixture-client-%s-%u", mode, i);
                config.ca_pem = ca; config.previous_run_id = first_run_id;
                assert(efrp_create(&config, &events.client) == EFRP_OK);
                char expected_run_id[EFRP_RUN_ID_BYTES]; memcpy(expected_run_id, first_run_id, sizeof first_run_id);
                memset(first_run_id, 'x', strlen(first_run_id));
                assert(efrp_start(events.client) == EFRP_OK);
                s = wait_phase(events.client, EFRP_PHASE_READY, 1);
                assert(s.ready_sessions == 1 && !strcmp(expected_run_id, s.run_id));
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
