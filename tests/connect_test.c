// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_connect.h"
#include "dns_fixture.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static unsigned port_of(int fd)
{
    struct sockaddr_in addr; socklen_t n = sizeof addr;
    assert(getsockname(fd, (struct sockaddr *)&addr, &n) == 0); return ntohs(addr.sin_port);
}
static int listener(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0 && listen(fd, 8) == 0); return fd;
}
static void closed(efrp_connect_t **c, efrp_result_t result)
{
    efrp_connect_status_t s;
    assert(efrp_connect_status(*c, &s) == EFRP_OK && s.state == EFRP_CONNECT_CLOSED);
    assert(s.result == result && !s.owns_socket && !s.pending_dns && !fixture_dns_active());
    assert(efrp_connect_step(*c, UINT64_MAX) == result);
    assert(efrp_connect_destroy(c) == EFRP_OK && !*c);
    assert(efrp_connect_destroy(c) == EFRP_OK);
}
static efrp_result_t ready(efrp_connect_t *c)
{
    for (unsigned i = 0; i < 1000; ++i) {
        efrp_result_t result = efrp_connect_step(c, i);
        if (result != EFRP_WOULD_BLOCK) return result;
        poll(NULL, 0, 1);
    }
    efrp_connect_status_t s; assert(efrp_connect_status(c, &s) == EFRP_OK);
    fprintf(stderr, "connect stalled: state=%d result=%d errno=%d socket=%d dns=%d\n",
        s.state, s.result, s.system_error, s.owns_socket, s.pending_dns);
    assert(!"connect never completed"); return EFRP_TIMEOUT;
}
int main(void)
{
    efrp_connect_t *c = NULL;
    const char *invalid[] = {NULL, "", "bad/host", "bad host", ".invalid", "a..invalid", "-a.invalid", "a-.invalid", "::1"};
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i)
        assert(efrp_connect_create(invalid[i], 1, 0, &c) == EFRP_INVALID_ARGUMENT && !c);
    char long_label[65]; memset(long_label, 'a', 64); long_label[64] = 0;
    assert(efrp_connect_create(long_label, 1, 0, &c) == EFRP_INVALID_ARGUMENT && !c);
    assert(efrp_connect_create("frp.fixture.invalid", 0, 0, &c) == EFRP_INVALID_ARGUMENT && !c);
    assert(efrp_connect_create("frp.fixture.invalid", 1, UINT64_MAX, &c) == EFRP_INVALID_ARGUMENT && !c);
    fixture_dns_mode(FIXTURE_DNS_NO_MEMORY);
    assert(efrp_connect_create("frp.fixture.invalid", 1, 0, &c) == EFRP_NO_MEMORY && !c);
    fixture_dns_mode(FIXTURE_DNS_FAIL);
    assert(efrp_connect_create("frp.fixture.invalid", 1, 0, &c) == EFRP_OK);
    assert(efrp_connect_step(c, 0) == EFRP_DNS_ERROR); closed(&c, EFRP_DNS_ERROR);
    for (unsigned i = 0; i < 100; ++i) {
        fixture_dns_mode(FIXTURE_DNS_PENDING);
        assert(efrp_connect_create("frp.fixture.invalid", 1, 100, &c) == EFRP_OK);
        assert(efrp_connect_create("frp.fixture.invalid", 1, 100, &c) == EFRP_INVALID_STATE);
        assert(efrp_connect_step(c, 99) == EFRP_INVALID_ARGUMENT);
        assert(efrp_connect_step(c, UINT64_MAX) == EFRP_INVALID_ARGUMENT);
        assert(efrp_connect_step(c, 100) == EFRP_WOULD_BLOCK);
        efrp_result_t expected = i % 2 ? EFRP_CANCELLED : EFRP_TIMEOUT;
        assert((i % 2 ? efrp_connect_cancel(c) : efrp_connect_step(c, 100 + EFRP_CONNECT_DNS_MS)) == EFRP_WOULD_BLOCK);
        efrp_connect_status_t s;
        assert(efrp_connect_status(c, &s) == EFRP_OK && s.state == EFRP_CONNECT_DRAINING && s.result == expected);
        assert(s.pending_dns && !s.owns_socket);
        assert(efrp_connect_destroy(&c) == EFRP_WOULD_BLOCK && c);
        fixture_dns_complete(i % 3 == 0);
        assert(efrp_connect_step(c, 20000) == expected); closed(&c, expected);
    }
    fixture_dns_mode(FIXTURE_DNS_READY);
    int server = listener(); unsigned port = port_of(server);
    const uint8_t local[4] = {127, 0, 0, 1}, invalid_ip[4] = {224, 0, 0, 1};
    assert(efrp_connect_create_ipv4(invalid_ip, (uint16_t)port, 0, &c) == EFRP_INVALID_ARGUMENT && !c);
    for (unsigned i = 0; i < 100; ++i) {
        uint8_t copied[4]; memcpy(copied, local, sizeof copied);
        assert(efrp_connect_create_ipv4(copied, (uint16_t)port, 0, &c) == EFRP_OK);
        memset(copied, 0, sizeof copied);
        assert(!fixture_dns_active() && ready(c) == EFRP_OK);
        int fd, peer = accept(server, NULL, NULL); assert(peer >= 0);
        assert(efrp_connect_fd(c, &fd) == EFRP_OK);
        assert(efrp_connect_finish(c) == EFRP_INVALID_STATE);
        assert(shutdown(peer, SHUT_WR) == 0);
        uint8_t data[4096], back[4096]; memset(data, (int)(i & 255u), sizeof data);
        efrp_result_t result; size_t n, total = 0;
        do { result = efrp_connect_recv(c, back, sizeof back, &n); if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (result == EFRP_WOULD_BLOCK);
        assert(result == EFRP_EOF);
        for (unsigned part = 0; part < 16; ++part) {
            result = efrp_connect_send(c, data, sizeof data, &n);
            if (result == EFRP_WOULD_BLOCK) break;
            assert(result == EFRP_OK); total += n;
        }
        assert(total && efrp_connect_close_write(c) == EFRP_OK);
        assert(efrp_connect_close_write(c) == EFRP_OK);
        assert(efrp_connect_send(c, data, 1, &n) == EFRP_INVALID_STATE);
        assert(efrp_connect_fd(c, &fd) == EFRP_OK);
        result = efrp_connect_finish(c);
        if (result != EFRP_OK) {
            efrp_connect_status_t diagnostic; assert(efrp_connect_status(c, &diagnostic) == EFRP_OK);
            fprintf(stderr, "graceful close result=%d state=%d errno=%d\n", result, diagnostic.state, diagnostic.system_error);
        }
        assert(result == EFRP_OK);
        assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        size_t received = 0; ssize_t count;
        while ((count = recv(peer, back, sizeof back, 0)) > 0) {
            assert(!memcmp(data, back, (size_t)count)); received += (size_t)count;
        }
        assert(count == 0 && received == total);
        closed(&c, EFRP_OK); close(peer);
    }
    for (unsigned i = 0; i < 100; ++i) {
        assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, 0, &c) == EFRP_OK);
        assert(ready(c) == EFRP_OK);
        int fd = -1; assert(efrp_connect_fd(c, &fd) == EFRP_OK && (fcntl(fd, F_GETFL) & O_NONBLOCK));
        int peer = accept(server, NULL, NULL); assert(peer >= 0);
        const uint8_t data[] = "binary\0payload"; uint8_t buffer[32]; size_t n;
        assert(efrp_connect_recv(c, buffer, sizeof buffer, &n) == EFRP_WOULD_BLOCK && !n);
        assert(efrp_connect_send(c, data, sizeof data, &n) == EFRP_OK && n == sizeof data);
        assert(recv(peer, buffer, sizeof data, MSG_WAITALL) == sizeof data && !memcmp(data, buffer, sizeof data));
        assert(send(peer, data, sizeof data, 0) == sizeof data);
        efrp_result_t r;
        do { r = efrp_connect_recv(c, buffer, sizeof buffer, &n); if (r == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (r == EFRP_WOULD_BLOCK);
        assert(r == EFRP_OK && n == sizeof data && !memcmp(data, buffer, n));
        assert(shutdown(peer, SHUT_WR) == 0);
        do { r = efrp_connect_recv(c, buffer, sizeof buffer, &n); if (r == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (r == EFRP_WOULD_BLOCK);
        assert(r == EFRP_EOF && !n);
        assert(efrp_connect_send(c, data, sizeof data, &n) == EFRP_OK && n == sizeof data);
        assert(recv(peer, buffer, sizeof data, MSG_WAITALL) == sizeof data && !memcmp(data, buffer, sizeof data));
        assert(efrp_connect_cancel(c) == EFRP_CANCELLED);
        assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        assert(efrp_connect_recv(c, buffer, sizeof buffer, &n) == EFRP_INVALID_STATE);
        closed(&c, EFRP_CANCELLED); assert(close(peer) == 0);
    }
    /* Cancel/timeout after connect() starts, before readiness is consumed. */
    for (unsigned i = 0; i < 2; ++i) {
        assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, 0, &c) == EFRP_OK);
        efrp_result_t r = efrp_connect_step(c, 0); assert(r == EFRP_WOULD_BLOCK);
        int peer = accept(server, NULL, NULL); assert(peer >= 0);
        efrp_result_t expected = i ? EFRP_CANCELLED : EFRP_TIMEOUT;
        assert((i ? efrp_connect_cancel(c) : efrp_connect_step(c, EFRP_CONNECT_TCP_MS)) == expected);
        closed(&c, expected); close(peer);
    }
    /* Real TCP backpressure: the server accepts but never reads. */
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, 0, &c) == EFRP_OK);
    assert(ready(c) == EFRP_OK);
    int peer = accept(server, NULL, NULL); assert(peer >= 0);
    uint8_t payload[4096] = {0}; size_t n; bool blocked = false;
    for (unsigned i = 0; i < 4096; ++i) {
        efrp_result_t r = efrp_connect_send(c, payload, sizeof payload, &n);
        assert(r == EFRP_OK || r == EFRP_WOULD_BLOCK);
        if (r == EFRP_WOULD_BLOCK) { assert(!n); blocked = true; break; }
    }
    assert(blocked && efrp_connect_cancel(c) == EFRP_CANCELLED);
    closed(&c, EFRP_CANCELLED); close(peer);
    /* RST is a network error, unlike the receive half-close above. */
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, 0, &c) == EFRP_OK);
    assert(ready(c) == EFRP_OK); peer = accept(server, NULL, NULL); assert(peer >= 0);
    struct linger abort_now = {.l_onoff = 1, .l_linger = 0};
    assert(setsockopt(peer, SOL_SOCKET, SO_LINGER, &abort_now, sizeof abort_now) == 0 && close(peer) == 0);
    efrp_result_t reset;
    do { reset = efrp_connect_recv(c, payload, sizeof payload, &n); if (reset == EFRP_WOULD_BLOCK) poll(NULL, 0, 1); } while (reset == EFRP_WOULD_BLOCK);
    assert(reset == EFRP_NETWORK_ERROR); closed(&c, EFRP_NETWORK_ERROR);
    assert(close(server) == 0);
    assert(efrp_connect_create("frp.fixture.invalid", (uint16_t)port, 0, &c) == EFRP_OK);
    assert(ready(c) == EFRP_NETWORK_ERROR); closed(&c, EFRP_NETWORK_ERROR);
    puts("TCP connector: late DNS, deadlines, refusal, 100 duplex and 100 fixed-target graceful FIN connections passed");
    return 0;
}
