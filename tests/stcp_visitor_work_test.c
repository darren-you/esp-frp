// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "tcp_listener.h"
#include "stream_yamux_fixture.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
static bool fail_listener_close;
int fixture_visit_close(int fd)
{
    if (fail_listener_close) { fail_listener_close = false; errno = ENOMEM; return -1; }
    return close(fd);
}
#define EFRP_TCP_LISTENER_TEST_CLOSE 1
#define close fixture_visit_close
#include "../src/tcp_listener.c"
#undef close
#include "../src/work.c"

static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static struct sockaddr_in reserve_address(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET};
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(bind(fd, (struct sockaddr *)&address, sizeof address) == 0);
    socklen_t length = sizeof address;
    assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    assert(close(fd) == 0); return address;
}
static int local_client(const struct sockaddr_in *address)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(fd >= 0);
    assert(connect(fd, (const struct sockaddr *)address, sizeof *address) == 0);
    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0); return fd;
}
static ssize_t client_read(int fd, uint8_t *bytes, size_t capacity)
{
    ssize_t result = -1;
    for (unsigned i = 0; i < 1000; ++i) {
        result = recv(fd, bytes, capacity, 0);
        if (result >= 0) return result;
        assert(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
        poll(NULL, 0, 1);
    }
    return result;
}
static void mux_header(uint8_t *p, uint8_t type, uint16_t flags, uint32_t id, uint32_t value)
{
    p[0] = 0; p[1] = type; p[2] = (uint8_t)(flags >> 8); p[3] = (uint8_t)flags;
    for (unsigned i = 0; i < 4; ++i) {
        p[4 + i] = (uint8_t)(id >> (24 - 8 * i));
        p[8 + i] = (uint8_t)(value >> (24 - 8 * i));
    }
}
static void mux_feed(efrp_yamux_t *mux, efrp_stream_id_t id, const uint8_t *bytes, size_t length, uint16_t flags)
{
    uint8_t input[1024]; size_t used = 0;
    assert(length <= sizeof input - 12 && id <= UINT32_MAX);
    mux_header(input, 0, flags, (uint32_t)id, (uint32_t)length);
    if (length) memcpy(input + 12, bytes, length);
    assert(efrp_yamux_feed(mux, input, length + 12, &used) == EFRP_OK && used == length + 12);
}
static void mux_flush(efrp_yamux_t *mux)
{
    const uint8_t *bytes; size_t length;
    while (efrp_yamux_output(mux, &bytes, &length) == EFRP_OK)
        assert(bytes && length && efrp_yamux_consume_output(mux, length) == EFRP_OK);
}
static void connection_ready(efrp_work_set_t *set)
{
    efrp_result_t result = EFRP_WOULD_BLOCK;
    for (unsigned i = 0; i < 1000 && result == EFRP_WOULD_BLOCK; ++i) {
        result = efrp_tcp_listener_ready(set->visitor->listener);
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    }
    assert(result == EFRP_OK);
}
static void step(efrp_work_set_t *set, efrp_yamux_t *mux, uint64_t now)
{
    efrp_test_yamux_transport_t transport; efrp_test_yamux_transport_init(&transport, mux);
    assert(efrp_work_visit_step(set, &transport.base, now, "fixture-run", 1) == EFRP_OK);
}
static efrp_work_stream_t *admission(efrp_work_set_t *set)
{
    efrp_work_stream_t *found = NULL;
    for (unsigned i = 0; i < 3; ++i) {
        efrp_work_stream_t *w = set->streams[i];
        if (w && (w->phase == EFRP_WORK_SENDING || w->phase == EFRP_WORK_WAITING)) {
            assert(!found); found = w;
        }
    }
    assert(found); return found;
}
static size_t response(uint8_t *bytes, const char *target, const char *error, const uint8_t *tail, size_t tail_length)
{
    char json[512];
    int printed = snprintf(json, sizeof json, "{\"proxy_name\":\"%s\",\"error\":\"%s\"}", target, error);
    assert(printed > 0 && (size_t)printed < sizeof json);
    assert(efrp_wire_header(EFRP_MESSAGE, (size_t)printed + 2, bytes) == EFRP_OK);
    bytes[8] = 0; bytes[9] = 10; memcpy(bytes + 10, json, (size_t)printed);
    if (tail_length) memcpy(bytes + 10 + (size_t)printed, tail, tail_length);
    return (size_t)printed + 10 + tail_length;
}
static void accept_auth(efrp_work_set_t *set, efrp_yamux_t *mux, uint64_t now)
{
    efrp_work_stream_t *w = admission(set);
    mux_flush(mux); step(set, mux, now); mux_flush(mux);
    assert(w->phase == EFRP_WORK_WAITING);
    uint8_t bytes[512]; size_t length = response(bytes, "fixture-target", "", NULL, 0);
    mux_feed(mux, w->stream_id, bytes, length, 2); step(set, mux, now + 1); mux_flush(mux);
    assert(w->phase == EFRP_WORK_ACTIVE && !set->handshake_json);
}
int main(void)
{
    unsigned baseline = open_fds(); struct sockaddr_in address = reserve_address();
    efrp_stcp_visitor_settings_t settings = {.server_proxy_name = "fixture-target", .secret_key = "fixture-secret",
        .bind_ipv4 = {127, 0, 0, 1}, .bind_port = ntohs(address.sin_port)};
    efrp_work_set_t set;
    assert(efrp_work_visit_init(&set, &settings) == EFRP_OK && set.visitor && !set.visitor->listener);
    assert(open_fds() == baseline); /* No pre-Pong listener. */
    efrp_yamux_t mux; efrp_yamux_init(&mux, 0);
    efrp_test_yamux_transport_t transport; efrp_test_yamux_transport_init(&transport, &mux);
    assert(efrp_work_visit_step(&set, &transport.base, 0, "fixture-run", 1) == EFRP_INVALID_STATE);
    assert(efrp_work_visit_start(&set) == EFRP_OK && open_fds() == baseline + 1);
    assert(efrp_work_visit_start(&set) == EFRP_INVALID_STATE);
    int first = local_client(&address); connection_ready(&set); step(&set, &mux, 1);
    efrp_work_stream_t *w = admission(&set); efrp_stream_id_t first_id = w->stream_id;
    assert(first_id && open_fds() == baseline + 3);
    int second = local_client(&address); connection_ready(&set); step(&set, &mux, 2);
    assert(admission(&set) == w && set.status.requests == 1 && open_fds() == baseline + 4);
    mux_flush(&mux); step(&set, &mux, 3); mux_flush(&mux);
    assert(w->phase == EFRP_WORK_WAITING);
    const uint8_t untrusted[] = {1, 0, 255, 7};
    assert(send(first, untrusted, sizeof untrusted, 0) == (ssize_t)sizeof untrusted);
    step(&set, &mux, 4);
    assert(!set.status.local_received && !set.status.local_sent && !set.handshake_json);
    uint8_t bytes[512]; const uint8_t tail[] = {0, 3, 4, 255};
    size_t length = response(bytes, "fixture-target", "", tail, sizeof tail);
    mux_feed(&mux, first_id, bytes, 3, 2); step(&set, &mux, 5); mux_flush(&mux);
    assert(set.handshake_json && w->partial_header && !w->started);
    step(&set, &mux, 6); assert(set.status.requests == 1); /* No second parser/admission. */
    mux_feed(&mux, first_id, bytes + 3, length - 3, 0); step(&set, &mux, 7); mux_flush(&mux);
    assert(w->phase == EFRP_WORK_ACTIVE && !set.handshake_json);
    uint8_t received[16]; ssize_t got = client_read(first, received, sizeof received);
    assert(got == (ssize_t)sizeof tail && !memcmp(received, tail, sizeof tail));
    assert(set.status.local_sent == sizeof tail && set.status.local_received == sizeof untrusted);
    step(&set, &mux, 8); assert(set.status.requests == 2 && open_fds() == baseline + 5);
    accept_auth(&set, &mux, 9);
    efrp_work_status_t status; efrp_work_status(&set, &status);
    assert(status.active == 2 && !status.waiting && !status.cleaning);
    int third = local_client(&address); connection_ready(&set);
    for (uint64_t now = 11; now < 20; ++now) { step(&set, &mux, now); mux_flush(&mux); }
    assert(set.status.requests == 2 && open_fds() == baseline + 6); /* OS backlog only. */
    mux_feed(&mux, first_id, NULL, 0, 8); step(&set, &mux, 20); mux_flush(&mux);
    assert(set.status.failed == 1 && set.status.last_error == EFRP_STREAM_RESET && open_fds() == baseline + 5);
    step(&set, &mux, 21); w = admission(&set); efrp_stream_id_t third_id = w->stream_id;
    assert(set.status.requests == 3 && third_id != first_id && open_fds() == baseline + 6);
    mux_flush(&mux); step(&set, &mux, 22); mux_flush(&mux);
    length = response(bytes, "other-target", "", tail, sizeof tail);
    mux_feed(&mux, third_id, bytes, length, 2); step(&set, &mux, 23); mux_flush(&mux);
    assert(set.status.failed == 2 && set.status.last_error == EFRP_PROTOCOL_ERROR);
    assert(set.status.local_sent == sizeof tail); /* Failed response tail never delivered. */
    int fourth = local_client(&address); connection_ready(&set); step(&set, &mux, 24); accept_auth(&set, &mux, 25);
    efrp_work_status(&set, &status); assert(status.active == 2 && !status.cleaning);
    fail_listener_close = true;
    assert(!efrp_work_cancel(&set) && set.visitor && !set.visitor->started);
    assert(open_fds() == baseline + 5); /* Four clients, one retained listener; no managed business fd. */
    for (unsigned i = 0; i < 3; ++i) assert(!set.streams[i]);
    assert(!set.handshake_json && efrp_work_cancel(&set) && !set.visitor);
    assert(close(first) == 0 && close(second) == 0 && close(third) == 0 && close(fourth) == 0);
    efrp_yamux_destroy(&mux); assert(open_fds() == baseline && efrp_work_cancel(&set));
    /* Accepted sockets have a total admission deadline even when no response
     * arrives. A partial response does not renew that deadline. */
    for (unsigned partial = 0; partial < 2; ++partial) {
        assert(efrp_work_visit_init(&set, &settings) == EFRP_OK);
        efrp_yamux_init(&mux, 0); assert(efrp_work_visit_start(&set) == EFRP_OK);
        int timed = local_client(&address); connection_ready(&set); step(&set, &mux, 1);
        w = admission(&set); mux_flush(&mux); step(&set, &mux, 2); mux_flush(&mux);
        assert(w->phase == EFRP_WORK_WAITING && w->deadline == EFRP_SESSION_RESPONSE_MS + 1);
        if (partial) {
            length = response(bytes, "fixture-target", "", NULL, 0);
            assert(length > 3); mux_feed(&mux, w->stream_id, bytes, 3, 2);
            step(&set, &mux, EFRP_SESSION_RESPONSE_MS);
            assert(w->partial_header && !w->started && w->deadline == EFRP_SESSION_RESPONSE_MS + 1);
            mux_flush(&mux);
        }
        step(&set, &mux, EFRP_SESSION_RESPONSE_MS + 1); mux_flush(&mux);
        efrp_work_status(&set, &status);
        assert(status.failed == 1 && status.last_error == EFRP_TIMEOUT && !status.active && !status.cleaning);
        assert(!set.handshake_json && open_fds() == baseline + 2);
        assert(efrp_work_cancel(&set) && close(timed) == 0);
        efrp_yamux_destroy(&mux); assert(open_fds() == baseline);
    }
    puts("STCP visitor work: single admission, two-socket bound, authenticated tail, rejection and close retry passed"); return 0;
}
