// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_connect.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned positive_calls, abort_calls, close_calls;
static unsigned fail_positive, fail_abort, fail_close;

/* The connector object is compiled with only its socket operations wrapped.
 * A failed close leaves the real descriptor open, matching lwIP's retry path. */
int fixture_connect_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    if (level == SOL_SOCKET && option == SO_LINGER && length == sizeof(struct linger)) {
        const struct linger *linger = value;
        if (linger->l_onoff && linger->l_linger > 0) {
            ++positive_calls;
            if (fail_positive) { --fail_positive; errno = ENOMEM; return -1; }
            /* Do not ask the host kernel to block the test during close. */
            struct linger off = {0};
            return setsockopt(fd, level, option, &off, sizeof off);
        }
        if (linger->l_onoff && linger->l_linger == 0) {
            ++abort_calls;
            if (fail_abort) { --fail_abort; errno = ENOBUFS; return -1; }
        }
    }
    return setsockopt(fd, level, option, value, length);
}

int fixture_connect_close(int fd)
{
    ++close_calls;
    if (fail_close) { --fail_close; errno = EWOULDBLOCK; return -1; }
    return close(fd);
}

static int listen_local(unsigned *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)&address, sizeof address) == 0);
    assert(listen(fd, 2) == 0);
    socklen_t length = sizeof address;
    assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    *port = ntohs(address.sin_port);
    return fd;
}

static efrp_connect_t *connect_local(unsigned port, int listener, int *peer, int *owned_fd)
{
    const uint8_t loopback[4] = {127, 0, 0, 1};
    efrp_connect_t *connection = NULL;
    assert(efrp_connect_create_ipv4(loopback, (uint16_t)port, 0, &connection) == EFRP_OK);
    efrp_result_t result = EFRP_WOULD_BLOCK;
    for (uint64_t now = 0; now < 1000 && result == EFRP_WOULD_BLOCK; ++now) {
        result = efrp_connect_step(connection, now);
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    }
    assert(result == EFRP_OK);
    *peer = accept(listener, NULL, NULL); assert(*peer >= 0);
    assert(efrp_connect_fd(connection, owned_fd) == EFRP_OK);
    return connection;
}

static void receive_eof(efrp_connect_t *connection, int peer)
{
    assert(shutdown(peer, SHUT_WR) == 0);
    uint8_t byte; size_t count;
    efrp_result_t result;
    do {
        result = efrp_connect_recv(connection, &byte, 1, &count);
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_EOF && count == 0);
}

static void expect_draining(efrp_connect_t *connection, efrp_result_t result, int error)
{
    efrp_connect_status_t status;
    assert(efrp_connect_status(connection, &status) == EFRP_OK);
    assert(status.state == EFRP_CONNECT_DRAINING && status.result == result);
    assert(status.owns_socket && status.system_error == error);
}

int main(void)
{
    unsigned port;
    int listener = listen_local(&port), peer, fd;

    efrp_connect_t *connection = connect_local(port, listener, &peer, &fd);
    unsigned before = positive_calls;
    fail_positive = 1;
    assert(efrp_connect_close_write(connection) == EFRP_WOULD_BLOCK);
    assert(efrp_connect_close_write(connection) == EFRP_OK);
    assert(positive_calls == before + 2);
    receive_eof(connection, peer);
    fail_close = 2;
    assert(efrp_connect_finish(connection) == EFRP_WOULD_BLOCK);
    expect_draining(connection, EFRP_OK, EWOULDBLOCK);
    assert(efrp_connect_finish(connection) == EFRP_WOULD_BLOCK);
    assert(efrp_connect_finish(connection) == EFRP_OK);
    assert(positive_calls == before + 2); /* finish does not reset linger */
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    assert(efrp_connect_destroy(&connection) == EFRP_OK && !connection);
    assert(close(peer) == 0);

    connection = connect_local(port, listener, &peer, &fd);
    assert(efrp_connect_close_write(connection) == EFRP_OK);
    fail_abort = 2;
    before = close_calls;
    assert(efrp_connect_cancel(connection) == EFRP_WOULD_BLOCK);
    expect_draining(connection, EFRP_CANCELLED, ENOBUFS);
    assert(close_calls == before && fcntl(fd, F_GETFD) >= 0);
    assert(efrp_connect_destroy(&connection) == EFRP_WOULD_BLOCK && connection);
    expect_draining(connection, EFRP_CANCELLED, ENOBUFS);
    assert(close_calls == before && fcntl(fd, F_GETFD) >= 0);
    assert(efrp_connect_cancel(connection) == EFRP_CANCELLED);
    efrp_connect_status_t closed_status;
    assert(efrp_connect_status(connection, &closed_status) == EFRP_OK);
    assert(closed_status.state == EFRP_CONNECT_CLOSED && closed_status.result == EFRP_CANCELLED);
    assert(!closed_status.owns_socket && closed_status.system_error == 0);
    assert(efrp_connect_destroy(&connection) == EFRP_OK && !connection);
    assert(close_calls == before + 1 && fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    assert(close(peer) == 0);

    connection = connect_local(port, listener, &peer, &fd);
    assert(efrp_connect_close_write(connection) == EFRP_OK);
    receive_eof(connection, peer);
    fail_close = 1;
    assert(efrp_connect_finish(connection) == EFRP_WOULD_BLOCK);
    expect_draining(connection, EFRP_OK, EWOULDBLOCK);
    fail_abort = 1;
    assert(efrp_connect_cancel(connection) == EFRP_WOULD_BLOCK);
    expect_draining(connection, EFRP_CANCELLED, ENOBUFS);
    assert(fcntl(fd, F_GETFD) >= 0);
    assert(efrp_connect_destroy(&connection) == EFRP_OK && !connection);
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    assert(close(peer) == 0 && close(listener) == 0);
    puts("Linger close: transient option and close failures retain fd; finish reuses configured linger; cancel retries to actual close");
    return 0;
}
