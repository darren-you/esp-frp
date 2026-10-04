// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "tcp_listener.h"
#include "connect_internal.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned fail_close, fail_linger;
static bool fail_adopt, fail_socket, fail_flags;
int fixture_listener_close(int fd);
int fixture_listener_socket(int family, int type, int protocol);
int fixture_listener_fcntl(int fd, int command, ...);
int fixture_listener_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
efrp_result_t fixture_listener_adopt(int fd, uint64_t now, efrp_connect_t **out);
#define EFRP_TCP_LISTENER_TEST_CLOSE 1
#define close fixture_listener_close
#define socket fixture_listener_socket
#define fcntl fixture_listener_fcntl
#define setsockopt fixture_listener_setsockopt
#define efrp_connect_adopt_fd fixture_listener_adopt
#include "../src/tcp_listener.c"
#undef close
#undef socket
#undef fcntl
#undef setsockopt
#undef efrp_connect_adopt_fd
int fixture_listener_close(int fd)
{
    if (fail_close) { --fail_close; errno = ENOMEM; return -1; }
    return close(fd);
}
int fixture_listener_socket(int family, int type, int protocol)
{
    if (fail_socket) { fail_socket = false; errno = EMFILE; return -1; }
    return socket(family, type, protocol);
}
int fixture_listener_fcntl(int fd, int command, ...)
{
    va_list args; va_start(args, command); int argument = va_arg(args, int); va_end(args);
    if (fail_flags && command == F_SETFL) { fail_flags = false; errno = EIO; return -1; }
    return fcntl(fd, command, argument);
}
int fixture_listener_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    if (fail_linger && option == SO_LINGER) { --fail_linger; errno = ENOMEM; return -1; }
    return setsockopt(fd, level, option, value, length);
}
efrp_result_t fixture_listener_adopt(int fd, uint64_t now, efrp_connect_t **out)
{
    if (fail_adopt) { fail_adopt = false; return EFRP_NO_MEMORY; }
    return efrp_connect_adopt_fd(fd, now, out);
}
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
static int client_connect(const struct sockaddr_in *address)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(fd >= 0);
    assert(connect(fd, (const struct sockaddr *)address, sizeof *address) == 0); return fd;
}
static void ready(efrp_tcp_listener_t *listener)
{
    efrp_result_t result = EFRP_WOULD_BLOCK;
    for (unsigned i = 0; i < 1000 && result == EFRP_WOULD_BLOCK; ++i) {
        result = efrp_tcp_listener_ready(listener);
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    }
    assert(result == EFRP_OK);
}
static size_t receive(efrp_connect_t *local, uint8_t *bytes, size_t capacity, efrp_result_t expected)
{
    size_t length = 0; efrp_result_t result = EFRP_WOULD_BLOCK;
    for (unsigned i = 0; i < 1000 && result == EFRP_WOULD_BLOCK; ++i) {
        result = efrp_connect_recv(local, bytes, capacity, &length);
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    }
    assert(result == expected); return length;
}
int main(void)
{
    unsigned baseline = open_fds();
    uint8_t ip[4] = {127, 0, 0, 1}, denied[4] = {0};
    struct sockaddr_in address = reserve_address(); uint16_t port = ntohs(address.sin_port);
    efrp_tcp_listener_t *listener = NULL;
    assert(efrp_tcp_listener_create(ip, 0, &listener) == EFRP_INVALID_ARGUMENT && !listener);
    assert(efrp_tcp_listener_create(denied, port, &listener) == EFRP_INVALID_ARGUMENT && !listener);
    denied[0] = 224;
    assert(efrp_tcp_listener_create(denied, port, &listener) == EFRP_INVALID_ARGUMENT && !listener);
    fail_socket = true;
    assert(efrp_tcp_listener_create(ip, port, &listener) == EFRP_NETWORK_ERROR && !listener);
    assert(open_fds() == baseline);
    fail_flags = true; fail_close = 1;
    assert(efrp_tcp_listener_create(ip, port, &listener) == EFRP_NETWORK_ERROR && listener);
    assert(open_fds() == baseline + 1 && !listener->listening);
    assert(efrp_tcp_listener_destroy(&listener) == EFRP_OK && !listener && open_fds() == baseline);

    assert(efrp_tcp_listener_create(ip, port, &listener) == EFRP_OK);
    assert(efrp_tcp_listener_ready(listener) == EFRP_WOULD_BLOCK && open_fds() == baseline + 1);
    efrp_tcp_listener_t *collision = NULL;
    assert(efrp_tcp_listener_create(ip, port, &collision) == EFRP_NETWORK_ERROR && !collision);
    assert(open_fds() == baseline + 1);
    int client = client_connect(&address); ready(listener);
    efrp_connect_t *local = NULL;
    assert(efrp_tcp_listener_accept(listener, 1, &local) == EFRP_OK && local);
    efrp_connect_status_t status;
    assert(efrp_connect_status(local, &status) == EFRP_OK && status.state == EFRP_CONNECT_OPEN && status.owns_socket);
    assert(!efrp_tcp_listener_pending(listener) && open_fds() == baseline + 3);
    const uint8_t data[] = {0, 1, 255, 3, 4}; uint8_t output[16]; size_t length = 0;
    assert(send(client, data, sizeof data, 0) == (ssize_t)sizeof data);
    assert(receive(local, output, sizeof output, EFRP_OK) == sizeof data && !memcmp(output, data, sizeof data));
    assert(efrp_connect_send(local, data, sizeof data, &length) == EFRP_OK && length == sizeof data);
    assert(recv(client, output, sizeof output, 0) == (ssize_t)sizeof data && !memcmp(output, data, sizeof data));
    assert(shutdown(client, SHUT_WR) == 0);
    assert(receive(local, output, sizeof output, EFRP_EOF) == 0);
    assert(efrp_connect_close_write(local) == EFRP_OK && recv(client, output, sizeof output, 0) == 0);
    assert(efrp_connect_finish(local) == EFRP_OK && efrp_connect_destroy(&local) == EFRP_OK && !local);
    assert(close(client) == 0 && open_fds() == baseline + 1);

    client = client_connect(&address); ready(listener); fail_adopt = true; fail_linger = 1;
    assert(efrp_tcp_listener_accept(listener, 2, &local) == EFRP_NO_MEMORY && !local);
    assert(efrp_tcp_listener_pending(listener) && open_fds() == baseline + 3);
    fail_close = 1;
    assert(efrp_tcp_listener_ready(listener) == EFRP_WOULD_BLOCK);
    assert(efrp_tcp_listener_pending(listener) && open_fds() == baseline + 3);
    assert(efrp_tcp_listener_ready(listener) == EFRP_WOULD_BLOCK);
    assert(!efrp_tcp_listener_pending(listener) && open_fds() == baseline + 2);
    assert(close(client) == 0);
    fail_close = 1;
    assert(efrp_tcp_listener_destroy(&listener) == EFRP_WOULD_BLOCK && listener);
    assert(open_fds() == baseline + 1 && !listener->listening);
    assert(efrp_tcp_listener_destroy(&listener) == EFRP_OK && !listener && open_fds() == baseline);
    assert(efrp_tcp_listener_destroy(&listener) == EFRP_OK);
    puts("TCP visitor listener: adoption, whole-duplex FIN and delayed cleanup passed"); return 0;
}
