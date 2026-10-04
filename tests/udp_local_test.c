// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "udp_local.h"
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

static bool fail_close, fail_socket, fail_flags;
int fixture_udp_socket(int family, int type, int protocol)
{
    if (fail_socket) { fail_socket = false; errno = EMFILE; return -1; }
    return socket(family, type, protocol);
}
int fixture_udp_fcntl(int fd, int command, ...)
{
    va_list args; va_start(args, command); int argument = va_arg(args, int); va_end(args);
    if (fail_flags && command == F_SETFL) { fail_flags = false; errno = EIO; return -1; }
    return fcntl(fd, command, argument);
}
int fixture_udp_close(int fd)
{
    if (fail_close) { fail_close = false; errno = ENOMEM; return -1; }
    return close(fd);
}
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static size_t receive(efrp_udp_local_t *local, uint8_t *bytes, size_t capacity, efrp_result_t expected)
{
    size_t length = 999; efrp_result_t result = EFRP_WOULD_BLOCK;
    for (unsigned retry = 0; retry < 1000 && result == EFRP_WOULD_BLOCK; ++retry) {
        result = efrp_udp_local_recv(local, bytes, capacity, &length);
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    }
    assert(result == expected); return length;
}
int main(void)
{
    unsigned baseline = open_fds();
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); assert(server >= 0);
    struct sockaddr_in target = {.sin_family = AF_INET};
    assert(inet_pton(AF_INET, "127.0.0.1", &target.sin_addr) == 1);
    assert(bind(server, (struct sockaddr *)&target, sizeof target) == 0);
    socklen_t length = sizeof target;
    assert(getsockname(server, (struct sockaddr *)&target, &length) == 0);
    uint8_t address[4] = {127, 0, 0, 1};
    efrp_udp_local_t *local = NULL;
    assert(efrp_udp_local_create(address, 0, &local) == EFRP_INVALID_ARGUMENT && !local);
    uint8_t denied[4] = {224, 0, 0, 1};
    assert(efrp_udp_local_create(denied, ntohs(target.sin_port), &local) == EFRP_INVALID_ARGUMENT && !local);
#if defined(EFRP_UDP_LOCAL_TEST_SETUP)
    fail_socket = true;
    assert(efrp_udp_local_create(address, ntohs(target.sin_port), &local) == EFRP_OK);
    assert(efrp_udp_local_step(local) == EFRP_NETWORK_ERROR && open_fds() == baseline + 1);
    assert(efrp_udp_local_destroy(&local) == EFRP_OK && !local);
    fail_flags = true;
    assert(efrp_udp_local_create(address, ntohs(target.sin_port), &local) == EFRP_OK);
    assert(efrp_udp_local_step(local) == EFRP_NETWORK_ERROR && open_fds() == baseline + 2);
    assert(efrp_udp_local_destroy(&local) == EFRP_OK && !local && open_fds() == baseline + 1);
#endif
    assert(efrp_udp_local_create(address, ntohs(target.sin_port), &local) == EFRP_OK);
    assert(open_fds() == baseline + 1); /* create does not open the socket */
    assert(efrp_udp_local_step(local) == EFRP_OK);
    assert(efrp_udp_local_step(local) == EFRP_OK);
    assert(open_fds() == baseline + 2);
    uint8_t input[1501], output[1501];
    for (size_t i = 0; i < sizeof input; ++i) input[i] = (uint8_t)(i * 31U);
    struct sockaddr_in source; socklen_t source_length = sizeof source;
    assert(efrp_udp_local_send(local, NULL, 0) == EFRP_OK);
    assert(recvfrom(server, output, sizeof output, 0, (struct sockaddr *)&source, &source_length) == 0);
    assert(sendto(server, output, 0, 0, (struct sockaddr *)&source, source_length) == 0);
    assert(receive(local, output, 1500, EFRP_OK) == 0);
    assert(efrp_udp_local_send(local, input, 1500) == EFRP_OK);
    assert(recvfrom(server, output, sizeof output, 0, (struct sockaddr *)&source, &source_length) == 1500);
    assert(!memcmp(input, output, 1500));
    assert(sendto(server, input, 1500, 0, (struct sockaddr *)&source, source_length) == 1500);
    assert(receive(local, output, 1500, EFRP_OK) == 1500 && !memcmp(input, output, 1500));
    /* Oversize is consumed whole, then the following datagram stays separate. */
    assert(sendto(server, input, sizeof input, 0, (struct sockaddr *)&source, source_length) == (ssize_t)sizeof input);
    assert(sendto(server, input, 4, 0, (struct sockaddr *)&source, source_length) == 4);
    memset(output, 0xa7, sizeof output);
    assert(receive(local, output, 1500, EFRP_CAPACITY_EXCEEDED) == 0);
    for (size_t i = 0; i < sizeof output; ++i) assert(output[i] == 0);
    assert(receive(local, output, 1500, EFRP_OK) == 4 && !memcmp(input, output, 4));
    int other = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); assert(other >= 0);
    assert(sendto(other, input, 4, 0, (struct sockaddr *)&source, source_length) == 4);
    poll(NULL, 0, 10); size_t received = 99;
    assert(efrp_udp_local_recv(local, output, 1500, &received) == EFRP_WOULD_BLOCK && !received);
    assert(close(other) == 0);
#if defined(EFRP_UDP_LOCAL_TEST_CLOSE)
    fail_close = true;
    assert(efrp_udp_local_destroy(&local) == EFRP_WOULD_BLOCK && local);
    assert(open_fds() == baseline + 2);
#endif
    assert(efrp_udp_local_destroy(&local) == EFRP_OK && !local);
    assert(efrp_udp_local_destroy(&local) == EFRP_OK);
    assert(close(server) == 0 && open_fds() == baseline);
    puts("UDP fixed target: empty/binary boundary, oversize drain, source isolation and fd recovery passed");
    return 0;
}
