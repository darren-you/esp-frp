// SPDX-License-Identifier: Apache-2.0
#include "sample_udp_echo.h"
#include "sample_config.h"
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* One complete datagram and its source, advanced by app_main. No extra task,
 * allocation or per-source socket. The extra byte detects truncation. */
static int socket_fd = -1;
static uint16_t payload_limit;
static bool stopping, pending;
static uint8_t bytes[SAMPLE_UDP_MAX_BYTES + 1];
static size_t length;
static struct sockaddr_in remote;
static uint64_t received, sent, dropped, failed;
static bool transient(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
void sample_udp_echo_clear_pending(void)
{
    memset(bytes, 0, sizeof bytes); memset(&remote, 0, sizeof remote);
    pending = false; length = 0;
}
bool sample_udp_echo_stop(void)
{
    stopping = true; sample_udp_echo_clear_pending();
    if (socket_fd >= 0) {
        int result = close(socket_fd);
#if defined(ESP_PLATFORM) || defined(EFRP_SAMPLE_UDP_TEST_CLOSE)
        if (result != 0) return false; /* lwIP keeps ownership until close succeeds. */
#else
        (void)result; /* POSIX never retries a potentially reused fd. */
#endif
        socket_fd = -1;
    }
    payload_limit = 0; stopping = false; return true;
}
bool sample_udp_echo_start(uint16_t port, uint16_t max_payload)
{
    if (stopping || !port || !max_payload || max_payload > SAMPLE_UDP_MAX_BYTES) return false;
    if (socket_fd >= 0) return payload_limit == max_payload;
    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) return false;
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_port=htons(port), .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) != 0 ||
        bind(socket_fd, (struct sockaddr *)&address, sizeof address) != 0) {
        sample_udp_echo_stop(); return false;
    }
    payload_limit = max_payload; return true;
}
void sample_udp_echo_step(void)
{
    if (stopping) { sample_udp_echo_stop(); return; }
    if (socket_fd < 0) return;
    if (!pending) {
        socklen_t address_length = sizeof remote;
        ssize_t n = recvfrom(socket_fd, bytes, (size_t)payload_limit + 1u, 0,
            (struct sockaddr *)&remote, &address_length);
        if (n < 0) { if (!transient()) ++failed; return; }
        ++received;
        if ((size_t)n > payload_limit || address_length != sizeof remote || remote.sin_family != AF_INET ||
            remote.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            ++dropped; sample_udp_echo_clear_pending(); return;
        }
        length = (size_t)n; pending = true;
    }
    ssize_t n = sendto(socket_fd, bytes, length, 0, (const struct sockaddr *)&remote, sizeof remote);
    if (n < 0 && (transient() || errno == ENOMEM || errno == ENOBUFS)) return;
    if (n < 0 || (size_t)n != length) ++failed;
    else ++sent;
    sample_udp_echo_clear_pending();
}
void sample_udp_echo_report(void)
{
    printf("EFRP_SAMPLE_UDP_ECHO listener=%u pending=%u received=%" PRIu64 " sent=%" PRIu64
        " dropped=%" PRIu64 " failed=%" PRIu64 " capacity=%u\n",
        socket_fd >= 0, pending, received, sent, dropped, failed, payload_limit);
}
