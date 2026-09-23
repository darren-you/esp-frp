// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_connect.h"
#include "dns_backend.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#include "lwip/tcp.h"
#if !LWIP_SO_LINGER
#error "ESP FRP requires CONFIG_LWIP_SO_LINGER=y for bounded TCP cancellation"
#endif
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#if defined(ESP_PLATFORM) || defined(EFRP_CONNECT_TEST_LINGER)
#define EFRP_CONNECT_BOUNDED_LINGER 1
#else
#define EFRP_CONNECT_BOUNDED_LINGER 0
#endif

struct efrp_connect {
    efrp_dns_request_t *dns;
    efrp_connect_status_t status;
    int fd;
    uint16_t port;
    uint64_t last_now, deadline;
    uint8_t address[4];
    bool write_closed, read_eof, graceful_linger;
};
enum { EFRP_CONNECT_LINGER_SECONDS = 5 };
static bool transient(int error) { return error == EAGAIN || error == EWOULDBLOCK || error == EINTR; }
static efrp_result_t drain(efrp_connect_t *c)
{
    if (c->dns) {
        efrp_dns_cancel(c->dns);
        if (efrp_dns_destroy(&c->dns) != EFRP_OK) return EFRP_WOULD_BLOCK;
    }
    c->status.pending_dns = false;
    if (c->fd >= 0) {
        if (c->status.result != EFRP_OK && c->graceful_linger) {
            struct linger abort_now = {.l_onoff = 1, .l_linger = 0};
            /* An ESP socket option can fail while the tcpip mailbox is full.
             * Retry on every drain until cancellation no longer inherits the
             * positive linger used by a normal completed work stream. */
            if (setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &abort_now, sizeof abort_now) == 0)
                c->graceful_linger = false;
#if EFRP_CONNECT_BOUNDED_LINGER
            else if (transient(errno) || errno == ENOMEM || errno == ENOBUFS) {
                c->status.system_error = errno;
                return EFRP_WOULD_BLOCK;
            }
#endif
        }
        int closed = close(c->fd);
#if EFRP_CONNECT_BOUNDED_LINGER
        /* lwIP retains its socket on close failure, e.g. API message ENOMEM. */
        if (closed != 0) { c->status.system_error = errno; return EFRP_WOULD_BLOCK; }
#else
        /* POSIX close must not be retried against a potentially reused fd. */
        if (closed != 0) c->status.system_error = errno;
#endif
        c->fd = -1;
        if (closed == 0 && (c->status.result == EFRP_OK || c->status.result == EFRP_CANCELLED))
            c->status.system_error = 0;
    }
    c->status.owns_socket = false; c->status.state = EFRP_CONNECT_CLOSED;
    return c->status.result;
}
static efrp_result_t stop(efrp_connect_t *c, efrp_result_t result, int error)
{
    c->status.result = result; c->status.system_error = error; c->status.state = EFRP_CONNECT_DRAINING;
    return drain(c);
}
static bool valid_hostname(const char *hostname)
{
    if (!hostname) return false;
    size_t n = 0, label = 0; unsigned char previous = 0;
    while (n < 254 && hostname[n]) {
        unsigned char ch = (unsigned char)hostname[n++];
        if (ch == '.') {
            if (!label || previous == '-') return false;
            label = 0; previous = ch; continue;
        }
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-')) return false;
        if ((!label && ch == '-') || ++label > 63) return false;
        previous = ch;
    }
    return n && n < 254 && previous != '-';
}
efrp_result_t efrp_connect_create(const char *hostname, uint16_t port, uint64_t now, efrp_connect_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if (!valid_hostname(hostname) || !port || now > UINT64_MAX - EFRP_CONNECT_DNS_MS) return EFRP_INVALID_ARGUMENT;
    efrp_connect_t *c = calloc(1, sizeof *c); if (!c) return EFRP_NO_MEMORY;
    c->fd = -1; c->port = port; c->last_now = now; c->deadline = now + EFRP_CONNECT_DNS_MS;
    efrp_result_t result = efrp_dns_start(hostname, &c->dns);
    if (result != EFRP_OK) { free(c); return result; }
    c->status.state = EFRP_CONNECT_RESOLVING; c->status.pending_dns = true;
    *out = c; return EFRP_OK;
}
static efrp_result_t start_tcp(efrp_connect_t *c, const uint8_t address[4], uint64_t now)
{
    c->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->fd < 0) return stop(c, EFRP_NETWORK_ERROR, errno);
    c->status.owns_socket = true;
    /* Configure abortive cleanup before connect. Some POSIX systems reject
     * setsockopt after a refused connect, so cleanup must not depend on it.
     * Zero linger also prevents lwIP's 20-second FIN-memory retry wait. */
    struct linger linger = {.l_onoff = 1, .l_linger = 0};
    if (setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger) != 0)
        return stop(c, EFRP_NETWORK_ERROR, errno);
    int flags = fcntl(c->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(c->fd, F_SETFL, flags | O_NONBLOCK) != 0) return stop(c, EFRP_NETWORK_ERROR, errno);
    int enabled = 1;
    if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof enabled) != 0)
        return stop(c, EFRP_NETWORK_ERROR, errno);
#if defined(SO_NOSIGPIPE)
    if (setsockopt(c->fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof enabled) != 0)
        return stop(c, EFRP_NETWORK_ERROR, errno);
#endif
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(c->port)};
    memcpy(&peer.sin_addr.s_addr, address, 4);
    c->status.state = EFRP_CONNECT_CONNECTING; c->deadline = now + EFRP_CONNECT_TCP_MS;
    if (connect(c->fd, (struct sockaddr *)&peer, sizeof peer) == 0) {
        c->status.state = EFRP_CONNECT_OPEN; return EFRP_OK;
    }
    if (errno == EINPROGRESS || errno == EALREADY || errno == EINTR) return EFRP_WOULD_BLOCK;
    return stop(c, EFRP_NETWORK_ERROR, errno);
}
efrp_result_t efrp_connect_create_ipv4(const uint8_t address[4], uint16_t port,
                                     uint64_t now, efrp_connect_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if (!address || !address[0] || address[0] >= 224 || !port || now > UINT64_MAX - EFRP_CONNECT_TCP_MS)
        return EFRP_INVALID_ARGUMENT;
    efrp_connect_t *c = calloc(1, sizeof *c); if (!c) return EFRP_NO_MEMORY;
    c->fd = -1; c->port = port; c->last_now = now; c->deadline = now + EFRP_CONNECT_TCP_MS;
    memcpy(c->address, address, sizeof c->address); c->status.state = EFRP_CONNECT_CONNECTING;
    *out = c; return EFRP_OK;
}
efrp_result_t efrp_connect_step(efrp_connect_t *c, uint64_t now)
{
    if (!c) return EFRP_INVALID_ARGUMENT;
    if (c->status.state == EFRP_CONNECT_CLOSED) return c->status.result;
    if (c->status.state == EFRP_CONNECT_DRAINING) return drain(c);
    if (now < c->last_now || now > UINT64_MAX - EFRP_CONNECT_TCP_MS) return EFRP_INVALID_ARGUMENT;
    c->last_now = now;
    if (c->status.state == EFRP_CONNECT_OPEN) return EFRP_OK;
    if (now >= c->deadline) return stop(c, EFRP_TIMEOUT, 0);
    if (c->status.state == EFRP_CONNECT_RESOLVING) {
        uint8_t address[4]; int error = 0;
        efrp_result_t result = efrp_dns_poll(c->dns, address, &error);
        if (result == EFRP_WOULD_BLOCK) return result;
        if (result != EFRP_OK) return stop(c, result, error);
        result = efrp_dns_destroy(&c->dns);
        if (result != EFRP_OK) return stop(c, EFRP_DNS_ERROR, 0);
        c->status.pending_dns = false;
        return start_tcp(c, address, now);
    }
    if (c->fd < 0) return start_tcp(c, c->address, now);
    if (c->fd >= FD_SETSIZE) return stop(c, EFRP_CAPACITY_EXCEEDED, 0);
    fd_set write_set, error_set; FD_ZERO(&write_set); FD_ZERO(&error_set);
    FD_SET(c->fd, &write_set); FD_SET(c->fd, &error_set);
    struct timeval no_wait = {0};
    int ready = select(c->fd + 1, NULL, &write_set, &error_set, &no_wait);
    if (ready < 0) return transient(errno) ? EFRP_WOULD_BLOCK : stop(c, EFRP_NETWORK_ERROR, errno);
    if (!ready) return EFRP_WOULD_BLOCK;
    int error = 0; socklen_t length = sizeof error;
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0) return stop(c, EFRP_NETWORK_ERROR, errno);
    if (error) return stop(c, EFRP_NETWORK_ERROR, error);
    c->status.state = EFRP_CONNECT_OPEN; return EFRP_OK;
}
efrp_result_t efrp_connect_fd(const efrp_connect_t *c, int *fd)
{
    if (!c || !fd) return EFRP_INVALID_ARGUMENT;
    *fd = -1;
    if (c->status.state != EFRP_CONNECT_OPEN) return EFRP_INVALID_STATE;
    *fd = c->fd; return EFRP_OK;
}
efrp_result_t efrp_connect_send(void *context, const uint8_t *bytes, size_t length, size_t *sent)
{
    efrp_connect_t *c = context; if (sent) *sent = 0;
    if (!c || !bytes || !length || length > INT_MAX || !sent) return EFRP_INVALID_ARGUMENT;
    if (c->status.state != EFRP_CONNECT_OPEN || c->write_closed) return EFRP_INVALID_STATE;
    int flags = 0;
#if defined(MSG_NOSIGNAL)
    flags = MSG_NOSIGNAL;
#endif
    ssize_t n = send(c->fd, bytes, length, flags);
    if (n > 0) { *sent = (size_t)n; return EFRP_OK; }
    if (n < 0 && transient(errno)) return EFRP_WOULD_BLOCK;
    stop(c, EFRP_NETWORK_ERROR, n < 0 ? errno : 0); return EFRP_NETWORK_ERROR;
}
efrp_result_t efrp_connect_recv(void *context, uint8_t *bytes, size_t length, size_t *received)
{
    efrp_connect_t *c = context; if (received) *received = 0;
    if (!c || !bytes || !length || length > INT_MAX || !received) return EFRP_INVALID_ARGUMENT;
    if (c->status.state != EFRP_CONNECT_OPEN) return EFRP_INVALID_STATE;
    ssize_t n = recv(c->fd, bytes, length, 0);
    if (n > 0) { *received = (size_t)n; return EFRP_OK; }
    if (!n) { c->read_eof = true; return EFRP_EOF; }
    if (transient(errno)) return EFRP_WOULD_BLOCK;
    stop(c, EFRP_NETWORK_ERROR, errno); return EFRP_NETWORK_ERROR;
}
efrp_result_t efrp_connect_close_write(efrp_connect_t *c)
{
    if (!c) return EFRP_INVALID_ARGUMENT;
    if (c->status.state != EFRP_CONNECT_OPEN) return EFRP_INVALID_STATE;
    if (c->write_closed) return EFRP_OK;
#if !EFRP_CONNECT_BOUNDED_LINGER
    /* macOS may reject SO_LINGER once both halves have closed. POSIX close
     * queues FIN without lwIP's API-message memory wait; set it before SHUT_WR. */
    if (!c->graceful_linger) {
        struct linger linger = {0};
        if (setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger) != 0) {
            if (transient(errno) || errno == ENOMEM || errno == ENOBUFS) return EFRP_WOULD_BLOCK;
            return stop(c, EFRP_NETWORK_ERROR, errno);
        }
        c->graceful_linger = true;
    }
#else
    /* The socket starts with abortive linger for cancellation. Set bounded
     * graceful linger before either half-close or final close can run. */
    if (!c->graceful_linger) {
        struct linger linger = {.l_onoff = 1, .l_linger = EFRP_CONNECT_LINGER_SECONDS};
        if (setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger) != 0) {
            if (transient(errno) || errno == ENOMEM || errno == ENOBUFS) return EFRP_WOULD_BLOCK;
            return stop(c, EFRP_NETWORK_ERROR, errno);
        }
        c->graceful_linger = true;
    }
#endif
    if (shutdown(c->fd, SHUT_WR) == 0) { c->write_closed = true; return EFRP_OK; }
    if (transient(errno) || errno == ENOMEM || errno == ENOBUFS) return EFRP_WOULD_BLOCK;
    stop(c, EFRP_NETWORK_ERROR, errno); return EFRP_NETWORK_ERROR;
}
efrp_result_t efrp_connect_finish(efrp_connect_t *c)
{
    if (!c) return EFRP_INVALID_ARGUMENT;
    if (c->status.state == EFRP_CONNECT_CLOSED) return c->status.result;
    if (c->status.state == EFRP_CONNECT_DRAINING) return drain(c);
    if (c->status.state != EFRP_CONNECT_OPEN || !c->write_closed || !c->read_eof) return EFRP_INVALID_STATE;
    /* close_write already selected graceful linger before SHUT_WR. A second
     * setsockopt here could fail under transient lwIP mailbox pressure and
     * incorrectly abort a successfully half-closed stream. */
    /* FIN is already queued (or lwIP owns TF_CLOSEPEND), and inbound EOF was
     * consumed. The stack, not this object, retains retransmission ownership. */
    return stop(c, EFRP_OK, 0);
}
efrp_result_t efrp_connect_cancel(efrp_connect_t *c)
{
    if (!c) return EFRP_INVALID_ARGUMENT;
    if (c->status.state == EFRP_CONNECT_CLOSED) return c->status.result;
    if (c->status.state == EFRP_CONNECT_DRAINING) {
        /* Cancellation supersedes a pending graceful linger wait. */
        if (c->status.result == EFRP_OK) return stop(c, EFRP_CANCELLED, 0);
        return drain(c);
    }
    return stop(c, EFRP_CANCELLED, 0);
}
efrp_result_t efrp_connect_status(const efrp_connect_t *c, efrp_connect_status_t *status)
{
    if (!c || !status) return EFRP_INVALID_ARGUMENT;
    *status = c->status; return EFRP_OK;
}
efrp_result_t efrp_connect_destroy(efrp_connect_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (!*out) return EFRP_OK;
    efrp_connect_t *c = *out; efrp_connect_cancel(c);
    if (c->status.state != EFRP_CONNECT_CLOSED) return EFRP_WOULD_BLOCK;
    free(c); *out = NULL; return EFRP_OK;
}
