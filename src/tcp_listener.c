// SPDX-License-Identifier: Apache-2.0
#include "tcp_listener.h"
#include "connect_internal.h"
#include "crypto_backend.h"
#include "memory_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#if !LWIP_SO_LINGER
#error "ESP FRP visitor requires CONFIG_LWIP_SO_LINGER=y"
#endif
#else
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#if defined(ESP_PLATFORM) || defined(EFRP_TCP_LISTENER_TEST_CLOSE)
#define EFRP_LISTENER_RETRY_CLOSE 1
#else
#define EFRP_LISTENER_RETRY_CLOSE 0
#endif
struct efrp_tcp_listener { int fd, accepted_fd; bool listening; };
static bool transient(int error)
{
    return error == EAGAIN || error == EWOULDBLOCK || error == EINTR ||
        error == ENOMEM || error == ENOBUFS;
}
static efrp_result_t close_fd(int *fd, bool accepted)
{
    if (*fd < 0) return EFRP_OK;
    if (accepted) {
        /* Adoption can fail before its zero linger is installed. Abortive
         * close also bounds lwIP cleanup of this still-owned accepted fd. */
        struct linger abort_now = {.l_onoff = 1, .l_linger = 0};
        int configured = setsockopt(*fd, SOL_SOCKET, SO_LINGER, &abort_now, sizeof abort_now);
#if EFRP_LISTENER_RETRY_CLOSE
        if (configured != 0 && transient(errno)) return EFRP_WOULD_BLOCK;
#else
        (void)configured;
#endif
    }
    int result = close(*fd);
#if EFRP_LISTENER_RETRY_CLOSE
    if (result != 0) return EFRP_WOULD_BLOCK;
#else
    /* POSIX close cannot safely be repeated against a possibly reused fd. */
    (void)result;
#endif
    *fd = -1; return EFRP_OK;
}
efrp_result_t efrp_tcp_listener_destroy(efrp_tcp_listener_t **handle)
{
    if (!handle) return EFRP_INVALID_ARGUMENT;
    efrp_tcp_listener_t *listener = *handle; if (!listener) return EFRP_OK;
    listener->listening = false;
    /* Close the listener even if accepted cleanup must retry, so session
     * loss immediately stops all new admission. Each fd has one owner. */
    efrp_result_t a = close_fd(&listener->accepted_fd, true);
    efrp_result_t b = close_fd(&listener->fd, false);
    if (a != EFRP_OK || b != EFRP_OK) return EFRP_WOULD_BLOCK;
    efrp_crypto_zero(listener, sizeof *listener); free(listener); *handle = NULL;
    return EFRP_OK;
}
efrp_result_t efrp_tcp_listener_create(const uint8_t address[4], uint16_t port,
    efrp_tcp_listener_t **out)
{
    if (!out || !address || !address[0] || address[0] >= 224 || !port) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    efrp_tcp_listener_t *listener = efrp_heap_calloc(sizeof *listener);
    if (!listener) return EFRP_NO_MEMORY;
    listener->fd = listener->accepted_fd = -1; *out = listener;
    listener->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener->fd < 0) goto failed;
    int flags = fcntl(listener->fd, F_GETFL, 0), enabled = 1;
    if (listener->fd >= FD_SETSIZE || flags < 0 ||
        fcntl(listener->fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        setsockopt(listener->fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) != 0) goto failed;
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(port)};
    memcpy(&local.sin_addr.s_addr, address, sizeof local.sin_addr.s_addr);
    if (bind(listener->fd, (struct sockaddr *)&local, sizeof local) != 0 || listen(listener->fd, 2) != 0) goto failed;
    listener->listening = true; return EFRP_OK;
failed:
    (void)efrp_tcp_listener_destroy(out); return EFRP_NETWORK_ERROR;
}
efrp_result_t efrp_tcp_listener_ready(efrp_tcp_listener_t *listener)
{
    if (!listener || !listener->listening) return EFRP_INVALID_STATE;
    if (close_fd(&listener->accepted_fd, true) != EFRP_OK) return EFRP_WOULD_BLOCK;
    fd_set read_set; FD_ZERO(&read_set); FD_SET(listener->fd, &read_set);
    struct timeval immediately = {0};
    int ready = select(listener->fd + 1, &read_set, NULL, NULL, &immediately);
    if (ready < 0) return transient(errno) ? EFRP_WOULD_BLOCK : EFRP_NETWORK_ERROR;
    return ready ? EFRP_OK : EFRP_WOULD_BLOCK;
}
efrp_result_t efrp_tcp_listener_accept(efrp_tcp_listener_t *listener,
    uint64_t now, efrp_connect_t **out)
{
    if (!listener || !out) return EFRP_INVALID_ARGUMENT;
    if (!listener->listening || *out || listener->accepted_fd >= 0) return EFRP_INVALID_STATE;
    listener->accepted_fd = accept(listener->fd, NULL, NULL);
    if (listener->accepted_fd < 0) return transient(errno) ? EFRP_WOULD_BLOCK : EFRP_NETWORK_ERROR;
    efrp_result_t result = efrp_connect_adopt_fd(listener->accepted_fd, now, out);
    if (result == EFRP_OK) listener->accepted_fd = -1;
    else (void)close_fd(&listener->accepted_fd, true);
    return result;
}
bool efrp_tcp_listener_pending(const efrp_tcp_listener_t *listener)
{
    return listener && listener->accepted_fd >= 0;
}
