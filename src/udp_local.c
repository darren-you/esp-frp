// SPDX-License-Identifier: Apache-2.0
#include "udp_local.h"
#include "crypto_backend.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

struct efrp_udp_local { int fd; uint8_t address[4]; uint16_t port; bool opened; };
static bool transient(int error) { return error == EAGAIN || error == EWOULDBLOCK || error == EINTR; }
efrp_result_t efrp_udp_local_create(const uint8_t address[4], uint16_t port, efrp_udp_local_t **out)
{
    if (!out || !address || !address[0] || address[0] >= 224 || !port) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    efrp_udp_local_t *local = calloc(1, sizeof *local);
    if (!local) return EFRP_NO_MEMORY;
    local->fd = -1; memcpy(local->address, address, 4); local->port = port; *out = local;
    return EFRP_OK;
}
efrp_result_t efrp_udp_local_step(efrp_udp_local_t *local)
{
    if (!local) return EFRP_INVALID_ARGUMENT;
    if (local->opened) return EFRP_OK;
    if (local->fd < 0) {
        local->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (local->fd < 0) return EFRP_NETWORK_ERROR;
        int flags = fcntl(local->fd, F_GETFL, 0);
        if (flags < 0 || fcntl(local->fd, F_SETFL, flags | O_NONBLOCK) != 0) return EFRP_NETWORK_ERROR;
    }
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(local->port)};
    memcpy(&target.sin_addr.s_addr, local->address, 4);
    if (connect(local->fd, (struct sockaddr *)&target, sizeof target) != 0)
        return transient(errno) || errno == EINPROGRESS || errno == EALREADY ? EFRP_WOULD_BLOCK : EFRP_NETWORK_ERROR;
    local->opened = true; return EFRP_OK;
}
efrp_result_t efrp_udp_local_send(efrp_udp_local_t *local, const uint8_t *payload, size_t length)
{
    if (!local || (!payload && length) || length > 65507U) return EFRP_INVALID_ARGUMENT;
    if (!local->opened) return EFRP_INVALID_STATE;
    static const uint8_t empty = 0;
    ssize_t sent = send(local->fd, length ? payload : &empty, length, 0);
    if (sent < 0) return transient(errno) || errno == ENOMEM || errno == ENOBUFS ? EFRP_WOULD_BLOCK : EFRP_NETWORK_ERROR;
    return (size_t)sent == length ? EFRP_OK : EFRP_NETWORK_ERROR;
}
efrp_result_t efrp_udp_local_recv(efrp_udp_local_t *local, uint8_t *buffer, size_t max_payload, size_t *length)
{
    if (length) *length = 0;
    if (!local || !buffer || !length || !max_payload || max_payload > 65507U) return EFRP_INVALID_ARGUMENT;
    if (!local->opened) return EFRP_INVALID_STATE;
    ssize_t received = recv(local->fd, buffer, max_payload + 1U, 0);
    if (received < 0) return transient(errno) ? EFRP_WOULD_BLOCK : EFRP_NETWORK_ERROR;
    if ((size_t)received > max_payload) { efrp_crypto_zero(buffer, max_payload + 1U); return EFRP_CAPACITY_EXCEEDED; }
    *length = (size_t)received; return EFRP_OK;
}
efrp_result_t efrp_udp_local_destroy(efrp_udp_local_t **handle)
{
    if (!handle) return EFRP_INVALID_ARGUMENT;
    efrp_udp_local_t *local = *handle; if (!local) return EFRP_OK;
    if (local->fd >= 0) {
        int result = close(local->fd);
#if defined(ESP_PLATFORM) || defined(EFRP_UDP_LOCAL_TEST_CLOSE)
        if (result != 0) return EFRP_WOULD_BLOCK;
#else
        (void)result; /* POSIX close never retries a potentially reused fd. */
#endif
        local->fd = -1;
    }
    efrp_crypto_zero(local, sizeof *local); free(local); *handle = NULL; return EFRP_OK;
}
