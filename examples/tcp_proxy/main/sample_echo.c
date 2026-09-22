// SPDX-License-Identifier: Apache-2.0
#include "sample_echo.h"
#include "lwip/sockets.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
/* Two fixed buffers, owned and driven by app_main, no extra task per socket. */
static int listener = -1;
static bool stopping;
static struct { int fd; uint8_t bytes[1024]; size_t used, offset; bool eof, cancelled; } peers[2] = {{.fd=-1}, {.fd=-1}};
static uint64_t accepted, received, sent, failed;
static bool transient(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static void close_peer(unsigned i, bool cancelled)
{
    if (peers[i].fd < 0) return;
    peers[i].cancelled |= cancelled;
    if (peers[i].cancelled) {
        struct linger abort_now = {.l_onoff=1, .l_linger=0};
        (void)setsockopt(peers[i].fd, SOL_SOCKET, SO_LINGER, &abort_now, sizeof abort_now);
    }
    if (close(peers[i].fd) != 0) return; /* IDF retains fd on close failure. */
    peers[i].fd = -1; peers[i].used = peers[i].offset = 0; peers[i].eof = peers[i].cancelled = false;
    memset(peers[i].bytes, 0, sizeof peers[i].bytes);
}
bool sample_echo_start(uint16_t port)
{
    if (stopping) return false;
    if (listener >= 0) return true;
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (listener < 0) return false;
    struct sockaddr_in local = {.sin_family=AF_INET, .sin_port=htons(port), .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    int enabled = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) != 0 ||
        fcntl(listener, F_SETFL, O_NONBLOCK) != 0 || bind(listener, (struct sockaddr *)&local, sizeof local) != 0 ||
        listen(listener, 2) != 0) { sample_echo_stop(); return false; }
    return true;
}
void sample_echo_stop(void)
{
    stopping = true;
    if (listener >= 0 && close(listener) == 0) listener = -1;
    for (unsigned i=0;i<2;++i) close_peer(i, true);
    if (listener < 0 && peers[0].fd < 0 && peers[1].fd < 0) stopping = false;
}
void sample_echo_step(void)
{
    if (stopping) { sample_echo_stop(); return; }
    if (listener >= 0) {
        unsigned slot = 0; while (slot < 2 && peers[slot].fd >= 0) ++slot;
        /* Full capacity applies accept backpressure instead of allocating an
         * untracked third fd whose close could itself need a retry. */
        if (slot < 2) {
            int fd = accept(listener, NULL, NULL);
            if (fd >= 0) {
                peers[slot].fd = fd; ++accepted;
                if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) { ++failed; close_peer(slot, true); }
            }
        }
    }
    for (unsigned i=0;i<2;++i) {
        if (peers[i].fd < 0) continue;
        if (peers[i].cancelled) { close_peer(i, true); continue; }
        if (peers[i].used) {
            int n = send(peers[i].fd, peers[i].bytes + peers[i].offset, peers[i].used - peers[i].offset, 0);
            if (n > 0) { peers[i].offset += (size_t)n; sent += (unsigned)n; }
            else if (n == 0 || !transient()) { ++failed; close_peer(i, true); continue; }
            if (peers[i].offset == peers[i].used) peers[i].offset = peers[i].used = 0;
        }
        if (!peers[i].used && !peers[i].eof) {
            int n = recv(peers[i].fd, peers[i].bytes, sizeof peers[i].bytes, 0);
            if (n > 0) { peers[i].used = (size_t)n; received += (unsigned)n; }
            else if (!n) peers[i].eof = true;
            else if (!transient()) { ++failed; close_peer(i, true); continue; }
        }
        if (peers[i].eof && !peers[i].used) close_peer(i, false);
    }
}
void sample_echo_report(void)
{
    printf("EFRP_SAMPLE_ECHO listener=%u active=%u accepted=%" PRIu64 " received=%" PRIu64 " sent=%" PRIu64 " failed=%" PRIu64 "\n",
        listener >= 0, (unsigned)(peers[0].fd >= 0) + (unsigned)(peers[1].fd >= 0), accepted, received, sent, failed);
}
