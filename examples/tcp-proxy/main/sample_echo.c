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
static sample_echo_mode_t next_mode;
static struct {
    int fd; uint8_t bytes[1024]; size_t used, offset; bool eof, cancelled, write_closed;
    sample_echo_mode_t mode; uint32_t generated, input_bytes, output_bytes, mismatches;
} peers[2] = {{.fd=-1}, {.fd=-1}};
static uint64_t accepted, received, sent, failed;
enum { LOCAL_FIN_BYTES = 300001 };
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
    if (peers[i].mode == SAMPLE_ECHO_LOCAL_FIN) {
        bool valid = !peers[i].cancelled && peers[i].eof && peers[i].write_closed &&
            peers[i].input_bytes == LOCAL_FIN_BYTES && peers[i].output_bytes == LOCAL_FIN_BYTES && !peers[i].mismatches;
        printf("EFRP_SAMPLE_ECHO_PROOF mode=local_fin valid=%u input_bytes=%" PRIu32 " output_bytes=%" PRIu32
            " mismatches=%" PRIu32 " write_closed=%u peer_eof=%u cancelled=%u\n", valid,
            peers[i].input_bytes, peers[i].output_bytes, peers[i].mismatches,
            peers[i].write_closed, peers[i].eof, peers[i].cancelled);
    }
    memset(&peers[i], 0, sizeof peers[i]); peers[i].fd = -1;
}
bool sample_echo_arm(sample_echo_mode_t mode)
{
    if (stopping || listener < 0 || next_mode != SAMPLE_ECHO_NORMAL || peers[0].fd >= 0 || peers[1].fd >= 0 ||
        (mode != SAMPLE_ECHO_LOCAL_FIN && mode != SAMPLE_ECHO_PAUSED)) return false;
    next_mode = mode; return true;
}
bool sample_echo_resume(void)
{
    unsigned found=2;
    for (unsigned i=0;i<2;++i) if (peers[i].fd >= 0 && peers[i].mode == SAMPLE_ECHO_PAUSED) {
        if (found != 2) return false;
        found=i;
    }
    if (found == 2) return false;
    peers[found].mode=SAMPLE_ECHO_NORMAL; return true;
}
bool sample_echo_reset(void)
{
    if ((peers[0].fd >= 0) == (peers[1].fd >= 0)) return false;
    unsigned slot = peers[0].fd >= 0 ? 0 : 1;
    uint8_t unread_probe;
    int unread = peers[slot].mode == SAMPLE_ECHO_PAUSED ?
        recv(peers[slot].fd, &unread_probe, 1, MSG_PEEK) : 0;
    if (peers[slot].mode == SAMPLE_ECHO_PAUSED && unread != 1) return false;
    printf("EFRP_SAMPLE_ECHO_RESET paused=%u pending_read=%u\n",
           peers[slot].mode == SAMPLE_ECHO_PAUSED, unread == 1);
    close_peer(slot, true);
    return peers[slot].fd < 0;
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
    stopping = true; next_mode = SAMPLE_ECHO_NORMAL;
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
                peers[slot].fd = fd; peers[slot].mode=next_mode; next_mode=SAMPLE_ECHO_NORMAL; ++accepted;
                if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) { ++failed; close_peer(slot, true); }
            }
        }
    }
    for (unsigned i=0;i<2;++i) {
        if (peers[i].fd < 0) continue;
        if (peers[i].cancelled) { close_peer(i, true); continue; }
        if (peers[i].mode == SAMPLE_ECHO_PAUSED) continue;
        if (peers[i].mode == SAMPLE_ECHO_LOCAL_FIN && !peers[i].used && peers[i].generated < LOCAL_FIN_BYTES) {
            size_t n=LOCAL_FIN_BYTES-peers[i].generated;
            if (n>sizeof peers[i].bytes) n=sizeof peers[i].bytes;
            for (size_t j=0;j<n;++j)
                peers[i].bytes[j]=(uint8_t)(((peers[i].generated+j)*31u+42u*17u)^0xa7u);
            peers[i].used=n; peers[i].generated+=(uint32_t)n;
        }
        if (peers[i].used) {
            int n = send(peers[i].fd, peers[i].bytes + peers[i].offset, peers[i].used - peers[i].offset, 0);
            if (n > 0) { peers[i].offset += (size_t)n; sent += (unsigned)n; peers[i].output_bytes+=(unsigned)n; }
            else if (n == 0 || !transient()) { ++failed; close_peer(i, true); continue; }
            if (peers[i].offset == peers[i].used) peers[i].offset = peers[i].used = 0;
        }
        if (peers[i].mode == SAMPLE_ECHO_LOCAL_FIN && !peers[i].write_closed) {
            if (peers[i].used || peers[i].generated < LOCAL_FIN_BYTES) continue;
            if (shutdown(peers[i].fd, SHUT_WR) != 0) {
                if (!transient()) { ++failed; close_peer(i, true); }
                continue;
            }
            peers[i].write_closed=true;
        }
        if (!peers[i].used && !peers[i].eof) {
            int n = recv(peers[i].fd, peers[i].bytes, sizeof peers[i].bytes, 0);
            if (n > 0) {
                received += (unsigned)n;
                if (peers[i].mode == SAMPLE_ECHO_LOCAL_FIN) {
                    for (int j=0;j<n;++j) if (peers[i].bytes[j] != (uint8_t)((peers[i].input_bytes+(unsigned)j)*31u+42u*17u)) ++peers[i].mismatches;
                } else peers[i].used = (size_t)n;
                peers[i].input_bytes+=(unsigned)n;
            }
            else if (!n) peers[i].eof = true;
            else if (!transient()) {
                printf("EFRP_SAMPLE_ECHO_ERROR mode=%u operation=recv system_error=%d input_bytes=%" PRIu32
                    " output_bytes=%" PRIu32 "\n", (unsigned)peers[i].mode, errno,
                    peers[i].input_bytes, peers[i].output_bytes);
                ++failed; close_peer(i, true); continue;
            }
        }
        if (peers[i].eof && !peers[i].used) close_peer(i, false);
    }
}
void sample_echo_report(void)
{
    printf("EFRP_SAMPLE_ECHO listener=%u active=%u accepted=%" PRIu64 " received=%" PRIu64 " sent=%" PRIu64 " failed=%" PRIu64 "\n",
        listener >= 0, (unsigned)(peers[0].fd >= 0) + (unsigned)(peers[1].fd >= 0), accepted, received, sent, failed);
}
