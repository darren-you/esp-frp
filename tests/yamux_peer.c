// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_yamux.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PAYLOAD_BYTES 300001u
static uint64_t milliseconds(void)
{
    struct timespec ts; assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static uint8_t expected(size_t offset, unsigned round, unsigned index)
{
    return (uint8_t)(offset * 17 + round * 13 + index * 29);
}
typedef struct {
    uint32_t id;
    size_t received, sent, echo_used, echo_offset;
    uint8_t echo[4096];
    bool eof, done;
} flow_t;
static void run(unsigned port, unsigned round)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0 && fd < FD_SETSIZE);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0);
    assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    efrp_yamux_t m; uint64_t start = milliseconds(); efrp_yamux_init(&m, start);
    flow_t flows[2] = {0};
    for (unsigned i = 0; i < 2; ++i) assert(efrp_yamux_open(&m, &flows[i].id) == EFRP_OK);
    uint8_t input[8192]; size_t input_used = 0, input_offset = 0;
    bool ping_sent = false;
    for (;;) {
        uint64_t now = milliseconds(); assert(now - start < 10000);
        assert(efrp_yamux_tick(&m, now) == EFRP_OK);
        const uint8_t *output; size_t output_length;
        if (efrp_yamux_output(&m, &output, &output_length) == EFRP_OK) {
            /* Exercise transport partial writes independently of Yamux frames. */
            size_t take = output_length < 113 ? output_length : 113;
            ssize_t n = write(fd, output, take);
            if (n > 0) assert(efrp_yamux_consume_output(&m, (size_t)n) == EFRP_OK);
            else assert(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
        }
        if (!input_used) {
            ssize_t n = read(fd, input, sizeof input);
            if (n > 0) input_used = (size_t)n;
            else if (!n) {
                assert(flows[0].done && flows[1].done && efrp_yamux_finish(&m) == EFRP_OK); break;
            } else assert(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
        }
        size_t consumed;
        efrp_result_t result = efrp_yamux_feed(&m, input + input_offset, input_used - input_offset, &consumed);
        assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
        input_offset += consumed;
        if (input_offset == input_used) input_offset = input_used = 0;
        for (unsigned i = 0; i < 2; ++i) {
            flow_t *f = &flows[i]; if (f->done) continue;
            if (f->echo_used) {
                size_t written;
                result = efrp_yamux_write(&m, f->id, f->echo + f->echo_offset, f->echo_used - f->echo_offset, &written);
                assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
                f->echo_offset += written; f->sent += written;
                if (f->echo_offset == f->echo_used) f->echo_offset = f->echo_used = 0;
            }
            if (!f->echo_used && !f->eof) {
                size_t n;
                result = efrp_yamux_read(&m, f->id, f->echo, sizeof f->echo, &n);
                assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK || result == EFRP_EOF);
                for (size_t j = 0; j < n; ++j) assert(f->echo[j] == expected(f->received + j, round, i));
                f->received += n; f->echo_used = n;
                if (result == EFRP_EOF) f->eof = true;
            }
            if (f->eof && !f->echo_used) {
                assert(f->received == PAYLOAD_BYTES && f->sent == PAYLOAD_BYTES);
                result = efrp_yamux_close_write(&m, f->id);
                assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
                if (result == EFRP_OK) {
                    assert(efrp_yamux_release(&m, f->id) == EFRP_OK); f->done = true;
                }
            }
        }
        if (!ping_sent) { assert(efrp_yamux_ping(&m, round) == EFRP_OK); ping_sent = true; }
        if (flows[0].done && flows[1].done && !m.ping_pending && !m.output_used && !m.control_count) break;
        fd_set reads, writes; FD_ZERO(&reads); FD_ZERO(&writes);
        if (!input_used) FD_SET(fd, &reads);
        if (m.output_used || m.control_count) FD_SET(fd, &writes);
        struct timeval delay = {.tv_sec = 0, .tv_usec = 100};
        int selected = select(fd + 1, &reads, &writes, NULL, &delay);
        assert(selected >= 0 || errno == EINTR);
    }
    assert(!input_used && efrp_yamux_finish(&m) == EFRP_OK);
    assert(close(fd) == 0);
}
int main(int argc, char **argv)
{
    assert(argc == 3); signal(SIGPIPE, SIG_IGN);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), rounds = (unsigned)strtoul(argv[2], NULL, 10);
    assert(port > 0 && port <= 65535 && rounds > 0 && rounds <= 100);
    for (unsigned i = 0; i < rounds; ++i) run(port, i);
    printf("C Yamux peer: %u TCP sessions, two 300001-byte duplex streams each, FIN and ping passed\n", rounds);
    return 0;
}
