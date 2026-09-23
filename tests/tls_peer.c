// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_tls.h"
#include "esp_frp_connect.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct { int fd; efrp_connect_t *connection; bool split, block_send; unsigned sends, recvs; } io_t;
void tls_contract_tests(const uint8_t *ca, size_t length);
static uint64_t now_ms(void)
{
    struct timespec ts; assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static efrp_result_t send_data(void *ctx, const uint8_t *p, size_t n, size_t *sent)
{
    io_t *io = ctx; *sent = 0; ++io->sends;
    if (io->block_send || (io->split && io->sends % 2)) return EFRP_WOULD_BLOCK;
    if (io->split && n > 17) n = 17;
    return efrp_connect_send(io->connection, p, n, sent);
}
static efrp_result_t recv_data(void *ctx, uint8_t *p, size_t n, size_t *received)
{
    io_t *io = ctx; *received = 0; ++io->recvs;
    if (io->split && io->recvs % 2) return EFRP_WOULD_BLOCK;
    if (io->split && n > 19) n = 19;
    return efrp_connect_recv(io->connection, p, n, received);
}
static void wait_io(efrp_tls_t *tls, io_t *io)
{
    efrp_tls_status_t s; assert(efrp_tls_status(tls, &s) == EFRP_OK);
    if (s.want == EFRP_TLS_WANT_NONE) return;
    struct pollfd p = {.fd = io->fd, .events = s.want == EFRP_TLS_WANT_READ ? POLLIN : POLLOUT};
    int n = poll(&p, 1, 10); assert(n >= 0 || errno == EINTR);
}
static void connect_loopback(io_t *io, unsigned port, const char *host)
{
    assert(efrp_connect_create(host, (uint16_t)port, now_ms(), &io->connection) == EFRP_OK);
    efrp_result_t result;
    do { result = efrp_connect_step(io->connection, now_ms());
        if (result == EFRP_WOULD_BLOCK) poll(NULL, 0, 1);
    } while (result == EFRP_WOULD_BLOCK);
    assert(result == EFRP_OK && efrp_connect_fd(io->connection, &io->fd) == EFRP_OK);
}
static void terminal(efrp_tls_t *tls, io_t *io, efrp_result_t expected)
{
    efrp_tls_status_t s; assert(efrp_tls_status(tls, &s) == EFRP_OK && !s.pending_bytes);
    unsigned before = io->sends + io->recvs;
    assert(efrp_tls_step(tls, now_ms()) == expected);
    efrp_tls_destroy(tls); assert(io->sends + io->recvs == before);
    assert(efrp_connect_destroy(&io->connection) == EFRP_OK && !io->connection);
    assert(fcntl(io->fd, F_GETFD) == -1 && errno == EBADF);
}
static void round_trip(unsigned port, const uint8_t *ca, size_t ca_n, const char *host, const char *mode, unsigned version)
{
    io_t io = {.fd = -1, .split = !strcmp(mode, "split")}; connect_loopback(&io, port, host);
    efrp_tls_config_t config = {.hostname = host, .ca_pem = ca, .ca_length = ca_n, .time_is_trusted = true,
        .send = send_data, .recv = recv_data, .io_context = &io};
    efrp_tls_t *tls = NULL; uint64_t start = now_ms();
    assert(efrp_tls_create(&config, start, &tls) == EFRP_OK && tls);
    if (!strcmp(mode, "cancel-handshake") || !strcmp(mode, "stall")) {
        efrp_tls_status_t waiting;
        for (unsigned attempt = 0;; ++attempt) {
            assert(attempt < 2000 && efrp_tls_step(tls, now_ms()) == EFRP_WOULD_BLOCK);
            assert(efrp_tls_status(tls, &waiting) == EFRP_OK);
            if (waiting.want == EFRP_TLS_WANT_READ) break;
            wait_io(tls, &io);
        }
        assert(io.sends);
    }
    if (!strcmp(mode, "cancel-handshake")) {
        assert(efrp_tls_cancel(tls) == EFRP_CANCELLED); terminal(tls, &io, EFRP_CANCELLED); return;
    }
    if (!strcmp(mode, "stall")) {
        assert(efrp_tls_step(tls, start + EFRP_TLS_HANDSHAKE_MS) == EFRP_TIMEOUT);
        terminal(tls, &io, EFRP_TIMEOUT); return;
    }
    efrp_result_t result;
    do { result = efrp_tls_step(tls, now_ms()); if (result == EFRP_WOULD_BLOCK) wait_io(tls, &io); } while (result == EFRP_WOULD_BLOCK);
    if (!strcmp(mode, "reject")) {
        assert(result == EFRP_TLS_TRUST_ERROR);
        efrp_tls_status_t s; assert(efrp_tls_status(tls, &s) == EFRP_OK && s.verify_flags && s.verify_flags != UINT32_MAX);
        terminal(tls, &io, result); return;
    }
    if (result != EFRP_OK) { fprintf(stderr, "handshake result=%d\n", result); abort(); }
    efrp_tls_status_t s; assert(efrp_tls_status(tls, &s) == EFRP_OK && s.state == EFRP_TLS_OPEN && !s.verify_flags);
    assert(s.negotiated_version == version);
    if (!strcmp(mode, "cancel-write") || !strcmp(mode, "stall-write") || !strcmp(mode, "stall-close")) {
        io.block_send = true; size_t accepted;
        assert(efrp_tls_write(tls, now_ms(), (const uint8_t *)"retained bytes", 14, &accepted) == EFRP_OK && accepted == 14);
        uint64_t at = now_ms(); assert(efrp_tls_step(tls, at) == EFRP_WOULD_BLOCK);
        if (!strcmp(mode, "cancel-write")) {
            assert(efrp_tls_cancel(tls) == EFRP_CANCELLED); terminal(tls, &io, EFRP_CANCELLED);
        } else {
            if (!strcmp(mode, "stall-close")) assert(efrp_tls_close(tls, at) == EFRP_WOULD_BLOCK);
            assert(efrp_tls_step(tls, at + EFRP_TLS_IO_MS) == EFRP_TIMEOUT); terminal(tls, &io, EFRP_TIMEOUT);
        }
        return;
    }
    uint8_t buffer[4096]; size_t used;
    if (!strcmp(mode, "abrupt") || !strcmp(mode, "clean")) {
        do { result = efrp_tls_read(tls, now_ms(), buffer, sizeof buffer, &used); if (result == EFRP_WOULD_BLOCK) wait_io(tls, &io); } while (result == EFRP_WOULD_BLOCK);
        assert(result == (!strcmp(mode, "clean") ? EFRP_EOF : EFRP_TRUNCATED)); terminal(tls, &io, result); return;
    }
    /* The peer sends 70001 bytes in a single TLS Write, forcing full-size
     * incoming records independently of the small application read buffer. */
    size_t received = 0;
    while (received < 70001) {
        result = efrp_tls_read(tls, now_ms(), buffer, sizeof buffer, &used);
        assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
        if (result == EFRP_WOULD_BLOCK) { wait_io(tls, &io); continue; }
        assert(used <= 70001 - received);
        for (size_t i = 0; i < used; ++i) assert(buffer[i] == (uint8_t)((received + i) * 13u));
        received += used;
    }
    for (size_t offset = 0; offset < 200001;) {
        size_t count = 200001 - offset; if (count > sizeof buffer) count = sizeof buffer;
        for (size_t i = 0; i < count; ++i) buffer[i] = (uint8_t)((offset + i) * 31u);
        size_t expected = count < EFRP_TLS_TX_BYTES ? count : EFRP_TLS_TX_BYTES;
        assert(efrp_tls_write(tls, now_ms(), buffer, count, &used) == EFRP_OK && used == expected);
        count = used; /* Retry the unaccepted suffix on the next iteration. */
        memset(buffer, 0xee, sizeof buffer); /* Queue must own accepted bytes. */
        assert(efrp_tls_write(tls, now_ms(), buffer, 1, &used) == EFRP_WOULD_BLOCK && !used);
        do {
            result = efrp_tls_step(tls, now_ms()); assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
            assert(efrp_tls_status(tls, &s) == EFRP_OK); if (s.pending_bytes) wait_io(tls, &io);
        } while (s.pending_bytes);
        size_t echo = 0;
        while (echo < count) {
            result = efrp_tls_read(tls, now_ms(), buffer, count - echo, &used);
            assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
            if (result == EFRP_WOULD_BLOCK) { wait_io(tls, &io); continue; }
            for (size_t i = 0; i < used; ++i) assert(buffer[i] == (uint8_t)((offset + echo + i) * 31u));
            echo += used;
        }
        offset += count;
    }
    result = efrp_tls_close(tls, now_ms());
    while (result != EFRP_EOF) { assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK); wait_io(tls, &io); result = efrp_tls_step(tls, now_ms()); }
    terminal(tls, &io, EFRP_EOF);
}
int main(int argc, char **argv)
{
    assert(argc == 7); signal(SIGPIPE, SIG_IGN);
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10), rounds = (unsigned)strtoul(argv[5], NULL, 10);
    unsigned version = (unsigned)strtoul(argv[6], NULL, 10); assert(port && port <= 65535 && rounds && rounds <= 100);
    FILE *f = fopen(argv[2], "rb"); assert(f); uint8_t ca[EFRP_TLS_MAX_CA_BYTES]; size_t n = fread(ca, 1, sizeof ca, f);
    assert(n && n < sizeof ca && !ferror(f)); assert(fclose(f) == 0);
    if (!strcmp(argv[4], "contract")) { tls_contract_tests(ca, n); return 0; }
    for (unsigned i = 0; i < rounds; ++i) round_trip(port, ca, n, argv[3], argv[4], version);
    printf("TLS peer: mode=%s rounds=%u passed\n", argv[4], rounds); return 0;
}
