// SPDX-License-Identifier: Apache-2.0
/* Compile the production cleanup directly. Only this translation unit's close
 * call is replaced; helper libraries and the real OS retain their syscalls. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int fixture_quic_close(int fd);
#define close fixture_quic_close
#include "../src/quic.c"
#undef close

static unsigned close_calls, failures_left;
#if !defined(EFRP_QUIC_TEST_CLOSE)
static int foreign_fd = -1;
#endif

static int fixture_quic_close(int fd)
{
    ++close_calls;
    if (failures_left) {
        --failures_left;
#if defined(EFRP_QUIC_TEST_CLOSE)
        /* The fixed lwIP error branch retains the actual socket. */
        assert(fcntl(fd, F_GETFD) >= 0);
        errno = ENOMEM;
#else
        /* Model a POSIX error after actual descriptor release. A caller takes
         * the same number before cleanup can be retried. */
        assert(close(fd) == 0);
        int replacement = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        assert(replacement >= 0);
        if (replacement != fd) {
            assert(dup2(replacement, fd) == fd);
            assert(close(replacement) == 0);
        }
        foreign_fd = fd;
        assert(fcntl(foreign_fd, F_GETFD) >= 0);
        errno = EINTR;
#endif
        return -1;
    }
    return close(fd);
}

static efrp_transport_t *fixture_transport(int *owned_fd)
{
    /* Cancellation is valid before a QUIC connection or TLS session exists.
     * Give that partial transport an actual owned UDP socket. */
    efrp_quic_transport_t *t = calloc(1, sizeof *t);
    assert(t);
    *owned_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(*owned_fd >= 0);
    t->base.operations = &operations;
    t->socket = *owned_fd;
    t->now = 1000;
    t->status = (efrp_transport_status_t){.kind = EFRP_TRANSPORT_QUIC,
        .state = EFRP_TRANSPORT_HANDSHAKING, .owns_socket = true,
        .next_deadline_ms = UINT64_MAX};
    mbedtls_x509_crt_init(&t->certificate.ca);
    return &t->base;
}

static void status_check(efrp_transport_t *transport, bool owns_socket,
                         efrp_transport_state_t state, int error)
{
    efrp_transport_status_t s;
    assert(efrp_transport_status(transport, &s) == EFRP_OK);
    assert(s.kind == EFRP_TRANSPORT_QUIC && s.result == EFRP_CANCELLED);
    assert(s.owns_socket == owns_socket && s.state == state);
    assert(s.system_error == error && !s.pending_dns && !s.pending_tx_bytes);
}

int main(void)
{
#if defined(EFRP_QUIC_TEST_CLOSE)
    int owned_fd;
    efrp_transport_t *transport = fixture_transport(&owned_fd);
    failures_left = 2; close_calls = 0;
    assert(efrp_transport_cancel(transport) == EFRP_WOULD_BLOCK);
    assert(close_calls == 1 && fcntl(owned_fd, F_GETFD) >= 0);
    status_check(transport, true, EFRP_TRANSPORT_DRAINING, ENOMEM);
    /* Five seconds limits the close datagram, not a still-live lwIP owner. */
    assert(efrp_transport_step(transport, 7000) == EFRP_WOULD_BLOCK);
    assert(close_calls == 2 && fcntl(owned_fd, F_GETFD) >= 0);
    status_check(transport, true, EFRP_TRANSPORT_DRAINING, ENOMEM);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
    assert(close_calls == 3);
    errno = 0;
    assert(fcntl(owned_fd, F_GETFD) == -1 && errno == EBADF);
    puts("QUIC IDF close failure retains fd; retry releases the real owner");
#else
    for (unsigned use_destroy = 0; use_destroy < 2; ++use_destroy) {
        int owned_fd;
        efrp_transport_t *transport = fixture_transport(&owned_fd);
        failures_left = 1; close_calls = 0; foreign_fd = -1;
        efrp_result_t first = efrp_transport_cancel(transport);
        assert(close_calls == 1 && foreign_fd == owned_fd);
        assert(fcntl(foreign_fd, F_GETFD) >= 0);
        if (use_destroy)
            assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
        else
            assert(efrp_transport_cancel(transport) == EFRP_OK);
        /* Old unconditional retry closes this actual foreign socket. */
        assert(fcntl(foreign_fd, F_GETFD) >= 0);
        assert(close_calls == 1 && first == EFRP_OK);
        if (transport) {
            status_check(transport, false, EFRP_TRANSPORT_CLOSED, EINTR);
            assert(((efrp_quic_transport_t *)transport)->socket == -1);
            assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
        }
        assert(close_calls == 1 && fcntl(foreign_fd, F_GETFD) >= 0);
        assert(close(foreign_fd) == 0); foreign_fd = -1;
    }
    puts("QUIC POSIX close error preserves errno; cancel/destroy leave reused fd open");
#endif
    return 0;
}
