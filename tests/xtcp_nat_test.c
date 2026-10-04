// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "crypto_backend.h"
static bool fail_socket, fail_flags, fail_close, fail_send, fail_entropy, fail_allocate;
static int observed_ttl;
static uint16_t observed_port;
int fixture_nat_socket(int family, int type, int protocol);
int fixture_nat_fcntl(int fd, int command, ...);
int fixture_nat_close(int fd);
ssize_t fixture_nat_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *address, socklen_t length);
efrp_result_t fixture_nat_random(uint8_t *output, size_t length);
void *fixture_nat_calloc(size_t count, size_t size);
#define EFRP_XTCP_NAT_TEST_CLOSE 1
#define socket fixture_nat_socket
#define fcntl fixture_nat_fcntl
#define close fixture_nat_close
#define sendto fixture_nat_sendto
#define efrp_crypto_random fixture_nat_random
#define calloc fixture_nat_calloc
#include "../src/xtcp_nat.c"
#undef socket
#undef fcntl
#undef close
#undef sendto
#undef efrp_crypto_random
#undef calloc
int fixture_nat_socket(int family, int type, int protocol)
{ if (fail_socket) { fail_socket = false; errno = EMFILE; return -1; } return socket(family, type, protocol); }
int fixture_nat_fcntl(int fd, int command, ...)
{
    va_list args; va_start(args, command); int argument = va_arg(args, int); va_end(args);
    if (fail_flags && command == F_SETFL) { fail_flags = false; errno = EIO; return -1; }
    return fcntl(fd, command, argument);
}
int fixture_nat_close(int fd)
{ if (fail_close) { fail_close = false; errno = ENOMEM; return -1; } return close(fd); }
ssize_t fixture_nat_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *address, socklen_t length)
{
    const struct sockaddr_in *to = (const struct sockaddr_in *)address; observed_port = ntohs(to->sin_port);
    socklen_t size = sizeof observed_ttl; assert(!getsockopt(fd, IPPROTO_IP, IP_TTL, &observed_ttl, &size));
    if (fail_send) { fail_send = false; errno = EAGAIN; return -1; }
    return sendto(fd, p, n, flags, address, length);
}
efrp_result_t fixture_nat_random(uint8_t *output, size_t length)
{ if (fail_entropy) { fail_entropy = false; return EFRP_CRYPTO_ERROR; } return efrp_crypto_random(output, length); }
void *fixture_nat_calloc(size_t count, size_t size)
{ if (fail_allocate) { fail_allocate = false; return NULL; } return calloc(count, size); }
static unsigned open_fds(void)
{ unsigned n = 0; for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++n; return n; }
static bool zero(const void *p, size_t size)
{ const uint8_t *b = p; for (size_t i = 0; i < size; ++i) if (b[i]) return false; return true; }
static int udp_server(efrp_xtcp_endpoint_t *endpoint)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET}; assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(!bind(fd, (struct sockaddr *)&address, sizeof address)); socklen_t size = sizeof address;
    assert(!getsockname(fd, (struct sockaddr *)&address, &size)); *endpoint = socket_to_address(&address); return fd;
}
static size_t receive(int server, uint8_t *bytes, size_t capacity, struct sockaddr_in *source)
{
    struct pollfd wait = {.fd = server, .events = POLLIN}; assert(poll(&wait, 1, 1000) == 1);
    socklen_t size = sizeof *source; ssize_t got = recvfrom(server, bytes, capacity, 0, (struct sockaddr *)source, &size);
    assert(got >= 0 && size == sizeof *source); return (size_t)got;
}
static efrp_result_t receive_step(efrp_xtcp_nat_t *nat, uint64_t now)
{
    struct pollfd ready = {.fd = nat->fd, .events = POLLIN};
    assert(poll(&ready, 1, 1000) == 1);
    return efrp_xtcp_nat_step(nat, now);
}
static void send_bytes(int server, const struct sockaddr_in *to, const uint8_t *bytes, size_t size)
{ assert(sendto(server, bytes, size, 0, (const struct sockaddr *)to, sizeof *to) == (ssize_t)size); }
static size_t address_attribute(uint8_t *out, uint16_t type, const efrp_xtcp_endpoint_t *address)
{
    put16(out, type); put16(out+2, 8); out[4] = 0; out[5] = 1;
    uint16_t port = address->port; put16(out+6, type == 0x20 ? (uint16_t)(port^0x2112u) : port);
    memcpy(out+8, address->ipv4, 4);
    if (type == 0x20) { const uint8_t mask[4] = {0x21,0x12,0xa4,0x42}; for (unsigned i = 0; i < 4; ++i) out[8+i] ^= mask[i]; }
    return 12;
}
static size_t stun_reply(uint8_t *out, const uint8_t request[20], const efrp_xtcp_endpoint_t *mapped, const efrp_xtcp_endpoint_t *other, bool xored)
{
    memcpy(out, request, 20); put16(out, 0x101); size_t size = 20+address_attribute(out+20, xored ? 0x20 : 1, mapped);
    if (other) size += address_attribute(out+size, 0x802c, other);
    put16(out+2, (uint16_t)(size-20)); return size;
}
static const uint8_t secret[] = "public-nat-fixture-secret";
static const char sid[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static efrp_xtcp_nat_t *new_nat(efrp_xtcp_endpoint_t primary, uint64_t now)
{
    efrp_xtcp_nat_config_t config = {.stun_servers = {primary}, .stun_server_count = 1, .bind_ipv4 = {127,0,0,1}, .secret = secret, .secret_length = sizeof secret-1};
    efrp_xtcp_nat_t *nat = NULL; assert(efrp_xtcp_nat_create(&config, now, &nat) == EFRP_OK && nat); return nat;
}
static efrp_xtcp_nat_t *mapped_nat(int server, efrp_xtcp_endpoint_t primary, uint64_t now)
{
    efrp_xtcp_nat_t *nat = new_nat(primary, now); assert(efrp_xtcp_nat_step(nat, now) == EFRP_WOULD_BLOCK);
    uint8_t request[20], reply[100]; struct sockaddr_in source;
    assert(receive(server, request, sizeof request, &source) == 20);
    efrp_xtcp_endpoint_t mapped = socket_to_address(&source);
    size_t size = stun_reply(reply, request, &mapped, NULL, true); send_bytes(server, &source, reply, size);
    assert(receive_step(nat, now+1) == EFRP_OK && nat->status.state == EFRP_XTCP_NAT_MAPPED); return nat;
}
static efrp_xtcp_signal_response_t detect_config(efrp_xtcp_endpoint_t *peer, efrp_xtcp_detect_role_t role)
{
    return (efrp_xtcp_signal_response_t){.sid = sid, .candidate_addresses = peer, .candidate_address_count = 1,
        .detect = {.mode = 1, .role = role, .read_timeout_ms = 1000}};
}
static void send_sid(int peer, const struct sockaddr_in *to, const efrp_xtcp_sid_message_t *message)
{
    uint8_t wire[EFRP_XTCP_DATAGRAM_MAX_BYTES]; size_t size = 0;
    assert(efrp_xtcp_codec_sid_encode(message, secret, sizeof secret-1, wire, sizeof wire, &size) == EFRP_OK);
    send_bytes(peer, to, wire, size);
}
static void test_discovery(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary, alternate; int first = udp_server(&primary), second = udp_server(&alternate);
    efrp_xtcp_nat_t *nat = new_nat(primary, 1000);
    fail_send = true; assert(efrp_xtcp_nat_step(nat, 1000) == EFRP_WOULD_BLOCK && !nat->stun_sent);
    uint8_t nonce[12]; memcpy(nonce, nat->stun_request+8, 12);
    assert(efrp_xtcp_nat_step(nat, 1001) == EFRP_WOULD_BLOCK && nat->stun_sent);
    uint8_t request[20], reply[100]; struct sockaddr_in source, next_source;
    assert(receive(first, request, sizeof request, &source) == 20 && !memcmp(request+8, nonce, 12));
    efrp_xtcp_endpoint_t external = {.ipv4={198,51,100,12}, .port=40000};
    size_t size = stun_reply(reply, request, &external, &alternate, true);
    send_bytes(second, &source, reply, size); // Wrong server cannot declare the mapping.
    assert(receive_step(nat, 1002) == EFRP_WOULD_BLOCK && nat->status.mapped_address_count == 0);
    send_bytes(first, &source, reply, size);
    efrp_result_t discovery_result = receive_step(nat, 1003);
    if (discovery_result != EFRP_WOULD_BLOCK || !nat->alternate || nat->status.mapped_address_count != 1) fprintf(stderr, "OTHER_ADDRESS step result=%d state=%d alternate=%d mapped=%zu\n", discovery_result, nat->status.state, nat->alternate, nat->status.mapped_address_count);
    assert(discovery_result == EFRP_WOULD_BLOCK && nat->alternate && nat->status.mapped_address_count == 1);
    assert(efrp_xtcp_nat_step(nat, 1004) == EFRP_WOULD_BLOCK);
    assert(receive(second, request, sizeof request, &next_source) == 20);
    assert(next_source.sin_port == source.sin_port && next_source.sin_addr.s_addr == source.sin_addr.s_addr);
    assert(memcmp(request+8, nonce, 12)); external.port = 40001;
    size = stun_reply(reply, request, &external, NULL, false); send_bytes(second, &source, reply, size);
    assert(receive_step(nat, 1005) == EFRP_OK);
    efrp_xtcp_nat_status_t status; assert(efrp_xtcp_nat_status(nat, &status) == EFRP_OK);
    assert(status.state == EFRP_XTCP_NAT_MAPPED && status.mapped_address_count == 2 && status.owns_socket);
    assert(status.mapped_addresses[0].port == 40000 && status.mapped_addresses[1].port == 40001 && status.local.port == ntohs(source.sin_port));
    assert(status.rejected_datagrams == 1 && status.sent_datagrams == 2);
    assert(efrp_xtcp_nat_step(nat, 60999) == EFRP_OK); // Signal wait does not renew the whole-attempt deadline.
    assert(efrp_xtcp_nat_step(nat, 61000) == EFRP_TIMEOUT && !nat->status.owns_socket && zero(nat->secret, sizeof nat->secret));
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK && !nat); assert(!close(first) && !close(second)); assert(open_fds() == baseline);
}
static bool trusted(void *context) { (void)context; return true; }
static void test_sender_and_real_handoff(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary, target; int stun = udp_server(&primary), peer = udp_server(&target);
    efrp_xtcp_nat_t *nat = mapped_nat(stun, primary, 1000);
    efrp_xtcp_signal_response_t response = detect_config(&target, EFRP_XTCP_DETECT_SENDER); response.detect.send_delay_ms = 10;
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 1002) == EFRP_OK);
    assert(efrp_xtcp_nat_step(nat, 1011) == EFRP_WOULD_BLOCK);
    struct pollfd empty = {.fd=peer, .events=POLLIN}; assert(poll(&empty, 1, 0) == 0);
    assert(efrp_xtcp_nat_step(nat, 1012) == EFRP_WOULD_BLOCK);
    uint8_t bytes[600]; struct sockaddr_in source; size_t size = receive(peer, bytes, sizeof bytes, &source);
    efrp_xtcp_sid_message_t probe; assert(efrp_xtcp_codec_sid_decode(bytes, size, secret, sizeof secret-1, &probe) == EFRP_OK);
    assert(!probe.response && canonical_hex(probe.nonce) && canonical_hex(probe.transaction_id));
    efrp_xtcp_sid_message_t bad = probe; bad.response = true;
    bad.nonce[0] = bad.nonce[0] == '0' ? '1' : '0'; send_sid(peer, &source, &bad);
    assert(receive_step(nat, 1013) == EFRP_WOULD_BLOCK);
    bad = probe; bad.response = true; bad.transaction_id[0] = bad.transaction_id[0] == '0' ? '1' : '0'; send_sid(peer, &source, &bad);
    assert(receive_step(nat, 1014) == EFRP_WOULD_BLOCK);
    bad = probe; bad.response = true; bad.sid[0] = 'f'; send_sid(peer, &source, &bad);
    assert(receive_step(nat, 1015) == EFRP_WOULD_BLOCK);
    bytes[size-1] ^= 1; send_bytes(peer, &source, bytes, size);
    assert(receive_step(nat, 1016) == EFRP_WOULD_BLOCK && nat->status.state == EFRP_XTCP_NAT_PUNCHING && nat->status.rejected_datagrams == 4);
    probe.response = true; send_sid(peer, &source, &probe);
    const uint8_t queued[] = {0xc0, 0x01, 0x02, 0x03}; send_bytes(peer, &source, queued, sizeof queued);
    assert(receive_step(nat, 1017) == EFRP_OK && nat->status.state == EFRP_XTCP_NAT_PUNCHED);
    struct pollfd tail_ready = {.fd = nat->fd, .events = POLLIN}; assert(poll(&tail_ready, 1, 1000) == 1);
    assert(recv(nat->fd, bytes, sizeof bytes, MSG_PEEK) == (ssize_t)sizeof queued && !memcmp(bytes, queued, sizeof queued));
    efrp_quic_peer_config_t config = {.role = EFRP_XTCP_PROVIDER, .profile = EFRP_QUIC_PROFILE_P256_AES128_X25519,
        .time_is_trusted = trusted, .peer_spki_sha256={1}, .manifest_sha256={2}};
    memcpy(config.local.ipv4, nat->status.local.ipv4, 4); config.local.port = nat->status.local.port;
    memcpy(config.remote.ipv4, nat->status.remote.ipv4, 4); config.remote.port = nat->status.remote.port;
    efrp_transport_t *transport = NULL; int fd = nat->fd;
    assert(efrp_xtcp_nat_handoff(nat, &config, 1018, &transport) == EFRP_INVALID_ARGUMENT && !transport && nat->fd == fd);
    assert(!zero(nat->secret, sizeof nat->secret));
    efrp_quic_peer_identity_t *identity = NULL; assert(efrp_quic_peer_identity_create(EFRP_XTCP_PROVIDER, trusted, NULL, &identity) == EFRP_OK);
    config.identity = identity; ++config.local.port;
    assert(efrp_xtcp_nat_handoff(nat, &config, 1019, &transport) == EFRP_INVALID_ARGUMENT && nat->fd == fd); --config.local.port;
    assert(efrp_xtcp_nat_handoff(nat, &config, 1020, &transport) == EFRP_OK && transport && nat->fd == -1 && !nat->status.owns_socket);
    assert(nat->status.state == EFRP_XTCP_NAT_TRANSFERRED && zero(nat->secret, sizeof nat->secret) && zero(&nat->probe, sizeof nat->probe));
    efrp_transport_status_t ts; assert(efrp_transport_status(transport, &ts) == EFRP_OK && ts.owns_socket);
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK && !nat && fcntl(fd, F_GETFD) >= 0);
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
    efrp_quic_peer_identity_destroy(&identity); assert(!close(stun) && !close(peer)); assert(open_fds() == baseline);
}
static void test_mode_zero_udp_pair_and_timeout(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary; int stun = udp_server(&primary);
    efrp_xtcp_nat_t *sender = mapped_nat(stun, primary, 1000), *receiver = mapped_nat(stun, primary, 1000);
    efrp_xtcp_endpoint_t sender_address = sender->status.local, receiver_address = receiver->status.local;
    assert(sender_address.port != receiver_address.port);
    int sender_fd = sender->fd, receiver_fd = receiver->fd;
    efrp_xtcp_signal_response_t to_sender = detect_config(&receiver_address, EFRP_XTCP_DETECT_SENDER);
    efrp_xtcp_signal_response_t to_receiver = detect_config(&sender_address, EFRP_XTCP_DETECT_RECEIVER);
    // Official mode 0 performs the direct sender/receiver exchange, including the receiver's low-TTL probe.
    to_sender.detect.mode = 0; to_receiver.detect.mode = 0; to_receiver.detect.ttl = 7;
    assert(efrp_xtcp_nat_start_detect(sender, sid, &to_sender, 1002) == EFRP_OK);
    assert(efrp_xtcp_nat_start_detect(receiver, sid, &to_receiver, 1002) == EFRP_OK);
    assert(efrp_xtcp_nat_step(receiver, 1002) == EFRP_WOULD_BLOCK && observed_ttl == 7);
    assert(efrp_xtcp_nat_step(sender, 1002) == EFRP_WOULD_BLOCK);
    // The sender may read the receiver's request before its response reaches the socket queue.
    // Advance both real sockets until the authenticated exchange completes, while retaining the protocol deadlines.
    struct timespec began; assert(!clock_gettime(CLOCK_MONOTONIC, &began));
    uint64_t begin_ms = (uint64_t)began.tv_sec*1000u+(uint64_t)began.tv_nsec/1000000u;
    while (sender->status.state != EFRP_XTCP_NAT_PUNCHED || receiver->status.state != EFRP_XTCP_NAT_PUNCHED) {
        struct timespec current; assert(!clock_gettime(CLOCK_MONOTONIC, &current));
        uint64_t current_ms = (uint64_t)current.tv_sec*1000u+(uint64_t)current.tv_nsec/1000000u;
        assert(current_ms >= begin_ms && current_ms-begin_ms < 500u);
        uint64_t now = 1003u+current_ms-begin_ms;
        if (receiver->status.state == EFRP_XTCP_NAT_PUNCHING) {
            efrp_result_t result = efrp_xtcp_nat_step(receiver, now);
            assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
        }
        if (sender->status.state == EFRP_XTCP_NAT_PUNCHING) {
            efrp_result_t result = efrp_xtcp_nat_step(sender, now);
            assert(result == EFRP_OK || result == EFRP_WOULD_BLOCK);
        }
        if (sender->status.state == EFRP_XTCP_NAT_PUNCHED && receiver->status.state == EFRP_XTCP_NAT_PUNCHED) break;
        struct pollfd ready[2] = {
            {.fd=sender->status.state == EFRP_XTCP_NAT_PUNCHING ? sender_fd : -1, .events=POLLIN},
            {.fd=receiver->status.state == EFRP_XTCP_NAT_PUNCHING ? receiver_fd : -1, .events=POLLIN}};
        assert(poll(ready, 2, 10) >= 0);
    }
    assert(sender->fd == sender_fd && receiver->fd == receiver_fd);
    assert(sender->status.remote.port == receiver_address.port && receiver->status.remote.port == sender_address.port);
    assert(!memcmp(sender->status.remote.ipv4, receiver_address.ipv4, 4));
    assert(!memcmp(receiver->status.remote.ipv4, sender_address.ipv4, 4));
    assert(sender->status.sent_datagrams == 2 && receiver->status.sent_datagrams == 3);
    assert(efrp_xtcp_nat_destroy(&sender) == EFRP_OK && efrp_xtcp_nat_destroy(&receiver) == EFRP_OK);

    efrp_xtcp_endpoint_t silent_address; int silent_peer = udp_server(&silent_address);
    sender = mapped_nat(stun, primary, 3000); to_sender = detect_config(&silent_address, EFRP_XTCP_DETECT_SENDER);
    to_sender.detect.mode = 0;
    assert(efrp_xtcp_nat_start_detect(sender, sid, &to_sender, 3002) == EFRP_OK);
    assert(efrp_xtcp_nat_step(sender, 3002) == EFRP_WOULD_BLOCK);
    uint8_t bytes[EFRP_XTCP_DATAGRAM_MAX_BYTES]; struct sockaddr_in from;
    size_t size = receive(silent_peer, bytes, sizeof bytes, &from);
    efrp_xtcp_sid_message_t probe; assert(efrp_xtcp_codec_sid_decode(bytes, size, secret, sizeof secret-1, &probe) == EFRP_OK);
    assert(efrp_xtcp_nat_step(sender, 3003) == EFRP_WOULD_BLOCK && sender->read_started && sender->phase_deadline == 4003);
    probe.response = true; probe.nonce[0] = probe.nonce[0] == '0' ? '1' : '0'; send_sid(silent_peer, &from, &probe);
    assert(receive_step(sender, 4002) == EFRP_WOULD_BLOCK && sender->status.rejected_datagrams == 1 && sender->phase_deadline == 4003);
    assert(efrp_xtcp_nat_step(sender, 4003) == EFRP_TIMEOUT && !sender->status.owns_socket);
    assert(zero(sender->secret, sizeof sender->secret) && zero(&sender->probe, sizeof sender->probe));
    assert(efrp_xtcp_nat_destroy(&sender) == EFRP_OK);
    sender = mapped_nat(stun, primary, 5000); to_sender.detect.mode = 5;
    assert(efrp_xtcp_nat_start_detect(sender, sid, &to_sender, 5002) == EFRP_PROTOCOL_ERROR && !sender->status.owns_socket);
    assert(efrp_xtcp_nat_destroy(&sender) == EFRP_OK);
    assert(!close(silent_peer) && !close(stun)); assert(open_fds() == baseline);
}
static void test_receiver_response_retry(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary, target; int stun = udp_server(&primary), peer = udp_server(&target);
    efrp_xtcp_nat_t *nat = mapped_nat(stun, primary, 1000);
    int original = 0; socklen_t ttl_size = sizeof original; assert(!getsockopt(nat->fd, IPPROTO_IP, IP_TTL, &original, &ttl_size));
    efrp_xtcp_signal_response_t response = detect_config(&target, EFRP_XTCP_DETECT_RECEIVER); response.detect.ttl = 4;
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 1002) == EFRP_OK);
    assert(efrp_xtcp_nat_step(nat, 1002) == EFRP_WOULD_BLOCK && observed_ttl == 4);
    uint8_t bytes[600]; struct sockaddr_in source; size_t size = receive(peer, bytes, sizeof bytes, &source);
    efrp_xtcp_sid_message_t incoming; assert(efrp_xtcp_codec_sid_decode(bytes, size, secret, sizeof secret-1, &incoming) == EFRP_OK);
    incoming.transaction_id[0] = incoming.transaction_id[0] == '0' ? '1' : '0'; incoming.nonce[0] = incoming.nonce[0] == '0' ? '1' : '0';
    send_sid(peer, &source, &incoming); fail_send = true;
    assert(receive_step(nat, 1003) == EFRP_WOULD_BLOCK && nat->response_pending && nat->status.state == EFRP_XTCP_NAT_PUNCHING);
    int restored = 0; ttl_size = sizeof restored; assert(!getsockopt(nat->fd, IPPROTO_IP, IP_TTL, &restored, &ttl_size) && restored == original);
    const uint8_t queued[] = {0xc0,0x33}; send_bytes(peer, &source, queued, sizeof queued);
    assert(efrp_xtcp_nat_step(nat, 1004) == EFRP_OK && !nat->response_pending && nat->status.state == EFRP_XTCP_NAT_PUNCHED && observed_ttl == original);
    size = receive(peer, bytes, sizeof bytes, &source); efrp_xtcp_sid_message_t echo;
    assert(efrp_xtcp_codec_sid_decode(bytes, size, secret, sizeof secret-1, &echo) == EFRP_OK && echo.response);
    assert(!strcmp(echo.nonce, incoming.nonce) && !strcmp(echo.transaction_id, incoming.transaction_id));
    struct pollfd tail_ready = {.fd = nat->fd, .events = POLLIN}; assert(poll(&tail_ready, 1, 1000) == 1);
    assert(recv(nat->fd, bytes, sizeof bytes, MSG_PEEK) == (ssize_t)sizeof queued);
    fail_close = true; assert(efrp_xtcp_nat_cancel(nat) == EFRP_WOULD_BLOCK && nat->status.owns_socket);
    assert(zero(nat->secret, sizeof nat->secret) && zero(nat->request, sizeof nat->request) && zero(nat->response, sizeof nat->response));
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK && !nat); assert(!close(stun) && !close(peer)); assert(open_fds() == baseline);
}
static void test_malformed_stun(void)
{
    for (unsigned mode = 0; mode < 9; ++mode) {
        unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary; int server = udp_server(&primary);
        efrp_xtcp_nat_t *nat = new_nat(primary, 1000); assert(efrp_xtcp_nat_step(nat, 1000) == EFRP_WOULD_BLOCK);
        uint8_t request[20], reply[1100]; struct sockaddr_in source; assert(receive(server, request, sizeof request, &source) == 20);
        efrp_xtcp_endpoint_t mapped = socket_to_address(&source); size_t size = stun_reply(reply, request, &mapped, NULL, true);
        efrp_result_t expected = EFRP_PROTOCOL_ERROR;
        switch (mode) {
        case 0: put16(reply+2, (uint16_t)(size-21)); break;
        case 1: put16(reply+22, 20); break;
        case 2: --size; break;
        case 3: reply[25] = 2; expected = EFRP_NEGOTIATION_FAILED; break;
        case 4: put16(reply+2, 0); size = 20; break;
        case 5: put16(reply, 0x111); put16(reply+20, 9); put16(reply+22, 4); memset(reply+24, 0, 4); reply[26] = 4; size = 28; put16(reply+2, 8); expected = EFRP_NETWORK_ERROR; break;
        case 6: memset(reply+size, 0, 1100-size); size = 1100; put16(reply+2, 1080); expected = EFRP_CAPACITY_EXCEEDED; break;
        case 7: put16(reply+size, 0x8028); put16(reply+size+2, 4); memset(reply+size+4, 0, 4); size += 8; put16(reply+2, (uint16_t)(size-20)); break;
        case 8: put16(reply, 0x111); break;
        default: assert(false);
        }
        send_bytes(server, &source, reply, size);
        assert(receive_step(nat, 1001) == expected && nat->status.state == EFRP_XTCP_NAT_FAILED && !nat->status.owns_socket);
        assert(zero(nat->secret, sizeof nat->secret)); assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK && !nat);
        assert(!close(server)); assert(open_fds() == baseline);
    }
}
static void test_cleanup_and_detect_boundaries(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary, target; int server = udp_server(&primary), peer = udp_server(&target);
    efrp_xtcp_nat_t *nat = new_nat(primary, 1000); fail_socket = true;
    assert(efrp_xtcp_nat_step(nat, 1000) == EFRP_NETWORK_ERROR && !nat->status.owns_socket); assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK);
    nat = new_nat(primary, 1000); fail_flags = true; fail_close = true;
    assert(efrp_xtcp_nat_step(nat, 1000) == EFRP_NETWORK_ERROR && nat->status.owns_socket && zero(nat->secret, sizeof nat->secret));
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK && open_fds() == baseline+2);
    nat = new_nat(primary, 1000); fail_entropy = true;
    assert(efrp_xtcp_nat_step(nat, 1000) == EFRP_CRYPTO_ERROR && !nat->status.owns_socket); assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK);
    nat = new_nat(primary, 1000); assert(efrp_xtcp_nat_step(nat, 1000) == EFRP_WOULD_BLOCK);
    assert(efrp_xtcp_nat_step(nat, 4000) == EFRP_TIMEOUT); assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK);
    // Drain the request from the timeout case before a new transaction.
    uint8_t request[20]; struct sockaddr_in source; assert(receive(server, request, sizeof request, &source) == 20);
    nat = mapped_nat(server, primary, 5000); efrp_xtcp_signal_response_t response = detect_config(&target, EFRP_XTCP_DETECT_RECEIVER);
    response.detect.listen_random_ports = 256;
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 5002) == EFRP_NEGOTIATION_FAILED && !nat->status.owns_socket);
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK);
    nat = mapped_nat(server, primary, 6000); response = detect_config(&target, EFRP_XTCP_DETECT_SENDER);
    response.detect.send_random_ports = 1000; fail_allocate = true;
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 6002) == EFRP_NO_MEMORY && zero(nat->secret, sizeof nat->secret));
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK);
    nat = mapped_nat(server, primary, 7000); response = detect_config(&target, EFRP_XTCP_DETECT_SENDER);
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 7002) == EFRP_OK);
    assert(efrp_xtcp_nat_step(nat, 6999) == EFRP_TIME_UNTRUSTED && !nat->status.owns_socket); assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK);
    assert(!close(server) && !close(peer)); assert(open_fds() == baseline);
}
static void test_two_servers_and_four_mappings(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t first_address, second_address;
    int first = udp_server(&first_address), second = udp_server(&second_address);
    efrp_xtcp_nat_config_t config = {.stun_servers = {first_address, second_address}, .stun_server_count = 2,
        .bind_ipv4 = {127,0,0,1}, .secret = secret, .secret_length = sizeof secret-1};
    efrp_xtcp_nat_t *nat = NULL; assert(efrp_xtcp_nat_create(&config, 1000, &nat) == EFRP_OK);
    uint16_t local_port = 0;
    for (unsigned i = 0; i < 4; ++i) {
        uint64_t now = 1000u+i*2u; assert(efrp_xtcp_nat_step(nat, now) == EFRP_WOULD_BLOCK);
        uint8_t request[20], reply[100]; struct sockaddr_in source;
        int server = i == 0 || i == 3 ? first : second;
        assert(receive(server, request, sizeof request, &source) == 20);
        if (!i) local_port = source.sin_port; else assert(source.sin_port == local_port);
        efrp_xtcp_endpoint_t mapped = {.ipv4={198,51,100,12}, .port=(uint16_t)(40000u+i)};
        const efrp_xtcp_endpoint_t *other = i == 0 ? &second_address : i == 2 ? &first_address : NULL;
        size_t size = stun_reply(reply, request, &mapped, other, true); send_bytes(server, &source, reply, size);
        efrp_result_t result = receive_step(nat, now+1);
        assert(result == (i == 3 ? EFRP_OK : EFRP_WOULD_BLOCK));
    }
    assert(nat->status.state == EFRP_XTCP_NAT_MAPPED && nat->status.mapped_address_count == 4);
    for (unsigned i = 0; i < 4; ++i) assert(nat->status.mapped_addresses[i].port == 40000u+i);
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK); assert(!close(first) && !close(second)); assert(open_fds() == baseline);
}
static void test_range_random_and_read_deadline(void)
{
    unsigned baseline = open_fds(); efrp_xtcp_endpoint_t primary, target; int stun = udp_server(&primary), peer = udp_server(&target);
    efrp_xtcp_nat_t *nat = mapped_nat(stun, primary, 1000);
    efrp_xtcp_signal_response_t response = detect_config(&target, EFRP_XTCP_DETECT_RECEIVER);
    response.detect.port_range_count = 1; response.detect.port_ranges[0] = (efrp_xtcp_port_range_t){target.port, target.port};
    response.detect.ttl = 7;
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 1002) == EFRP_OK);
    uint16_t saved = target.port; target.port = 1; // Signal input is copied, never borrowed.
    assert(efrp_xtcp_nat_step(nat, 1002) == EFRP_WOULD_BLOCK && observed_port == saved && observed_ttl == 7);
    uint8_t bytes[600]; struct sockaddr_in source; assert(receive(peer, bytes, sizeof bytes, &source) > 0);
    assert(efrp_xtcp_nat_step(nat, 1003) == EFRP_WOULD_BLOCK && !nat->read_started);
    assert(efrp_xtcp_nat_step(nat, 1004) == EFRP_WOULD_BLOCK && nat->read_started && nat->phase_deadline == 2004);
    assert(efrp_xtcp_nat_step(nat, 2004) == EFRP_TIMEOUT && !nat->status.owns_socket);
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK); target.port = saved;
    nat = mapped_nat(stun, primary, 3000); response = detect_config(&target, EFRP_XTCP_DETECT_SENDER);
    response.detect.send_random_ports = 2;
    assert(efrp_xtcp_nat_start_detect(nat, sid, &response, 3002) == EFRP_OK && nat->random_used);
    assert(efrp_xtcp_nat_step(nat, 3002) == EFRP_WOULD_BLOCK); assert(receive(peer, bytes, sizeof bytes, &source) > 0);
    fail_send = true; assert(efrp_xtcp_nat_step(nat, 3003) == EFRP_WOULD_BLOCK);
    uint16_t first_port = observed_port; assert(first_port >= 1024 && first_port < 65535 && nat->random_port == first_port);
    assert(efrp_xtcp_nat_step(nat, 3004) == EFRP_WOULD_BLOCK && observed_port == first_port && nat->status.sent_datagrams == 3);
    assert(nat->next_send == 3019); assert(efrp_xtcp_nat_step(nat, 3018) == EFRP_WOULD_BLOCK && nat->status.sent_datagrams == 3);
    assert(efrp_xtcp_nat_step(nat, 3019) == EFRP_WOULD_BLOCK && observed_port != first_port && observed_port >= 1024 && observed_port < 65535);
    assert(nat->status.sent_datagrams == 4 && nat->next_send == 3034);
    assert(efrp_xtcp_nat_step(nat, 3034) == EFRP_WOULD_BLOCK && nat->send_phase == 3 && nat->random_done == 2);
    assert(efrp_xtcp_nat_cancel(nat) == EFRP_OK && !nat->random_used && zero(nat->secret, sizeof nat->secret));
    assert(efrp_xtcp_nat_destroy(&nat) == EFRP_OK); assert(!close(stun) && !close(peer)); assert(open_fds() == baseline);
}
int main(void)
{
    test_discovery(); test_sender_and_real_handoff(); test_mode_zero_udp_pair_and_timeout(); test_receiver_response_retry(); test_malformed_stun(); test_cleanup_and_detect_boundaries(); test_two_servers_and_four_mappings(); test_range_random_and_read_deadline();
    puts("XTCP NAT: actual STUN/OTHER_ADDRESS, strict SID/nonce/HMAC, one-fd QUIC handoff, cleanup boundaries passed");
    return 0;
}
