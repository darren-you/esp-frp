// SPDX-License-Identifier: Apache-2.0
#include "xtcp_nat.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define STUN_HEADER_BYTES 20u
#define STUN_MAX_BYTES 1024u
#define STUN_COOKIE UINT32_C(0x2112a442)
#define RANDOM_FIRST_PORT 1024u
#define RANDOM_PORT_COUNT 64511u /* Official [1024, 65535) selection. */
#define RANDOM_PORT_BITS 8192u
#define STEP_RX_BUDGET 4u

struct efrp_xtcp_nat {
    int fd;
    efrp_xtcp_nat_status_t status;
    efrp_xtcp_endpoint_t servers[EFRP_XTCP_STUN_MAX_COUNT], stun_target;
    size_t server_count, server_index;
    bool alternate, stun_sent, response_pending, read_started;
    uint8_t bind_address[4]; uint16_t bind_port;
    uint8_t secret[128]; size_t secret_length;
    uint8_t stun_request[STUN_HEADER_BYTES];
    uint64_t last_now, attempt_deadline, phase_deadline, next_send;
    efrp_xtcp_sid_message_t probe;
    uint8_t request[EFRP_XTCP_DATAGRAM_MAX_BYTES], response[EFRP_XTCP_DATAGRAM_MAX_BYTES];
    size_t request_length, response_length;
    efrp_xtcp_endpoint_t response_target;
    efrp_xtcp_detect_behavior_t detect;
    efrp_xtcp_endpoint_t candidates[EFRP_XTCP_ADDRESS_MAX_COUNT], assisted[EFRP_XTCP_ADDRESS_MAX_COUNT];
    size_t candidate_count, assisted_count, direct_index, range_ip, range_index, random_ip;
    uint32_t range_port;
    uint16_t random_port, random_done;
    uint8_t *random_used;
    unsigned send_phase; /* direct, ranges, random, complete */
};
static bool transient(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == EINTR || e == ENOMEM || e == ENOBUFS; }
static bool endpoint_valid(const efrp_xtcp_endpoint_t *a) { return a && a->ipv4[0] && a->ipv4[0] < 224 && a->port; }
static bool endpoint_equal(const efrp_xtcp_endpoint_t *a, const efrp_xtcp_endpoint_t *b)
{ return a->port == b->port && !memcmp(a->ipv4, b->ipv4, 4); }
static uint16_t u16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static uint32_t u32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void increment(uint64_t *v) { if (*v != UINT64_MAX) ++*v; }
static void address_to_socket(const efrp_xtcp_endpoint_t *a, struct sockaddr_in *s)
{ memset(s, 0, sizeof *s); s->sin_family = AF_INET; s->sin_port = htons(a->port); memcpy(&s->sin_addr.s_addr, a->ipv4, 4); }
static efrp_xtcp_endpoint_t socket_to_address(const struct sockaddr_in *s)
{ efrp_xtcp_endpoint_t a; memcpy(a.ipv4, &s->sin_addr.s_addr, 4); a.port = ntohs(s->sin_port); return a; }
static efrp_result_t close_socket(efrp_xtcp_nat_t *n)
{
    if (n->fd >= 0) {
        int result = close(n->fd);
#if defined(ESP_PLATFORM) || defined(EFRP_XTCP_NAT_TEST_CLOSE)
        if (result != 0) return EFRP_WOULD_BLOCK;
#else
        (void)result; /* POSIX EINTR cannot safely retry a possibly reused fd. */
#endif
        n->fd = -1;
    }
    n->status.owns_socket = false; return EFRP_OK;
}
static void wipe_attempt(efrp_xtcp_nat_t *n)
{
    efrp_crypto_zero(n->secret, sizeof n->secret); n->secret_length = 0;
    efrp_crypto_zero(n->stun_request, sizeof n->stun_request);
    efrp_crypto_zero(&n->probe, sizeof n->probe);
    efrp_crypto_zero(n->request, sizeof n->request); n->request_length = 0;
    efrp_crypto_zero(n->response, sizeof n->response); n->response_length = 0; n->response_pending = false;
    efrp_crypto_zero(n->candidates, sizeof n->candidates); n->candidate_count = 0;
    efrp_crypto_zero(n->assisted, sizeof n->assisted); n->assisted_count = 0;
    if (n->random_used) { efrp_crypto_zero(n->random_used, RANDOM_PORT_BITS); free(n->random_used); n->random_used = NULL; }
    n->status.next_deadline_ms = 0;
}
static efrp_result_t fail(efrp_xtcp_nat_t *n, efrp_result_t error)
{ n->status.state = EFRP_XTCP_NAT_FAILED; n->status.last_error = error; wipe_attempt(n); (void)close_socket(n); return error; }
static efrp_result_t check_time(efrp_xtcp_nat_t *n, uint64_t now)
{
    if (now < n->last_now) return fail(n, EFRP_TIME_UNTRUSTED);
    n->last_now = now;
    if (now >= n->attempt_deadline) return fail(n, EFRP_TIMEOUT);
    return EFRP_OK;
}
static efrp_result_t random_hex(char output[65])
{
    uint8_t bytes[32]; efrp_result_t r = efrp_crypto_random(bytes, sizeof bytes);
    static const char hex[] = "0123456789abcdef";
    if (r == EFRP_OK) { for (size_t i = 0; i < sizeof bytes; ++i) { output[2*i] = hex[bytes[i] >> 4]; output[2*i+1] = hex[bytes[i] & 15u]; } output[64] = 0; }
    efrp_crypto_zero(bytes, sizeof bytes); return r;
}
static bool canonical_hex(const char *s)
{ if (!s) return false; for (size_t i = 0; i < 64; ++i) if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false; return s[64] == 0; }
static efrp_result_t begin_stun(efrp_xtcp_nat_t *n, const efrp_xtcp_endpoint_t *target, uint64_t now)
{
    n->stun_target = *target; n->stun_sent = false; memset(n->stun_request, 0, sizeof n->stun_request);
    put16(n->stun_request, 1); n->stun_request[4] = 0x21; n->stun_request[5] = 0x12; n->stun_request[6] = 0xa4; n->stun_request[7] = 0x42;
    efrp_result_t r = efrp_crypto_random(n->stun_request+8, 12);
    n->phase_deadline = now + EFRP_XTCP_STUN_RESPONSE_MS;
    n->status.next_deadline_ms = n->phase_deadline < n->attempt_deadline ? n->phase_deadline : n->attempt_deadline;
    return r;
}
static efrp_result_t open_socket(efrp_xtcp_nat_t *n, uint64_t now)
{
    n->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (n->fd < 0) return EFRP_NETWORK_ERROR;
    n->status.owns_socket = true;
    int flags = fcntl(n->fd, F_GETFL, 0);
    efrp_xtcp_endpoint_t bind_address = {.port = n->bind_port}; memcpy(bind_address.ipv4, n->bind_address, 4);
    struct sockaddr_in local; address_to_socket(&bind_address, &local);
    if (flags < 0 || fcntl(n->fd, F_SETFL, flags | O_NONBLOCK) || bind(n->fd, (struct sockaddr *)&local, sizeof local)) return EFRP_NETWORK_ERROR;
    socklen_t length = sizeof local;
    if (getsockname(n->fd, (struct sockaddr *)&local, &length) || length != sizeof local || local.sin_family != AF_INET || !local.sin_port) return EFRP_NETWORK_ERROR;
    n->status.local = socket_to_address(&local);
    return begin_stun(n, &n->servers[0], now);
}
static efrp_result_t send_packet(efrp_xtcp_nat_t *n, const efrp_xtcp_endpoint_t *target, const uint8_t *bytes, size_t length, uint8_t ttl)
{
    struct sockaddr_in remote; address_to_socket(target, &remote);
    int old_ttl = 0; socklen_t size = sizeof old_ttl;
    if (ttl) {
        int new_ttl = ttl;
        if (getsockopt(n->fd, IPPROTO_IP, IP_TTL, &old_ttl, &size) || setsockopt(n->fd, IPPROTO_IP, IP_TTL, &new_ttl, sizeof new_ttl)) return EFRP_NETWORK_ERROR;
    }
    ssize_t sent = sendto(n->fd, bytes, length, 0, (struct sockaddr *)&remote, sizeof remote);
    int saved_error = errno;
    if (ttl && setsockopt(n->fd, IPPROTO_IP, IP_TTL, &old_ttl, sizeof old_ttl)) return EFRP_NETWORK_ERROR;
    if (sent < 0) return transient(saved_error) ? EFRP_WOULD_BLOCK : EFRP_NETWORK_ERROR;
    if ((size_t)sent != length) return EFRP_NETWORK_ERROR;
    increment(&n->status.sent_datagrams); return EFRP_OK;
}
static uint32_t crc32(const uint8_t *p, size_t length)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < length; ++i) { crc ^= p[i]; for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1u) ? UINT32_C(0xedb88320) : 0u); }
    return crc ^ UINT32_MAX;
}
static efrp_result_t decode_address(const uint8_t *p, size_t size, bool xored, efrp_xtcp_endpoint_t *out)
{
    if (size != 8 || p[1] != 1) return EFRP_NEGOTIATION_FAILED; /* Explicit IPv4 contract. */
    out->port = u16(p+2); memcpy(out->ipv4, p+4, 4);
    if (xored) { out->port ^= 0x2112u; static const uint8_t mask[4] = {0x21, 0x12, 0xa4, 0x42}; for (unsigned i = 0; i < 4; ++i) out->ipv4[i] ^= mask[i]; }
    return endpoint_valid(out) ? EFRP_OK : EFRP_PROTOCOL_ERROR;
}
/* Returns WB for unrelated datagrams. Correlated malformed responses fail the
 * transaction, exactly as the fixed official golib BindingTransaction does. */
static efrp_result_t decode_stun(efrp_xtcp_nat_t *n, const uint8_t *p, size_t size, const efrp_xtcp_endpoint_t *source,
                                  efrp_xtcp_endpoint_t *mapped, efrp_xtcp_endpoint_t *other, bool *has_other)
{
    if (!endpoint_equal(source, &n->stun_target) || size < STUN_HEADER_BYTES ||
        (u16(p) != 0x0101 && u16(p) != 0x0111) || u32(p+4) != STUN_COOKIE || memcmp(p+8, n->stun_request+8, 12)) return EFRP_WOULD_BLOCK;
    if (size > STUN_MAX_BYTES) return EFRP_CAPACITY_EXCEEDED;
    if ((u16(p+2) & 3u) || (size_t)u16(p+2)+STUN_HEADER_BYTES != size) return EFRP_PROTOCOL_ERROR;
    bool has_mapped = false, has_xor = false, has_changed = false, fingerprint = false, has_error = false;
    efrp_xtcp_endpoint_t plain = {0}, xored = {0}, changed = {0};
    *has_other = false;
    for (size_t at = STUN_HEADER_BYTES; at < size;) {
        if (size-at < 4) return EFRP_PROTOCOL_ERROR;
        uint16_t type = u16(p+at); size_t length = u16(p+at+2), padded = (length+3u)&~(size_t)3u;
        if (padded > size-at-4u) return EFRP_PROTOCOL_ERROR;
        const uint8_t *value = p+at+4;
        efrp_result_t r = EFRP_OK;
        if (type == 0x0001 && !has_mapped) { r = decode_address(value, length, false, &plain); has_mapped = true; }
        else if (type == 0x0020 && !has_xor) { r = decode_address(value, length, true, &xored); has_xor = true; }
        else if (type == 0x0005 && !has_changed) { r = decode_address(value, length, false, &changed); has_changed = true; }
        else if (type == 0x802c && !*has_other) { r = decode_address(value, length, false, other); *has_other = true; }
        else if (type == 0x0009 && u16(p) == 0x0111 && !has_error) {
            if (length < 4 || length > 767 || (value[2] & 7u) < 3 || (value[2] & 7u) > 6 || value[3] > 99 ||
                !efrp_json_utf8(value+4, length-4)) return EFRP_PROTOCOL_ERROR;
            size_t characters = 0; for (size_t i = 4; i < length; ++i) if ((value[i] & 0xc0u) != 0x80u) ++characters;
            if (characters >= 128) return EFRP_PROTOCOL_ERROR;
            has_error = true;
        }
        else if (type == 0x8028) {
            if (fingerprint || length != 4 || at+8 != size || u32(value) != (crc32(p, at) ^ UINT32_C(0x5354554e))) return EFRP_PROTOCOL_ERROR;
            fingerprint = true;
        }
        if (r != EFRP_OK) return r;
        at += 4u+padded;
    }
    if (u16(p) == 0x0111) return has_error ? EFRP_NETWORK_ERROR : EFRP_PROTOCOL_ERROR;
    if (!has_xor && !has_mapped) return EFRP_PROTOCOL_ERROR;
    *mapped = has_xor ? xored : plain;
    if (!*has_other && has_changed) { *other = changed; *has_other = true; }
    return EFRP_OK;
}
static efrp_result_t discover_receive(efrp_xtcp_nat_t *n, const uint8_t *p, size_t length, const efrp_xtcp_endpoint_t *source, uint64_t now)
{
    efrp_xtcp_endpoint_t mapped = {0}, other = {0}; bool has_other = false;
    efrp_result_t r = decode_stun(n, p, length, source, &mapped, &other, &has_other);
    if (r != EFRP_OK) return r;
    if (n->status.mapped_address_count >= EFRP_XTCP_MAPPED_MAX_COUNT) return EFRP_CAPACITY_EXCEEDED;
    n->status.mapped_addresses[n->status.mapped_address_count++] = mapped;
    if (!n->alternate && has_other) { n->alternate = true; return begin_stun(n, &other, now); }
    ++n->server_index; n->alternate = false;
    if (n->server_index < n->server_count) return begin_stun(n, &n->servers[n->server_index], now);
    efrp_crypto_zero(n->stun_request, sizeof n->stun_request);
    n->status.state = EFRP_XTCP_NAT_MAPPED; n->status.next_deadline_ms = n->attempt_deadline; return EFRP_OK;
}
static size_t direct_count(const efrp_xtcp_nat_t *n)
{
    if (n->detect.role == EFRP_XTCP_DETECT_SENDER) return n->assisted_count+n->candidate_count;
    return n->detect.port_range_count ? 0 : n->candidate_count;
}
static efrp_xtcp_endpoint_t direct_target(const efrp_xtcp_nat_t *n, size_t index)
{ return n->detect.role == EFRP_XTCP_DETECT_SENDER && index < n->assisted_count ? n->assisted[index] : n->candidates[index-(n->detect.role == EFRP_XTCP_DETECT_SENDER ? n->assisted_count : 0u)]; }
static bool first_ip(const efrp_xtcp_nat_t *n, size_t index)
{ for (size_t i = 0; i < index; ++i) if (!memcmp(n->candidates[i].ipv4, n->candidates[index].ipv4, 4)) return false; return true; }
static efrp_result_t next_random_port(efrp_xtcp_nat_t *n)
{
    for (unsigned trial = 0; trial < 10; ++trial) {
        uint8_t bytes[2]; efrp_result_t r = efrp_crypto_random(bytes, sizeof bytes);
        if (r != EFRP_OK) return r;
        uint16_t sample = u16(bytes); if (sample >= RANDOM_PORT_COUNT) continue;
        uint16_t port = (uint16_t)(sample+RANDOM_FIRST_PORT);
        if (!(n->random_used[port/8u] & (uint8_t)(1u << (port%8u)))) {
            n->random_used[port/8u] |= (uint8_t)(1u << (port%8u)); n->random_port = port; return EFRP_OK;
        }
    }
    /* The official algorithm also skips a round after ten collisions. */
    n->random_port = 0; return EFRP_OK;
}
static efrp_result_t send_probe(efrp_xtcp_nat_t *n, uint64_t now)
{
    if (now < n->next_send || n->response_pending || n->send_phase >= 3) return EFRP_WOULD_BLOCK;
    efrp_xtcp_endpoint_t target = {0}; unsigned interval = 0, advances = 0;
    while (++advances <= 64) {
        if (n->send_phase == 0) {
            if (n->direct_index < direct_count(n)) { target = direct_target(n, n->direct_index); break; }
            n->send_phase = 1;
        } else if (n->send_phase == 1) {
            while (n->range_ip < n->candidate_count && !first_ip(n, n->range_ip)) ++n->range_ip;
            if (!n->detect.port_range_count || n->range_ip >= n->candidate_count) { n->send_phase = 2; continue; }
            if (n->range_index >= n->detect.port_range_count) { n->range_index = 0; n->range_port = 0; ++n->range_ip; continue; }
            efrp_xtcp_port_range_t range = n->detect.port_ranges[n->range_index];
            if (!n->range_port) n->range_port = range.from;
            target = n->candidates[n->range_ip]; target.port = (uint16_t)n->range_port; interval = 2; break;
        } else if (n->send_phase == 2) {
            if (!n->read_started) {
                uint64_t read_ms = n->detect.read_timeout_ms ? n->detect.read_timeout_ms : 5000u;
                n->phase_deadline = read_ms < n->attempt_deadline-now ? now+read_ms : n->attempt_deadline;
                n->read_started = true;
            }
            if (n->random_done >= n->detect.send_random_ports || !n->candidate_count) { n->send_phase = 3; break; }
            if (!n->random_port) { efrp_result_t r = next_random_port(n); if (r != EFRP_OK) return r; if (!n->random_port) { ++n->random_done; continue; } }
            while (n->random_ip < n->candidate_count && !first_ip(n, n->random_ip)) ++n->random_ip;
            if (n->random_ip >= n->candidate_count) { n->random_ip = 0; n->random_port = 0; ++n->random_done; continue; }
            target = n->candidates[n->random_ip]; target.port = n->random_port; interval = 15; break;
        } else break;
    }
    if (n->send_phase >= 3 || !endpoint_valid(&target)) return EFRP_WOULD_BLOCK;
    efrp_result_t r = send_packet(n, &target, n->request, n->request_length, n->detect.ttl);
    if (r == EFRP_WOULD_BLOCK) return r;
    if (r != EFRP_OK) return r;
    if (n->send_phase == 0) ++n->direct_index;
    else if (n->send_phase == 1) { if (n->range_port == n->detect.port_ranges[n->range_index].to) { ++n->range_index; n->range_port = 0; } else ++n->range_port; }
    else ++n->random_ip;
    n->next_send = now+interval; return EFRP_OK;
}
static efrp_result_t detect_receive(efrp_xtcp_nat_t *n, const uint8_t *p, size_t length, const efrp_xtcp_endpoint_t *source)
{
    if (!endpoint_valid(source)) return EFRP_WOULD_BLOCK;
    efrp_xtcp_sid_message_t message;
    efrp_result_t r = efrp_xtcp_codec_sid_decode(p, length, n->secret, n->secret_length, &message);
    if (r != EFRP_OK || strcmp(message.sid, n->probe.sid)) { efrp_crypto_zero(&message, sizeof message); return EFRP_WOULD_BLOCK; }
    if (message.response) {
        if (strcmp(message.transaction_id, n->probe.transaction_id) || strcmp(message.nonce, n->probe.nonce)) { efrp_crypto_zero(&message, sizeof message); return EFRP_WOULD_BLOCK; }
        n->status.remote = *source; n->status.state = EFRP_XTCP_NAT_PUNCHED; n->status.next_deadline_ms = n->attempt_deadline;
    } else if (n->detect.role == EFRP_XTCP_DETECT_RECEIVER) {
        message.response = true;
        r = efrp_xtcp_codec_sid_encode(&message, n->secret, n->secret_length, n->response, sizeof n->response, &n->response_length);
        if (r != EFRP_OK) { efrp_crypto_zero(&message, sizeof message); return r; }
        n->response_target = *source; n->response_pending = true;
    } else { efrp_crypto_zero(&message, sizeof message); return EFRP_WOULD_BLOCK; }
    efrp_crypto_zero(&message, sizeof message); return EFRP_OK;
}
static efrp_result_t send_response(efrp_xtcp_nat_t *n)
{
    efrp_result_t r = send_packet(n, &n->response_target, n->response, n->response_length, 0);
    if (r == EFRP_OK) {
        n->status.remote = n->response_target; n->status.state = EFRP_XTCP_NAT_PUNCHED;
        n->response_pending = false; efrp_crypto_zero(n->response, sizeof n->response); n->response_length = 0;
        n->status.next_deadline_ms = n->attempt_deadline;
    }
    return r;
}
efrp_result_t efrp_xtcp_nat_create(const efrp_xtcp_nat_config_t *c, uint64_t now, efrp_xtcp_nat_t **out)
{
    if (!c || !out || !c->secret || !c->secret_length || c->secret_length > 128 || !c->stun_server_count ||
        c->stun_server_count > EFRP_XTCP_STUN_MAX_COUNT || now > UINT64_MAX-EFRP_XTCP_NAT_ATTEMPT_MS) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    bool zero_bind = true; for (unsigned i = 0; i < 4; ++i) if (c->bind_ipv4[i]) zero_bind = false;
    if (!zero_bind && (!c->bind_ipv4[0] || c->bind_ipv4[0] >= 224)) return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < c->stun_server_count; ++i) if (!endpoint_valid(&c->stun_servers[i])) return EFRP_INVALID_ARGUMENT;
    efrp_xtcp_nat_t *n = calloc(1, sizeof *n); if (!n) return EFRP_NO_MEMORY;
    n->fd = -1; n->last_now = now; n->attempt_deadline = now+EFRP_XTCP_NAT_ATTEMPT_MS;
    n->status.state = EFRP_XTCP_NAT_DISCOVERING; n->status.next_deadline_ms = n->attempt_deadline;
    memcpy(n->servers, c->stun_servers, c->stun_server_count*sizeof n->servers[0]); n->server_count = c->stun_server_count;
    memcpy(n->bind_address, c->bind_ipv4, 4); n->bind_port = c->bind_port;
    memcpy(n->secret, c->secret, c->secret_length); n->secret_length = c->secret_length;
    *out = n; return EFRP_OK;
}
efrp_result_t efrp_xtcp_nat_status(const efrp_xtcp_nat_t *n, efrp_xtcp_nat_status_t *s)
{ if (s) memset(s, 0, sizeof *s); if (!n || !s) return EFRP_INVALID_ARGUMENT; *s = n->status; return EFRP_OK; }
efrp_result_t efrp_xtcp_nat_start_detect(efrp_xtcp_nat_t *n, const char *sid, const efrp_xtcp_signal_response_t *r, uint64_t now)
{
    if (!n || !r || !canonical_hex(sid) || !r->sid || strcmp(sid, r->sid) || (r->error && r->error[0])) return EFRP_INVALID_ARGUMENT;
    if (n->status.state != EFRP_XTCP_NAT_MAPPED) return EFRP_INVALID_STATE;
    efrp_result_t result = check_time(n, now); if (result != EFRP_OK) return result;
    if (r->detect.mode > 4 || (r->detect.role != EFRP_XTCP_DETECT_SENDER && r->detect.role != EFRP_XTCP_DETECT_RECEIVER) ||
        r->candidate_address_count > EFRP_XTCP_ADDRESS_MAX_COUNT || r->assisted_address_count > EFRP_XTCP_ADDRESS_MAX_COUNT ||
        (r->candidate_address_count && !r->candidate_addresses) || (r->assisted_address_count && !r->assisted_addresses) ||
        r->detect.port_range_count > EFRP_XTCP_PORT_RANGE_MAX_COUNT || r->detect.send_random_ports > RANDOM_PORT_COUNT) return fail(n, EFRP_PROTOCOL_ERROR);
    if (r->detect.listen_random_ports) return fail(n, EFRP_NEGOTIATION_FAILED);
    if (!r->candidate_address_count && !(r->detect.role == EFRP_XTCP_DETECT_SENDER && r->assisted_address_count)) return fail(n, EFRP_PROTOCOL_ERROR);
    for (size_t i = 0; i < r->candidate_address_count; ++i) if (!endpoint_valid(&r->candidate_addresses[i])) return fail(n, EFRP_PROTOCOL_ERROR);
    for (size_t i = 0; i < r->assisted_address_count; ++i) if (!endpoint_valid(&r->assisted_addresses[i])) return fail(n, EFRP_PROTOCOL_ERROR);
    for (size_t i = 0; i < r->detect.port_range_count; ++i) if (!r->detect.port_ranges[i].from || r->detect.port_ranges[i].from > r->detect.port_ranges[i].to) return fail(n, EFRP_PROTOCOL_ERROR);
    n->detect = r->detect; n->candidate_count = r->candidate_address_count; n->assisted_count = r->assisted_address_count;
    if (n->candidate_count) memcpy(n->candidates, r->candidate_addresses, n->candidate_count*sizeof n->candidates[0]);
    if (n->assisted_count) memcpy(n->assisted, r->assisted_addresses, n->assisted_count*sizeof n->assisted[0]);
    memcpy(n->probe.sid, sid, 65);
    result = random_hex(n->probe.transaction_id); if (result == EFRP_OK) result = random_hex(n->probe.nonce);
    if (result == EFRP_OK) result = efrp_xtcp_codec_sid_encode(&n->probe, n->secret, n->secret_length, n->request, sizeof n->request, &n->request_length);
    if (result != EFRP_OK) return fail(n, result);
    if (n->detect.send_random_ports) { n->random_used = calloc(1, RANDOM_PORT_BITS); if (!n->random_used) return fail(n, EFRP_NO_MEMORY); }
    uint64_t delay = n->detect.role == EFRP_XTCP_DETECT_SENDER ? n->detect.send_delay_ms : 0u;
    n->next_send = delay < n->attempt_deadline-now ? now+delay : n->attempt_deadline;
    n->phase_deadline = n->attempt_deadline;
    n->status.state = EFRP_XTCP_NAT_PUNCHING;
    n->status.next_deadline_ms = n->next_send < n->phase_deadline ? n->next_send : n->phase_deadline;
    return EFRP_OK;
}
efrp_result_t efrp_xtcp_nat_step(efrp_xtcp_nat_t *n, uint64_t now)
{
    if (!n) return EFRP_INVALID_ARGUMENT;
    if (n->status.state == EFRP_XTCP_NAT_FAILED || n->status.state == EFRP_XTCP_NAT_CANCELLED) {
        efrp_result_t r = close_socket(n); return r != EFRP_OK ? r : n->status.last_error;
    }
    if (n->status.state == EFRP_XTCP_NAT_TRANSFERRED) return EFRP_INVALID_STATE;
    efrp_result_t result = check_time(n, now); if (result != EFRP_OK) return result;
    if (n->status.state == EFRP_XTCP_NAT_PUNCHED || n->status.state == EFRP_XTCP_NAT_MAPPED) return EFRP_OK;
    if (n->fd < 0) { result = open_socket(n, now); if (result != EFRP_OK) return fail(n, result); }
    if (now >= n->phase_deadline) return fail(n, EFRP_TIMEOUT);
    if (n->status.state == EFRP_XTCP_NAT_DISCOVERING && !n->stun_sent) {
        result = send_packet(n, &n->stun_target, n->stun_request, sizeof n->stun_request, 0);
        if (result == EFRP_OK) n->stun_sent = true;
        else return result == EFRP_WOULD_BLOCK ? result : fail(n, result);
    } else if (n->status.state == EFRP_XTCP_NAT_PUNCHING) {
        if (n->response_pending) { result = send_response(n); if (result == EFRP_OK) return EFRP_OK; }
        else result = send_probe(n, now);
        if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return fail(n, result);
        if (n->response_pending) return EFRP_WOULD_BLOCK;
        n->status.next_deadline_ms = n->next_send < n->phase_deadline && n->send_phase < 3 ? n->next_send : n->phase_deadline;
    }
    for (unsigned budget = 0; budget < STEP_RX_BUDGET; ++budget) {
        uint8_t bytes[STUN_MAX_BYTES+1u]; struct sockaddr_in source = {0}; socklen_t size = sizeof source;
        ssize_t got = recvfrom(n->fd, bytes, sizeof bytes, 0, (struct sockaddr *)&source, &size);
        if (got < 0) return transient(errno) ? EFRP_WOULD_BLOCK : fail(n, EFRP_NETWORK_ERROR);
        efrp_xtcp_endpoint_t endpoint = socket_to_address(&source);
        if (size != sizeof source || source.sin_family != AF_INET) result = EFRP_WOULD_BLOCK;
        else if (n->status.state == EFRP_XTCP_NAT_DISCOVERING) result = discover_receive(n, bytes, (size_t)got, &endpoint, now);
        else result = detect_receive(n, bytes, (size_t)got, &endpoint);
        efrp_crypto_zero(bytes, sizeof bytes);
        if (result == EFRP_WOULD_BLOCK) { increment(&n->status.rejected_datagrams); continue; }
        if (result != EFRP_OK) return fail(n, result);
        if (n->status.state == EFRP_XTCP_NAT_MAPPED || n->status.state == EFRP_XTCP_NAT_PUNCHED) return EFRP_OK;
        if (n->response_pending) { result = send_response(n); return result == EFRP_OK || result == EFRP_WOULD_BLOCK ? result : fail(n, result); }
        /* A new STUN transaction has no sent request yet; leave queued packets
         * for its next worker tick rather than accepting a pre-send response. */
        if (n->status.state == EFRP_XTCP_NAT_DISCOVERING && !n->stun_sent) return EFRP_WOULD_BLOCK;
    }
    return EFRP_WOULD_BLOCK;
}
efrp_result_t efrp_xtcp_nat_handoff(efrp_xtcp_nat_t *n, const efrp_quic_peer_config_t *config, uint64_t now, efrp_transport_t **transport)
{
    if (!n || !config || !transport) return EFRP_INVALID_ARGUMENT;
    if (n->status.state != EFRP_XTCP_NAT_PUNCHED || n->fd < 0) return EFRP_INVALID_STATE;
    efrp_result_t r = check_time(n, now); if (r != EFRP_OK) return r;
    efrp_xtcp_endpoint_t local = {.port = config->local.port}, remote = {.port = config->remote.port};
    memcpy(local.ipv4, config->local.ipv4, 4); memcpy(remote.ipv4, config->remote.ipv4, 4);
    if (!endpoint_equal(&local, &n->status.local) || !endpoint_equal(&remote, &n->status.remote)) return EFRP_INVALID_ARGUMENT;
    r = efrp_transport_quic_peer_create(config, &n->fd, now, transport);
    if (r == EFRP_OK) { n->status.owns_socket = false; n->status.state = EFRP_XTCP_NAT_TRANSFERRED; wipe_attempt(n); }
    return r;
}
efrp_result_t efrp_xtcp_nat_cancel(efrp_xtcp_nat_t *n)
{
    if (!n) return EFRP_INVALID_ARGUMENT;
    if (n->status.state != EFRP_XTCP_NAT_TRANSFERRED) { n->status.state = EFRP_XTCP_NAT_CANCELLED; n->status.last_error = EFRP_CANCELLED; }
    wipe_attempt(n); return close_socket(n);
}
efrp_result_t efrp_xtcp_nat_destroy(efrp_xtcp_nat_t **handle)
{
    if (!handle) return EFRP_INVALID_ARGUMENT;
    if (!*handle) return EFRP_OK;
    efrp_result_t r = efrp_xtcp_nat_cancel(*handle); if (r != EFRP_OK) return r;
    efrp_crypto_zero(*handle, sizeof **handle); free(*handle); *handle = NULL; return EFRP_OK;
}
