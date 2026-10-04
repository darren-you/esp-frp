// SPDX-License-Identifier: Apache-2.0
/* Exercise the actual bounded work parser and cancellation, without replacing
 * its codec or datagram adapter. TLS/FRPS is covered by udp_upstream. */
#define _POSIX_C_SOURCE 200809L
#include "../src/work.c"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#if defined(EFRP_UDP_LOCAL_TEST_CLOSE)
static bool fail_close;
int fixture_udp_close(int fd)
{
    if (fail_close) { fail_close = false; errno = ENOMEM; return -1; }
    return close(fd);
}
#endif

static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static size_t frame(uint8_t *output, size_t capacity, const uint8_t *payload, size_t length)
{
    efrp_udp_packet_t packet = {.remote_address = {.family = 4, .ip = {203, 0, 113, 9}, .port = 1234},
        .payload = payload, .payload_length = length};
    size_t encoded = 0;
    assert(efrp_udp_packet_encode(&packet, output + 8, capacity - 8, &encoded) == EFRP_OK);
    assert(efrp_wire_header(EFRP_MESSAGE, encoded, output) == EFRP_OK);
    return encoded + 8;
}
static efrp_result_t fragmented(efrp_work_set_t *set, efrp_udp_work_t *udp, const uint8_t *input, size_t length)
{
    size_t offset = 0; efrp_result_t result = EFRP_OK;
    while (offset < length) {
        size_t chunk = 37, used = 0;
        if (chunk > length - offset) chunk = length - offset;
        result = udp_feed(set, udp, input + offset, chunk, &used, 1000 + offset);
        offset += used;
        if (result != EFRP_OK) return result;
        assert(used == chunk);
    }
    return result;
}
int main(void)
{
    unsigned baseline = open_fds();
    efrp_work_set_t set = {.proxy_type = EFRP_PROXY_UDP, .udp_packet_size = 16};
    efrp_udp_work_t *udp = NULL;
    assert(udp_create(&udp, set.udp_packet_size, 0) == EFRP_OK);
    uint8_t payload[2000], input[2100];
    memset(payload, 0xa7, sizeof payload);
    size_t length = frame(input, sizeof input, payload, sizeof payload);
    assert(fragmented(&set, udp, input, length) == EFRP_OK);
    assert(set.status.udp_dropped_datagrams == 1 && !udp->pending && !udp->header_used);
    /* The valid oversized datagram was drained to its exact boundary. */
    length = frame(input, sizeof input, payload, 16);
    size_t first = length;
    length += frame(input + length, sizeof input - length, NULL, 0);
    size_t used = 0;
    assert(udp_feed(&set, udp, input, length, &used, 4000) == EFRP_OK && used == first && udp->pending);
    assert(udp->packet.payload_length == 16 && !memcmp(udp->packet.payload, payload, 16));
    udp->pending = false;
    size_t second = 0;
    assert(udp_feed(&set, udp, input + used, length - used, &second, 4000) == EFRP_OK);
    assert(second == length - used && udp->pending && udp->packet.payload_length == 0);
    assert(udp_cleanup(&udp) && !udp);
    /* Oversized malformed metadata cannot be counted as a valid discarded packet. */
    assert(udp_create(&udp, set.udp_packet_size, 0) == EFRP_OK);
    length = frame(input, sizeof input, payload, sizeof payload);
    input[10] |= 0x80;
    assert(fragmented(&set, udp, input, length) == EFRP_PROTOCOL_ERROR);
    assert(set.status.udp_dropped_datagrams == 1);
    assert(udp_cleanup(&udp));
    assert(udp_create(&udp, set.udp_packet_size, 0) == EFRP_OK);
    length = frame(input, sizeof input, payload, 16);
    input[9] = 13; /* JSON UDP after binary negotiation is a protocol error. */
    assert(fragmented(&set, udp, input, length) == EFRP_PROTOCOL_ERROR);
    assert(udp_cleanup(&udp));
    /* Cancellation releases every source and its packet buffers. */
    assert(udp_create(&udp, set.udp_packet_size, 0) == EFRP_OK);
    uint8_t address[4] = {127, 0, 0, 1};
    for (unsigned i = 0; i < EFRP_UDP_REMOTE_LIMIT; ++i) {
        assert(efrp_udp_local_create(address, 12345, &udp->remotes[i].local) == EFRP_OK);
        assert(efrp_udp_local_step(udp->remotes[i].local) == EFRP_OK);
    }
    assert(open_fds() == baseline + EFRP_UDP_REMOTE_LIMIT);
    udp_expire(&set, udp, EFRP_UDP_IDLE_MS);
    assert(set.status.udp_expired_remotes == EFRP_UDP_REMOTE_LIMIT && open_fds() == baseline);
    udp_expire(&set, udp, EFRP_UDP_IDLE_MS + 1U);
    assert(set.status.udp_expired_remotes == EFRP_UDP_REMOTE_LIMIT);
    for (unsigned i = 0; i < EFRP_UDP_REMOTE_LIMIT; ++i) {
        assert(efrp_udp_local_create(address, 12345, &udp->remotes[i].local) == EFRP_OK);
        assert(efrp_udp_local_step(udp->remotes[i].local) == EFRP_OK);
    }
    set.streams[0] = calloc(1, sizeof *set.streams[0]); assert(set.streams[0]);
    set.streams[0]->stream_id = EFRP_STREAM_NONE;
    set.streams[0]->udp = udp; set.streams[0]->phase = EFRP_WORK_ACTIVE;
    efrp_work_status_t status;
    efrp_work_status(&set, &status); assert(status.active == 1 && status.udp_active_remotes == 4);
#if defined(EFRP_UDP_LOCAL_TEST_CLOSE)
    udp->incoming[0] = 0xa7; udp->outgoing[0] = 0xda; udp->datagram[0] = 0xfb;
    udp->pending = true; fail_close = true;
    assert(!efrp_work_cancel(&set) && set.streams[0] && set.streams[0]->udp);
    assert(open_fds() == baseline + 1);
    assert(!udp->incoming[0] && !udp->outgoing[0] && !udp->datagram[0] && !udp->pending);
#endif
    assert(efrp_work_cancel(&set) && !set.streams[0] && open_fds() == baseline);
    assert(efrp_work_cancel(&set));
    puts("UDP work: fragmented/concatenated boundaries, validated oversized drain, codec rejection and cancellation passed");
    return 0;
}
