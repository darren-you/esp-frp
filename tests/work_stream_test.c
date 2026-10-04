// SPDX-License-Identifier: Apache-2.0
/* Only the work/stream contract boundary is driven here. These operation
 * callbacks are not a QUIC implementation or QUIC network evidence. */
#define _POSIX_C_SOURCE 200809L
#include "stream_backend.h"
#include "connect_internal.h"
#include "../src/work.c"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    efrp_transport_t base;
    efrp_stream_id_t next_id, id;
    unsigned open_blocks, release_blocks, opens, resets, releases, cancels;
    unsigned writes;
    efrp_transport_kind_t kind;
    bool accept_ready;
} transport_fixture_t;
static efrp_result_t transport_step(efrp_transport_t *base, uint64_t now)
{ (void)base; (void)now; return EFRP_OK; }
static efrp_result_t transport_status(const efrp_transport_t *base, efrp_transport_status_t *out)
{ *out = (efrp_transport_status_t){.state = EFRP_TRANSPORT_OPEN,
    .kind = ((const transport_fixture_t *)base)->kind}; return EFRP_OK; }
static efrp_result_t stream_accept(efrp_transport_t *base, efrp_stream_id_t *id)
{
    transport_fixture_t *fixture = (transport_fixture_t *)base;
    assert(*id == EFRP_STREAM_NONE);
    if (!fixture->accept_ready) return EFRP_WOULD_BLOCK;
    fixture->accept_ready = false; fixture->id = *id = fixture->next_id; return EFRP_OK;
}
static efrp_result_t stream_open(efrp_transport_t *base, efrp_stream_id_t *id)
{
    transport_fixture_t *fixture = (transport_fixture_t *)base;
    assert(*id == EFRP_STREAM_NONE); ++fixture->opens;
    if (fixture->open_blocks) { --fixture->open_blocks; return EFRP_WOULD_BLOCK; }
    assert(fixture->id == EFRP_STREAM_NONE);
    fixture->id = *id = fixture->next_id; return EFRP_OK;
}
static efrp_result_t stream_info(const efrp_transport_t *base, efrp_stream_id_t id, efrp_stream_info_t *out)
{
    assert(id == ((const transport_fixture_t *)base)->id);
    *out = (efrp_stream_info_t){0}; return EFRP_OK;
}
static efrp_result_t stream_write(efrp_transport_t *base, efrp_stream_id_t id,
    const uint8_t *bytes, size_t length, size_t *used)
{
    assert(id == ((transport_fixture_t *)base)->id && bytes && length && !*used);
    ++((transport_fixture_t *)base)->writes;
    return EFRP_WOULD_BLOCK;
}
static efrp_result_t stream_read(efrp_transport_t *base, efrp_stream_id_t id,
    uint8_t *bytes, size_t capacity, size_t *used)
{
    assert(id == ((transport_fixture_t *)base)->id && bytes && capacity && !*used);
    return EFRP_WOULD_BLOCK;
}
static efrp_result_t stream_close_write(efrp_transport_t *base, efrp_stream_id_t id)
{ assert(id == ((transport_fixture_t *)base)->id); return EFRP_OK; }
static efrp_result_t stream_reset(efrp_transport_t *base, efrp_stream_id_t id)
{
    transport_fixture_t *fixture = (transport_fixture_t *)base;
    assert(id == fixture->id); ++fixture->resets; return EFRP_OK;
}
static efrp_result_t stream_release(efrp_transport_t *base, efrp_stream_id_t id)
{
    transport_fixture_t *fixture = (transport_fixture_t *)base;
    assert(id == fixture->id); ++fixture->releases;
    if (fixture->release_blocks) { --fixture->release_blocks; return EFRP_WOULD_BLOCK; }
    fixture->id = EFRP_STREAM_NONE; return EFRP_OK;
}
static efrp_result_t transport_finish(const efrp_transport_t *base)
{ (void)base; return EFRP_OK; }
static efrp_result_t transport_cancel(efrp_transport_t *base)
{
    transport_fixture_t *fixture = (transport_fixture_t *)base;
    ++fixture->cancels; fixture->id = EFRP_STREAM_NONE; return EFRP_OK;
}
static efrp_result_t transport_destroy(efrp_transport_t **base)
{ (void)transport_cancel(*base); *base = NULL; return EFRP_OK; }
static const efrp_stream_operations_t operations = {.step = transport_step, .status = transport_status,
    .open = stream_open, .accept = stream_accept, .info = stream_info, .write = stream_write, .read = stream_read,
    .close_write = stream_close_write, .reset = stream_reset, .release = stream_release,
    .finish = transport_finish, .cancel = transport_cancel, .destroy = transport_destroy};
static unsigned open_fds(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}
static efrp_work_stream_t *prepare(efrp_work_set_t *work, transport_fixture_t *transport, efrp_stream_id_t id)
{
    *transport = (transport_fixture_t){.base = {.operations = &operations}, .next_id = id,
        .id = EFRP_STREAM_NONE, .open_blocks = 1, .release_blocks = 2};
    efrp_session_config_t config = {.local_ipv4 = {127, 0, 0, 1}, .local_port = 12345};
    efrp_work_init(work, &config, "stream-fixture"); efrp_work_request(work);
    assert(efrp_work_step(work, &transport->base, 1, "run", (const uint8_t *)"token", 5, 1) == EFRP_OK);
    assert(work->status.pending == 1 && !work->streams[0] && transport->opens == 1);
    assert(efrp_work_step(work, &transport->base, 2, "run", (const uint8_t *)"token", 5, 1) == EFRP_OK);
    efrp_work_stream_t *stream = work->streams[0];
    assert(stream && stream->stream_id == id && stream->phase == EFRP_WORK_SENDING);
    assert(!work->status.pending && transport->opens == 2); return stream;
}
static void assert_zero(const uint8_t *bytes, size_t length)
{ for (size_t i = 0; i < length; ++i) assert(!bytes[i]); }
static void accepted_local(efrp_work_stream_t *stream, int *server, int *peer)
{
    *server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(*server >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET};
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(bind(*server, (struct sockaddr *)&address, sizeof address) == 0 && listen(*server, 1) == 0);
    socklen_t length = sizeof address; assert(getsockname(*server, (struct sockaddr *)&address, &length) == 0);
    *peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(*peer >= 0);
    assert(connect(*peer, (struct sockaddr *)&address, sizeof address) == 0);
    int accepted = accept(*server, NULL, NULL); assert(accepted >= 0);
    assert(efrp_connect_adopt_fd(accepted, 2, &stream->local) == EFRP_OK && stream->local);
}
static void delayed_release(efrp_stream_id_t id, bool datagram)
{
    unsigned baseline = open_fds(); efrp_work_set_t work; transport_fixture_t transport;
    efrp_work_stream_t *stream = prepare(&work, &transport, id);
    int server = -1, peer = -1;
    if (datagram) {
        assert(udp_create(&stream->udp, 16, 2) == EFRP_OK);
        for (unsigned i = 0; i < EFRP_UDP_REMOTE_LIMIT; ++i) {
            uint8_t address[4] = {127, 0, 0, 1};
            assert(efrp_udp_local_create(address, 12345, &stream->udp->remotes[i].local) == EFRP_OK);
            assert(efrp_udp_local_step(stream->udp->remotes[i].local) == EFRP_OK);
        }
        stream->udp->incoming[0] = 0x77; stream->udp->outgoing[0] = 0x88; stream->udp->datagram[0] = 0x99;
        assert(open_fds() == baseline + EFRP_UDP_REMOTE_LIMIT);
    } else {
        accepted_local(stream, &server, &peer); assert(open_fds() == baseline + 3);
    }
    memset(stream->incoming, 0xa7, sizeof stream->incoming);
    memset(stream->outgoing, 0xf2, sizeof stream->outgoing);
    close_work(&work, stream, EFRP_PROTOCOL_ERROR);
    for (uint64_t now = 3; now < 5; ++now) {
        assert(efrp_work_step(&work, &transport.base, now, "run", (const uint8_t *)"token", 5, 1) == EFRP_OK);
        assert(work.streams[0] == stream && stream->stream_id == id);
        assert(!stream->local && !stream->udp);
        assert_zero(stream->incoming, sizeof stream->incoming); assert_zero(stream->outgoing, sizeof stream->outgoing);
        assert(open_fds() == baseline + (datagram ? 0U : 2U));
        efrp_work_status_t status; efrp_work_status(&work, &status);
        assert(!status.active && status.cleaning == 1 && !status.udp_active_remotes && status.failed == 1);
    }
    assert(transport.releases == 2 && transport.id == id);
    assert(efrp_work_step(&work, &transport.base, 5, "run", (const uint8_t *)"token", 5, 1) == EFRP_OK);
    assert(!work.streams[0] && transport.id == EFRP_STREAM_NONE && transport.releases == 3);
    if (!datagram) assert(close(server) == 0 && close(peer) == 0);
    assert(open_fds() == baseline && efrp_work_cancel(&work));
}
static void cancellation_retained_stream(void)
{
    efrp_work_set_t work; transport_fixture_t transport;
    efrp_work_stream_t *stream = prepare(&work, &transport, 0);
    close_work(&work, stream, EFRP_PROTOCOL_ERROR);
    assert(efrp_work_step(&work, &transport.base, 3, "run", (const uint8_t *)"token", 5, 1) == EFRP_OK);
    assert(work.streams[0] && transport.releases == 1);
    assert(efrp_work_cancel(&work) && !work.streams[0]);
    assert(transport.releases == 1 && !transport.cancels && transport.id == 0);
    assert(efrp_transport_cancel(&transport.base) == EFRP_OK && transport.cancels == 1);
}
static void native_timeout(void)
{
    efrp_work_set_t work; transport_fixture_t transport;
    efrp_stream_id_t id = UINT64_C(0x100000001);
    efrp_work_stream_t *stream = prepare(&work, &transport, id);
    assert(efrp_work_step(&work, &transport.base, stream->deadline, "run", (const uint8_t *)"token", 5, 1) == EFRP_OK);
    efrp_work_status_t status; efrp_work_status(&work, &status);
    assert(status.last_error == EFRP_TIMEOUT && status.cleaning == 1);
#if defined(EFRP_LAB_TIMEOUT_TRACE)
    assert(status.timeout_stream_id == id && status.timeout_source == EFRP_WORK_TIMEOUT_HANDSHAKE_SEND);
#endif
    assert(efrp_work_cancel(&work));
}
static void peer_visitor_credit(void)
{
    unsigned baseline = open_fds(); efrp_work_set_t work;
    transport_fixture_t transport = {.base = {.operations = &operations},
        .kind = EFRP_TRANSPORT_QUIC, .next_id = UINT64_C(0x100000004), .id = EFRP_STREAM_NONE, .open_blocks = 1};
    assert(efrp_work_peer_init(&work, EFRP_XTCP_VISITOR, NULL, 0) == EFRP_OK);
    efrp_work_stream_t accepted = {0}; int server, peer;
    accepted_local(&accepted, &server, &peer);
    assert(efrp_work_peer_adopt(&work, &accepted.local, 2) == EFRP_OK && !accepted.local);
    assert(efrp_work_peer_step(&work, &transport.base, 3) == EFRP_OK);
    assert(work.streams[0] && work.streams[0]->local && work.streams[0]->stream_id == EFRP_STREAM_NONE);
    assert(work.streams[0]->phase == EFRP_WORK_PEER_OPENING && !transport.writes);
    assert(efrp_work_peer_step(&work, &transport.base, 4) == EFRP_OK);
    assert(work.streams[0]->phase == EFRP_WORK_ACTIVE && work.streams[0]->stream_id == UINT64_C(0x100000004));
    assert(!transport.writes && !work.handshake_json);
    assert(efrp_work_cancel(&work)); assert(close(server) == 0 && close(peer) == 0);
    assert(open_fds() == baseline);
}
static void peer_quota_and_deadline(void)
{
    unsigned baseline = open_fds(); efrp_work_set_t work;
    transport_fixture_t transport = {.base = {.operations = &operations}, .kind = EFRP_TRANSPORT_QUIC,
        .next_id = 4, .id = EFRP_STREAM_NONE, .open_blocks = 10};
    assert(efrp_work_peer_init(&work, EFRP_XTCP_VISITOR, NULL, 0) == EFRP_OK);
    efrp_work_stream_t accepted[3] = {0}; int server[3], peer[3];
    for (unsigned i = 0; i < 3; ++i) {
        accepted_local(&accepted[i], &server[i], &peer[i]);
        efrp_result_t result = efrp_work_peer_adopt(&work, &accepted[i].local, 2);
        assert(result == (i < 2 ? EFRP_OK : EFRP_CAPACITY_EXCEEDED));
        assert((accepted[i].local == NULL) == (i < 2));
    }
    assert(efrp_work_peer_step(&work, &transport.base, 3) == EFRP_OK && !transport.writes);
    efrp_work_status_t status; efrp_work_status(&work, &status); assert(status.active == 2);
    assert(efrp_work_peer_step(&work, &transport.base, 2 + EFRP_SESSION_RESPONSE_MS) == EFRP_OK);
    efrp_work_status(&work, &status); assert(!status.active && status.failed == 2 && status.last_error == EFRP_TIMEOUT);
    assert(!work.streams[0] && !work.streams[1] && !transport.writes);
    assert(efrp_connect_destroy(&accepted[2].local) == EFRP_OK && efrp_work_cancel(&work));
    for (unsigned i = 0; i < 3; ++i) assert(close(server[i]) == 0 && close(peer[i]) == 0);
    assert(open_fds() == baseline);
}
static void peer_reserved_stream(void)
{
    unsigned baseline = open_fds(); efrp_work_set_t work; const uint8_t address[4] = {127, 0, 0, 1};
    transport_fixture_t transport = {.base = {.operations = &operations}, .kind = EFRP_TRANSPORT_QUIC,
        .next_id = 0, .id = EFRP_STREAM_NONE, .accept_ready = true};
    assert(efrp_work_peer_init(&work, EFRP_XTCP_PROVIDER, address, 12345) == EFRP_OK);
    assert(efrp_work_peer_step(&work, &transport.base, 2) == EFRP_OK);
    assert(work.status.failed == 1 && work.status.last_error == EFRP_PROTOCOL_ERROR && !work.streams[0]);
    assert(transport.resets == 1 && transport.releases == 1 && !transport.writes);
    assert(open_fds() == baseline && efrp_work_cancel(&work));
}
int main(void)
{
    delayed_release(0, false); delayed_release(UINT64_C(0x100000001), false);
    delayed_release(0, true); delayed_release(UINT64_C(0x100000001), true);
    cancellation_retained_stream(); native_timeout(); peer_visitor_credit(); peer_quota_and_deadline(); peer_reserved_stream();
    puts("Work stream boundary: native 0/64-bit IDs, delayed release, immediate fd/payload cleanup and cancellation passed");
    return 0;
}
