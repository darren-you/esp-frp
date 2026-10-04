// SPDX-License-Identifier: Apache-2.0
/* Real owned transport factory/stream API, never direct ngtcp2 test calls. */
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_transport.h"
#include "stream_internal.h"
#include "quic_dns_fixture.h"
#include "quic_socket_fixture.h"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#define LONG_BYTES 257031u
static uint64_t milliseconds(void)
{ struct timespec at; assert(!clock_gettime(CLOCK_MONOTONIC, &at)); return (uint64_t)at.tv_sec * 1000 + (uint64_t)at.tv_nsec / 1000000; }
static bool trusted(void *context) { return *(bool *)context; }
static bool acceptable(efrp_result_t result) { return result == EFRP_OK || result == EFRP_WOULD_BLOCK; }
static void pause_loop(void) { struct timespec pause = {.tv_nsec = 1000000}; (void)nanosleep(&pause, NULL); }
static void cancel_pending(const efrp_quic_config_t *config)
{
    quic_fixture_dns_pending(true); efrp_transport_t *transport = NULL;
    assert(efrp_transport_quic_create(config, milliseconds(), &transport) == EFRP_OK);
    assert(quic_fixture_dns_active() == 1);
    assert(efrp_transport_cancel(transport) == EFRP_WOULD_BLOCK);
    efrp_transport_status_t status;
    assert(efrp_transport_status(transport, &status) == EFRP_OK);
    assert(status.kind == EFRP_TRANSPORT_QUIC && status.state == EFRP_TRANSPORT_DRAINING && status.pending_dns && !status.owns_socket);
    assert(efrp_transport_destroy(&transport) == EFRP_WOULD_BLOCK && transport);
    quic_fixture_dns_complete();
    assert(efrp_transport_destroy(&transport) == EFRP_OK && !transport);
    assert(!quic_fixture_dns_active()); quic_fixture_dns_pending(false);
}
int main(int argc, char **argv)
{
    assert(argc == 5); unsigned long port = strtoul(argv[1], NULL, 10); assert(port > 0 && port <= 65535);
    FILE *file = fopen(argv[2], "rb"); assert(file); uint8_t ca[EFRP_TLS_MAX_CA_BYTES];
    size_t ca_length = fread(ca, 1, sizeof ca, file); assert(ca_length && feof(file)); assert(!fclose(file));
    bool time_trusted = strcmp(argv[4], "untrusted-time") != 0;
    efrp_quic_config_t config = {.hostname = argv[3], .port = (uint16_t)port, .ca_pem = ca, .ca_length = ca_length,
        .profile = EFRP_QUIC_PROFILE_P256_AES128_X25519, .time_is_trusted = trusted, .context = &time_trusted};
    bool late_stop = !strcmp(argv[4], "late-stop-zero");
    bool reset_mode = !strcmp(argv[4], "reset") || !strcmp(argv[4], "late-stop-error") || !strcmp(argv[4], "late-stop-no-fin");
    bool oversized = !strcmp(argv[4], "oversized");
    bool cancel_mode = !strncmp(argv[4], "cancel-", 7);
    bool success = !strcmp(argv[4], "ok") || !strcmp(argv[4], "long") || !strcmp(argv[4], "loss-reorder") || reset_mode || late_stop || cancel_mode;
    if (success) cancel_pending(&config);
    efrp_transport_t *transport = NULL;
    efrp_result_t result = efrp_transport_quic_create(&config, milliseconds(), &transport);
    efrp_transport_status_t status = {.verify_flags = UINT32_MAX};
    efrp_stream_id_t streams[2] = {EFRP_STREAM_NONE, EFRP_STREAM_NONE};
    size_t sent[2] = {0}, received[2] = {0}; bool closed[2] = {false}, fin[2] = {false}, released[2] = {false};
    bool handshake = false, reset_received = false, cancel_drained = false; unsigned blocked = 0; uint64_t until = milliseconds() + 11000;
    const size_t total = !strcmp(argv[4], "long") || !strcmp(argv[4], "loss-reorder") ? LONG_BYTES : 4096u;
    while (transport && acceptable(result) && milliseconds() < until) {
        result = efrp_transport_step(transport, milliseconds());
        assert(efrp_transport_status(transport, &status) == EFRP_OK && status.kind == EFRP_TRANSPORT_QUIC);
        if (!acceptable(result)) break;
        if (status.state == EFRP_TRANSPORT_OPEN) {
            handshake = true; assert(status.verify_flags == 0 && !status.pending_dns && status.owns_socket);
            if (cancel_mode) {
                efrp_stream_id_t id; assert(efrp_stream_open(transport, &id) == EFRP_OK && id == 0);
                uint8_t business[2048]; memset(business, 0x5a, sizeof business); size_t used;
                assert(efrp_stream_write(transport, id, business, sizeof business, &used) == EFRP_OK && used == sizeof business);
                quic_fixture_send_mode(QUIC_FIXTURE_SEND_BLOCK);
                uint64_t at = milliseconds();
                for (unsigned attempt = 0; attempt < 20 && !quic_fixture_send_attempts(); ++attempt) {
                    at = milliseconds(); assert(acceptable(efrp_transport_step(transport, at))); pause_loop();
                }
                assert(quic_fixture_send_attempts()); /* A real encrypted STREAM packet was retained. */
                assert(efrp_transport_cancel(transport) == EFRP_WOULD_BLOCK);
                assert(efrp_transport_status(transport, &status) == EFRP_OK);
                uint64_t deadline = status.next_deadline_ms;
                assert(status.state == EFRP_TRANSPORT_DRAINING && status.owns_socket && deadline == at + 5000);
                assert(efrp_stream_read(transport, id, business, 1, &used) == EFRP_CANCELLED && !used);
                assert(efrp_stream_write(transport, id, business, 1, &used) == EFRP_CANCELLED && !used);
                assert(efrp_transport_destroy(&transport) == EFRP_WOULD_BLOCK && transport);
                assert(efrp_transport_step(transport, at + 1) == EFRP_WOULD_BLOCK);
                assert(efrp_transport_status(transport, &status) == EFRP_OK && status.next_deadline_ms == deadline);
                if (!strcmp(argv[4], "cancel-eagain")) quic_fixture_send_mode(QUIC_FIXTURE_SEND_NORMAL);
                else if (!strcmp(argv[4], "cancel-fail")) quic_fixture_send_mode(QUIC_FIXTURE_SEND_FAIL);
                result = efrp_transport_step(transport, !strcmp(argv[4], "cancel-timeout") ? deadline : at + 2);
                assert(result == EFRP_CANCELLED);
                assert(efrp_transport_status(transport, &status) == EFRP_OK);
                assert(status.state == EFRP_TRANSPORT_CLOSED && !status.owns_socket && !status.pending_tx_bytes && !status.pending_dns);
                if (!strcmp(argv[4], "cancel-fail")) assert(status.system_error == EIO);
                if (!strcmp(argv[4], "cancel-timeout")) assert(status.system_error == EAGAIN);
                quic_fixture_send_mode(QUIC_FIXTURE_SEND_NORMAL); cancel_drained = true; break;
            }
            if (oversized) { pause_loop(); continue; }
            if (reset_mode) {
                if (streams[0] == EFRP_STREAM_NONE) {
                    assert(efrp_stream_open(transport, &streams[0]) == EFRP_OK && streams[0] == 0);
                    uint8_t bytes[512] = {0}; size_t used;
                    assert(efrp_stream_write(transport, streams[0], bytes, sizeof bytes, &used) == EFRP_OK && used == sizeof bytes);
                    assert(efrp_stream_release(transport, streams[0]) == EFRP_INVALID_STATE);
                }
                uint8_t byte; size_t used;
                result = efrp_stream_read(transport, streams[0], &byte, 1, &used);
                if (result == EFRP_STREAM_RESET) {
                    assert(!used); reset_received = true;
                    assert(efrp_stream_write(transport, streams[0], &byte, 1, &used) == EFRP_STREAM_RESET && !used);
                    result = efrp_stream_release(transport, streams[0]); assert(acceptable(result));
                    if (result == EFRP_OK) { released[0] = true; break; }
                } else if (result == EFRP_OK) assert(used);
                else assert((result == EFRP_WOULD_BLOCK || result == EFRP_EOF) && !used);
                result = EFRP_OK; pause_loop(); continue;
            }
            for (unsigned slot = 0; slot < 2; ++slot) {
                if (streams[slot] == EFRP_STREAM_NONE) {
                    result = efrp_stream_open(transport, &streams[slot]); assert(acceptable(result));
                    if (streams[slot] == EFRP_STREAM_NONE) continue;
                    assert(streams[slot] == (uint64_t)slot * 4); /* Native stream 0 remains valid. */
                    assert(efrp_stream_release(transport, streams[slot]) == EFRP_INVALID_STATE);
                }
                if (released[slot]) continue;
                uint8_t bytes[713];
                if (sent[slot] < total) {
                    size_t count = total - sent[slot]; if (count > sizeof bytes) count = sizeof bytes;
                    for (size_t i = 0; i < count; ++i) bytes[i] = (uint8_t)((sent[slot] + i) * 31 + slot * 7);
                    size_t used = 999; result = efrp_stream_write(transport, streams[slot], bytes, count, &used);
                    assert(acceptable(result)); if (result == EFRP_WOULD_BLOCK) { assert(!used); ++blocked; }
                    else { assert(used && used <= count); sent[slot] += used; }
                    memset(bytes, 0xa5, sizeof bytes); /* Accepted caller bytes can be overwritten immediately. */
                }
                if (sent[slot] == total && !closed[slot] && !late_stop) {
                    assert(efrp_stream_close_write(transport, streams[slot]) == EFRP_OK);
                    assert(efrp_stream_close_write(transport, streams[slot]) == EFRP_OK); closed[slot] = true;
                }
                size_t used = 999; result = efrp_stream_read(transport, streams[slot], bytes, sizeof bytes, &used);
                assert(acceptable(result) || result == EFRP_EOF);
                if (result == EFRP_EOF) { assert(!used && received[slot] == total); fin[slot] = true; }
                else if (result == EFRP_OK) {
                    assert(used && received[slot] + used <= total);
                    for (size_t i = 0; i < used; ++i) assert(bytes[i] == (uint8_t)((received[slot] + i) * 31 + slot * 7));
                    received[slot] += used;
                } else assert(!used);
                if (late_stop && fin[slot] && !closed[slot]) {
                    /* The peer closed receive before the application observed
                       local EOF. Additional payload stays a real failure. */
                    assert(efrp_stream_write(transport, streams[slot], bytes, 1, &used) == EFRP_INVALID_STATE && !used);
                    assert(efrp_stream_release(transport, streams[slot]) == EFRP_INVALID_STATE);
                    assert(efrp_stream_close_write(transport, streams[slot]) == EFRP_OK); closed[slot] = true;
                }
                efrp_stream_info_t info; assert(efrp_stream_info(transport, streams[slot], &info) == EFRP_OK);
                assert(info.readable_bytes <= 1024 && info.pending_bytes <= 2048);
                if (fin[slot]) {
                    result = efrp_stream_release(transport, streams[slot]); assert(acceptable(result));
                    released[slot] = result == EFRP_OK;
                }
            }
            result = EFRP_OK;
            if (released[0] && released[1]) break;
        }
        pause_loop();
    }
    if (cancel_mode) assert(handshake && cancel_drained);
    else if (reset_mode) assert(handshake && reset_received && released[0]);
    else if (success) assert(handshake && released[0] && released[1] && (!strcmp(argv[4], "ok") || late_stop || blocked));
    else if (oversized) assert(handshake && result == EFRP_PROTOCOL_ERROR);
    else assert(!handshake && !acceptable(result));
    fprintf(stderr, "transport result=%d tls_error=%d verify_flags=%u handshake=%u dual_fin=%u bytes=%zu blocked=%u reset_released=%u cancel_drained=%u\n",
        result, status.tls_error, status.verify_flags, handshake ? 1u : 0u, released[0] && released[1] ? 1u : 0u, received[0] + received[1], blocked,
        reset_received && released[0] ? 1u : 0u, cancel_drained ? 1u : 0u);
    while (transport && efrp_transport_destroy(&transport) == EFRP_WOULD_BLOCK) pause_loop();
    assert(!transport && !quic_fixture_dns_active()); return success ? 0 : 10;
}
