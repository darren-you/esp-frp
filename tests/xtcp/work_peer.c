// SPDX-License-Identifier: Apache-2.0
/* Direct data-plane fixture. Canonical manifest comes from the fixture file;
 * full authenticated FRPS signaling is tested by the candidate integration. */
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_quic_peer.h"
#include "stream_internal.h"
#include "work_internal.h"
#include "tcp_listener.h"
#undef NDEBUG
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define BODY_BYTES UINT64_C(300001)
static uint64_t milliseconds(void)
{ struct timespec now; assert(!clock_gettime(CLOCK_MONOTONIC, &now)); return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000; }
static bool trusted(void *context) { (void)context; return true; }
static void pause_loop(void) { struct timespec delay = {.tv_nsec = 1000000}; (void)nanosleep(&delay, NULL); }
static bool acceptable(efrp_result_t result) { return result == EFRP_OK || result == EFRP_WOULD_BLOCK; }
static uint16_t port(const char *text)
{ unsigned long value = strtoul(text, NULL, 10); assert(value && value <= 65535); return (uint16_t)value; }
static void destroy_local(efrp_connect_t **local)
{ while (efrp_connect_destroy(local) == EFRP_WOULD_BLOCK) pause_loop(); assert(!*local); }
static efrp_result_t exchange(efrp_transport_t *transport, efrp_xtcp_role_t role,
    const efrp_xtcp_binding_manifest_t *manifest, uint64_t deadline)
{
    efrp_stream_id_t stream = EFRP_STREAM_NONE;
    uint8_t exporter[32], own[EFRP_XTCP_BINDING_PROOF_BYTES], peer[EFRP_XTCP_BINDING_PROOF_BYTES + 1];
    size_t sent = 0, received = 0; bool verified = false, eof = false, fin = false;
    efrp_result_t result = efrp_quic_peer_exporter(transport, exporter); if (result != EFRP_OK) return result;
    result = efrp_xtcp_binding_make_proof(manifest, role, exporter, own); assert(result == EFRP_OK);
    while (milliseconds() < deadline) {
        result = efrp_transport_step(transport, milliseconds()); if (!acceptable(result)) break;
        if (stream == EFRP_STREAM_NONE) {
            result = role == EFRP_XTCP_PROVIDER ? efrp_stream_accept(transport, &stream) : efrp_stream_open(transport, &stream);
            if (result == EFRP_WOULD_BLOCK) { pause_loop(); continue; }
            if (result != EFRP_OK) break;
            if (stream != 0) { result = EFRP_PROTOCOL_ERROR; break; }
        }
        /* Visitor sends first. Provider sends only after exact opposite-role
         * proof plus real FIN, matching maintained ExchangeProof. */
        if (role == EFRP_XTCP_VISITOR || verified) {
            size_t used = 0;
            if (sent < sizeof own) {
                result = efrp_stream_write(transport, stream, own + sent, sizeof own - sent, &used);
                if (!acceptable(result)) break;
                sent += used;
            }
            if (sent == sizeof own && !fin) { result = efrp_stream_close_write(transport, stream); if (result != EFRP_OK) break; fin = true; }
        }
        if (!eof) {
            size_t used = 0;
            result = efrp_stream_read(transport, stream, peer + received, sizeof peer - received, &used);
            if (result == EFRP_OK) {
                received += used;
                if (received > EFRP_XTCP_BINDING_PROOF_BYTES) { result = EFRP_PROTOCOL_ERROR; break; }
            } else if (result == EFRP_EOF) {
                eof = true;
                result = efrp_xtcp_binding_verify_proof(manifest,
                    role == EFRP_XTCP_PROVIDER ? EFRP_XTCP_VISITOR : EFRP_XTCP_PROVIDER,
                    exporter, peer, received);
                if (result != EFRP_OK) break;
                verified = true;
            } else if (result != EFRP_WOULD_BLOCK) break;
        }
        if (verified && fin) {
            result = efrp_stream_release(transport, stream);
            if (result == EFRP_OK) break;
            if (result != EFRP_WOULD_BLOCK) break;
        }
        pause_loop();
    }
    memset(exporter, 0, sizeof exporter); memset(own, 0, sizeof own); memset(peer, 0, sizeof peer);
    if (acceptable(result) && (!verified || !fin || result != EFRP_OK)) return EFRP_TIMEOUT;
    return result;
}
int main(int argc, char **argv)
{
    assert(argc == 9);
    efrp_xtcp_role_t role = !strcmp(argv[1], "provider") ? EFRP_XTCP_PROVIDER : EFRP_XTCP_VISITOR;
    bool credit_case = !strcmp(argv[2], "credit-block");
    bool success = !strcmp(argv[2], "ok") || credit_case, bound = false, retained_credit = false;
    const uint8_t address[4] = {127, 0, 0, 1};
    efrp_quic_peer_config_t config = {.role = role, .profile = EFRP_QUIC_PROFILE_P256_AES128_X25519,
        .local = {{127, 0, 0, 1}, port(argv[3])}, .remote = {{127, 0, 0, 1}, port(argv[4])}, .time_is_trusted = trusted};
    assert(efrp_quic_peer_identity_create(role, trusted, NULL, &config.identity) == EFRP_OK);
    const uint8_t *own_der; size_t own_length; uint8_t own_pin[32];
    assert(efrp_quic_peer_identity_certificate(config.identity, &own_der, &own_length, own_pin) == EFRP_OK);
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); assert(socket_fd >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(config.local.port), .sin_addr.s_addr = htonl(UINT32_C(0x7f000001))};
    assert(!bind(socket_fd, (struct sockaddr *)&local, sizeof local));
    efrp_tcp_listener_t *listener = NULL;
    if (role == EFRP_XTCP_VISITOR) assert(efrp_tcp_listener_create(address, port(argv[7]), &listener) == EFRP_OK);
    FILE *file = fopen(argv[5], "wb"); assert(file && fwrite(own_der, 1, own_length, file) == own_length); assert(!fclose(file));
    efrp_connect_t *accepted[3] = {NULL, NULL, NULL};
    if (listener) {
        for (unsigned i = 0; i < (credit_case ? 3u : 2u); ++i) {
            uint64_t until = milliseconds() + 3000; efrp_result_t r = EFRP_WOULD_BLOCK;
            while (r == EFRP_WOULD_BLOCK && milliseconds() < until) { r = efrp_tcp_listener_accept(listener, milliseconds(), &accepted[i]); pause_loop(); }
            if (r != EFRP_OK) fprintf(stderr, "fixture accept slot=%u result=%d\n", i, r);
            assert(r == EFRP_OK && accepted[i]);
            if (credit_case && i == 1) {
                char marker[1024]; assert(strlen(argv[5]) + sizeof ".accepted" < sizeof marker);
                assert(snprintf(marker, sizeof marker, "%s.accepted", argv[5]) > 0);
                FILE *ready = fopen(marker, "wb"); assert(ready && !fclose(ready));
            }
        }
    }
    assert(getchar() == 'G');
    uint8_t wire[EFRP_XTCP_BINDING_MANIFEST_MAX_BYTES]; file = fopen(argv[6], "rb"); assert(file);
    size_t length = fread(wire, 1, sizeof wire, file); assert(length && feof(file)); assert(!fclose(file));
    efrp_xtcp_binding_manifest_t manifest;
    assert(efrp_xtcp_binding_decode(wire, length, (uint64_t)time(NULL), &manifest) == EFRP_OK);
    uint8_t control[32], nonce[32]; memset(control, (int)role + 10, sizeof control); memset(nonce, (int)role + 20, sizeof nonce);
    assert(efrp_xtcp_binding_check_local(&manifest, role, control, nonce, own_pin) == EFRP_OK);
    memcpy(config.peer_spki_sha256, role == EFRP_XTCP_PROVIDER ? manifest.visitor_spki_sha256 : manifest.provider_spki_sha256, 32);
    assert(efrp_xtcp_binding_hash(&manifest, config.manifest_sha256) == EFRP_OK);
    efrp_transport_t *transport = NULL; uint64_t deadline = milliseconds() + 10000;
    efrp_result_t result = efrp_transport_quic_peer_create(&config, &socket_fd, milliseconds(), &transport);
    assert(result == EFRP_OK && transport && socket_fd == -1);
    efrp_transport_status_t status = {0};
    while (milliseconds() < deadline) {
        result = efrp_transport_step(transport, milliseconds());
        assert(efrp_transport_status(transport, &status) == EFRP_OK);
        if (!acceptable(result) || status.state == EFRP_TRANSPORT_OPEN) break;
        pause_loop();
    }
    if (status.state == EFRP_TRANSPORT_OPEN) result = exchange(transport, role, &manifest, deadline);
    efrp_work_set_t work; memset(&work, 0, sizeof work);
    if (result == EFRP_OK) {
        bound = true;
        assert(efrp_work_peer_init(&work, role, address, port(argv[8])) == EFRP_OK);
        for (unsigned i = 0; i < 2 && role == EFRP_XTCP_VISITOR; ++i) {
            assert(efrp_work_peer_adopt(&work, &accepted[i], milliseconds()) == EFRP_OK && !accepted[i]);
        }
        if (credit_case) {
            efrp_connect_t *retained = accepted[2];
            assert(retained && efrp_work_peer_adopt(&work, &accepted[2], milliseconds()) == EFRP_CAPACITY_EXCEEDED);
            assert(accepted[2] == retained); destroy_local(&accepted[2]);
        }
        uint64_t until = milliseconds() + 15000;
        while (milliseconds() < until) {
            result = efrp_transport_step(transport, milliseconds()); if (!acceptable(result)) break;
            result = efrp_work_peer_step(&work, transport, milliseconds()); if (!acceptable(result)) break;
            if (credit_case && work.streams[0] && work.streams[0]->phase == EFRP_WORK_ACTIVE &&
                work.streams[1] && work.streams[1]->phase == EFRP_WORK_PEER_OPENING) {
                assert(work.streams[1]->local && work.streams[1]->stream_id == EFRP_STREAM_NONE);
                retained_credit = true;
            }
            efrp_work_status_t current; efrp_work_status(&work, &current);
            if (current.completed == 2 || current.failed) break;
            pause_loop();
        }
    }
    efrp_work_status_t final; efrp_work_status(&work, &final);
    fprintf(stderr, "xtcp work role=%u mode=%s result=%d bound=%u requests=%llu completed=%llu failed=%llu active=%u bytes=%llu/%llu\n",
        (unsigned)role, argv[2], result, bound ? 1u : 0u, (unsigned long long)final.requests,
        (unsigned long long)final.completed, (unsigned long long)final.failed, final.active,
        (unsigned long long)final.local_received, (unsigned long long)final.local_sent);
    if (success) {
        assert(bound && final.requests == 2 && final.completed == 2 && !final.failed && !final.active &&
            final.local_received == 2 * BODY_BYTES && final.local_sent == 2 * BODY_BYTES);
        if (credit_case) assert(retained_credit);
    }
    else assert(!bound && !final.requests && !final.local_received && !final.local_sent && !acceptable(result));
    while (!efrp_work_cancel(&work)) pause_loop();
    for (unsigned i = 0; i < 3; ++i) destroy_local(&accepted[i]);
    while (efrp_tcp_listener_destroy(&listener) == EFRP_WOULD_BLOCK) pause_loop();
    while (efrp_transport_destroy(&transport) == EFRP_WOULD_BLOCK) { (void)efrp_transport_step(transport, milliseconds()); pause_loop(); }
    efrp_quic_peer_identity_destroy(&config.identity); return success ? 0 : 10;
}
