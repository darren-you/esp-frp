// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp_quic_peer.h"
#include "stream_internal.h"
#include "psa/crypto.h"
#include "mbedtls/x509_crt.h"
#undef NDEBUG
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define BODY_BYTES 35017u
static uint64_t milliseconds(void)
{ struct timespec now; assert(!clock_gettime(CLOCK_MONOTONIC, &now)); return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000; }
static bool trusted(void *context) { (void)context; return true; }
static void pause_loop(void) { struct timespec delay = {.tv_nsec = 1000000}; (void)nanosleep(&delay, NULL); }
static bool acceptable(efrp_result_t result) { return result == EFRP_OK || result == EFRP_WOULD_BLOCK; }
int main(int argc, char **argv)
{
    assert(argc == 7); efrp_xtcp_role_t role = !strcmp(argv[1], "provider") ? EFRP_XTCP_PROVIDER : EFRP_XTCP_VISITOR;
    bool server = role == EFRP_XTCP_PROVIDER, success = !strcmp(argv[2], "ok");
    unsigned long local_port = strtoul(argv[3], NULL, 10), remote_port = strtoul(argv[4], NULL, 10);
    assert(local_port && local_port <= 65535 && remote_port && remote_port <= 65535);
    uint8_t peer_der[8192]; FILE *file = fopen(argv[5], "rb"); assert(file);
    size_t peer_length = fread(peer_der, 1, sizeof peer_der, file); assert(peer_length && feof(file)); assert(!fclose(file));
    assert(psa_crypto_init() == PSA_SUCCESS);
    mbedtls_x509_crt peer_certificate; mbedtls_x509_crt_init(&peer_certificate);
    assert(!mbedtls_x509_crt_parse_der(&peer_certificate, peer_der, peer_length));
    efrp_quic_peer_config_t config = {.role = role, .profile = EFRP_QUIC_PROFILE_P256_AES128_X25519,
        .local = {{127, 0, 0, 1}, (uint16_t)local_port}, .remote = {{127, 0, 0, 1}, (uint16_t)remote_port},
        .manifest_sha256 = {1}, .time_is_trusted = trusted};
    assert(efrp_quic_peer_identity_create(role, trusted, NULL, &config.identity) == EFRP_OK);
    const uint8_t *own_der; size_t own_length; uint8_t own_pin[32];
    assert(efrp_quic_peer_identity_certificate(config.identity, &own_der, &own_length, own_pin) == EFRP_OK);
    file = fopen(argv[6], "wb"); assert(file && fwrite(own_der, 1, own_length, file) == own_length); assert(!fclose(file));
    size_t hash_length = 0;
    assert(psa_hash_compute(PSA_ALG_SHA_256, peer_certificate.pk_raw.p, peer_certificate.pk_raw.len,
                            config.peer_spki_sha256, 32, &hash_length) == PSA_SUCCESS && hash_length == 32);
    mbedtls_x509_crt_free(&peer_certificate);
    if (!strcmp(argv[2], "wrong-pin")) config.peer_spki_sha256[0] ^= 1;
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); assert(socket_fd >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(config.local.port), .sin_addr.s_addr = htonl(UINT32_C(0x7f000001))};
    assert(!bind(socket_fd, (struct sockaddr *)&local, sizeof local)); assert(getchar() == 'G');
    efrp_transport_t *transport = NULL; int owned_fd = socket_fd; uint64_t created_at = milliseconds();
    efrp_result_t result = efrp_transport_quic_peer_create(&config, &socket_fd, created_at, &transport);
    assert(result == EFRP_OK && socket_fd == -1 && transport);
    efrp_stream_id_t streams[3] = {EFRP_STREAM_NONE, EFRP_STREAM_NONE, EFRP_STREAM_NONE};
    size_t sent[3] = {0}, received[3] = {0}; bool fin[3] = {false}, closed[3] = {false}, released[3] = {false};
    uint8_t exporter[32], expected[32]; bool handshake = false, bound = false; unsigned business = 0;
    efrp_transport_status_t status = {0}; uint64_t until = milliseconds() + 10000;
    if (!strcmp(argv[2], "delayed-initial")) {
        assert(server);
        uint8_t first; ssize_t peeked;
        while ((peeked = recv(owned_fd, &first, 1, MSG_PEEK)) < 0 && milliseconds() < until) pause_loop();
        assert(peeked == 1);
        /* Real Go Initial arrives, but the caller clock is already 9.5s into
         * this attempt. Starting ngtcp2 must preserve the factory deadline. */
        result = efrp_transport_step(transport, created_at + 9500);
        assert(acceptable(result)); assert(efrp_transport_status(transport, &status) == EFRP_OK);
        assert(status.state == EFRP_TRANSPORT_HANDSHAKING && status.next_deadline_ms <= created_at + 10000);
        result = efrp_transport_step(transport, created_at + 10000); assert(result == EFRP_TIMEOUT);
        goto finished;
    }
    while (acceptable(result) && milliseconds() < until) {
        result = efrp_transport_step(transport, milliseconds());
        assert(efrp_transport_status(transport, &status) == EFRP_OK);
        if (!acceptable(result)) break;
        if (status.state != EFRP_TRANSPORT_OPEN) { pause_loop(); continue; }
        if (!handshake) {
            handshake = true; assert(!status.verify_flags);
            assert(efrp_quic_peer_exporter(transport, exporter) == EFRP_OK);
            assert(psa_hash_compute(PSA_ALG_SHA_256, exporter, sizeof exporter, expected, sizeof expected, &hash_length) == PSA_SUCCESS && hash_length == 32);
            memset(exporter, 0, sizeof exporter);
        }
        for (unsigned slot = 0; slot < 3; ++slot) {
            if (slot && !bound) continue;
            if (released[slot]) continue;
            if (streams[slot] == EFRP_STREAM_NONE) {
                result = server ? efrp_stream_accept(transport, &streams[slot]) : efrp_stream_open(transport, &streams[slot]);
                assert(acceptable(result)); if (result == EFRP_WOULD_BLOCK) continue;
                assert(streams[slot] == (uint64_t)slot * 4); if (slot) ++business;
            }
            const size_t total = slot ? BODY_BYTES : 32;
            uint8_t bytes[617]; size_t used = 0;
            if (!server || received[slot] > sent[slot]) {
                size_t count = server ? received[slot] - sent[slot] : total - sent[slot];
                if (count > sizeof bytes) count = sizeof bytes;
                if (count) {
                    for (size_t i = 0; i < count; ++i) bytes[i] = slot ? (uint8_t)((sent[slot] + i) * 23 + slot * 11) : expected[sent[slot] + i];
                    result = efrp_stream_write(transport, streams[slot], bytes, count, &used); assert(acceptable(result)); sent[slot] += used;
                    memset(bytes, 0xff, sizeof bytes);
                }
            }
            if (sent[slot] == total && !closed[slot]) { assert(efrp_stream_close_write(transport, streams[slot]) == EFRP_OK); closed[slot] = true; }
            result = efrp_stream_read(transport, streams[slot], bytes, sizeof bytes, &used);
            if (result == EFRP_OK) {
                assert(used && received[slot] + used <= total);
                for (size_t i = 0; i < used; ++i) {
                    uint8_t value = slot ? (uint8_t)((received[slot] + i) * 23 + slot * 11) : expected[received[slot] + i];
                    if (bytes[i] != value) { result = EFRP_AUTHENTICATION_FAILED; goto finished; }
                }
                received[slot] += used;
            } else if (result == EFRP_EOF) { assert(received[slot] == total && !used); fin[slot] = true; }
            else assert(result == EFRP_WOULD_BLOCK && !used);
            if (fin[slot] && closed[slot]) {
                result = efrp_stream_release(transport, streams[slot]); assert(acceptable(result)); released[slot] = result == EFRP_OK;
                if (!slot && released[slot]) bound = true;
            }
        }
        result = EFRP_OK; if (released[1] && released[2]) break; pause_loop();
    }
finished:
    if (success) assert(handshake && bound && business == 2 && released[1] && released[2]);
    else assert(!bound && !business && !acceptable(result));
    fprintf(stderr, "candidate role=%u mode=%s result=%d tls=%d handshake=%u bound=%u business=%u bytes=%zu\n",
        (unsigned)role, argv[2], result, status.tls_error, handshake ? 1u : 0u, bound ? 1u : 0u, business, received[1] + received[2]);
    while (efrp_transport_destroy(&transport) == EFRP_WOULD_BLOCK) { (void)efrp_transport_step(transport, milliseconds()); pause_loop(); }
    assert(!transport); efrp_quic_peer_identity_destroy(&config.identity); return success ? 0 : 10;
}
