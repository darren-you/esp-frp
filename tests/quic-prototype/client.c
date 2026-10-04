// SPDX-License-Identifier: Apache-2.0
#include "quic_certificate.h"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <picotls/minicrypto.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STREAM_BYTES 4096u
#define STREAM_CAPACITY 16384u
#define STREAM_COUNT 3u
typedef struct {
    int64_t id;
    uint8_t bytes[STREAM_CAPACITY];
    size_t length, sent, received;
    bool fin_received, fin_requested, fin_sent;
} stream_t;
typedef struct {
    ngtcp2_crypto_conn_ref reference;
    ngtcp2_conn *connection;
    ngtcp2_crypto_picotls_ctx tls;
    ptls_context_t context;
    ptls_raw_extension_t extensions[2];
    efrp_quic_certificate_t certificate;
    struct sockaddr_in local, remote;
    stream_t streams[STREAM_COUNT];
    uint8_t command[4102];
    size_t command_length;
    int socket;
    bool handshake_complete, trusted_time, bridge, bridge_done;
} client_t;

static int bridge_event(uint8_t type, uint8_t slot, const uint8_t *bytes, size_t length)
{
    if (length > UINT16_MAX) return -1;
    uint8_t header[4] = {type, slot, (uint8_t)(length >> 8), (uint8_t)length};
    return fwrite(header, 1, sizeof header, stdout) == sizeof header &&
        (!length || fwrite(bytes, 1, length, stdout) == length) && fflush(stdout) == 0 ? 0 : -1;
}

static uint64_t timestamp(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
    return (uint64_t)now.tv_sec * NGTCP2_SECONDS + (uint64_t)now.tv_nsec;
}
static bool trusted_time(void *context) { return ((client_t *)context)->trusted_time; }
static ngtcp2_conn *get_connection(ngtcp2_crypto_conn_ref *reference)
{
    return ((client_t *)reference->user_data)->connection;
}
static void random_bytes(uint8_t *output, size_t length, const ngtcp2_rand_ctx *context)
{
    (void)context; ptls_minicrypto_random_bytes(output, length);
}
static int new_connection_id(ngtcp2_conn *connection, ngtcp2_cid *id,
                              ngtcp2_stateless_reset_token *token, size_t length, void *context)
{
    (void)connection; (void)context;
    id->datalen = length; ptls_minicrypto_random_bytes(id->data, length);
    ptls_minicrypto_random_bytes(token->data, sizeof token->data);
    return 0;
}
static int handshake_completed(ngtcp2_conn *connection, void *context)
{
    (void)connection;
    client_t *client = context;
    const char *protocol = ptls_get_negotiated_protocol(client->tls.ptls);
    if (!protocol || strcmp(protocol, "frp") || client->certificate.chain_checks != 1 ||
        client->certificate.signature_checks != 1 || !client->trusted_time)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    client->handshake_complete = true;
    if (client->bridge && bridge_event('H', 0, NULL, 0)) return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}
static int received_stream(ngtcp2_conn *connection, uint32_t flags, int64_t id, uint64_t offset,
                            const uint8_t *bytes, size_t length, void *context, void *stream_context)
{
    (void)stream_context;
    client_t *client = context;
    stream_t *stream = NULL;
    unsigned slot;
    for (slot = 0; slot < STREAM_COUNT; ++slot) if (client->streams[slot].id == id) { stream = &client->streams[slot]; break; }
    if (!stream || offset != stream->received) return NGTCP2_ERR_CALLBACK_FAILURE;
    if (client->bridge) {
        if (bridge_event('D', (uint8_t)slot, bytes, length)) return NGTCP2_ERR_CALLBACK_FAILURE;
    } else if (length > STREAM_BYTES - stream->received ||
               memcmp(bytes, stream->bytes + stream->received, length)) return NGTCP2_ERR_CALLBACK_FAILURE;
    stream->received += length;
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        if (!client->bridge && stream->received != STREAM_BYTES) return NGTCP2_ERR_CALLBACK_FAILURE;
        stream->fin_received = true;
        if (client->bridge && bridge_event('F', (uint8_t)slot, NULL, 0)) return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ngtcp2_conn_extend_max_stream_offset(connection, id, length);
    ngtcp2_conn_extend_max_offset(connection, length);
    return 0;
}
static int initialize(client_t *client, unsigned port, const uint8_t *ca, size_t ca_length, const char *hostname)
{
    client->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client->socket < 0) return -1;
    client->remote = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    client->remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t local_length = sizeof client->local;
    if (connect(client->socket, (struct sockaddr *)&client->remote, sizeof client->remote) ||
        getsockname(client->socket, (struct sockaddr *)&client->local, &local_length) ||
        fcntl(client->socket, F_SETFL, O_NONBLOCK)) return -1;
    if (efrp_quic_certificate_init(&client->certificate, ca, ca_length, trusted_time, client)) return -1;
    static ptls_cipher_suite_t *cipher_suites[] = {&ptls_minicrypto_aes128gcmsha256, NULL};
    static ptls_key_exchange_algorithm_t *key_exchanges[] = {&ptls_minicrypto_x25519, NULL};
    client->context = (ptls_context_t){.random_bytes = ptls_minicrypto_random_bytes,
        .get_time = &ptls_get_time, .cipher_suites = cipher_suites, .key_exchanges = key_exchanges,
        .verify_certificate = &client->certificate.certificate, .max_buffer_size = 16384};
    if (ngtcp2_crypto_picotls_configure_client_context(&client->context)) return -1;
    ngtcp2_crypto_picotls_ctx_init(&client->tls);
    client->tls.ptls = ptls_new(&client->context, 0);
    if (!client->tls.ptls || ptls_set_server_name(client->tls.ptls, hostname, 0)) return -1;
    client->reference = (ngtcp2_crypto_conn_ref){.get_conn = get_connection, .user_data = client};
    *ptls_get_data_ptr(client->tls.ptls) = &client->reference;
    static const ptls_iovec_t protocols[] = {{(uint8_t *)"frp", 3}};
    client->tls.handshake_properties.client.negotiated_protocols.list = protocols;
    client->tls.handshake_properties.client.negotiated_protocols.count = 1;
    client->extensions[0].type = client->extensions[1].type = UINT16_MAX;
    client->tls.handshake_properties.additional_extensions = client->extensions;
    ngtcp2_callbacks callbacks = {.client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb, .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb, .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .rand = random_bytes, .get_new_connection_id2 = new_connection_id,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
        .handshake_completed = handshake_completed, .recv_stream_data = received_stream};
    ngtcp2_cid destination = {.datalen = NGTCP2_MIN_INITIAL_DCIDLEN}, source = {.datalen = 8};
    ptls_minicrypto_random_bytes(destination.data, destination.datalen);
    ptls_minicrypto_random_bytes(source.data, source.datalen);
    ngtcp2_settings settings; ngtcp2_settings_default(&settings);
    settings.initial_ts = timestamp(); settings.handshake_timeout = 5 * NGTCP2_SECONDS;
    settings.max_tx_udp_payload_size = 1200;
    ngtcp2_transport_params parameters; ngtcp2_transport_params_default(&parameters);
    parameters.initial_max_streams_bidi = STREAM_COUNT;
    parameters.initial_max_stream_data_bidi_local = STREAM_CAPACITY;
    parameters.initial_max_stream_data_bidi_remote = STREAM_CAPACITY;
    parameters.initial_max_data = STREAM_COUNT * STREAM_CAPACITY;
    parameters.max_idle_timeout = 5 * NGTCP2_SECONDS;
    ngtcp2_path path = {.local = {(struct sockaddr *)&client->local, sizeof client->local},
        .remote = {(struct sockaddr *)&client->remote, sizeof client->remote}};
    if (ngtcp2_conn_client_new(&client->connection, &destination, &source, &path, NGTCP2_PROTO_VER_V1,
                              &callbacks, &settings, &parameters, NULL, client)) return -1;
    ngtcp2_conn_set_tls_native_handle(client->connection, &client->tls);
    return ngtcp2_crypto_picotls_configure_client_session(&client->tls, client->connection);
}
static int write_packets(client_t *client)
{
    if (client->handshake_complete && !client->bridge) {
        for (unsigned i = 0; i < 2; ++i) if (client->streams[i].id < 0)
            if (ngtcp2_conn_open_bidi_stream(client->connection, &client->streams[i].id, NULL)) break;
    }
    for (unsigned turn = 0; turn < 32; ++turn) {
        stream_t *stream = NULL;
        for (unsigned i = 0; i < STREAM_COUNT; ++i)
            if (client->streams[i].id >= 0 && (client->streams[i].sent < client->streams[i].length ||
                (client->streams[i].fin_requested && !client->streams[i].fin_sent))) { stream = &client->streams[i]; break; }
        uint8_t output[1200]; ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path);
        ngtcp2_pkt_info info = {0}; ngtcp2_ssize accepted = -1;
        ngtcp2_vec data = stream ? (ngtcp2_vec){stream->bytes + stream->sent, stream->length - stream->sent} : (ngtcp2_vec){0};
        ngtcp2_ssize length = ngtcp2_conn_writev_stream(client->connection, &path.path, &info,
            output, sizeof output, &accepted, stream && stream->fin_requested ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0,
            stream ? stream->id : -1, stream ? &data : NULL, stream ? 1 : 0, timestamp());
        if (length < 0) { fprintf(stderr, "QUIC write %s\n", ngtcp2_strerror((int)length)); return -1; }
        if (stream && accepted >= 0) {
            stream->sent += (size_t)accepted;
            if (stream->fin_requested && stream->sent == stream->length) stream->fin_sent = true;
        }
        if (!length) break;
        ssize_t written = send(client->socket, output, (size_t)length, 0);
        if (written != length) return -1;
        ngtcp2_conn_update_pkt_tx_time(client->connection, timestamp());
    }
    return 0;
}
/* Fixture-only process bridge. It preserves bounded immutable transmit data
   until connection teardown, so ngtcp2 retransmission never borrows overwritten
   bytes. Go owns FRP protocol operations; this C process owns QUIC/TLS only. */
static int bridge_commands(client_t *client)
{
    ssize_t length = read(STDIN_FILENO, client->command + client->command_length,
                          sizeof client->command - client->command_length);
    if (length < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    if (!length) return -1;
    client->command_length += (size_t)length;
    while (client->command_length >= 4) {
        uint8_t *command = client->command;
        size_t payload_length = ((size_t)command[2] << 8) | command[3];
        if (payload_length > 4096 || command[1] >= STREAM_COUNT) return -1;
        if (client->command_length < 4 + payload_length) break;
        stream_t *stream = &client->streams[command[1]];
        if (!client->handshake_complete) return -1;
        switch (command[0]) {
        case 'O':
            if (payload_length || stream->id >= 0 ||
                ngtcp2_conn_open_bidi_stream(client->connection, &stream->id, NULL)) return -1;
            break;
        case 'W':
            if (stream->id < 0 || stream->fin_requested || payload_length > STREAM_CAPACITY - stream->length) return -1;
            memcpy(stream->bytes + stream->length, command + 4, payload_length); stream->length += payload_length;
            break;
        case 'F':
            if (payload_length || stream->id < 0 || stream->fin_requested) return -1;
            stream->fin_requested = true;
            break;
        case 'Q':
            if (payload_length || !client->streams[1].fin_received || !client->streams[2].fin_received) return -1;
            client->bridge_done = true;
            break;
        default: return -1;
        }
        size_t used = 4 + payload_length;
        client->command_length -= used;
        memmove(command, command + used, client->command_length);
    }
    return 0;
}
static int drive(client_t *client)
{
    uint64_t deadline = timestamp() + (client->bridge ? 30 : 8) * NGTCP2_SECONDS;
    while (timestamp() < deadline) {
        if (write_packets(client)) return -1;
        if (client->bridge ? client->bridge_done : client->streams[0].fin_received && client->streams[1].fin_received) return 0;
        uint64_t now = timestamp(), expiry = ngtcp2_conn_get_expiry2(client->connection);
        int timeout_ms = expiry > now ? (int)((expiry - now) / NGTCP2_MILLISECONDS) : 0;
        if (timeout_ms > 20) timeout_ms = 20;
        fd_set readable; FD_ZERO(&readable); FD_SET(client->socket, &readable);
        int maximum = client->socket;
        if (client->bridge) { FD_SET(STDIN_FILENO, &readable); if (STDIN_FILENO > maximum) maximum = STDIN_FILENO; }
        struct timeval timeout = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        int ready = select(maximum + 1, &readable, NULL, NULL, &timeout);
        if (ready < 0 && errno != EINTR) return -1;
        if (ready > 0 && client->bridge && FD_ISSET(STDIN_FILENO, &readable) && bridge_commands(client)) return -1;
        if (ready > 0 && FD_ISSET(client->socket, &readable)) {
            uint8_t input[1500]; ssize_t length = recv(client->socket, input, sizeof input, 0);
            if (length < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
            if (length > 0) {
                ngtcp2_path path = {.local = {(struct sockaddr *)&client->local, sizeof client->local},
                    .remote = {(struct sockaddr *)&client->remote, sizeof client->remote}};
                ngtcp2_pkt_info info = {0};
                int result = ngtcp2_conn_read_pkt(client->connection, &path, &info, input, (size_t)length, timestamp());
                if (result) { fprintf(stderr, "QUIC read %s; TLS alert %u\n", ngtcp2_strerror(result),
                    ngtcp2_conn_get_tls_alert2(client->connection)); return -1; }
            }
        }
        if (ngtcp2_conn_get_expiry2(client->connection) <= timestamp() &&
            ngtcp2_conn_handle_expiry(client->connection, timestamp())) return -1;
    }
    return -1;
}
int efrp_quic_prototype_run(int argc, char **argv)
{
    if (argc != 5) return 2;
    char *end; unsigned long port = strtoul(argv[1], &end, 10);
    if (*end || !port || port > 65535) return 2;
    FILE *file = fopen(argv[2], "rb"); if (!file) return 2;
    uint8_t ca[16385]; size_t ca_length = fread(ca, 1, sizeof ca, file); fclose(file);
    if (!ca_length || ca_length == sizeof ca) return 2;
    client_t *client = calloc(1, sizeof *client); if (!client) return 2;
    client->socket = -1; client->trusted_time = strcmp(argv[4], "untrusted-time") != 0;
    client->bridge = !strcmp(argv[4], "bridge");
    if (client->bridge && fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK)) { free(client); return 2; }
    for (unsigned i = 0; i < STREAM_COUNT; ++i) {
        client->streams[i].id = -1;
        for (size_t j = 0; j < STREAM_BYTES; ++j) client->streams[i].bytes[j] = (uint8_t)(j * 31 + i * 7);
        if (!client->bridge && i < 2) { client->streams[i].length = STREAM_BYTES; client->streams[i].fin_requested = true; }
    }
    int result = initialize(client, (unsigned)port, ca, ca_length, argv[3]);
    if (!result) result = drive(client);
    fprintf(stderr, "QUIC prototype result=%d certificate=%u signature=%u handshake=%u dual_fin=%u\n", result,
        client->certificate.chain_checks, client->certificate.signature_checks, client->handshake_complete,
        client->bridge ? client->streams[1].fin_received && client->streams[2].fin_received :
                         client->streams[0].fin_received && client->streams[1].fin_received);
    if (client->connection) ngtcp2_conn_del(client->connection);
    ngtcp2_crypto_picotls_deconfigure_session(&client->tls);
    if (client->tls.ptls) ptls_free(client->tls.ptls);
    efrp_quic_certificate_dispose(&client->certificate);
    if (client->socket >= 0) close(client->socket);
    free(client);
    return result ? 10 : 0;
}
#ifdef EFRP_QUIC_HOST_MAIN
int main(int argc, char **argv) { return efrp_quic_prototype_run(argc, argv); }
#endif
