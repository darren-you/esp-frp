// SPDX-License-Identifier: Apache-2.0
#include "stream_backend.h"
#include "quic_certificate.h"
#include "quic_peer_security.h"
#include "crypto_backend.h"
#include "dns_backend.h"
#include "esp_frp_connect.h"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <picotls/minicrypto.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#if defined(EFRP_LAB_TIMEOUT_TRACE) && !defined(ESP_PLATFORM)
#include <stdio.h>
#endif
#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define EFRP_QUIC_STREAMS 4u
#define EFRP_QUIC_RX_BYTES 1024u
#define EFRP_QUIC_TX_BYTES 2048u
#define EFRP_QUIC_TX_PACKET_BYTES 1200u
#define EFRP_QUIC_RX_PACKET_BYTES 1500u
#define EFRP_QUIC_IO_MS UINT64_C(5000)
#define EFRP_QUIC_HANDSHAKE_MS UINT64_C(10000)
#define EFRP_QUIC_IDLE_MS UINT64_C(60000)
typedef struct {
    efrp_stream_id_t id;
    uint8_t receive[EFRP_QUIC_RX_BYTES], transmit[EFRP_QUIC_TX_BYTES];
    size_t receive_head, receive_used, transmit_head, transmit_used, submitted;
    uint64_t received_offset, acknowledged_offset;
    bool local_fin, fin_submitted, remote_fin, reset, closed, send_stopped, accepted;
} efrp_quic_stream_t;
typedef struct {
    efrp_transport_t base;
    efrp_transport_status_t status;
    ngtcp2_crypto_conn_ref reference;
    ngtcp2_conn *connection;
    ngtcp2_crypto_picotls_ctx tls;
    ptls_context_t context;
    ptls_raw_extension_t extensions[2];
    efrp_quic_certificate_t certificate;
    efrp_quic_peer_identity_t *identity;
    uint8_t manifest_sha256[32];
    efrp_dns_request_t *dns;
    efrp_quic_stream_t *streams[EFRP_QUIC_STREAMS];
    uint8_t input[EFRP_QUIC_RX_PACKET_BYTES], output[EFRP_QUIC_TX_PACKET_BYTES];
    struct sockaddr_in local, remote;
    size_t output_length;
    uint64_t now, deadline_ms, output_started_ms;
    unsigned cursor;
    uint16_t port;
    int socket;
    char hostname[254];
    bool cancelled, cleaned, peer, server;
} efrp_quic_transport_t;

static efrp_quic_stream_t *find_stream(const efrp_quic_transport_t *t, efrp_stream_id_t id)
{ for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) if (t->streams[i] && t->streams[i]->id == id) return t->streams[i]; return NULL; }
static ngtcp2_conn *get_connection(ngtcp2_crypto_conn_ref *reference)
{ return ((efrp_quic_transport_t *)reference->user_data)->connection; }
static void random_bytes(uint8_t *p, size_t n, const ngtcp2_rand_ctx *context)
{ (void)context; ptls_minicrypto_random_bytes(p, n); }
static int new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *id, ngtcp2_stateless_reset_token *token, size_t n, void *context)
{ (void)conn; (void)context; id->datalen = n; ptls_minicrypto_random_bytes(id->data, n); ptls_minicrypto_random_bytes(token->data, sizeof token->data); return 0; }
static int handshake_completed(ngtcp2_conn *conn, void *context)
{
    (void)conn; efrp_quic_transport_t *t = context;
    const char *protocol = ptls_get_negotiated_protocol(t->tls.ptls);
    if (!protocol || strcmp(protocol, t->peer ? EFRP_XTCP_BINDING_ALPN : "frp") || t->certificate.chain_checks != 1 ||
        t->certificate.signature_checks != 1 || !t->certificate.time_is_trusted(t->certificate.context))
        return NGTCP2_ERR_CALLBACK_FAILURE;
    t->status.state = EFRP_TRANSPORT_OPEN; t->status.verify_flags = 0; return 0;
}
static int incoming_stream(ngtcp2_conn *conn, int64_t id, void *context)
{
    (void)conn; efrp_quic_transport_t *t = context;
    if (!t->peer || !t->server || id < 0 || (id & 3) != 0) return NGTCP2_ERR_CALLBACK_FAILURE;
    unsigned slot = 0; while (slot < EFRP_QUIC_STREAMS && t->streams[slot]) ++slot;
    if (slot == EFRP_QUIC_STREAMS) return NGTCP2_ERR_CALLBACK_FAILURE;
    efrp_quic_stream_t *s = calloc(1, sizeof *s); if (!s) return NGTCP2_ERR_CALLBACK_FAILURE;
    s->id = (uint64_t)id; t->streams[slot] = s; return 0;
}
static int receive_stream(ngtcp2_conn *conn, uint32_t flags, int64_t id, uint64_t offset,
                          const uint8_t *p, size_t n, void *context, void *stream_context)
{
    (void)conn; (void)stream_context;
    efrp_quic_transport_t *t = context;
    efrp_quic_stream_t *s = find_stream(t, (uint64_t)id);
    if (!s || s->reset || s->closed || offset != s->received_offset ||
        n > EFRP_QUIC_RX_BYTES - s->receive_used) return NGTCP2_ERR_CALLBACK_FAILURE;
    size_t tail = (s->receive_head + s->receive_used) % EFRP_QUIC_RX_BYTES;
    size_t first = EFRP_QUIC_RX_BYTES - tail; if (first > n) first = n;
    if (first) memcpy(s->receive + tail, p, first);
    if (n > first) memcpy(s->receive, p + first, n - first);
    s->receive_used += n; s->received_offset += n;
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) s->remote_fin = true;
    /* No credit here. Only efrp_stream_read's actual application consumption
       increases MAX_STREAM_DATA/MAX_DATA, bounding unread+reordered bytes. */
    return 0;
}
static int acknowledge_stream(ngtcp2_conn *conn, int64_t id, uint64_t offset, uint64_t n,
                              void *context, void *stream_context)
{
    (void)conn; (void)stream_context;
    efrp_quic_stream_t *s = find_stream(context, (uint64_t)id);
    if (!s || s->closed || offset != s->acknowledged_offset || n > s->submitted || n > s->transmit_used)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    size_t size = (size_t)n;
    size_t first = EFRP_QUIC_TX_BYTES - s->transmit_head; if (first > size) first = size;
    if (first) efrp_crypto_zero(s->transmit + s->transmit_head, first);
    if (size > first) efrp_crypto_zero(s->transmit, size - first);
    s->transmit_head = (s->transmit_head + size) % EFRP_QUIC_TX_BYTES;
    s->submitted -= size; s->transmit_used -= size; s->acknowledged_offset += n;
    return 0;
}
static int reset_stream(ngtcp2_conn *conn, int64_t id, uint64_t final_size, uint64_t code, void *context, void *stream_context)
{
    (void)conn; (void)final_size; (void)code; (void)stream_context;
    efrp_quic_stream_t *s = find_stream(context, (uint64_t)id);
    if (!s) return NGTCP2_ERR_CALLBACK_FAILURE;
    s->reset = true; efrp_crypto_zero(s->receive, sizeof s->receive); s->receive_used = 0; return 0;
}
static int close_stream(ngtcp2_conn *conn, uint32_t flags, int64_t id, uint64_t rx_code,
                        uint64_t tx_code, void *context, void *stream_context)
{
    (void)conn; (void)rx_code; (void)tx_code; (void)stream_context;
    efrp_quic_stream_t *s = find_stream(context, (uint64_t)id);
    if (!s) return NGTCP2_ERR_CALLBACK_FAILURE;
#if defined(EFRP_LAB_TIMEOUT_TRACE) && !defined(ESP_PLATFORM)
    fprintf(stderr, "QUIC close id=%llu flags=%u rx=%llu tx=%llu local_fin=%u remote_fin=%u pending=%zu submitted=%zu readable=%zu\n",
        (unsigned long long)s->id, flags, (unsigned long long)rx_code, (unsigned long long)tx_code,
        s->local_fin ? 1u : 0u, s->remote_fin ? 1u : 0u, s->transmit_used, s->submitted, s->receive_used);
#endif
    /* STOP_SENDING is one direction. The official FRPS adapter cancels read
       with code 0 after finishing its response, before our local TCP EOF is
       necessarily observed. Preserve a real RX FIN and fully ACKed TX prefix;
       never invent local FIN or discard a valid unread RX tail. Any additional
       caller payload is still rejected because the native write side closed. */
    bool completed_send_stop = flags == NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET &&
        !tx_code && s->remote_fin && !s->transmit_used && !s->submitted;
    if (flags && !completed_send_stop) {
        s->reset = true; efrp_crypto_zero(s->receive, sizeof s->receive); s->receive_used = 0;
    }
    s->closed = true; efrp_crypto_zero(s->transmit, sizeof s->transmit);
    s->transmit_used = s->submitted = 0; return 0;
}
static int receive_stop_sending(ngtcp2_conn *conn, int64_t id, uint64_t code, void *context, void *stream_context)
{
    (void)conn; (void)code; (void)stream_context;
    efrp_quic_stream_t *s = find_stream(context, (uint64_t)id);
    if (!s) return NGTCP2_ERR_CALLBACK_FAILURE;
    /* Retain copied TX data until ngtcp2's close callback releases references.
       Stop offering STREAM/FIN after native shutdown, but continue ACK/RST I/O. */
    s->send_stopped = true; return 0;
}
static efrp_result_t cleanup(efrp_quic_transport_t *t)
{
    if (!t->cleaned) {
        /* Delete protocol references before wiping or freeing borrowed rings. */
        if (t->connection) { ngtcp2_conn_del(t->connection); t->connection = NULL; }
        ngtcp2_crypto_picotls_deconfigure_session(&t->tls);
        if (t->tls.ptls) { ptls_free(t->tls.ptls); t->tls.ptls = NULL; }
        efrp_quic_certificate_dispose(&t->certificate);
        for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) if (t->streams[i]) {
            efrp_crypto_zero(t->streams[i], sizeof *t->streams[i]); free(t->streams[i]); t->streams[i] = NULL;
        }
        efrp_crypto_zero(t->input, sizeof t->input); efrp_crypto_zero(t->output, sizeof t->output);
        t->output_length = 0; t->cleaned = true;
        if (t->dns) efrp_dns_cancel(t->dns);
    }
    efrp_result_t result = efrp_dns_destroy(&t->dns);
    t->status.pending_dns = t->dns != NULL;
    if (t->socket >= 0) {
        int closed = close(t->socket);
        if (closed != 0) t->status.system_error = errno;
#if defined(ESP_PLATFORM) || defined(EFRP_QUIC_TEST_CLOSE)
        /* Fixed lwIP retains a valid socket when close cannot complete. */
        if (closed != 0) result = EFRP_WOULD_BLOCK;
        else { t->socket = -1; t->status.owns_socket = false; }
#else
        /* POSIX close errors do not authorize retry against a reused fd. */
        t->socket = -1; t->status.owns_socket = false;
#endif
    }
    t->status.pending_tx_bytes = 0; t->status.want = EFRP_TRANSPORT_WANT_NONE;
    t->status.next_deadline_ms = result == EFRP_OK ? UINT64_MAX : t->now + 1;
    if (result == EFRP_OK) t->status.state = t->cancelled ? EFRP_TRANSPORT_CLOSED : EFRP_TRANSPORT_FAILED;
    else t->status.state = EFRP_TRANSPORT_DRAINING;
    return result;
}
static efrp_result_t fail(efrp_quic_transport_t *t, efrp_result_t reason)
{ t->status.result = reason; (void)cleanup(t); return reason; }
static efrp_result_t finish_cancel(efrp_quic_transport_t *t)
{
    if (t->output_length) {
        ssize_t n = send(t->socket, t->output, t->output_length, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            t->now - t->output_started_ms < EFRP_QUIC_IO_MS) {
            t->status.state = EFRP_TRANSPORT_DRAINING; t->status.want = EFRP_TRANSPORT_WANT_WRITE;
            t->status.next_deadline_ms = t->output_started_ms + EFRP_QUIC_IO_MS; return EFRP_WOULD_BLOCK;
        }
        if (n < 0) t->status.system_error = errno;
        else if ((size_t)n != t->output_length) t->status.system_error = EMSGSIZE;
        /* A failed/timed out close still destroys all local owners. No older
           business datagram can survive this one-packet cancellation queue. */
        efrp_crypto_zero(t->output, sizeof t->output); t->output_length = 0;
    }
    return cleanup(t);
}
static efrp_result_t library_failure(efrp_quic_transport_t *t, int code)
{
    t->status.tls_error = code;
    if (code == NGTCP2_ERR_CRYPTO) {
        uint8_t alert = ngtcp2_conn_get_tls_alert2(t->connection);
        t->status.tls_error = alert;
        if (alert == PTLS_ALERT_BAD_CERTIFICATE || alert == PTLS_ALERT_CERTIFICATE_EXPIRED ||
            alert == PTLS_ALERT_UNKNOWN_CA || alert == PTLS_ALERT_DECRYPT_ERROR)
            return fail(t, EFRP_TLS_TRUST_ERROR);
        return fail(t, EFRP_NEGOTIATION_FAILED);
    }
    if (code == NGTCP2_ERR_NOMEM) return fail(t, EFRP_NO_MEMORY);
    if (code == NGTCP2_ERR_HANDSHAKE_TIMEOUT || code == NGTCP2_ERR_IDLE_CLOSE) return fail(t, EFRP_TIMEOUT);
    if (code == NGTCP2_ERR_DRAINING || code == NGTCP2_ERR_CLOSING) { t->status.eof = true; return fail(t, EFRP_SESSION_CLOSED); }
    return fail(t, EFRP_PROTOCOL_ERROR);
}
static efrp_result_t start_connection(efrp_quic_transport_t *t, const uint8_t address[4], const ngtcp2_pkt_hd *initial)
{
    if (!t->peer) {
    t->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (t->socket < 0) { t->status.system_error = errno; return fail(t, EFRP_NETWORK_ERROR); }
    t->status.owns_socket = true;
    int flags = fcntl(t->socket, F_GETFL, 0);
    t->remote = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = htons(t->port)};
    memcpy(&t->remote.sin_addr.s_addr, address, 4);
    socklen_t local_length = sizeof t->local;
    if (flags < 0 || fcntl(t->socket, F_SETFL, flags | O_NONBLOCK) != 0 ||
        connect(t->socket, (struct sockaddr *)&t->remote, sizeof t->remote) != 0 ||
        getsockname(t->socket, (struct sockaddr *)&t->local, &local_length) != 0) {
        t->status.system_error = errno; return fail(t, EFRP_NETWORK_ERROR);
    }
    }
    static ptls_cipher_suite_t *ciphers[] = {&ptls_minicrypto_aes128gcmsha256, NULL};
    static ptls_key_exchange_algorithm_t *exchanges[] = {&ptls_minicrypto_x25519, NULL};
    t->context = (ptls_context_t){.random_bytes = ptls_minicrypto_random_bytes, .get_time = &ptls_get_time,
        .cipher_suites = ciphers, .key_exchanges = exchanges,
        .verify_certificate = &t->certificate.certificate, .max_buffer_size = 16384};
    if (t->peer) {
        t->context.sign_certificate = &t->identity->callback;
        t->context.certificates.list = &t->identity->certificate; t->context.certificates.count = 1;
        t->context.use_exporter = 1;
        if (t->server) { t->context.on_client_hello = &efrp_quic_peer_client_hello; t->context.require_client_authentication = 1; }
    }
    int configured = t->server ? ngtcp2_crypto_picotls_configure_server_context(&t->context) :
        ngtcp2_crypto_picotls_configure_client_context(&t->context);
    if (configured) return fail(t, EFRP_TLS_ERROR);
    t->context.max_early_data_size = 0; /* Override helper's server default; candidate has no 0-RTT. */
    ngtcp2_crypto_picotls_ctx_init(&t->tls); t->tls.ptls = ptls_new(&t->context, t->server ? 1 : 0);
    if (!t->tls.ptls) return fail(t, EFRP_NO_MEMORY);
    if (!t->server && ptls_set_server_name(t->tls.ptls, t->hostname, 0)) return fail(t, EFRP_TLS_ERROR);
    t->reference = (ngtcp2_crypto_conn_ref){.get_conn = get_connection, .user_data = t};
    *ptls_get_data_ptr(t->tls.ptls) = &t->reference;
    static const ptls_iovec_t protocols[] = {{(uint8_t *)"frp", 3}};
    static const ptls_iovec_t peer_protocols[] = {{(uint8_t *)EFRP_XTCP_BINDING_ALPN, sizeof EFRP_XTCP_BINDING_ALPN - 1}};
    if (!t->server) {
        t->tls.handshake_properties.client.negotiated_protocols.list = t->peer ? peer_protocols : protocols;
        t->tls.handshake_properties.client.negotiated_protocols.count = 1;
    }
    t->extensions[0].type = t->extensions[1].type = UINT16_MAX;
    t->tls.handshake_properties.additional_extensions = t->extensions;
    ngtcp2_callbacks callbacks = {.client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb, .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb, .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb, .rand = random_bytes,
        .get_new_connection_id2 = new_connection_id, .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
        .handshake_completed = handshake_completed, .recv_stream_data = receive_stream,
        .acked_stream_data_offset = acknowledge_stream, .stream_reset = reset_stream, .stream_close2 = close_stream,
        .recv_stop_sending = receive_stop_sending};
    if (t->server) { callbacks.client_initial = NULL; callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.stream_open = incoming_stream; callbacks.recv_retry = NULL; }
    ngtcp2_cid destination = {.datalen = NGTCP2_MIN_INITIAL_DCIDLEN}, source = {.datalen = 8};
    ptls_minicrypto_random_bytes(destination.data, destination.datalen); ptls_minicrypto_random_bytes(source.data, source.datalen);
    if (t->server) destination = initial->scid;
    ngtcp2_settings settings; ngtcp2_settings_default(&settings);
    settings.initial_ts = t->now * NGTCP2_MILLISECONDS; settings.handshake_timeout = EFRP_QUIC_HANDSHAKE_MS * NGTCP2_MILLISECONDS;
    settings.max_tx_udp_payload_size = EFRP_QUIC_TX_PACKET_BYTES;
    ngtcp2_transport_params parameters; ngtcp2_transport_params_default(&parameters);
    parameters.initial_max_stream_data_bidi_local = EFRP_QUIC_RX_BYTES;
    parameters.initial_max_stream_data_bidi_remote = EFRP_QUIC_RX_BYTES;
    parameters.initial_max_data = EFRP_QUIC_STREAMS * EFRP_QUIC_RX_BYTES;
    parameters.max_idle_timeout = EFRP_QUIC_IDLE_MS * NGTCP2_MILLISECONDS;
    parameters.max_udp_payload_size = EFRP_QUIC_RX_PACKET_BYTES; parameters.disable_active_migration = 1;
    if (t->server) { parameters.initial_max_streams_bidi = EFRP_QUIC_STREAMS;
        parameters.original_dcid = initial->dcid; parameters.original_dcid_present = 1; }
    ngtcp2_path path = {.local = {(struct sockaddr *)&t->local, sizeof t->local},
        .remote = {(struct sockaddr *)&t->remote, sizeof t->remote}};
    int result = t->server ? ngtcp2_conn_server_new(&t->connection, &destination, &source, &path, NGTCP2_PROTO_VER_V1,
        &callbacks, &settings, &parameters, NULL, t) :
        ngtcp2_conn_client_new(&t->connection, &destination, &source, &path, NGTCP2_PROTO_VER_V1,
        &callbacks, &settings, &parameters, NULL, t);
    if (result) return library_failure(t, result);
    ngtcp2_conn_set_tls_native_handle(t->connection, &t->tls);
    configured = t->server ? ngtcp2_crypto_picotls_configure_server_session(&t->tls) :
        ngtcp2_crypto_picotls_configure_client_session(&t->tls, t->connection);
    if (configured) return fail(t, EFRP_TLS_ERROR);
    t->status.state = EFRP_TRANSPORT_HANDSHAKING;
    /* Hole-punch peer admission owns one absolute handshake deadline from
     * factory creation. A delayed first Initial must not grant another 10s. */
    if (!t->peer) t->deadline_ms = t->now + EFRP_QUIC_HANDSHAKE_MS;
    return EFRP_OK;
}
static bool transient(int error)
{ return error == EAGAIN || error == EWOULDBLOCK || error == EINTR || error == ENOBUFS; }
static efrp_result_t send_pending(efrp_quic_transport_t *t)
{
    if (!t->output_length) return EFRP_OK;
    ssize_t n = send(t->socket, t->output, t->output_length, 0);
    if (n < 0 && transient(errno)) {
        if (t->now - t->output_started_ms >= EFRP_QUIC_IO_MS) return fail(t, EFRP_TIMEOUT);
        t->status.want = EFRP_TRANSPORT_WANT_WRITE; return EFRP_WOULD_BLOCK;
    }
    if (n < 0 || (size_t)n != t->output_length) { t->status.system_error = n < 0 ? errno : 0; return fail(t, EFRP_NETWORK_ERROR); }
    efrp_crypto_zero(t->output, t->output_length); t->output_length = 0;
    ngtcp2_conn_update_pkt_tx_time(t->connection, t->now * NGTCP2_MILLISECONDS);
    t->status.want = EFRP_TRANSPORT_WANT_READ; return EFRP_OK;
}
static efrp_result_t receive_packets(efrp_quic_transport_t *t)
{
    for (unsigned turn = 0; turn < 8; ++turn) {
        struct iovec vector = {.iov_base = t->input, .iov_len = sizeof t->input};
        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
        ssize_t n = recvmsg(t->socket, &message, 0);
        if (n < 0 && transient(errno)) return EFRP_OK;
        if (n < 0) { t->status.system_error = errno; return fail(t, EFRP_NETWORK_ERROR); }
        if (message.msg_flags & MSG_TRUNC) return fail(t, EFRP_PROTOCOL_ERROR);
        if (!n) continue;
        if (!t->connection) {
            ngtcp2_pkt_hd initial;
            if (!t->server) return fail(t, EFRP_INVALID_STATE);
            if (ngtcp2_accept(&initial, t->input, (size_t)n) || initial.version != NGTCP2_PROTO_VER_V1) continue;
            efrp_result_t started = start_connection(t, NULL, &initial);
            if (started != EFRP_OK) return started;
        }
        ngtcp2_path path = {.local = {(struct sockaddr *)&t->local, sizeof t->local},
            .remote = {(struct sockaddr *)&t->remote, sizeof t->remote}};
        ngtcp2_pkt_info info = {0};
        int result = ngtcp2_conn_read_pkt(t->connection, &path, &info, t->input, (size_t)n, t->now * NGTCP2_MILLISECONDS);
        efrp_crypto_zero(t->input, (size_t)n);
        if (result) return library_failure(t, result);
    }
    return EFRP_OK;
}
static efrp_result_t write_packets(efrp_quic_transport_t *t)
{
    for (unsigned turn = 0; turn < 8; ++turn) {
        efrp_result_t result = send_pending(t);
        if (result != EFRP_OK) return result;
        efrp_quic_stream_t *s = NULL;
        for (unsigned offset = 0; offset < EFRP_QUIC_STREAMS; ++offset) {
            unsigned slot = (t->cursor + offset) % EFRP_QUIC_STREAMS;
            efrp_quic_stream_t *candidate = t->streams[slot];
            if (candidate && !candidate->reset && !candidate->closed && !candidate->send_stopped &&
                (candidate->submitted < candidate->transmit_used || (candidate->local_fin && !candidate->fin_submitted))) {
                s = candidate; t->cursor = slot; break;
            }
        }
        ngtcp2_vec vectors[2] = {{0}}; size_t count = 0;
        if (s) {
            size_t start = (s->transmit_head + s->submitted) % EFRP_QUIC_TX_BYTES;
            size_t remaining = s->transmit_used - s->submitted;
            size_t first = EFRP_QUIC_TX_BYTES - start; if (first > remaining) first = remaining;
            vectors[0] = (ngtcp2_vec){s->transmit + start, first}; count = 1;
            if (remaining > first) { vectors[1] = (ngtcp2_vec){s->transmit, remaining - first}; count = 2; }
        }
        ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path); ngtcp2_pkt_info info = {0};
        ngtcp2_ssize accepted = -1;
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(t->connection, &path.path, &info, t->output, sizeof t->output,
            &accepted, s && s->local_fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0,
            s ? (int64_t)s->id : -1, s ? vectors : NULL, count, t->now * NGTCP2_MILLISECONDS);
        if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            if (s) t->cursor = (t->cursor + 1) % EFRP_QUIC_STREAMS;
            continue;
        }
        if (n < 0) return library_failure(t, (int)n);
        if (s && accepted >= 0) {
            if ((size_t)accepted > s->transmit_used - s->submitted) return fail(t, EFRP_PROTOCOL_ERROR);
            s->submitted += (size_t)accepted;
            if (s->local_fin && s->submitted == s->transmit_used) s->fin_submitted = true;
            /* Pacing/cwnd or control-only packets do not consume this stream's
             * turn. Rotate only after native data or a zero-byte FIN is accepted. */
            if (accepted > 0 || s->fin_submitted)
                t->cursor = (t->cursor + 1) % EFRP_QUIC_STREAMS;
        }
        if (!n) return EFRP_OK;
        if (path.path.remote.addrlen != sizeof t->remote || path.path.local.addrlen != sizeof t->local ||
            memcmp(path.path.remote.addr, &t->remote, sizeof t->remote) || memcmp(path.path.local.addr, &t->local, sizeof t->local))
            return fail(t, EFRP_PROTOCOL_ERROR);
        t->output_length = (size_t)n; t->output_started_ms = t->now;
    }
    return send_pending(t);
}
static efrp_result_t step(efrp_transport_t *base, uint64_t now)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base;
    if (now < t->now || now > (UINT64_MAX / NGTCP2_MILLISECONDS) - EFRP_QUIC_IDLE_MS) return EFRP_INVALID_ARGUMENT;
    t->now = now;
    if (t->cancelled) return finish_cancel(t) == EFRP_WOULD_BLOCK ? EFRP_WOULD_BLOCK : EFRP_CANCELLED;
    if (t->cleaned) { (void)cleanup(t); return t->status.result; }
    if (!t->certificate.time_is_trusted(t->certificate.context)) return fail(t, EFRP_TIME_UNTRUSTED);
    if (t->status.state != EFRP_TRANSPORT_OPEN && now >= t->deadline_ms) return fail(t, EFRP_TIMEOUT);
    if (t->dns) {
        uint8_t address[4]; int error = 0; efrp_result_t result = efrp_dns_poll(t->dns, address, &error);
        if (result == EFRP_WOULD_BLOCK) { t->status.next_deadline_ms = now + 1; return result; }
        if (result != EFRP_OK) { t->status.system_error = error; return fail(t, result); }
        result = efrp_dns_destroy(&t->dns); t->status.pending_dns = t->dns != NULL;
        if (result != EFRP_OK) return fail(t, EFRP_DNS_ERROR);
        if (!address[0] || address[0] >= 224) return fail(t, EFRP_DNS_ERROR);
        result = start_connection(t, address, NULL); if (result != EFRP_OK) return result;
    }
    efrp_result_t result = receive_packets(t); if (result != EFRP_OK) return result;
    if (!t->connection) { t->status.want = EFRP_TRANSPORT_WANT_READ; t->status.next_deadline_ms = t->deadline_ms; return EFRP_WOULD_BLOCK; }
    result = send_pending(t); if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
    if (!t->output_length) {
        if (ngtcp2_conn_get_expiry2(t->connection) <= now * NGTCP2_MILLISECONDS) {
            int expired = ngtcp2_conn_handle_expiry(t->connection, now * NGTCP2_MILLISECONDS);
            if (expired) return library_failure(t, expired);
        }
        result = write_packets(t); if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) return result;
    }
    uint64_t expiry = ngtcp2_conn_get_expiry2(t->connection);
    t->status.next_deadline_ms = expiry == UINT64_MAX ? UINT64_MAX : expiry / NGTCP2_MILLISECONDS + (expiry % NGTCP2_MILLISECONDS != 0);
    if (t->status.state != EFRP_TRANSPORT_OPEN && t->deadline_ms < t->status.next_deadline_ms)
        t->status.next_deadline_ms = t->deadline_ms;
    if (t->output_length || t->status.next_deadline_ms <= now) t->status.next_deadline_ms = now + 1;
    return t->status.state == EFRP_TRANSPORT_OPEN ? EFRP_OK : EFRP_WOULD_BLOCK;
}
static efrp_result_t status(const efrp_transport_t *base, efrp_transport_status_t *out)
{
    const efrp_quic_transport_t *t = (const efrp_quic_transport_t *)base; *out = t->status;
    out->pending_tx_bytes = 0;
    for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) if (t->streams[i]) out->pending_tx_bytes += t->streams[i]->transmit_used;
    return EFRP_OK;
}
static efrp_result_t ready(const efrp_quic_transport_t *t)
{ return t->status.result != EFRP_OK ? t->status.result : t->status.state == EFRP_TRANSPORT_OPEN ? EFRP_OK : EFRP_WOULD_BLOCK; }
static efrp_result_t open_stream(efrp_transport_t *base, efrp_stream_id_t *id)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    if (t->server) return EFRP_INVALID_STATE;
    unsigned slot = 0; while (slot < EFRP_QUIC_STREAMS && t->streams[slot]) ++slot;
    if (slot == EFRP_QUIC_STREAMS) return EFRP_WOULD_BLOCK;
    efrp_quic_stream_t *s = calloc(1, sizeof *s); if (!s) return EFRP_NO_MEMORY;
    int64_t native = -1; int result = ngtcp2_conn_open_bidi_stream(t->connection, &native, s);
    if (result) { free(s); return result == NGTCP2_ERR_STREAM_ID_BLOCKED ? EFRP_WOULD_BLOCK : result == NGTCP2_ERR_NOMEM ? EFRP_NO_MEMORY : EFRP_PROTOCOL_ERROR; }
    s->id = (uint64_t)native; s->accepted = true; t->streams[slot] = s; *id = s->id; return EFRP_OK;
}
static efrp_result_t accept_stream(efrp_transport_t *base, efrp_stream_id_t *id)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base; if (ready(t) != EFRP_OK) return ready(t);
    if (!t->peer || !t->server) return EFRP_INVALID_STATE;
    efrp_quic_stream_t *selected = NULL;
    for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) if (t->streams[i] && !t->streams[i]->accepted &&
        (!selected || t->streams[i]->id < selected->id)) selected = t->streams[i];
    if (!selected) return EFRP_WOULD_BLOCK;
    selected->accepted = true; *id = selected->id; return EFRP_OK;
}
static efrp_result_t info(const efrp_transport_t *base, efrp_stream_id_t id, efrp_stream_info_t *out)
{
    const efrp_quic_transport_t *t = (const efrp_quic_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    const efrp_quic_stream_t *s = find_stream(t, id); if (!s) return EFRP_INVALID_ARGUMENT;
    *out = (efrp_stream_info_t){.readable_bytes = s->receive_used, .pending_bytes = s->transmit_used,
        .local_fin = s->local_fin, .remote_fin = s->remote_fin, .reset = s->reset}; return EFRP_OK;
}
static efrp_result_t write_stream(efrp_transport_t *base, efrp_stream_id_t id, const uint8_t *p, size_t n, size_t *written)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    efrp_quic_stream_t *s = find_stream(t, id); if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_STREAM_RESET;
    if (s->local_fin || s->closed || s->send_stopped) return EFRP_INVALID_STATE;
    size_t free_bytes = EFRP_QUIC_TX_BYTES - s->transmit_used; if (!free_bytes) return EFRP_WOULD_BLOCK;
    if (n > free_bytes) n = free_bytes;
    size_t tail = (s->transmit_head + s->transmit_used) % EFRP_QUIC_TX_BYTES;
    size_t first = EFRP_QUIC_TX_BYTES - tail; if (first > n) first = n;
    memcpy(s->transmit + tail, p, first); if (n > first) memcpy(s->transmit, p + first, n - first);
    s->transmit_used += n; *written = n; return EFRP_OK;
}
static efrp_result_t read_stream(efrp_transport_t *base, efrp_stream_id_t id, uint8_t *p, size_t n, size_t *read)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base;
    if (ready(t) != EFRP_OK) return ready(t);
    efrp_quic_stream_t *s = find_stream(t, id); if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_STREAM_RESET;
    if (!s->receive_used) return s->remote_fin ? EFRP_EOF : EFRP_WOULD_BLOCK;
    if (n > s->receive_used) n = s->receive_used;
    if (!s->closed) {
        int result = ngtcp2_conn_extend_max_stream_offset(t->connection, (int64_t)s->id, n);
        if (result) return library_failure(t, result);
    }
    size_t first = EFRP_QUIC_RX_BYTES - s->receive_head; if (first > n) first = n;
    memcpy(p, s->receive + s->receive_head, first); if (n > first) memcpy(p + first, s->receive, n - first);
    efrp_crypto_zero(s->receive + s->receive_head, first); if (n > first) efrp_crypto_zero(s->receive, n - first);
    s->receive_head = (s->receive_head + n) % EFRP_QUIC_RX_BYTES; s->receive_used -= n;
    ngtcp2_conn_extend_max_offset(t->connection, n); *read = n; return EFRP_OK;
}
static efrp_result_t close_write(efrp_transport_t *base, efrp_stream_id_t id)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base; if (ready(t) != EFRP_OK) return ready(t);
    efrp_quic_stream_t *s = find_stream(t, id); if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_STREAM_RESET;
    s->local_fin = true; return EFRP_OK;
}
static efrp_result_t reset(efrp_transport_t *base, efrp_stream_id_t id)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base; if (ready(t) != EFRP_OK) return ready(t);
    efrp_quic_stream_t *s = find_stream(t, id); if (!s) return EFRP_INVALID_ARGUMENT;
    if (s->reset) return EFRP_OK;
    int result = ngtcp2_conn_shutdown_stream(t->connection, 0, (int64_t)id, 1);
    if (result) return result == NGTCP2_ERR_NOMEM ? EFRP_NO_MEMORY : EFRP_PROTOCOL_ERROR;
    s->reset = true; efrp_crypto_zero(s->receive, sizeof s->receive); s->receive_used = 0; return EFRP_OK;
}
static efrp_result_t release(efrp_transport_t *base, efrp_stream_id_t id)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base; if (ready(t) != EFRP_OK) return ready(t);
    efrp_quic_stream_t *s = find_stream(t, id); if (!s) return EFRP_INVALID_ARGUMENT;
    if (!s->reset && !(s->local_fin && s->remote_fin && !s->receive_used)) return EFRP_INVALID_STATE;
    if (!s->closed) return EFRP_WOULD_BLOCK;
    for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) if (t->streams[i] == s) t->streams[i] = NULL;
    efrp_crypto_zero(s, sizeof *s); free(s); return EFRP_OK;
}
static efrp_result_t cancel(efrp_transport_t *base)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base;
    if (!t->cancelled) {
        t->cancelled = true; t->status.result = EFRP_CANCELLED;
        /* Replace, never drain, a retained encrypted STREAM packet. */
        efrp_crypto_zero(t->output, sizeof t->output); t->output_length = 0;
        if (t->connection) {
            ngtcp2_ccerr error; ngtcp2_ccerr_default(&error); ngtcp2_ccerr_set_application_error(&error, 0, NULL, 0);
            ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path); ngtcp2_pkt_info info = {0};
            ngtcp2_ssize n = ngtcp2_conn_write_connection_close(t->connection, &path.path, &info,
                t->output, sizeof t->output, &error, t->now * NGTCP2_MILLISECONDS);
            if (n > 0) { t->output_length = (size_t)n; t->output_started_ms = t->now; }
        }
    }
    return finish_cancel(t);
}
static efrp_result_t finish(const efrp_transport_t *base)
{ const efrp_quic_transport_t *t = (const efrp_quic_transport_t *)base; return t->status.result; }
static efrp_result_t destroy(efrp_transport_t **base)
{
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)*base;
    efrp_result_t result = cancel(*base); if (result != EFRP_OK) return result;
    efrp_crypto_zero(t, sizeof *t); free(t); *base = NULL; return EFRP_OK;
}
static const efrp_stream_operations_t operations = {.step = step, .status = status, .open = open_stream, .info = info,
    .accept = accept_stream,
    .write = write_stream, .read = read_stream, .close_write = close_write, .reset = reset, .release = release,
    .finish = finish, .cancel = cancel, .destroy = destroy};
efrp_result_t efrp_transport_quic_create(const efrp_quic_config_t *config, uint64_t now, efrp_transport_t **out)
{
    if (!out || !config || !config->hostname || !config->port || !config->ca_pem || !config->ca_length ||
        !config->time_is_trusted || config->profile != EFRP_QUIC_PROFILE_P256_AES128_X25519 ||
        now > (UINT64_MAX / NGTCP2_MILLISECONDS) - EFRP_QUIC_IDLE_MS) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    size_t length = 0;
    while (length <= 253 && config->hostname[length]) {
        unsigned char c = (unsigned char)config->hostname[length];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-'))
            return EFRP_INVALID_ARGUMENT;
        ++length;
    }
    if (!length || length > 253 || config->ca_length > EFRP_TLS_MAX_CA_BYTES) return EFRP_INVALID_ARGUMENT;
    if (!config->time_is_trusted(config->context)) return EFRP_TIME_UNTRUSTED;
    efrp_quic_transport_t *t = calloc(1, sizeof *t); if (!t) return EFRP_NO_MEMORY;
    t->socket = -1; t->base.operations = &operations; t->port = config->port; t->now = now;
    t->deadline_ms = now + EFRP_CONNECT_DNS_MS;
    memcpy(t->hostname, config->hostname, length + 1);
    t->status = (efrp_transport_status_t){.kind = EFRP_TRANSPORT_QUIC, .state = EFRP_TRANSPORT_RESOLVING,
        .next_deadline_ms = now + 1, .verify_flags = UINT32_MAX};
    if (efrp_quic_certificate_init(&t->certificate, config->ca_pem, config->ca_length,
                                   config->time_is_trusted, config->context)) {
        (void)cleanup(t); free(t); return EFRP_TLS_TRUST_ERROR;
    }
    efrp_result_t result = efrp_dns_start(t->hostname, &t->dns);
    if (result != EFRP_OK) { (void)cleanup(t); free(t); return result; }
    t->status.pending_dns = true; *out = &t->base; return EFRP_OK;
}

efrp_result_t efrp_transport_quic_peer_create(const efrp_quic_peer_config_t *config,
                                            int *socket, uint64_t now, efrp_transport_t **out)
{
    if (!config || !out || !socket || *socket < 0 || !config->identity ||
        config->identity->role != config->role || !config->identity->key_id || !config->identity->certificate.base ||
        (config->role != EFRP_XTCP_PROVIDER && config->role != EFRP_XTCP_VISITOR) ||
        config->profile != EFRP_QUIC_PROFILE_P256_AES128_X25519 || !config->time_is_trusted ||
        !config->local.port || !config->remote.port || !config->remote.ipv4[0] || config->remote.ipv4[0] >= 224 ||
        now > (UINT64_MAX / NGTCP2_MILLISECONDS) - EFRP_QUIC_IDLE_MS) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if (!config->time_is_trusted(config->context)) return EFRP_TIME_UNTRUSTED;
    unsigned binding = 0; for (unsigned i = 0; i < 32; ++i) binding |= config->manifest_sha256[i];
    if (!binding) return EFRP_INVALID_ARGUMENT;
    struct sockaddr_in local, connected, remote = {.sin_family = AF_INET, .sin_port = htons(config->remote.port)};
    memcpy(&remote.sin_addr.s_addr, config->remote.ipv4, 4);
    socklen_t length = sizeof local; int type = 0; socklen_t type_length = sizeof type;
    if (getsockopt(*socket, SOL_SOCKET, SO_TYPE, &type, &type_length) || type != SOCK_DGRAM ||
        getsockname(*socket, (struct sockaddr *)&local, &length) || length != sizeof local || local.sin_family != AF_INET ||
        local.sin_port != htons(config->local.port) || memcmp(&local.sin_addr.s_addr, config->local.ipv4, 4))
        return EFRP_INVALID_ARGUMENT;
    length = sizeof connected;
    if (!getpeername(*socket, (struct sockaddr *)&connected, &length) &&
        (length != sizeof connected || connected.sin_family != AF_INET || connected.sin_port != remote.sin_port ||
         connected.sin_addr.s_addr != remote.sin_addr.s_addr)) return EFRP_INVALID_ARGUMENT;
    efrp_quic_transport_t *t = calloc(1, sizeof *t); if (!t) return EFRP_NO_MEMORY;
    t->socket = -1; t->base.operations = &operations; t->peer = true; t->server = config->role == EFRP_XTCP_PROVIDER;
    t->identity = config->identity; t->local = local; t->remote = remote; t->now = now;
    t->deadline_ms = now + EFRP_QUIC_HANDSHAKE_MS; memcpy(t->manifest_sha256, config->manifest_sha256, 32);
    memcpy(t->hostname, "esp-frp-xtcp-provider", sizeof "esp-frp-xtcp-provider");
    t->status = (efrp_transport_status_t){.kind = EFRP_TRANSPORT_QUIC, .state = EFRP_TRANSPORT_HANDSHAKING,
        .verify_flags = UINT32_MAX, .next_deadline_ms = t->deadline_ms, .want = EFRP_TRANSPORT_WANT_READ};
    if (efrp_quic_certificate_pin_init(&t->certificate, config->peer_spki_sha256,
                                      !t->server, config->time_is_trusted, config->context)) {
        (void)cleanup(t); free(t); return EFRP_TLS_TRUST_ERROR;
    }
    int flags = fcntl(*socket, F_GETFL, 0); length = sizeof t->local;
    if (flags < 0 || fcntl(*socket, F_SETFL, flags | O_NONBLOCK) ||
        connect(*socket, (struct sockaddr *)&remote, sizeof remote) ||
        getsockname(*socket, (struct sockaddr *)&t->local, &length)) {
        (void)cleanup(t); free(t); return EFRP_NETWORK_ERROR;
    }
    efrp_result_t result = t->server ? EFRP_OK : start_connection(t, NULL, NULL);
    if (result != EFRP_OK) { (void)cleanup(t); free(t); return result; }
    t->socket = *socket; *socket = -1; t->status.owns_socket = true; *out = &t->base; return EFRP_OK;
}
efrp_result_t efrp_quic_peer_exporter(efrp_transport_t *base, uint8_t output[32])
{
    if (output) efrp_crypto_zero(output, 32);
    if (!base || !output || base->operations != &operations) return EFRP_INVALID_ARGUMENT;
    efrp_quic_transport_t *t = (efrp_quic_transport_t *)base;
    if (!t->peer) return EFRP_INVALID_STATE;
    if (ready(t) != EFRP_OK) return ready(t);
    if (!t->certificate.time_is_trusted(t->certificate.context)) return EFRP_TIME_UNTRUSTED;
    if (ptls_export_secret(t->tls.ptls, output, 32, EFRP_XTCP_EXPORTER_LABEL,
                            ptls_iovec_init(t->manifest_sha256, sizeof t->manifest_sha256), 0)) {
        efrp_crypto_zero(output, 32); return EFRP_CRYPTO_ERROR;
    }
    return EFRP_OK;
}
