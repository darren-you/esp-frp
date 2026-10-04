// SPDX-License-Identifier: Apache-2.0
/* Exercise production receive consumption with the locked native ngtcp2
 * allocator and queue. This fixture assembles stream state without a TLS
 * handshake or packet exchange; it does not mock the credit operation. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ngtcp2_conn.h>
#include <ngtcp2_transport_params.h>
/* The locked internal and public crypto headers share an upstream guard. */
#undef NGTCP2_CRYPTO_H

static void fixture_ring_free(void *pointer);
#define free fixture_ring_free
#include "../src/quic.c"
#undef free

static void *owned_rings[EFRP_QUIC_STREAMS];
static unsigned rings_freed;

static void fixture_ring_free(void *pointer)
{
    for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) {
        if (pointer && pointer == owned_rings[i]) {
            const uint8_t *bytes = pointer;
            for (size_t j = 0; j < sizeof(efrp_quic_stream_t); ++j) assert(bytes[j] == 0);
            owned_rings[i] = NULL;
            ++rings_freed;
        }
    }
    free(pointer);
}

typedef struct {
    ngtcp2_mem allocator;
    ngtcp2_conn *connection;
    size_t allocations;
    unsigned queue_growths, refused_growths;
    uint64_t failed_credit, failed_advertised_credit;
    bool refuse_queue_growth;
} fixture_memory_t;

static void *native_malloc(size_t size, void *context)
{
    fixture_memory_t *memory = context;
    void *pointer = malloc(size);
    if (pointer) ++memory->allocations;
    return pointer;
}
static void *native_calloc(size_t count, size_t size, void *context)
{
    fixture_memory_t *memory = context;
    void *pointer = calloc(count, size);
    if (pointer) ++memory->allocations;
    return pointer;
}
static void native_free(void *pointer, void *context)
{
    fixture_memory_t *memory = context;
    if (pointer) { assert(memory->allocations); --memory->allocations; }
    free(pointer);
}
static void *native_realloc(void *pointer, size_t size, void *context)
{
    fixture_memory_t *memory = context;
    if (memory->connection && !memory->connection->tx.strmq.capacity &&
        pointer == memory->connection->tx.strmq.q &&
        size == 4 * sizeof(ngtcp2_pq_entry *)) {
        ++memory->queue_growths;
        assert(!memory->connection->tx.strmq.length);
        if (memory->refuse_queue_growth) {
            ngtcp2_strm *stream = ngtcp2_conn_find_stream(memory->connection, 0);
            assert(stream && !ngtcp2_strm_is_tx_queued(stream));
            memory->failed_credit = stream->rx.unsent_max_offset;
            memory->failed_advertised_credit = stream->rx.max_offset;
            ++memory->refused_growths;
            return NULL;
        }
    }
    void *replacement = realloc(pointer, size);
    if (replacement && !pointer) ++memory->allocations;
    return replacement;
}

static efrp_transport_t *fixture_transport(fixture_memory_t *memory, int *owned_fd)
{
    memset(owned_rings, 0, sizeof owned_rings);
    rings_freed = 0;
    efrp_quic_transport_t *transport = calloc(1, sizeof *transport);
    assert(transport);
    transport->base.operations = &operations;
    *owned_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(*owned_fd >= 0);
    transport->socket = *owned_fd;
    transport->now = 1000;
    transport->status = (efrp_transport_status_t){.kind = EFRP_TRANSPORT_QUIC,
        .state = EFRP_TRANSPORT_OPEN, .owns_socket = true};
    mbedtls_x509_crt_init(&transport->certificate.ca);
    transport->local = (struct sockaddr_in){.sin_family = AF_INET};
    transport->remote = (struct sockaddr_in){.sin_family = AF_INET};
    ngtcp2_path path = {.local = {(struct sockaddr *)&transport->local, sizeof transport->local},
        .remote = {(struct sockaddr *)&transport->remote, sizeof transport->remote}};
    ngtcp2_settings settings; ngtcp2_settings_default(&settings);
    settings.initial_ts = transport->now * NGTCP2_MILLISECONDS;
    ngtcp2_transport_params parameters; ngtcp2_transport_params_default(&parameters);
    parameters.initial_max_stream_data_bidi_local = EFRP_QUIC_RX_BYTES;
    parameters.initial_max_stream_data_bidi_remote = EFRP_QUIC_RX_BYTES;
    parameters.initial_max_data = EFRP_QUIC_STREAMS * EFRP_QUIC_RX_BYTES;
    ngtcp2_callbacks callbacks = {.client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb, .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb, .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb, .rand = random_bytes,
        .get_new_connection_id2 = new_connection_id, .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb};
    ngtcp2_cid destination = {.datalen = 8}, source = {.datalen = 8};
    destination.data[0] = 1; source.data[0] = 2;
    memory->allocator = (ngtcp2_mem){.user_data = memory, .malloc = native_malloc, .calloc = native_calloc,
        .realloc = native_realloc, .free = native_free};
    assert(!ngtcp2_conn_client_new(&transport->connection, &destination, &source, &path,
        NGTCP2_PROTO_VER_V1, &callbacks, &settings, &parameters, &memory->allocator, transport));
    memory->connection = transport->connection;
    /* Populate the peer's negotiated limits, without creating crypto keys or
     * claiming handshake coverage. The public stream-open API and native
     * stream objects below are unchanged production code. */
    ngtcp2_transport_params remote = parameters;
    remote.initial_max_streams_bidi = EFRP_QUIC_STREAMS;
    assert(!ngtcp2_transport_params_copy_new(&transport->connection->remote.transport_params,
        &remote, transport->connection->mem));
    transport->connection->local.bidi.max_streams = EFRP_QUIC_STREAMS;
    for (unsigned i = 0; i < 2; ++i) {
        efrp_stream_id_t id;
        assert(efrp_stream_open(&transport->base, &id) == EFRP_OK && id == i * UINT64_C(4));
        owned_rings[i] = transport->streams[i];
    }
    assert(!transport->connection->tx.strmq.capacity && !transport->connection->tx.strmq.length);
    return &transport->base;
}

static void receive_bytes(efrp_transport_t *base, const uint8_t *bytes, size_t size)
{
    efrp_quic_transport_t *transport = (efrp_quic_transport_t *)base;
    transport->streams[0]->receive_head = EFRP_QUIC_RX_BYTES - 7;
    assert(!receive_stream(transport->connection, 0, 0, 0, bytes, size, transport, NULL));
}

static void destroy_checked(efrp_transport_t **base, fixture_memory_t *memory, int owned_fd)
{
    assert(efrp_transport_destroy(base) == EFRP_OK && !*base);
    assert(!memory->allocations && rings_freed == 2);
    errno = 0;
    assert(fcntl(owned_fd, F_GETFD) == -1 && errno == EBADF);
}

static void credit_allocation_failure(void)
{
    fixture_memory_t memory = {0}; int owned_fd;
    efrp_transport_t *base = fixture_transport(&memory, &owned_fd);
    uint8_t bytes[EFRP_QUIC_RX_BYTES], output[EFRP_QUIC_RX_BYTES];
    memset(bytes, 0x37, sizeof bytes); memset(output, 0xa5, sizeof output);
    receive_bytes(base, bytes, sizeof bytes);
    memory.refuse_queue_growth = true;
    size_t read = SIZE_MAX;
    efrp_result_t result = efrp_stream_read(base, 0, output, sizeof output, &read);
    fprintf(stderr, "native credit OOM result=%d read=%zu refused=%u unsent=%llu advertised=%llu\n",
        result, read, memory.refused_growths, (unsigned long long)memory.failed_credit,
        (unsigned long long)memory.failed_advertised_credit);
    assert(memory.refused_growths == 1 && memory.queue_growths == 1);
    assert(memory.failed_credit == 2 * EFRP_QUIC_RX_BYTES && memory.failed_advertised_credit == EFRP_QUIC_RX_BYTES);
    assert(result == EFRP_NO_MEMORY && read == 0);
    for (size_t i = 0; i < sizeof output; ++i) assert(output[i] == 0xa5);
    efrp_quic_transport_t *transport = (efrp_quic_transport_t *)base;
    assert(transport->cleaned && !transport->connection && transport->socket == -1);
    for (unsigned i = 0; i < EFRP_QUIC_STREAMS; ++i) assert(!transport->streams[i]);
    efrp_transport_status_t status;
    assert(efrp_transport_status(base, &status) == EFRP_OK && status.result == EFRP_NO_MEMORY);
    assert(status.state == EFRP_TRANSPORT_FAILED && status.tls_error == NGTCP2_ERR_NOMEM);
    assert(!status.owns_socket && !status.pending_tx_bytes && !status.pending_dns);
    read = SIZE_MAX;
    assert(efrp_stream_read(base, 0, output, 1, &read) == EFRP_NO_MEMORY && read == 0);
    destroy_checked(&base, &memory, owned_fd);
    puts("native credit OOM rejects delivery and releases native/ring/socket owners");
}

static void successful_credit(bool closed)
{
    fixture_memory_t memory = {0}; int owned_fd;
    efrp_transport_t *base = fixture_transport(&memory, &owned_fd);
    efrp_quic_transport_t *transport = (efrp_quic_transport_t *)base;
    ngtcp2_strm *native = ngtcp2_conn_find_stream(transport->connection, 0);
    assert(native);
    uint8_t bytes[768], output[1024];
    for (size_t i = 0; i < sizeof bytes; ++i) bytes[i] = (uint8_t)i;
    receive_bytes(base, bytes, sizeof bytes);
    if (closed) {
        transport->streams[0]->remote_fin = true;
        assert(!close_stream(transport->connection, 0, 0, 0, 0, transport, NULL));
        memory.refuse_queue_growth = true;
    }
    uint64_t connection_credit = transport->connection->rx.unsent_max_offset;
    uint64_t stream_credit = native->rx.unsent_max_offset;
    const size_t requests[] = {256, 1, sizeof output};
    size_t delivered = 0;
    for (unsigned i = 0; i < sizeof requests / sizeof requests[0]; ++i) {
        size_t expected = sizeof bytes - delivered; if (expected > requests[i]) expected = requests[i];
        size_t read = SIZE_MAX; memset(output, 0xa5, sizeof output);
        assert(efrp_stream_read(base, 0, output, requests[i], &read) == EFRP_OK && read == expected);
        assert(!memcmp(output, bytes + delivered, expected));
        for (size_t j = expected; j < sizeof output; ++j) assert(output[j] == 0xa5);
        delivered += read;
        assert(transport->connection->rx.unsent_max_offset == connection_credit + delivered);
        assert(native->rx.unsent_max_offset == stream_credit + (closed ? 0 : delivered));
        assert(native->rx.max_offset == EFRP_QUIC_RX_BYTES);
        assert(memory.queue_growths == (closed || i == 0 ? 0u : 1u));
    }
    assert(delivered == sizeof bytes && !memory.refused_growths);
    assert(!transport->streams[0]->receive_used);
    for (size_t i = 0; i < EFRP_QUIC_RX_BYTES; ++i) assert(!transport->streams[0]->receive[i]);
    size_t read = SIZE_MAX;
    assert(efrp_stream_read(base, 0, output, 1, &read) == (closed ? EFRP_EOF : EFRP_WOULD_BLOCK) && read == 0);
    if (!closed) assert(transport->connection->tx.strmq.capacity == 4 && transport->connection->tx.strmq.length == 1);
    destroy_checked(&base, &memory, owned_fd);
    puts(closed ? "closed stream tail preserves delivery/EOF and connection credit" :
        "successful wrapped reads extend both native credits by exact consumed bytes");
}

int main(void)
{
    credit_allocation_failure();
    successful_credit(false);
    successful_credit(true);
    return 0;
}
