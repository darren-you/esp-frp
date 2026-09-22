// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_tls.h"
#include "crypto_backend.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(MBEDTLS_HAVE_TIME_DATE) || !defined(MBEDTLS_HAVE_TIME)
#error "ESP FRP requires certificate date verification: CONFIG_MBEDTLS_HAVE_TIME_DATE=y"
#endif
#if !defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) || !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#error "ESP FRP requires SNI and TLS 1.2 support"
#endif

struct efrp_tls {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt ca;
    efrp_tls_send_t send;
    efrp_tls_recv_t recv;
    void *io_context;
    efrp_tls_status_t status;
    uint8_t pending[EFRP_TLS_TX_BYTES];
    size_t used, offset;
    uint64_t last_now, deadline, write_deadline;
    bool resources, io_failed;
};

static void release(efrp_tls_t *t)
{
    if (t->resources) {
        mbedtls_ssl_free(&t->ssl); mbedtls_ssl_config_free(&t->config); mbedtls_x509_crt_free(&t->ca);
        t->resources = false;
    }
    efrp_crypto_zero(t->pending, sizeof t->pending); t->used = t->offset = 0;
    t->send = NULL; t->recv = NULL; t->io_context = NULL;
    t->status.pending_bytes = 0; t->status.want = EFRP_TLS_WANT_NONE;
}
static efrp_result_t fail(efrp_tls_t *t, efrp_result_t result, int error)
{
    t->status.result = result; t->status.library_error = error; t->status.state = EFRP_TLS_FAILED;
    if (t->resources) t->status.verify_flags = mbedtls_ssl_get_verify_result(&t->ssl);
    release(t); return result;
}
static efrp_result_t check(efrp_tls_t *t, uint64_t now)
{
    if (!t) return EFRP_INVALID_ARGUMENT;
    if (t->status.result != EFRP_OK) return t->status.result;
    if (now < t->last_now || now > UINT64_MAX - EFRP_TLS_HANDSHAKE_MS) return EFRP_INVALID_ARGUMENT;
    t->last_now = now;
    if (t->status.state == EFRP_TLS_CLOSED) return EFRP_EOF;
    if (((t->status.state == EFRP_TLS_HANDSHAKING || t->status.state == EFRP_TLS_CLOSING) && now >= t->deadline) ||
        (t->used && now >= t->write_deadline)) return fail(t, EFRP_TIMEOUT, 0);
    return EFRP_OK;
}
static int send_bytes(void *context, const unsigned char *bytes, size_t length)
{
    efrp_tls_t *t = context; size_t n = 0;
    efrp_result_t result = t->send(t->io_context, bytes, length, &n);
    if (result == EFRP_OK && n && n <= length && n <= INT_MAX) return (int)n;
    if (result == EFRP_WOULD_BLOCK && !n) return MBEDTLS_ERR_SSL_WANT_WRITE;
    t->io_failed = true; return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int recv_bytes(void *context, unsigned char *bytes, size_t length)
{
    efrp_tls_t *t = context; size_t n = 0;
    efrp_result_t result = t->recv(t->io_context, bytes, length, &n);
    if (result == EFRP_OK && n && n <= length && n <= INT_MAX) return (int)n;
    if (result == EFRP_WOULD_BLOCK && !n) return MBEDTLS_ERR_SSL_WANT_READ;
    if (result == EFRP_EOF && !n) return MBEDTLS_ERR_SSL_CONN_EOF;
    t->io_failed = true; return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static efrp_result_t interpret(efrp_tls_t *t, int code)
{
    t->status.want = EFRP_TLS_WANT_NONE;
    if (code == MBEDTLS_ERR_SSL_WANT_READ || code == MBEDTLS_ERR_SSL_WANT_WRITE) {
        t->status.want = code == MBEDTLS_ERR_SSL_WANT_READ ? EFRP_TLS_WANT_READ : EFRP_TLS_WANT_WRITE;
        return EFRP_WOULD_BLOCK;
    }
    if (code == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS || code == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS)
        return EFRP_WOULD_BLOCK;
    if (code >= 0) return EFRP_OK;
    if (t->io_failed) return fail(t, EFRP_NETWORK_ERROR, code);
    if (code == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        t->status.state = EFRP_TLS_CLOSED; release(t); return EFRP_EOF;
    }
    if (code == MBEDTLS_ERR_SSL_CONN_EOF) return fail(t, EFRP_TRUNCATED, code);
    uint32_t flags = mbedtls_ssl_get_verify_result(&t->ssl);
    if (code == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || (flags != UINT32_MAX && flags))
        return fail(t, EFRP_TLS_TRUST_ERROR, code);
    if (code == PSA_ERROR_INSUFFICIENT_MEMORY) return fail(t, EFRP_NO_MEMORY, code);
    return fail(t, EFRP_TLS_ERROR, code);
}
static bool valid_hostname(const char *host)
{
    if (!host) return false;
    size_t n = 0;
    while (n <= 253 && host[n]) {
        unsigned char c = (unsigned char)host[n++];
        if (c <= 32 || c >= 127 || c == '/' || c == '\\' || c == '*' || c == '@') return false;
    }
    return n && n <= 253;
}
efrp_result_t efrp_tls_create(const efrp_tls_config_t *c, uint64_t now, efrp_tls_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    if (!c || !valid_hostname(c->hostname) || !c->ca_pem || !c->ca_length || c->ca_length > EFRP_TLS_MAX_CA_BYTES ||
        memchr(c->ca_pem, 0, c->ca_length) || !c->send || !c->recv || now > UINT64_MAX - EFRP_TLS_HANDSHAKE_MS)
        return EFRP_INVALID_ARGUMENT;
    if (!c->time_is_trusted || time(NULL) < (time_t)1704067200) return EFRP_TIME_UNTRUSTED;
    psa_status_t initialized = psa_crypto_init();
    if (initialized != PSA_SUCCESS)
        return initialized == PSA_ERROR_INSUFFICIENT_MEMORY ? EFRP_NO_MEMORY : EFRP_CRYPTO_ERROR;
    efrp_tls_t *t = calloc(1, sizeof *t);
    if (!t) return EFRP_NO_MEMORY;
    mbedtls_ssl_init(&t->ssl); mbedtls_ssl_config_init(&t->config); mbedtls_x509_crt_init(&t->ca);
    t->resources = true; t->status.verify_flags = UINT32_MAX;
    t->status.state = EFRP_TLS_HANDSHAKING; t->deadline = now + EFRP_TLS_HANDSHAKE_MS; t->last_now = now;
    uint8_t *pem = malloc(c->ca_length + 1);
    if (!pem) { efrp_tls_destroy(t); return EFRP_NO_MEMORY; }
    memcpy(pem, c->ca_pem, c->ca_length); pem[c->ca_length] = 0;
    int code = mbedtls_x509_crt_parse(&t->ca, pem, c->ca_length + 1);
    free(pem);
    if (code != 0) { efrp_tls_destroy(t); return code == PSA_ERROR_INSUFFICIENT_MEMORY ? EFRP_NO_MEMORY : EFRP_TLS_TRUST_ERROR; }
    code = mbedtls_ssl_config_defaults(&t->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (code != 0) { efrp_tls_destroy(t); return code == PSA_ERROR_INSUFFICIENT_MEMORY ? EFRP_NO_MEMORY : EFRP_TLS_ERROR; }
    mbedtls_ssl_conf_authmode(&t->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&t->config, &t->ca, NULL);
    mbedtls_ssl_conf_min_tls_version(&t->config, MBEDTLS_SSL_VERSION_TLS1_2);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_conf_max_tls_version(&t->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(&t->config, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
#else
    mbedtls_ssl_conf_max_tls_version(&t->config, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets(&t->config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&t->config, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif
    code = mbedtls_ssl_setup(&t->ssl, &t->config);
    if (!code) code = mbedtls_ssl_set_hostname(&t->ssl, c->hostname);
    if (code) { efrp_tls_destroy(t); return code == PSA_ERROR_INSUFFICIENT_MEMORY ? EFRP_NO_MEMORY : EFRP_TLS_ERROR; }
    t->send = c->send; t->recv = c->recv; t->io_context = c->io_context;
    mbedtls_ssl_set_bio(&t->ssl, t, send_bytes, recv_bytes, NULL);
    *out = t; return EFRP_OK;
}
efrp_result_t efrp_tls_step(efrp_tls_t *t, uint64_t now)
{
    efrp_result_t result = check(t, now); if (result != EFRP_OK) return result;
    t->status.want = EFRP_TLS_WANT_NONE;
    if (t->status.state == EFRP_TLS_HANDSHAKING) {
        result = interpret(t, mbedtls_ssl_handshake_step(&t->ssl));
        if (result != EFRP_OK) return result;
        if (!mbedtls_ssl_is_handshake_over(&t->ssl)) return EFRP_WOULD_BLOCK;
        t->status.verify_flags = mbedtls_ssl_get_verify_result(&t->ssl);
        if (t->status.verify_flags) return fail(t, EFRP_TLS_TRUST_ERROR, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
        t->status.negotiated_version = (uint16_t)mbedtls_ssl_get_version_number(&t->ssl);
        t->status.state = EFRP_TLS_OPEN; return EFRP_OK;
    }
    if (t->used) {
        int n = mbedtls_ssl_write(&t->ssl, t->pending + t->offset, t->used - t->offset);
        result = interpret(t, n); if (result != EFRP_OK) return result;
        if (!n || (size_t)n > t->used - t->offset) return fail(t, EFRP_TLS_ERROR, n);
        efrp_crypto_zero(t->pending + t->offset, (size_t)n); t->offset += (size_t)n;
        if (t->offset == t->used) t->offset = t->used = 0;
        t->status.pending_bytes = t->used - t->offset;
        return t->used ? EFRP_WOULD_BLOCK : EFRP_OK;
    }
    if (t->status.state == EFRP_TLS_CLOSING) {
        result = interpret(t, mbedtls_ssl_close_notify(&t->ssl));
        if (result == EFRP_OK) { t->status.state = EFRP_TLS_CLOSED; release(t); return EFRP_EOF; }
        return result;
    }
    return EFRP_OK;
}
efrp_result_t efrp_tls_read(efrp_tls_t *t, uint64_t now, uint8_t *bytes, size_t capacity, size_t *received)
{
    if (received) *received = 0;
    if (!bytes || !capacity || !received) return EFRP_INVALID_ARGUMENT;
    efrp_result_t result = check(t, now); if (result != EFRP_OK) return result;
    if (t->status.state != EFRP_TLS_OPEN || t->used) return EFRP_WOULD_BLOCK;
    int n = mbedtls_ssl_read(&t->ssl, bytes, capacity);
    result = interpret(t, n); if (result != EFRP_OK) return result;
    if (!n) return fail(t, EFRP_TRUNCATED, 0);
    if ((size_t)n > capacity) return fail(t, EFRP_TLS_ERROR, n);
    *received = (size_t)n; return EFRP_OK;
}
efrp_result_t efrp_tls_write(efrp_tls_t *t, uint64_t now, const uint8_t *bytes, size_t length, size_t *accepted)
{
    if (accepted) *accepted = 0;
    if ((!bytes && length) || !accepted) return EFRP_INVALID_ARGUMENT;
    efrp_result_t result = check(t, now); if (result != EFRP_OK) return result;
    if (t->status.state != EFRP_TLS_OPEN) return EFRP_INVALID_STATE;
    if (!length) return EFRP_OK;
    if (t->used) return EFRP_WOULD_BLOCK;
    size_t n = length < sizeof t->pending ? length : sizeof t->pending;
    memcpy(t->pending, bytes, n); t->used = n; t->offset = 0; t->write_deadline = now + EFRP_TLS_IO_MS;
    t->status.pending_bytes = n; t->status.want = EFRP_TLS_WANT_NONE; *accepted = n; return EFRP_OK;
}
efrp_result_t efrp_tls_close(efrp_tls_t *t, uint64_t now)
{
    efrp_result_t result = check(t, now); if (result != EFRP_OK) return result;
    if (t->status.state == EFRP_TLS_OPEN) { t->status.state = EFRP_TLS_CLOSING; t->deadline = now + EFRP_TLS_IO_MS; }
    if (t->status.state != EFRP_TLS_CLOSING) return EFRP_INVALID_STATE;
    return efrp_tls_step(t, now);
}
efrp_result_t efrp_tls_cancel(efrp_tls_t *t)
{
    if (!t) return EFRP_INVALID_ARGUMENT;
    if (t->status.state == EFRP_TLS_FAILED) return t->status.result;
    if (t->status.state == EFRP_TLS_CLOSED) return EFRP_EOF;
    return fail(t, EFRP_CANCELLED, 0);
}
efrp_result_t efrp_tls_status(const efrp_tls_t *t, efrp_tls_status_t *status)
{
    if (!t || !status) return EFRP_INVALID_ARGUMENT;
    *status = t->status; return EFRP_OK;
}
void efrp_tls_destroy(efrp_tls_t *t)
{
    if (!t) return;
    release(t); efrp_crypto_zero(t, sizeof *t); free(t);
}
