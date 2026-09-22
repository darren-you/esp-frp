// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_handshake.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void length_header(uint32_t value, uint8_t out[4])
{
    for (unsigned i = 0; i < 4; ++i) out[i] = (uint8_t)(value >> (24u - i*8u));
}
int main(int argc, char **argv)
{
    assert(argc == 3); size_t step = (size_t)strtoul(argv[1], NULL, 10); assert(step && step <= 100000);
    const uint8_t token[] = "public-handshake-token";
    efrp_handshake_config_t config = {.token = token, .token_length = sizeof token - 1,
        .hostname = "board\"\\\n", .user = "公开测试", .client_id = "fixture", .previous_run_id = "old-id",
        .unix_seconds = strtoll(argv[2], NULL, 10)};
    uint8_t storage[EFRP_HANDSHAKE_RX_BYTES], header[4]; efrp_handshake_t h = {0};
    assert(efrp_handshake_init(&h, &config, storage, sizeof storage, 0) == EFRP_OK);
    const uint8_t *p; size_t n;
    assert(efrp_handshake_output(&h, &p, &n) == EFRP_OK);
    length_header((uint32_t)n, header); assert(fwrite(header, 1, 4, stdout) == 4);
    while (efrp_handshake_output(&h, &p, &n) == EFRP_OK) {
        if (n > 17) n = 17;
        assert(fwrite(p, 1, n, stdout) == n); assert(efrp_handshake_consume_output(&h, n) == EFRP_OK);
    }
    assert(fflush(stdout) == 0 && fread(header, 1, 4, stdin) == 4);
    size_t length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) | ((uint32_t)header[2] << 8) | header[3];
    assert(length <= 100000);
    uint8_t *wire = malloc(length), *rx = malloc(EFRP_AEAD_RX_BYTES), tx[4128], plain[4096]; assert(wire && rx);
    assert(fread(wire, 1, length, stdin) == length && getchar() == EOF);
    efrp_aead_reader_t r = {0}; efrp_aead_writer_t w = {0}; efrp_aead_keys_t keys = {0};
    size_t at = 0, plain_used = 0; int status = 10;
    while (at < length) {
        size_t take = length - at, used; if (take > step) take = step;
        efrp_result_t result;
        if (h.state != EFRP_HANDSHAKE_TAKEN) {
            result = efrp_handshake_feed(&h, wire + at, take, &used);
            if (result != EFRP_OK) goto done;
            at += used;
            if (h.state == EFRP_HANDSHAKE_DONE) {
                char run_id[EFRP_RUN_ID_BYTES];
                assert(efrp_handshake_take_result(&h, &keys, run_id) == EFRP_OK);
                assert(!strcmp(run_id, "0123456789abcdef"));
                assert(efrp_aead_reader_init(&r, keys.server_to_client, rx, EFRP_AEAD_RX_BYTES) == EFRP_OK);
            }
        } else {
            result = efrp_aead_feed(&r, wire + at, take, &used);
            if (result != EFRP_OK && result != EFRP_WOULD_BLOCK) goto done;
            at += used;
            if (efrp_aead_plaintext(&r, &p, &n) == EFRP_OK) {
                assert(n <= sizeof plain - plain_used); memcpy(plain + plain_used, p, n); plain_used += n;
                assert(efrp_aead_consume_plaintext(&r, n) == EFRP_OK);
            }
        }
    }
    if (efrp_handshake_finish(&h) != EFRP_OK || efrp_aead_finish(&r) != EFRP_OK || !plain_used) goto done;
    assert(efrp_aead_writer_init(&w, keys.client_to_server, tx, sizeof tx) == EFRP_OK);
    assert(efrp_aead_write(&w, plain, plain_used, &n) == EFRP_OK && n == plain_used);
    assert(efrp_aead_output(&w, &p, &n) == EFRP_OK && fwrite(p, 1, n, stdout) == n);
    assert(fflush(stdout) == 0); status = 0;
done:
    efrp_aead_clear_keys(&keys); efrp_aead_reader_destroy(&r); efrp_aead_writer_destroy(&w); efrp_handshake_destroy(&h);
    free(wire); free(rx); return status;
}
