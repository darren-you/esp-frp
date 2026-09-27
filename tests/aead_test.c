// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_aead.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void all_zero(const void *bytes, size_t length)
{
    const uint8_t *p = bytes;
    for (size_t i = 0; i < length; ++i) assert(p[i] == 0);
}

int main(void)
{
    static const uint8_t token[] = "esp-frp-public-fixture-token";
    static const uint8_t client[] = " {\"fixture\":\"client\", \"raw\":\"bytes\"} ";
    static const uint8_t server[] = "{\"fixture\": \"server\"}";
    efrp_aead_keys_t keys = {0}, changed = {0};
    assert(efrp_aead_derive(token, sizeof token - 1, client, sizeof client - 1,
                            server, sizeof server - 1, &keys) == EFRP_OK);
    assert(memcmp(keys.client_to_server, keys.server_to_client, 32));
    assert(efrp_aead_derive(token, sizeof token - 1, client + 1, sizeof client - 2,
                            server, sizeof server - 1, &changed) == EFRP_OK);
    assert(memcmp(changed.transcript_hash, keys.transcript_hash, 32));
    assert(efrp_aead_derive(token, 0, client, sizeof client - 1,
                            server, sizeof server - 1, &changed) == EFRP_INVALID_ARGUMENT);
    all_zero(&changed, sizeof changed);

    uint8_t storage[4128];
    efrp_aead_writer_t writer = {0};
    assert(efrp_aead_writer_init(&writer, keys.client_to_server, storage, 32) == EFRP_INVALID_ARGUMENT);
    assert(efrp_aead_writer_init(&writer, keys.client_to_server, storage, sizeof storage) == EFRP_OK);
    assert(efrp_aead_writer_init(&writer, keys.client_to_server, storage, sizeof storage) == EFRP_INVALID_STATE);
    const uint8_t plaintext[] = "authenticated control record";
    size_t written = 0, length = 0;
    const uint8_t *output = NULL;
    assert(efrp_aead_write(&writer, NULL, 0, &written) == EFRP_OK && !written);
    assert(efrp_aead_write(&writer, plaintext, sizeof plaintext - 1, &written) == EFRP_OK);
    assert(written == sizeof plaintext - 1);
    assert(efrp_aead_output(&writer, &output, &length) == EFRP_OK && length == written + 32);
    assert(efrp_aead_write(&writer, plaintext, 1, &written) == EFRP_WOULD_BLOCK && !written);
    assert(efrp_aead_consume_output(&writer, length + 1) == EFRP_INVALID_ARGUMENT);
    while (efrp_aead_output(&writer, &output, &length) == EFRP_OK) {
        size_t take = length > 7 ? 7 : length;
        assert(efrp_aead_consume_output(&writer, take) == EFRP_OK);
    }
    all_zero(storage, sizeof storage);
    writer.records = EFRP_AEAD_MAX_RECORDS;
    assert(efrp_aead_write(&writer, plaintext, 1, &written) == EFRP_COUNTER_EXHAUSTED && !written);
    efrp_aead_writer_destroy(&writer);
    all_zero(&writer, sizeof writer);
    all_zero(storage, sizeof storage);

    uint8_t previous_nonce[12] = {0};
    for (unsigned cycle = 0; cycle < 100; ++cycle) {
        efrp_aead_writer_t next = {0};
        assert(efrp_aead_writer_init(&next, keys.client_to_server, storage, sizeof storage) == EFRP_OK);
        assert(memcmp(previous_nonce, next.stream_nonce, sizeof previous_nonce));
        memcpy(previous_nonce, next.stream_nonce, sizeof previous_nonce);
        efrp_aead_writer_destroy(&next);
        all_zero(storage, sizeof storage);
    }
    efrp_aead_clear_keys(&keys);
    all_zero(&keys, sizeof keys);
    puts("AEAD key derivation and sender boundaries passed; receiver is Flash-only");
    return 0;
}
