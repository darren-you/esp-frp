// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_udp.h"
#include "esp_frp_wire.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static efrp_udp_address_t ipv4(uint16_t port)
{
    return (efrp_udp_address_t){.family = EFRP_UDP_IPV4, .ip = {203, 0, 113, 9}, .port = port};
}

static efrp_udp_address_t ipv6(uint16_t port, const uint8_t *zone, size_t length)
{
    return (efrp_udp_address_t){.family = EFRP_UDP_IPV6,
        .ip = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        .port = port, .zone = zone, .zone_length = length};
}

static void unchanged_encode(const efrp_udp_packet_t *packet, size_t capacity, efrp_result_t expected)
{
    uint8_t output[128]; memset(output, 0xa5, sizeof output);
    size_t length = 99;
    assert(efrp_udp_packet_encode(packet, output, capacity, &length) == expected && !length);
    for (size_t i = 0; i < sizeof output; ++i) assert(output[i] == 0xa5);
}

static void rejected(const uint8_t *input, size_t length, efrp_result_t expected)
{
    efrp_udp_packet_t packet; memset(&packet, 0xa5, sizeof packet);
    assert(efrp_udp_packet_decode(input, length, &packet) == expected);
    assert(!packet.payload && !packet.payload_length && !packet.has_local_address &&
        !packet.local_address.family && !packet.remote_address.family && !packet.remote_address.zone);
}

int main(void)
{
    uint8_t *output = malloc(EFRP_WIRE_MAX_PAYLOAD + 1);
    uint8_t *payload = malloc(EFRP_UDP_MAX_PAYLOAD_SIZE + 1);
    assert(output && payload);
    for (size_t i = 0; i <= EFRP_UDP_MAX_PAYLOAD_SIZE; ++i) payload[i] = (uint8_t)(i * 31 + 7);
    efrp_udp_packet_t packet = {.remote_address = ipv4(54321), .payload = payload, .payload_length = 3};
    size_t length;
    assert(efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) == EFRP_OK);
    const uint8_t golden[] = {0, 19, 2, 4, 203, 0, 113, 9, 0xd4, 0x31, 0, 0, 3, 7, 38, 69};
    assert(length == sizeof golden && !memcmp(output, golden, length));
    efrp_udp_packet_t decoded;
    assert(efrp_udp_packet_decode(golden, sizeof golden, &decoded) == EFRP_OK);
    assert(!decoded.has_local_address && decoded.remote_address.port == 54321 &&
        decoded.remote_address.family == EFRP_UDP_IPV4 && decoded.payload_length == 3 && decoded.payload == golden + 13);
    for (size_t n = 0; n < sizeof golden; ++n) rejected(golden, n, EFRP_TRUNCATED);
    for (size_t n = 0; n <= sizeof golden; ++n) {
        size_t offset = 99;
        assert(efrp_udp_packet_header_decode(golden, n, sizeof golden, &decoded, &offset) ==
            (n < 13 ? EFRP_WOULD_BLOCK : EFRP_OK));
        if (n < 13) assert(!offset && !decoded.payload && !decoded.remote_address.family);
        else assert(offset == 13 && !decoded.payload && decoded.payload_length == 3);
    }
    const size_t sizes[] = {0, 1, 32, 128, 512, 1200, 1472, 4096, 49107, 65507};
    const uint8_t zone[] = {'e', 'n', '0', 0, 0xe4, 0xb8, 0xad, 0xf4, 0x8f, 0xbf, 0xbf};
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        packet.has_local_address = scenario >= 2;
        packet.local_address = scenario == 2 ? ipv4(0) : ipv6(65535, zone, sizeof zone);
        packet.remote_address = scenario % 2 ? ipv6(1, NULL, 0) : ipv4(54321);
        for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; ++i) {
            packet.payload_length = sizes[i]; packet.payload = sizes[i] ? payload : NULL;
            size_t total = 5 + (scenario % 2 ? 20 : 8) + (scenario == 2 ? 8 : scenario == 3 ? 20 + sizeof zone : 0) + sizes[i];
            efrp_result_t result = efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length);
            if (total > EFRP_WIRE_MAX_PAYLOAD) { assert(result == EFRP_CAPACITY_EXCEEDED && !length); continue; }
            assert(result == EFRP_OK && length == total);
            assert(efrp_udp_packet_decode(output, length, &decoded) == EFRP_OK);
            assert(decoded.has_local_address == packet.has_local_address && decoded.payload_length == sizes[i]);
            if (sizes[i]) assert(!memcmp(decoded.payload, payload, sizes[i]));
            assert(decoded.remote_address.family == packet.remote_address.family &&
                decoded.remote_address.port == packet.remote_address.port &&
                !memcmp(decoded.remote_address.ip, packet.remote_address.ip, scenario % 2 ? 16 : 4));
            if (scenario == 3) {
                assert(decoded.local_address.zone_length == sizeof zone &&
                    !memcmp(decoded.local_address.zone, zone, sizeof zone));
                assert(decoded.local_address.zone >= output && decoded.local_address.zone < output + length);
            }
        }
    }
    /* Both independent limits: legal 65507-byte datagram and exact 65536-byte frame. */
    const uint8_t boundary_zone[] = {'a', 'b', 'c', 'd', 'e'};
    packet = (efrp_udp_packet_t){.remote_address = ipv6(0, boundary_zone, 4), .payload = payload, .payload_length = 65507};
    assert(efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) == EFRP_OK && length == 65536);
    assert(efrp_udp_packet_decode(output, length, &decoded) == EFRP_OK && decoded.payload_length == 65507);
    packet.remote_address.zone_length = 5;
    unchanged_encode(&packet, sizeof golden, EFRP_CAPACITY_EXCEEDED);
    packet.remote_address = ipv4(1); packet.payload_length = 65508;
    unchanged_encode(&packet, sizeof golden, EFRP_CAPACITY_EXCEEDED);
    packet.payload_length = 3; unchanged_encode(&packet, sizeof golden - 1, EFRP_CAPACITY_EXCEEDED);
    packet.payload = NULL; unchanged_encode(&packet, sizeof golden, EFRP_INVALID_ARGUMENT);
    packet.payload_length = 0; packet.remote_address.family = 0;
    unchanged_encode(&packet, sizeof golden, EFRP_INVALID_ARGUMENT);
    packet.remote_address = ipv4(1); packet.remote_address.zone = zone; packet.remote_address.zone_length = 1;
    unchanged_encode(&packet, sizeof golden, EFRP_INVALID_ARGUMENT);
    const uint8_t *invalid[] = {(const uint8_t *)"\xc0\x80", (const uint8_t *)"\xed\xa0\x80",
        (const uint8_t *)"\xf4\x90\x80\x80", (const uint8_t *)"\xc2", (const uint8_t *)"\xff"};
    const size_t invalid_lengths[] = {2, 3, 4, 1, 1};
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        packet.remote_address = ipv6(1, invalid[i], invalid_lengths[i]);
        unchanged_encode(&packet, sizeof golden, EFRP_INVALID_ARGUMENT);
    }
    uint8_t large_zone[256]; memset(large_zone, 'z', sizeof large_zone);
    packet.remote_address = ipv6(1, large_zone, 256);
    unchanged_encode(&packet, sizeof golden, EFRP_INVALID_ARGUMENT);
    packet.remote_address.zone_length = 255;
    assert(efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) == EFRP_OK);
    assert(efrp_udp_packet_decode(output, length, &decoded) == EFRP_OK && decoded.remote_address.zone_length == 255);
    for (size_t n = 0; n < length; ++n) rejected(output, n, EFRP_TRUNCATED);
    packet.has_local_address = true; packet.local_address = ipv6(65535, large_zone, 255);
    packet.payload = payload; packet.payload_length = 1;
    assert(efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) == EFRP_OK &&
        length == EFRP_UDP_MAX_HEADER_SIZE + 1);
    for (size_t n = 0; n <= EFRP_UDP_MAX_HEADER_SIZE; ++n) {
        size_t payload_offset = 99;
        assert(efrp_udp_packet_header_decode(output, n, length, &decoded, &payload_offset) ==
            (n == EFRP_UDP_MAX_HEADER_SIZE ? EFRP_OK : EFRP_WOULD_BLOCK));
        if (n == EFRP_UDP_MAX_HEADER_SIZE)
            assert(payload_offset == EFRP_UDP_MAX_HEADER_SIZE && decoded.payload_length == 1 && !decoded.payload);
        else assert(!payload_offset && !decoded.remote_address.family);
    }
    /* IPv4-mapped IPv6 is canonicalized by the official encoder. */
    packet.has_local_address = false;
    packet.remote_address = (efrp_udp_address_t){.family = EFRP_UDP_IPV6,
        .ip = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 9}, .port = 54321};
    packet.payload = payload; packet.payload_length = 3;
    assert(efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) == EFRP_OK &&
        length == sizeof golden && !memcmp(output, golden, length));
    packet.remote_address.zone = zone; packet.remote_address.zone_length = 1;
    unchanged_encode(&packet, sizeof golden, EFRP_INVALID_ARGUMENT);
    uint8_t bad[64];
    for (unsigned mutation = 0; mutation < 7; ++mutation) {
        memcpy(bad, golden, sizeof golden);
        efrp_result_t expected = EFRP_PROTOCOL_ERROR; size_t n = sizeof golden;
        if (mutation == 0) bad[1] = 18;
        if (mutation == 1) bad[2] |= 4;
        if (mutation == 2) bad[2] = 0;
        if (mutation == 3) bad[3] = 5;
        if (mutation == 4) { bad[10] = 1; bad[11] = 'z'; }
        if (mutation == 5) { bad[11] = 0xff; bad[12] = 0xff; expected = EFRP_CAPACITY_EXCEEDED; }
        if (mutation == 6) bad[n++] = 0;
        rejected(bad, n, expected);
    }
    packet = (efrp_udp_packet_t){.remote_address = ipv6(1, zone, sizeof zone)};
    assert(efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) == EFRP_OK);
    output[23] = 0xff; rejected(output, length, EFRP_PROTOCOL_ERROR);
    assert(efrp_udp_packet_decode(NULL, 1, &decoded) == EFRP_INVALID_ARGUMENT);
    assert(efrp_udp_packet_decode(output, 65537, &decoded) == EFRP_CAPACITY_EXCEEDED);
    assert(efrp_udp_packet_decode(output, length, NULL) == EFRP_INVALID_ARGUMENT);
    assert(efrp_udp_packet_encode(NULL, output, 65536, &length) == EFRP_INVALID_ARGUMENT && !length);
    size_t offset;
    assert(efrp_udp_packet_header_decode(golden, sizeof golden, sizeof golden - 1, &decoded, &offset) == EFRP_INVALID_ARGUMENT);
    assert(efrp_udp_packet_header_decode(golden, 13, sizeof golden + 1, &decoded, &offset) == EFRP_PROTOCOL_ERROR && !offset);
    assert(efrp_udp_packet_header_decode(golden, 13, sizeof golden - 1, &decoded, &offset) == EFRP_TRUNCATED && !offset);
    /* Deterministic untrusted prefixes exercise all paths under ASan/UBSan. */
    uint32_t random = 0x12345678;
    for (unsigned round = 0; round < 20000; ++round) {
        size_t n = round % sizeof bad;
        for (size_t i = 0; i < n; ++i) { random = random * 1664525u + 1013904223u; bad[i] = (uint8_t)(random >> 24); }
        efrp_result_t result = efrp_udp_packet_decode(bad, n, &decoded);
        assert(result == EFRP_OK || result == EFRP_PROTOCOL_ERROR || result == EFRP_TRUNCATED || result == EFRP_CAPACITY_EXCEEDED);
    }
    free(output); free(payload);
    return 0;
}
