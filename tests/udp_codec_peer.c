// SPDX-License-Identifier: Apache-2.0
#include "esp_frp_udp.h"
#include "esp_frp_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool read_u32(uint32_t *value)
{
    uint8_t bytes[4];
    if (fread(bytes, 1, sizeof bytes, stdin) != sizeof bytes) return false;
    *value = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
    return true;
}

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

static bool fixture(uint32_t id, uint8_t *payload, uint8_t zone[255], efrp_udp_packet_t *packet)
{
    static const size_t sizes[] = {0, 1, 32, 128, 512, 1200, 1472, 4096, 49107, 65507};
    static const uint8_t text_zone[] = {'e', 'n', '0', 0, 0xe4, 0xb8, 0xad, 0xf4, 0x8f, 0xbf, 0xbf};
    if (id >= 45) return false;
    *packet = (efrp_udp_packet_t){.remote_address = ipv4(54321), .payload = payload};
    if (id < 40) {
        packet->payload_length = sizes[id % 10];
        if (id >= 10 && id < 20) packet->remote_address = ipv6(1, NULL, 0);
        if (id >= 20) {
            packet->has_local_address = true; packet->local_address = ipv4(0);
        }
        if (id >= 30) {
            packet->local_address = ipv6(65535, (const uint8_t *)"en0", 3);
            packet->remote_address = ipv6(1, NULL, 0);
            if (id == 39) packet->payload_length = 65488;
        }
    } else if (id == 40) {
        memset(zone, 'z', 255);
        packet->has_local_address = true; packet->local_address = ipv6(0, zone, 255);
        packet->remote_address = ipv6(65535, zone, 255);
    } else if (id == 41) {
        packet->remote_address = (efrp_udp_address_t){.family = EFRP_UDP_IPV6,
            .ip = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 9}, .port = 54321};
        packet->payload_length = 1472;
    } else if (id == 42) {
        packet->remote_address = ipv6(0, (const uint8_t *)"abcd", 4); packet->payload_length = 65507;
    } else if (id == 43) {
        packet->has_local_address = true; packet->local_address = ipv6(65535, text_zone, sizeof text_zone);
        packet->payload_length = 1472;
    } else {
        packet->has_local_address = true; packet->local_address = ipv4(65535); packet->remote_address = ipv4(0);
    }
    for (size_t i = 0; i < packet->payload_length; ++i) payload[i] = (uint8_t)(i * 31 + id);
    return true;
}

int main(void)
{
    uint8_t *input = malloc(EFRP_WIRE_MAX_PAYLOAD), *output = malloc(EFRP_WIRE_MAX_PAYLOAD);
    uint8_t *payload = malloc(EFRP_UDP_MAX_PAYLOAD_SIZE), zone[255];
    if (!input || !output || !payload) { free(input); free(output); free(payload); return 2; }
    efrp_udp_packet_t packet;
    uint32_t value; size_t length = 0; int operation = fgetc(stdin), result = 10;
    if (!read_u32(&value)) goto done;
    if (operation == 0) {
        if (value > EFRP_WIRE_MAX_PAYLOAD || fread(input, 1, value, stdin) != value ||
            efrp_udp_packet_decode(input, value, &packet) != EFRP_OK) goto done;
    } else if (operation == 1) {
        if (!fixture(value, payload, zone, &packet)) goto done;
    } else goto done;
    if (fgetc(stdin) != EOF || efrp_udp_packet_encode(&packet, output, EFRP_WIRE_MAX_PAYLOAD, &length) != EFRP_OK) goto done;
    if (fwrite(output, 1, length, stdout) != length) { result = 2; goto done; }
    result = 0;
done:
    free(input); free(output); free(payload);
    return result;
}
