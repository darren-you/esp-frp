// SPDX-License-Identifier: Apache-2.0
// Protocol reference: fatedier/frp v0.71.0 pkg/msg/udp_binary.go.
// Independent, allocation-free codec with caller-owned output and borrowed input.
#include "esp_frp_udp.h"
#include "esp_frp_wire.h"
#include <string.h>

#define UDP_FLAG_LOCAL 1u
#define UDP_FLAG_REMOTE 2u

static bool valid_utf8(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length;) {
        uint8_t first = bytes[i++];
        if (first < 0x80) continue;
        unsigned count;
        uint8_t low = 0x80, high = 0xbf;
        if (first >= 0xc2 && first <= 0xdf) count = 1;
        else if (first >= 0xe0 && first <= 0xef) {
            count = 2;
            if (first == 0xe0) low = 0xa0;
            if (first == 0xed) high = 0x9f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3;
            if (first == 0xf0) low = 0x90;
            if (first == 0xf4) high = 0x8f;
        } else return false;
        if (length - i < count || bytes[i] < low || bytes[i] > high) return false;
        ++i;
        for (unsigned continuation = 1; continuation < count; ++continuation, ++i)
            if (bytes[i] < 0x80 || bytes[i] > 0xbf) return false;
    }
    return true;
}

static bool mapped_ipv4(const efrp_udp_address_t *address)
{
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return address->family == EFRP_UDP_IPV6 && !memcmp(address->ip, prefix, sizeof prefix);
}

static efrp_result_t address_size(const efrp_udp_address_t *address, size_t *length)
{
    if (address->family != EFRP_UDP_IPV4 && address->family != EFRP_UDP_IPV6)
        return EFRP_INVALID_ARGUMENT;
    if (address->zone_length > EFRP_UDP_MAX_ZONE_SIZE ||
        (!address->zone && address->zone_length) ||
        ((address->family == EFRP_UDP_IPV4 || mapped_ipv4(address)) && address->zone_length) ||
        !valid_utf8(address->zone, address->zone_length)) return EFRP_INVALID_ARGUMENT;
    *length = 4 + ((address->family == EFRP_UDP_IPV4 || mapped_ipv4(address)) ? 4 : 16) + address->zone_length;
    return EFRP_OK;
}

static void put_u16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value;
}

static uint16_t get_u16(const uint8_t *input)
{
    return (uint16_t)((uint16_t)input[0] << 8 | input[1]);
}

static void put_address(uint8_t *output, size_t *offset, const efrp_udp_address_t *address)
{
    bool mapped = mapped_ipv4(address);
    bool ipv4 = address->family == EFRP_UDP_IPV4 || mapped;
    size_t ip_length = ipv4 ? 4 : 16;
    output[(*offset)++] = ipv4 ? EFRP_UDP_IPV4 : EFRP_UDP_IPV6;
    memcpy(output + *offset, address->ip + (mapped ? 12 : 0), ip_length); *offset += ip_length;
    put_u16(output + *offset, address->port); *offset += 2;
    output[(*offset)++] = (uint8_t)address->zone_length;
    if (address->zone_length) memcpy(output + *offset, address->zone, address->zone_length);
    *offset += address->zone_length;
}

efrp_result_t efrp_udp_packet_encode(const efrp_udp_packet_t *packet,
                                    uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (!packet || !output || !length || (!packet->payload && packet->payload_length))
        return EFRP_INVALID_ARGUMENT;
    if (packet->payload_length > EFRP_UDP_MAX_PAYLOAD_SIZE) return EFRP_CAPACITY_EXCEEDED;
    size_t remote_length, local_length = 0;
    efrp_result_t result = address_size(&packet->remote_address, &remote_length);
    if (result != EFRP_OK) return result;
    if (packet->has_local_address) {
        result = address_size(&packet->local_address, &local_length);
        if (result != EFRP_OK) return result;
    }
    size_t total = 5 + local_length + remote_length + packet->payload_length;
    if (total > EFRP_WIRE_MAX_PAYLOAD || total > capacity) return EFRP_CAPACITY_EXCEEDED;
    put_u16(output, EFRP_UDP_BINARY_TYPE);
    output[2] = UDP_FLAG_REMOTE | (packet->has_local_address ? UDP_FLAG_LOCAL : 0);
    size_t offset = 3;
    if (packet->has_local_address) put_address(output, &offset, &packet->local_address);
    put_address(output, &offset, &packet->remote_address);
    put_u16(output + offset, (uint16_t)packet->payload_length); offset += 2;
    if (packet->payload_length) memcpy(output + offset, packet->payload, packet->payload_length);
    *length = total;
    return EFRP_OK;
}

static efrp_result_t read_address(const uint8_t *input, size_t length, size_t *offset,
                                 efrp_udp_address_t *address)
{
    if (*offset == length) return EFRP_TRUNCATED;
    address->family = input[(*offset)++];
    size_t ip_length;
    if (address->family == EFRP_UDP_IPV4) ip_length = 4;
    else if (address->family == EFRP_UDP_IPV6) ip_length = 16;
    else return EFRP_PROTOCOL_ERROR;
    if (length - *offset < ip_length + 3) return EFRP_TRUNCATED;
    memcpy(address->ip, input + *offset, ip_length); *offset += ip_length;
    address->port = get_u16(input + *offset); *offset += 2;
    address->zone_length = input[(*offset)++];
    if (length - *offset < address->zone_length) return EFRP_TRUNCATED;
    if ((address->family == EFRP_UDP_IPV4 && address->zone_length) ||
        !valid_utf8(input + *offset, address->zone_length)) return EFRP_PROTOCOL_ERROR;
    if (address->zone_length) address->zone = input + *offset;
    *offset += address->zone_length;
    return EFRP_OK;
}

efrp_result_t efrp_udp_packet_header_decode(const uint8_t *input, size_t length,
                                           size_t frame_length,
                                           efrp_udp_packet_t *packet, size_t *payload_offset)
{
    if (payload_offset) *payload_offset = 0;
    if (!packet) return EFRP_INVALID_ARGUMENT;
    *packet = (efrp_udp_packet_t){0};
    if (!payload_offset || (!input && length) || length > frame_length) return EFRP_INVALID_ARGUMENT;
    if (frame_length > EFRP_WIRE_MAX_PAYLOAD) return EFRP_CAPACITY_EXCEEDED;
    efrp_result_t incomplete = length < frame_length ? EFRP_WOULD_BLOCK : EFRP_TRUNCATED;
    if (length < 3) return incomplete;
    if (get_u16(input) != EFRP_UDP_BINARY_TYPE ||
        (input[2] & ~(UDP_FLAG_LOCAL | UDP_FLAG_REMOTE)) || !(input[2] & UDP_FLAG_REMOTE))
        return EFRP_PROTOCOL_ERROR;
    efrp_udp_packet_t decoded = {.has_local_address = (input[2] & UDP_FLAG_LOCAL) != 0};
    size_t offset = 3;
    efrp_result_t result;
    if (decoded.has_local_address) {
        result = read_address(input, length, &offset, &decoded.local_address);
        if (result != EFRP_OK) return result == EFRP_TRUNCATED ? incomplete : result;
    }
    result = read_address(input, length, &offset, &decoded.remote_address);
    if (result != EFRP_OK) return result == EFRP_TRUNCATED ? incomplete : result;
    if (length - offset < 2) return incomplete;
    decoded.payload_length = get_u16(input + offset); offset += 2;
    if (decoded.payload_length > EFRP_UDP_MAX_PAYLOAD_SIZE) return EFRP_CAPACITY_EXCEEDED;
    if (frame_length - offset < decoded.payload_length) return EFRP_TRUNCATED;
    if (frame_length - offset > decoded.payload_length) return EFRP_PROTOCOL_ERROR;
    *payload_offset = offset;
    *packet = decoded;
    return EFRP_OK;
}

efrp_result_t efrp_udp_packet_decode(const uint8_t *input, size_t length,
                                    efrp_udp_packet_t *packet)
{
    size_t offset;
    efrp_result_t result = efrp_udp_packet_header_decode(input, length, length, packet, &offset);
    if (result == EFRP_OK) packet->payload = input + offset;
    return result;
}
