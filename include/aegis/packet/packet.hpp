#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

struct IPPacket {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
    const uint8_t* payload;
    size_t payload_length;

    static std::optional<IPPacket> parse(const uint8_t* data, size_t len);
};

// Internet checksum (16-bit one's complement sum).
// Returns the raw sum; when computed over the entire header including
// the checksum field, 0xFFFF (or 0) indicates a valid checksum.
uint16_t ip_checksum(const void* data, size_t len);
