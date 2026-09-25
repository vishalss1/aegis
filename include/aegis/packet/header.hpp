#pragma once

#include "aegis/protocol/wire.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <span>

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t version;
    uint8_t packet_type;
    uint8_t flags;
    uint8_t reserved;
    uint32_t session_id;
    uint32_t sequence_number;
    uint32_t payload_length;
};
#pragma pack(pop)

static constexpr uint8_t PACKET_VERSION = 0x01;

static constexpr uint8_t TYPE_HANDSHAKE_INIT = 0x00;
static constexpr uint8_t TYPE_HANDSHAKE_RESP = 0x01;
static constexpr uint8_t TYPE_DATA = 0x02;
static constexpr uint8_t TYPE_KEEPALIVE = 0x03;
static constexpr uint8_t TYPE_DISCOVERY = 0x04;
static constexpr uint8_t TYPE_PEER_TABLE = 0x05;
static constexpr uint8_t TYPE_RELAY = 0x06;
static constexpr uint8_t TYPE_CHAT_MSG = 0x07;
static constexpr uint8_t TYPE_FILE_HEADER = 0x08;
static constexpr uint8_t TYPE_FILE_CHUNK = 0x09;
static constexpr uint8_t TYPE_FILE_ACK = 0x0A;
static constexpr uint8_t TYPE_NETWORK_TEARDOWN = 0x0B;

static constexpr uint8_t FLAG_RELAY = 0x01;
static constexpr uint8_t FLAG_FRAGMENTED = 0x02;

static constexpr size_t PACKET_HEADER_SIZE = 16;
static constexpr uint8_t PACKET_KNOWN_FLAGS = FLAG_RELAY | FLAG_FRAGMENTED;

inline std::array<uint8_t, PACKET_HEADER_SIZE> serialize_packet_header(
    const PacketHeader& header) {
    std::array<uint8_t, PACKET_HEADER_SIZE> bytes{};
    WireWriter writer(bytes);
    const bool encoded = writer.write_u8(header.version) &&
        writer.write_u8(header.packet_type) && writer.write_u8(header.flags) &&
        writer.write_u8(header.reserved) && writer.write_u32(header.session_id) &&
        writer.write_u32(header.sequence_number) &&
        writer.write_u32(header.payload_length) && writer.finished();
    (void)encoded;
    return bytes;
}

inline std::optional<PacketHeader> parse_packet_header(
    std::span<const uint8_t> bytes) {
    WireReader reader(bytes);
    const auto version = reader.read_u8();
    const auto packet_type = reader.read_u8();
    const auto flags = reader.read_u8();
    const auto reserved = reader.read_u8();
    const auto session_id = reader.read_u32();
    const auto sequence_number = reader.read_u32();
    const auto payload_length = reader.read_u32();
    if (!version || !packet_type || !flags || !reserved || !session_id ||
        !sequence_number || !payload_length || !reader.finished())
        return std::nullopt;
    return PacketHeader{*version, *packet_type, *flags, *reserved,
                        *session_id, *sequence_number, *payload_length};
}
