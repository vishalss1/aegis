#pragma once

#include "identity.hpp"
#include <cstdint>
#include <vector>
#include <array>
#include <winsock2.h>

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

static constexpr uint8_t FLAG_RELAY = 0x01;
static constexpr uint8_t FLAG_FRAGMENTED = 0x02;

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
};

struct EncryptedFrame {
    PacketHeader header;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

struct OnionLayer {
    NodeId next_hop;
    std::vector<uint8_t> inner;
};

class PacketEngine {
public:
    PacketEngine();

    bool parse_ip_packet(const std::vector<uint8_t>& raw, IPPacket& out) const;

    EncryptedFrame create_frame(
        const PacketHeader& header,
        const std::vector<uint8_t>& plaintext
    ) const;

    OnionLayer wrap_for_relay(
        const NodeId& next_hop,
        const std::vector<uint8_t>& inner
    ) const;

    std::vector<uint8_t> serialize_frame(const EncryptedFrame& frame) const;
    std::vector<uint8_t> serialize_onion(const OnionLayer& layer) const;

    bool deserialize_header(
        const std::vector<uint8_t>& data,
        PacketHeader& out
    ) const;
};
