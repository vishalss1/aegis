#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/packet/header.hpp"
#include "aegis/packet/packet.hpp"
#include <cstdint>
#include <vector>
#include <array>

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
