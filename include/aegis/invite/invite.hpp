#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/transport/transport.hpp"
#include <cstdint>
#include <optional>
#include <string>

struct InvitePayload {
    NetworkId   network_id{};          // 32 bytes
    Key         bootstrap_pubkey{};    // 32 bytes
    NodeId      creator_node_id{};     // 32 bytes
    Endpoint    bootstrap_endpoint{};  // 6 bytes (4-byte IP, 2-byte port)
    uint32_t    bootstrap_prefix = 0;  // 4 bytes
    uint8_t     bootstrap_prefix_len = 0; // 1 byte
    std::string network_name;          // variable length (up to 64 bytes)
};

std::string encode_invite(const InvitePayload& payload);
std::optional<InvitePayload> decode_invite(const std::string& invite_str);
