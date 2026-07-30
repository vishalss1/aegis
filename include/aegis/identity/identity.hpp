#pragma once

#include "aegis/crypto/x25519.hpp"
#include <array>
#include <cstdint>

static constexpr size_t KEY_SIZE = 32;
static constexpr size_t NODE_ID_SIZE = 32;
static constexpr size_t NETWORK_ID_SIZE = 32;

using Key = std::array<uint8_t, KEY_SIZE>;
using NodeId = std::array<uint8_t, NODE_ID_SIZE>;
using NetworkId = std::array<uint8_t, NETWORK_ID_SIZE>;

NodeId hash_public_key(const X25519Key& public_key);

struct Identity {
    X25519KeyPair keypair{};
    NodeId node_id{};
    NetworkId network_id{};

    static Identity create(const NetworkId& network_id);

    bool matches_network(const NetworkId& other) const;
};
