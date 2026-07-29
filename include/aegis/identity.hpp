#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

static constexpr size_t KEY_SIZE = 32;
static constexpr size_t NODE_ID_SIZE = 32;
static constexpr size_t NETWORK_ID_SIZE = 32;

using Key = std::array<uint8_t, KEY_SIZE>;
using NodeId = std::array<uint8_t, NODE_ID_SIZE>;
using NetworkId = std::array<uint8_t, NETWORK_ID_SIZE>;

class Identity {
public:
    Identity();

    bool generate();
    bool load_from_file(const std::string& path);
    bool save_to_file(const std::string& path) const;

    const Key& private_key() const { return private_key_; }
    const Key& public_key() const { return public_key_; }
    const NodeId& node_id() const { return node_id_; }
    const NetworkId& network_id() const { return network_id_; }

    void set_network_id(const NetworkId& nid) { network_id_ = nid; }

private:
    Key private_key_{};
    Key public_key_{};
    NodeId node_id_{};
    NetworkId network_id_{};

    void derive_node_id();
};
