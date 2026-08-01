#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/routing/routing.hpp"
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

// Peer table gossip message (TYPE_PEER_TABLE). Peers are advertised by NodeID
// + public key + allowed prefixes — NEVER by endpoint. The receiving node must
// route to an advertised peer through the sender (relay), which is exactly the
// identity-hiding property: a non-adjacent peer's real IP is never revealed.
struct AdvertisedPeer {
    NodeId node_id{};
    Key public_key{};
    // (prefix, prefix_length) pairs in the same representation as
    // IPPacket::dest_ip / AllowedIP.prefix (big-endian value).
    std::vector<std::pair<uint32_t, uint8_t>> prefixes;
};

// Wire format:
//   [0]      version (1)
//   [1..2]   uint16 peer_count (big-endian)
//   per peer:
//     [32]  NodeID
//     [32]  public key
//     [1]   flags (reserved)
//     [1]   prefix_count
//     per prefix: [4] prefix (big-endian value) + [1] prefix_length
std::vector<uint8_t> serialize_peer_table(const std::vector<AdvertisedPeer>& peers);
std::optional<std::vector<AdvertisedPeer>> deserialize_peer_table(
    const uint8_t* data, size_t len);

// Merge advertised peers into the local tables. The sender of the gossip is
// always the next hop toward everything it advertises, so every advertised
// prefix becomes a Relay route via `sender`. Returns the number of newly
// learned peers (existing peers are refreshed in place, not re-counted).
size_t merge_peer_table(PeerManager& pm, RoutingEngine& re,
                        const std::vector<AdvertisedPeer>& advertised,
                        const NodeId& sender, const NodeId& self);
