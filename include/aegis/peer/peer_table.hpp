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
    // The advertiser's FULL hop list to this peer, first hop through the peer
    // itself (its relay path; `{peer}` when directly reachable). The receiver
    // reconstructs its own path as [sender] + path and rejects any path that
    // would loop back through it. Real endpoints are never advertised.
    std::vector<NodeId> path;
    // (prefix, prefix_length) pairs in the same representation as
    // IPPacket::dest_ip / AllowedIP.prefix (big-endian value).
    std::vector<std::pair<uint32_t, uint8_t>> prefixes;
};

// Wire format:
//   [0]      version (2)
//   [1..2]   uint16 peer_count (big-endian)
//   per peer:
//     [32]  NodeID
//     [32]  public key
//     [1]   path_count
//     per path hop: [32] NodeID
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
// `routes_installed` (optional out param) is incremented for every prefix that
// produced a new route, so the caller can re-announce and push new knowledge
// into the mesh without waiting for the next periodic gossip cycle.
size_t merge_peer_table(PeerManager& pm, RoutingEngine& re,
                        const std::vector<AdvertisedPeer>& advertised,
                        const NodeId& sender, const NodeId& self,
                        size_t* routes_installed = nullptr);
