#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/routing/routing.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

inline constexpr size_t PEER_TABLE_MAX_WIRE_BYTES = 60U * 1024U;
inline constexpr uint16_t PEER_TABLE_MAX_PEERS = 128;
inline constexpr uint8_t PEER_TABLE_MAX_PATH_HOPS = 8;
inline constexpr uint8_t PEER_TABLE_MAX_PREFIXES = 16;

struct AdvertisedPrefix {
    IPAddress prefix{};
    uint8_t prefix_length = 0;
    uint64_t sequence_number = 1;
    uint32_t lease_seconds =
        static_cast<uint32_t>(ROUTE_DEFAULT_LEASE.count());
    uint32_t metric = 0;

    AdvertisedPrefix() = default;
    AdvertisedPrefix(IPAddress network, uint8_t length,
                     uint64_t sequence = 1,
                     uint32_t lease = static_cast<uint32_t>(
                         ROUTE_DEFAULT_LEASE.count()),
                     uint32_t route_metric = 0)
        : prefix(network), prefix_length(length), sequence_number(sequence),
          lease_seconds(lease), metric(route_metric) {}
    AdvertisedPrefix(uint32_t network, uint8_t length,
                     uint64_t sequence = 1,
                     uint32_t lease = static_cast<uint32_t>(
                         ROUTE_DEFAULT_LEASE.count()),
                     uint32_t route_metric = 0)
        : AdvertisedPrefix(IPAddress::from_ipv4(network), length, sequence,
                           lease, route_metric) {}

    [[nodiscard]] bool operator==(const AdvertisedPrefix&) const = default;
    [[nodiscard]] bool operator<(const AdvertisedPrefix& other) const noexcept {
        if (prefix.family != other.prefix.family)
            return prefix.family < other.prefix.family;
        if (prefix.bytes != other.prefix.bytes)
            return prefix.bytes < other.prefix.bytes;
        if (prefix_length != other.prefix_length)
            return prefix_length < other.prefix_length;
        if (sequence_number != other.sequence_number)
            return sequence_number < other.sequence_number;
        if (lease_seconds != other.lease_seconds)
            return lease_seconds < other.lease_seconds;
        return metric < other.metric;
    }
};

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
    // Prefix records use family-tagged addresses and carry origin freshness
    // data.
    std::vector<AdvertisedPrefix> prefixes;
};

// Wire format:
//   [0]      version (4)
//   [1..2]   uint16 peer_count (big-endian)
//   per peer:
//     [32]  NodeID
//     [32]  public key
//     [1]   path_count
//     per path hop: [32] NodeID
//     [1]   flags (reserved)
//     [1]   prefix_count
//     per prefix: [1] family + [16] address + [1] prefix_length + [8] origin sequence
//                 + [4] lease seconds + [4] metric (all big-endian)
// Serialization fails rather than truncating counts that do not fit the
// bounded wire format.
std::optional<std::vector<uint8_t>> serialize_peer_table(
    const std::vector<AdvertisedPeer>& peers);
std::optional<std::vector<AdvertisedPeer>> deserialize_peer_table(
    const uint8_t* data, size_t len);

// Merge counters are independent outcome dimensions. `accepted` counts peer
// identities that passed validation, while malformed routing data or route
// capacity rejection may still prevent some of that peer's routes from being
// installed. `peers_changed` counts newly inserted identities and placeholders
// that acquired their first key.
struct PeerTableMergeStats {
    size_t accepted = 0;
    size_t peers_changed = 0;
    size_t routes_installed = 0;
    size_t malformed = 0;
    size_t stale_rejected = 0;
    size_t conflicting = 0;
    size_t capacity_rejected = 0;

    bool changed() const {
        return peers_changed > 0 || routes_installed > 0;
    }
};

// Merge advertised peers into the local tables. Self and sender entries are
// ignored. Every other key must be nonzero and hash to its NodeID before any
// state changes. Existing non-empty bindings are immutable; empty placeholders
// may be bound once. Accepted peers are endpoint-less and cannot lose an
// existing local trust designation. The sender is always the next hop toward
// advertised prefixes, but invalid/looping paths and route-capacity failures do
// not roll back an otherwise valid peer identity. The returned statistics make
// each outcome observable.
PeerTableMergeStats merge_peer_table(
    PeerManager& pm, RoutingEngine& re,
    const std::vector<AdvertisedPeer>& advertised,
    const NodeId& sender, const NodeId& self,
    ProtocolClock::time_point validated_at = system_protocol_clock().now());
