#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/protocol/sources.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

enum class NextHopType {
    Direct,
    Relay,
    Unknown
};

struct Route {
    uint32_t prefix = 0;
    uint32_t prefix_length = 0;
    NextHopType type = NextHopType::Unknown;
    NodeId next_hop{};      // peer to forward to (== destination for Direct)
    NodeId destination{};   // final destination peer (== next_hop for Direct)
    // Full ordered hop list [first_hop .. destination] for Relay routes. Used
    // to build the onion: one AEAD layer per hop, innermost = destination.
    // Direct routes carry { destination }.
    std::vector<NodeId> path;
    // Freshness metadata. `origin` owns the advertised prefix; `advertiser`
    // is the authenticated adjacent peer from which this candidate arrived.
    NodeId origin{};
    NodeId advertiser{};
    uint64_t sequence_number = 1;
    std::chrono::seconds lease{90};
    uint32_t metric = 0;
    ProtocolClock::time_point validated_at{};
};

inline constexpr size_t ROUTING_MAX_ROUTES = 2048;
inline constexpr size_t ROUTING_MAX_CANDIDATES_PER_PREFIX = 8;
inline constexpr std::chrono::seconds ROUTE_DEFAULT_LEASE{90};
inline constexpr std::chrono::seconds ROUTE_MAX_LEASE{600};
inline constexpr uint32_t ROUTE_MAX_METRIC = 1'000'000;

[[nodiscard]] bool learned_route_lease_expired(
    const Route& route, ProtocolClock::time_point now) noexcept;

class RoutingEngine {
public:
    explicit RoutingEngine(size_t max_routes = ROUTING_MAX_ROUTES);

    bool add_route(const Route& route);
    void remove_route(const NodeId& peer_id);
    size_t remove_older_learned_routes(
        const NodeId& origin, uint32_t prefix, uint32_t prefix_length,
        uint64_t minimum_sequence);
    size_t expire_learned_routes(ProtocolClock::time_point now);
    void clear();

    std::optional<Route> find_route(uint32_t dest_ip) const;
    std::optional<NodeId> find_peer(uint32_t dest_ip) const;
    std::optional<NodeId> find_next_hop(uint32_t dest_ip) const;

    size_t size() const;
    bool empty() const;
    std::vector<Route> routes() const;
    std::vector<Route> routes_to(const NodeId& dest) const;

private:
    mutable std::mutex mtx_;
    std::vector<Route> routes_;
    size_t max_routes_;
};
