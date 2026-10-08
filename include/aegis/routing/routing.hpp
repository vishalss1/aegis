#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/net/ip_address.hpp"
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
    IPAddress prefix{};
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
    std::optional<ProtocolClock::time_point> last_probe_sent_at;
    std::optional<ProtocolClock::time_point> last_probe_validated_at;
    std::optional<std::chrono::milliseconds> last_probe_rtt;
    // A timed-out end-to-end probe suppresses only this exact candidate.
    // Probing resumes after the hold-down, and only a later success restores
    // the candidate.
    bool probe_failed = false;
    uint32_t consecutive_probe_failures = 0;
    std::optional<ProtocolClock::time_point> probe_hold_down_until;
};

inline constexpr size_t ROUTING_MAX_ROUTES = 2048;
inline constexpr size_t ROUTING_MAX_CANDIDATES_PER_PREFIX = 8;
inline constexpr std::chrono::seconds ROUTE_DEFAULT_LEASE{90};
inline constexpr std::chrono::seconds ROUTE_MAX_LEASE{600};
inline constexpr uint32_t ROUTE_MAX_METRIC = 1'000'000;
inline constexpr std::chrono::seconds ROUTE_PROBE_HOLD_DOWN{30};

[[nodiscard]] bool learned_route_lease_expired(
    const Route& route, ProtocolClock::time_point now) noexcept;

class RoutingEngine {
public:
    explicit RoutingEngine(size_t max_routes = ROUTING_MAX_ROUTES);

    bool add_route(const Route& route);
    void remove_route(const NodeId& peer_id);
    size_t remove_older_learned_routes(
        const NodeId& origin, IPAddress prefix, uint32_t prefix_length,
        uint64_t minimum_sequence);
    size_t expire_learned_routes(ProtocolClock::time_point now);
    bool mark_probe_sent(
        const NodeId& destination, const NodeId& next_hop,
        IPAddress prefix, uint32_t prefix_length, uint64_t sequence,
        ProtocolClock::time_point now);
    bool record_probe_success(
        const NodeId& destination, const NodeId& next_hop,
        IPAddress prefix, uint32_t prefix_length, uint64_t sequence,
        ProtocolClock::time_point now,
        std::chrono::steady_clock::duration rtt);
    bool record_probe_failure(
        const NodeId& destination, const NodeId& next_hop,
        IPAddress prefix, uint32_t prefix_length, uint64_t sequence,
        ProtocolClock::time_point now);
    void clear();

    std::optional<Route> find_route(const IPAddress& dest_ip) const;
    std::optional<Route> find_route(uint32_t dest_ip) const {
        return find_route(IPAddress::from_ipv4(dest_ip));
    }
    std::optional<NodeId> find_peer(const IPAddress& dest_ip) const;
    std::optional<NodeId> find_peer(uint32_t dest_ip) const {
        return find_peer(IPAddress::from_ipv4(dest_ip));
    }
    std::optional<NodeId> find_next_hop(const IPAddress& dest_ip) const;
    std::optional<NodeId> find_next_hop(uint32_t dest_ip) const {
        return find_next_hop(IPAddress::from_ipv4(dest_ip));
    }

    size_t size() const;
    bool empty() const;
    std::vector<Route> routes() const;
    std::vector<Route> routes_to(const NodeId& dest) const;

private:
    mutable std::mutex mtx_;
    std::vector<Route> routes_;
    size_t max_routes_;
};
