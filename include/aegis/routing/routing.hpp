#pragma once

#include "aegis/identity/identity.hpp"
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
};

class RoutingEngine {
public:
    RoutingEngine();

    bool add_route(const Route& route);
    void remove_route(const NodeId& peer_id);
    void clear();

    std::optional<Route> find_route(uint32_t dest_ip) const;
    std::optional<NodeId> find_peer(uint32_t dest_ip) const;
    std::optional<NodeId> find_next_hop(uint32_t dest_ip) const;

    size_t size() const;
    bool empty() const;
    std::vector<Route> routes() const;

private:
    mutable std::mutex mtx_;
    std::vector<Route> routes_;
};
