#pragma once

#include "aegis/identity/identity.hpp"
#include <cstdint>
#include <vector>
#include <map>
#include <optional>

enum class NextHopType {
    Direct,
    Relay,
    Unknown
};

struct Route {
    uint32_t prefix;
    uint32_t prefix_length;
    NextHopType type;
    NodeId next_hop;
    NodeId destination;
};

class RoutingEngine {
public:
    RoutingEngine();

    void add_route(const Route& route);
    void remove_route(const NodeId& peer_id);

    std::optional<Route> find_route(uint32_t dest_ip) const;
    std::optional<NodeId> find_peer(uint32_t dest_ip) const;

    void clear();

private:
    std::vector<Route> routes_;
};
