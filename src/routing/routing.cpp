#include "aegis/routing/routing.hpp"
#include <algorithm>
#include <cstdio>

RoutingEngine::RoutingEngine() = default;

bool RoutingEngine::add_route(const Route& route) {
    // A relay must not forward to itself; that route could never be resolved.
    if (route.type == NextHopType::Relay && route.next_hop == route.destination)
        return false;
    // One route per prefix — relearning a peer's path replaces the old entry.
    std::erase_if(routes_, [&](const Route& r) {
        return r.prefix == route.prefix && r.prefix_length == route.prefix_length;
    });
    routes_.push_back(route);
    return true;
}

void RoutingEngine::remove_route(const NodeId& peer_id) {
    std::erase_if(routes_, [&](const Route& r) {
        return r.destination == peer_id || r.next_hop == peer_id;
    });
}

void RoutingEngine::clear() {
    routes_.clear();
}

static uint32_t prefix_mask(uint32_t prefix_length) {
    return prefix_length ? (0xFFFFFFFFu << (32 - prefix_length)) : 0;
}

std::optional<Route> RoutingEngine::find_route(uint32_t dest_ip) const {
    const Route* best = nullptr;
    uint32_t best_prefix_len = 0;

    for (const auto& route : routes_) {
        uint32_t mask = prefix_mask(route.prefix_length);
        if ((dest_ip & mask) != (route.prefix & mask)) continue;
        if (route.prefix_length > best_prefix_len) {
            best = &route;
            best_prefix_len = route.prefix_length;
        }
    }

    if (!best) return std::nullopt;

    // Loop avoidance: a relay route must resolve to a forwardable path. Walk
    // the next-hop chain; revisiting any node means the path cycles and the
    // route is unusable (the packet would loop forever in a mesh).
    if (best->type == NextHopType::Relay) {
        std::set<NodeId> visited;
        NodeId node = best->next_hop;
        while (true) {
            if (visited.contains(node)) return std::nullopt;
            visited.insert(node);
            const Route* hop = nullptr;
            for (const auto& r : routes_) {
                if (r.destination == node) { hop = &r; break; }
            }
            if (!hop) break;
            if (hop->type == NextHopType::Direct) break;
            node = hop->next_hop;
        }
    }

    return *best;
}

std::optional<NodeId> RoutingEngine::find_peer(uint32_t dest_ip) const {
    auto route = find_route(dest_ip);
    if (!route) return std::nullopt;
    return route->destination;
}

std::optional<NodeId> RoutingEngine::find_next_hop(uint32_t dest_ip) const {
    auto route = find_route(dest_ip);
    if (!route) return std::nullopt;
    return route->next_hop;
}
