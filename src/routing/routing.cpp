#include "aegis/routing.hpp"
#include <algorithm>
#include <cstdio>

RoutingEngine::RoutingEngine() = default;

void RoutingEngine::add_route(const Route& route) {
    routes_.push_back(route);
}

void RoutingEngine::remove_route(const NodeId& peer_id) {
    std::erase_if(routes_, [&](const Route& r) {
        return r.destination == peer_id || r.next_hop == peer_id;
    });
}

std::optional<Route> RoutingEngine::find_route(uint32_t dest_ip) const {
    const Route* best = nullptr;
    uint32_t best_prefix_len = 0;

    for (const auto& route : routes_) {
        uint32_t mask = route.prefix_length ? 0xFFFFFFFF << (32 - route.prefix_length) : 0;
        if ((dest_ip & mask) == (route.prefix & mask)) {
            if (route.prefix_length > best_prefix_len) {
                best = &route;
                best_prefix_len = route.prefix_length;
            }
        }
    }

    if (best) return *best;
    return std::nullopt;
}

std::optional<NodeId> RoutingEngine::find_peer(uint32_t dest_ip) const {
    auto route = find_route(dest_ip);
    if (route) return route->destination;
    return std::nullopt;
}

void RoutingEngine::clear() { routes_.clear(); }
