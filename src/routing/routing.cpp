#include "aegis/routing/routing.hpp"
#include <algorithm>
#include <cstdio>

RoutingEngine::RoutingEngine(size_t max_routes) : max_routes_(max_routes) {}

bool RoutingEngine::add_route(const Route& route) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (route.type == NextHopType::Relay) {
        // A relay must not forward to itself; that route could never be resolved.
        if (route.next_hop == route.destination)
            return false;
        // The path must be a complete, loop-free hop list from next_hop to the
        // destination — it is what the onion wrapping walks.
        if (route.path.size() < 2 || route.path.front() != route.next_hop ||
            route.path.back() != route.destination)
            return false;
        std::set<NodeId> seen;
        for (const auto& hop : route.path)
            if (!seen.insert(hop).second)
                return false;  // repeated hop => the path would loop forever
    } else if (route.path.empty()) {
        return false;  // Direct routes must at least name their destination
    }
    // One route per prefix. Replacements remain possible at capacity because
    // they do not increase persistent state.
    auto existing = std::find_if(routes_.begin(), routes_.end(), [&](const Route& r) {
        return r.prefix == route.prefix && r.prefix_length == route.prefix_length;
    });
    if (existing != routes_.end()) {
        *existing = route;
        return true;
    }
    if (routes_.size() >= max_routes_)
        return false;

    routes_.push_back(route);
    return true;
}

void RoutingEngine::remove_route(const NodeId& peer_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::erase_if(routes_, [&](const Route& r) {
        return r.destination == peer_id || r.next_hop == peer_id;
    });
}

void RoutingEngine::clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    routes_.clear();
}

static uint32_t prefix_mask(uint32_t prefix_length) {
    return prefix_length ? (0xFFFFFFFFu << (32 - prefix_length)) : 0;
}

std::optional<Route> RoutingEngine::find_route(uint32_t dest_ip) const {
    std::lock_guard<std::mutex> lock(mtx_);
    const Route* best = nullptr;

    for (const auto& route : routes_) {
        uint32_t mask = prefix_mask(route.prefix_length);
        if ((dest_ip & mask) != (route.prefix & mask)) continue;

        if (!best) {
            best = &route;
            continue;
        }

        if (route.prefix_length > best->prefix_length) {
            best = &route;
        } else if (route.prefix_length == best->prefix_length) {
            // Direct routes take precedence over Relay routes.
            if (route.type == NextHopType::Direct && best->type == NextHopType::Relay) {
                best = &route;
            } else if (route.type == NextHopType::Relay && best->type == NextHopType::Relay) {
                // For Relay routes, prefer shorter path length.
                if (route.path.size() < best->path.size()) {
                    best = &route;
                }
            }
        }
    }

    if (!best) return std::nullopt;

    // Loop avoidance: a relay route must resolve to a forwardable, loop-free
    // path. The path was validated when the route was added; re-check cheaply
    // here so a route can never be used if its next_hop/destination/path ever
    // drift out of sync.
    if (best->type == NextHopType::Relay) {
        const auto& path = best->path;
        if (path.size() < 2 || path.front() != best->next_hop ||
            path.back() != best->destination)
            return std::nullopt;
        std::set<NodeId> seen;
        for (const auto& hop : path)
            if (!seen.insert(hop).second)
                return std::nullopt;  // cycle in the path
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

size_t RoutingEngine::size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return routes_.size();
}

bool RoutingEngine::empty() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return routes_.empty();
}

std::vector<Route> RoutingEngine::routes() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return routes_;
}

std::vector<Route> RoutingEngine::routes_to(const NodeId& dest) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Route> out;
    for (const auto& r : routes_) {
        if (r.destination == dest) {
            out.push_back(r);
        }
    }
    return out;
}
