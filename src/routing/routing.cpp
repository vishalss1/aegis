#include "aegis/routing/routing.hpp"
#include <algorithm>
#include <cstdio>

RoutingEngine::RoutingEngine(size_t max_routes) : max_routes_(max_routes) {}

static uint32_t prefix_mask(uint32_t prefix_length) {
    return prefix_length ? (0xFFFFFFFFu << (32 - prefix_length)) : 0;
}

bool RoutingEngine::add_route(const Route& route) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (route.prefix_length > 32 || route.type == NextHopType::Unknown)
        return false;
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
    } else if (route.next_hop != route.destination || route.path.size() != 1 ||
               route.path.front() != route.destination) {
        return false;  // Direct routes are exactly one destination hop.
    }

    Route candidate = route;
    candidate.prefix &= prefix_mask(candidate.prefix_length);
    if (candidate.origin == NodeId{})
        candidate.origin = candidate.destination;
    if (candidate.advertiser == NodeId{})
        candidate.advertiser = candidate.next_hop;
    if (candidate.sequence_number == 0 || candidate.lease.count() <= 0 ||
        candidate.lease > ROUTE_MAX_LEASE ||
        candidate.metric > ROUTE_MAX_METRIC)
        return false;

    // A candidate is the path learned from one next hop toward one
    // destination. Refreshing that candidate may replace its path without
    // consuming capacity; alternatives for the same prefix remain available.
    auto existing = std::find_if(routes_.begin(), routes_.end(), [&](const Route& r) {
        return r.prefix == candidate.prefix &&
            r.prefix_length == candidate.prefix_length &&
            r.type == candidate.type && r.next_hop == candidate.next_hop &&
            r.destination == candidate.destination;
    });
    if (existing != routes_.end()) {
        *existing = std::move(candidate);
        return true;
    }
    if (routes_.size() >= max_routes_)
        return false;

    const size_t prefix_candidates = static_cast<size_t>(std::count_if(
        routes_.begin(), routes_.end(), [&](const Route& r) {
            return r.prefix == candidate.prefix &&
                r.prefix_length == candidate.prefix_length;
        }));
    if (prefix_candidates >= ROUTING_MAX_CANDIDATES_PER_PREFIX)
        return false;

    routes_.push_back(std::move(candidate));
    return true;
}

void RoutingEngine::remove_route(const NodeId& peer_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::erase_if(routes_, [&](const Route& r) {
        return r.destination == peer_id || r.next_hop == peer_id;
    });
}

size_t RoutingEngine::remove_older_learned_routes(
    const NodeId& origin, uint32_t prefix, uint32_t prefix_length,
    uint64_t minimum_sequence) {
    if (prefix_length > 32)
        return 0;
    const uint32_t canonical = prefix & prefix_mask(prefix_length);
    std::lock_guard<std::mutex> lock(mtx_);
    const size_t before = routes_.size();
    std::erase_if(routes_, [&](const Route& route) {
        return route.type == NextHopType::Relay &&
            route.origin == origin && route.prefix == canonical &&
            route.prefix_length == prefix_length &&
            route.sequence_number < minimum_sequence;
    });
    return before - routes_.size();
}

void RoutingEngine::clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    routes_.clear();
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
