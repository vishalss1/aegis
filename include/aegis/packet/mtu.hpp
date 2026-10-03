#pragma once

#include "aegis/crypto/chacha20poly1305.hpp"
#include "aegis/packet/header.hpp"
#include "aegis/packet/relay.hpp"
#include <cstddef>
#include <optional>

// Physical-wire overhead for carrying one inner IPv4 packet through Aegis.
// Route depth is the number of peers in Route::path: one for a direct route,
// or two through ONION_MAX_HOPS for a relayed route whose path includes the
// destination. The outer transport is currently IPv4 UDP.
inline constexpr size_t DIRECT_ROUTE_DEPTH = 1;
inline constexpr size_t DEFAULT_UNDERLAY_MTU = 1500;
inline constexpr size_t MINIMUM_IPV4_MTU = 576;
inline constexpr size_t MAXIMUM_IPV4_MTU = 65535;
inline constexpr size_t OUTER_IPV4_HEADER_SIZE = 20;
inline constexpr size_t OUTER_UDP_HEADER_SIZE = 8;
inline constexpr size_t OUTER_IPV4_UDP_OVERHEAD =
    OUTER_IPV4_HEADER_SIZE + OUTER_UDP_HEADER_SIZE;
inline constexpr size_t SESSION_FRAME_OVERHEAD =
    PACKET_HEADER_SIZE + CHACHA20_POLY1305_NONCE_SIZE +
    CHACHA20_POLY1305_TAG_SIZE;
inline constexpr size_t RELAY_SOURCE_OVERHEAD = NODE_ID_SIZE;

static_assert(ONION_OVERHEAD == 60,
              "The MTU contract assumes 60-byte onion layers");

// Returns the bytes added around an inner IPv4 packet on the physical wire.
// A direct route has only the outer IPv4/UDP and encrypted-session framing.
// Relayed routes additionally carry the source NodeID and one onion layer per
// peer in the route path.
[[nodiscard]] constexpr std::optional<size_t>
wire_overhead_for_route_depth(size_t route_depth) noexcept {
    if (route_depth < DIRECT_ROUTE_DEPTH || route_depth > ONION_MAX_HOPS)
        return std::nullopt;

    size_t overhead = OUTER_IPV4_UDP_OVERHEAD + SESSION_FRAME_OVERHEAD;
    if (route_depth > DIRECT_ROUTE_DEPTH) {
        overhead += RELAY_SOURCE_OVERHEAD + route_depth * ONION_OVERHEAD;
    }
    return overhead;
}

// The largest inner IPv4 packet that is guaranteed to fit the configured
// underlay at the permitted route depth. Values that cannot preserve IPv4's
// 576-byte minimum reassembly size are rejected instead of configuring an
// unusably small virtual interface.
[[nodiscard]] constexpr std::optional<size_t>
safe_overlay_mtu(size_t underlay_mtu, size_t route_depth) noexcept {
    if (underlay_mtu > MAXIMUM_IPV4_MTU)
        return std::nullopt;
    const auto overhead = wire_overhead_for_route_depth(route_depth);
    if (!overhead || underlay_mtu < *overhead + MINIMUM_IPV4_MTU)
        return std::nullopt;
    return underlay_mtu - *overhead;
}
