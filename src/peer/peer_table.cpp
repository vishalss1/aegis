#include "aegis/peer/peer_table.hpp"
#include <cstring>
#include <set>

static constexpr uint8_t PEER_TABLE_VERSION = 2;

static void put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back((uint8_t)(v >> 8));
    out.push_back((uint8_t)(v & 0xFF));
}

static void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back((uint8_t)(v >> 24));
    out.push_back((uint8_t)(v >> 16));
    out.push_back((uint8_t)(v >> 8));
    out.push_back((uint8_t)(v));
}

std::vector<uint8_t> serialize_peer_table(const std::vector<AdvertisedPeer>& peers) {
    std::vector<uint8_t> out;
    out.reserve(3 + peers.size() * (32 + 32 + 1 + 8 * 32 + 2 + 5));
    out.push_back(PEER_TABLE_VERSION);
    put_u16(out, (uint16_t)peers.size());
    for (const auto& p : peers) {
        out.insert(out.end(), p.node_id.begin(), p.node_id.end());
        out.insert(out.end(), p.public_key.begin(), p.public_key.end());
        out.push_back((uint8_t)p.path.size());
        for (const auto& hop : p.path)
            out.insert(out.end(), hop.begin(), hop.end());
        out.push_back(0);  // flags (reserved)
        out.push_back((uint8_t)p.prefixes.size());
        for (const auto& [prefix, prefix_length] : p.prefixes) {
            put_u32(out, prefix);
            out.push_back(prefix_length);
        }
    }
    return out;
}

std::optional<std::vector<AdvertisedPeer>> deserialize_peer_table(
    const uint8_t* data, size_t len) {
    if (!data || len < 3)
        return std::nullopt;
    size_t off = 0;
    if (data[off++] != PEER_TABLE_VERSION)
        return std::nullopt;
    uint16_t count = ((uint16_t)data[off] << 8) | data[off + 1];
    off += 2;

    std::vector<AdvertisedPeer> out;
    out.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        if (off + 32 + 32 + 1 > len)
            return std::nullopt;
        AdvertisedPeer p;
        std::memcpy(p.node_id.data(), data + off, 32);
        off += 32;
        std::memcpy(p.public_key.data(), data + off, 32);
        off += 32;
        uint8_t path_count = data[off++];
        for (uint8_t j = 0; j < path_count; ++j) {
            if (off + 32 > len)
                return std::nullopt;
            NodeId hop{};
            std::memcpy(hop.data(), data + off, 32);
            off += 32;
            p.path.push_back(hop);
        }
        if (off + 2 > len)
            return std::nullopt;
        off += 1;  // flags (reserved)
        uint8_t prefix_count = data[off++];
        for (uint8_t j = 0; j < prefix_count; ++j) {
            if (off + 5 > len)
                return std::nullopt;
            uint32_t prefix = ((uint32_t)data[off] << 24) |
                              ((uint32_t)data[off + 1] << 16) |
                              ((uint32_t)data[off + 2] << 8) | data[off + 3];
            off += 4;
            uint8_t prefix_length = data[off++];
            if (prefix_length > 32)
                return std::nullopt;
            p.prefixes.emplace_back(prefix, prefix_length);
        }
        out.push_back(std::move(p));
    }
    return out;
}

size_t merge_peer_table(PeerManager& pm, RoutingEngine& re,
                        const std::vector<AdvertisedPeer>& advertised,
                        const NodeId& sender, const NodeId& self) {
    size_t learned = 0;
    for (const auto& p : advertised) {
        if (p.node_id == self || p.node_id == sender)
            continue;

        bool is_new = !pm.has_peer(p.node_id);
        if (is_new)
            pm.upsert(p.node_id, p.public_key, std::nullopt, false);

        // Candidate relay path to this peer: through the sender, then along the
        // advertiser's advertised hop list (which already ends with the peer).
        // An empty advertised list means the advertiser reaches the peer
        // directly, so the path is just [sender, peer]. A path that revisits
        // any node or contains us would loop — the onion wraps every hop on
        // it, so reject it outright.
        std::vector<NodeId> path;
        path.push_back(sender);
        path.insert(path.end(), p.path.begin(), p.path.end());
        if (p.path.empty())
            path.push_back(p.node_id);
        bool path_ok = path.back() == p.node_id;
        {
            std::set<NodeId> seen;
            for (const auto& hop : path)
                if (hop == self || !seen.insert(hop).second) { path_ok = false; break; }
        }

        for (const auto& [prefix, prefix_length] : p.prefixes) {
            bool exists = false;
            for (const auto& r : re.routes()) {
                if (r.prefix == prefix && r.prefix_length == prefix_length) {
                    exists = true;
                    break;
                }
            }
            if (exists)
                continue;  // keep an existing route (e.g. a Direct one) as-is
            if (!path_ok)
                continue;  // a looping path can never be used, do not install

            Route route;
            route.prefix = prefix;
            route.prefix_length = prefix_length;
            route.type = NextHopType::Relay;
            route.next_hop = sender;
            route.destination = p.node_id;
            route.path = path;
            re.add_route(route);
        }

        if (is_new)
            ++learned;
    }
    return learned;
}
