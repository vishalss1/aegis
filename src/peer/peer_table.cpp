#include "aegis/peer/peer_table.hpp"
#include "aegis/protocol/wire.hpp"
#include <algorithm>
#include <set>

static constexpr uint8_t PEER_TABLE_VERSION = 4;
static constexpr size_t PEER_TABLE_PREFIX_BYTES = 1 + 16 + 1 + 8 + 4 + 4;

std::optional<std::vector<uint8_t>> serialize_peer_table(
    const std::vector<AdvertisedPeer>& peers) {
    if (peers.size() > PEER_TABLE_MAX_PEERS)
        return std::nullopt;

    size_t encoded_size = 3;
    for (const auto& p : peers) {
        if (p.path.size() > PEER_TABLE_MAX_PATH_HOPS ||
            p.prefixes.size() > PEER_TABLE_MAX_PREFIXES)
            return std::nullopt;

        constexpr size_t fixed_peer_bytes = 32 + 32 + 1 + 1 + 1;
        const size_t peer_bytes = fixed_peer_bytes + p.path.size() * 32 +
                                  p.prefixes.size() * PEER_TABLE_PREFIX_BYTES;
        if (peer_bytes > PEER_TABLE_MAX_WIRE_BYTES - encoded_size)
            return std::nullopt;
        encoded_size += peer_bytes;
    }

    std::vector<uint8_t> out(encoded_size);
    WireWriter writer(out);
    if (!writer.write_u8(PEER_TABLE_VERSION) ||
        !writer.write_u16(static_cast<uint16_t>(peers.size())))
        return std::nullopt;

    for (const auto& p : peers) {
        if (!writer.write_bytes(p.node_id) ||
            !writer.write_bytes(p.public_key) ||
            !writer.write_u8(static_cast<uint8_t>(p.path.size())))
            return std::nullopt;
        for (const auto& hop : p.path) {
            if (!writer.write_bytes(hop))
                return std::nullopt;
        }
        if (!writer.write_u8(0) ||  // flags (reserved)
            !writer.write_u8(static_cast<uint8_t>(p.prefixes.size())))
            return std::nullopt;
        for (const auto& advertised : p.prefixes) {
            if (!advertised.prefix.valid_family() ||
                advertised.prefix_length > advertised.prefix.bit_width() ||
                advertised.sequence_number == 0 ||
                advertised.lease_seconds == 0 ||
                advertised.lease_seconds > ROUTE_MAX_LEASE.count() ||
                advertised.metric > ROUTE_MAX_METRIC ||
                !writer.write_u8(static_cast<uint8_t>(advertised.prefix.family)) ||
                !writer.write_bytes(IPPrefix(
                    advertised.prefix, advertised.prefix_length).address.bytes) ||
                !writer.write_u8(advertised.prefix_length) ||
                !writer.write_u64(advertised.sequence_number) ||
                !writer.write_u32(advertised.lease_seconds) ||
                !writer.write_u32(advertised.metric))
                return std::nullopt;
        }
    }
    if (!writer.finished())
        return std::nullopt;
    return out;
}

std::optional<std::vector<AdvertisedPeer>> deserialize_peer_table(
    const uint8_t* data, size_t len) {
    if (!data || len < 3 || len > PEER_TABLE_MAX_WIRE_BYTES)
        return std::nullopt;
    WireReader reader(std::span<const uint8_t>(data, len));
    const auto version = reader.read_u8();
    const auto count = reader.read_u16();
    if (!version || (*version != 3 && *version != PEER_TABLE_VERSION) || !count ||
        *count > PEER_TABLE_MAX_PEERS)
        return std::nullopt;

    std::vector<AdvertisedPeer> out;
    out.reserve(*count);
    for (uint16_t i = 0; i < *count; ++i) {
        const auto node_id = reader.read_bytes(32);
        const auto public_key = reader.read_bytes(32);
        const auto path_count = reader.read_u8();
        if (!node_id || !public_key || !path_count ||
            *path_count > PEER_TABLE_MAX_PATH_HOPS)
            return std::nullopt;

        AdvertisedPeer p;
        std::copy(node_id->begin(), node_id->end(), p.node_id.begin());
        std::copy(public_key->begin(), public_key->end(), p.public_key.begin());
        p.path.reserve(*path_count);
        for (uint8_t j = 0; j < *path_count; ++j) {
            const auto encoded_hop = reader.read_bytes(32);
            if (!encoded_hop)
                return std::nullopt;
            NodeId hop{};
            std::copy(encoded_hop->begin(), encoded_hop->end(), hop.begin());
            p.path.push_back(hop);
        }

        const auto flags = reader.read_u8();
        const auto prefix_count = reader.read_u8();
        if (!flags || *flags != 0 || !prefix_count ||
            *prefix_count > PEER_TABLE_MAX_PREFIXES)
            return std::nullopt;
        p.prefixes.reserve(*prefix_count);
        for (uint8_t j = 0; j < *prefix_count; ++j) {
            IPAddress prefix;
            if (*version == 3) {
                const auto legacy_prefix = reader.read_u32();
                if (!legacy_prefix) return std::nullopt;
                prefix = IPAddress::from_ipv4(*legacy_prefix);
            } else {
                const auto family = reader.read_u8();
                const auto bytes = reader.read_bytes(16);
                if (!family || !bytes ||
                    (*family != static_cast<uint8_t>(IPAddressFamily::IPv4) &&
                     *family != static_cast<uint8_t>(IPAddressFamily::IPv6)))
                    return std::nullopt;
                prefix.family = static_cast<IPAddressFamily>(*family);
                std::copy(bytes->begin(), bytes->end(), prefix.bytes.begin());
                if (prefix.family == IPAddressFamily::IPv4 &&
                    std::any_of(prefix.bytes.begin() + 4, prefix.bytes.end(),
                                [](uint8_t byte) { return byte != 0; }))
                    return std::nullopt;
            }
            const auto prefix_length = reader.read_u8();
            const auto sequence_number = reader.read_u64();
            const auto lease_seconds = reader.read_u32();
            const auto metric = reader.read_u32();
            if (!prefix_length || !sequence_number ||
                !lease_seconds || !metric ||
                *prefix_length > prefix.bit_width() ||
                *sequence_number == 0 || *lease_seconds == 0 ||
                *lease_seconds > ROUTE_MAX_LEASE.count() ||
                *metric > ROUTE_MAX_METRIC)
                return std::nullopt;
            p.prefixes.emplace_back(
                prefix, *prefix_length, *sequence_number,
                *lease_seconds, *metric);
        }
        out.push_back(std::move(p));
    }
    if (!reader.finished())
        return std::nullopt;
    return out;
}

PeerTableMergeStats merge_peer_table(
    PeerManager& pm, RoutingEngine& re,
    const std::vector<AdvertisedPeer>& advertised,
    const NodeId& sender, const NodeId& self,
    ProtocolClock::time_point validated_at) {
    PeerTableMergeStats stats;
    for (const auto& p : advertised) {
        if (p.node_id == self || p.node_id == sender)
            continue;

        if (p.path.size() > PEER_TABLE_MAX_PATH_HOPS ||
            p.prefixes.size() > PEER_TABLE_MAX_PREFIXES) {
            ++stats.malformed;
            continue;
        }

        // A zero X25519 key is not a usable peer identity, even when the
        // advertiser supplies the NodeID that hashes from those zero bytes.
        // Reject it explicitly before checking the normal identity binding.
        if (p.public_key == Key{} ||
            hash_public_key(p.public_key) != p.node_id) {
            ++stats.malformed;
            continue;
        }

        const auto peer_result = pm.upsert(
            p.node_id, p.public_key, std::nullopt, false);
        if (peer_result == PeerUpsertResult::IdentityConflict) {
            ++stats.conflicting;
            continue;
        }
        if (peer_result == PeerUpsertResult::CapacityRejected) {
            ++stats.capacity_rejected;
            continue;
        }
        ++stats.accepted;
        if (peer_result == PeerUpsertResult::Inserted ||
            peer_result == PeerUpsertResult::IdentityBound)
            ++stats.peers_changed;

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
        bool malformed_routing = !path_ok;

        for (const auto& advertised_prefix : p.prefixes) {
            const IPAddress prefix = advertised_prefix.prefix;
            const uint8_t prefix_length = advertised_prefix.prefix_length;
            if (prefix_length > prefix.bit_width() ||
                advertised_prefix.sequence_number == 0 ||
                advertised_prefix.lease_seconds == 0 ||
                advertised_prefix.lease_seconds > ROUTE_MAX_LEASE.count() ||
                advertised_prefix.metric >= ROUTE_MAX_METRIC) {
                malformed_routing = true;
                continue;
            }
            if (!path_ok)
                continue;  // a looping path can never be used, do not install

            Route route;
            route.prefix = prefix;
            route.prefix_length = prefix_length;
            route.type = NextHopType::Relay;
            route.next_hop = sender;
            route.destination = p.node_id;
            route.path = path;
            route.origin = p.node_id;
            route.advertiser = sender;
            route.sequence_number = advertised_prefix.sequence_number;
            route.lease = std::chrono::seconds(
                advertised_prefix.lease_seconds);
            route.metric = advertised_prefix.metric + 1;
            route.validated_at = validated_at;

            const IPAddress canonical = IPPrefix(
                prefix, prefix_length).address;
            const auto routes = re.routes();
            uint64_t highest_sequence = 0;
            for (const auto& candidate : routes) {
                if (candidate.type == NextHopType::Relay &&
                    candidate.prefix == canonical &&
                    candidate.prefix_length == prefix_length &&
                    candidate.origin == p.node_id)
                    highest_sequence = (std::max)(
                        highest_sequence, candidate.sequence_number);
            }
            if (route.sequence_number < highest_sequence) {
                ++stats.stale_rejected;
                continue;
            }
            const auto existing = std::find_if(
                routes.begin(), routes.end(), [&](const Route& candidate) {
                    return candidate.prefix == canonical &&
                        candidate.prefix_length == prefix_length &&
                        candidate.type == NextHopType::Relay &&
                        candidate.next_hop == sender &&
                        candidate.destination == p.node_id;
                });
            if (existing != routes.end()) {
                if (route.sequence_number == existing->sequence_number &&
                    (route.path != existing->path ||
                     route.metric != existing->metric)) {
                    malformed_routing = true;
                    continue;
                }
                if (route.sequence_number == existing->sequence_number) {
                    (void)re.add_route(route);  // refresh lease validation only
                    continue;
                }
            }
            if (route.sequence_number > highest_sequence)
                (void)re.remove_older_learned_routes(
                    route.origin, route.prefix, route.prefix_length,
                    route.sequence_number);
            if (re.add_route(route))
                ++stats.routes_installed;
            else
                ++stats.capacity_rejected;
        }

        if (malformed_routing)
            ++stats.malformed;
    }
    return stats;
}
