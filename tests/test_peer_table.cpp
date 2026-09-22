#include "aegis/peer/peer_table.hpp"
#include "aegis/identity/identity.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

static uint32_t pt_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
           static_cast<uint32_t>(d);
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- peer table tests ---\n");

    NetworkId net{};
    net[0] = 0x01;
    Identity alice   = Identity::create(net);
    Identity bob     = Identity::create(net);
    Identity charlie = Identity::create(net);
    Identity dave    = Identity::create(net);

    // ---- 1. Serialize/deserialize round-trip --------------------------------
    {
        std::vector<AdvertisedPeer> in;
        AdvertisedPeer a;
        a.node_id = charlie.node_id;
        a.public_key = charlie.keypair.public_key;
        a.prefixes.emplace_back(pt_ip(10, 30, 0, 0), 24);
        a.prefixes.emplace_back(pt_ip(10, 30, 0, 2), 32);
        in.push_back(a);

        AdvertisedPeer b;
        b.node_id = dave.node_id;
        b.public_key = dave.keypair.public_key;
        b.path = { bob.node_id, charlie.node_id, dave.node_id };
        in.push_back(b);

        auto wire = serialize_peer_table(in);
        CHECK(wire.has_value());
        CHECK(wire && wire->size() >= 3);
        if (wire) {
            CHECK((*wire)[0] == 0x02);
            CHECK((*wire)[1] == 0x00 && (*wire)[2] == 0x02);
            CHECK((*wire)[67] == 0x00);  // first peer has no path hops
            CHECK((*wire)[68] == 0x00);  // reserved flags are canonical zero
            CHECK((*wire)[69] == 0x02);  // two advertised prefixes
            CHECK((*wire)[70] == 10 && (*wire)[71] == 30 &&
                  (*wire)[72] == 0 && (*wire)[73] == 0);
            CHECK((*wire)[74] == 24);
        }
        auto out = wire
            ? deserialize_peer_table(wire->data(), wire->size())
            : std::nullopt;
        CHECK(out.has_value());
        if (out) {
            CHECK(out->size() == 2);
            CHECK((*out)[0].node_id == charlie.node_id);
            CHECK((*out)[0].public_key == charlie.keypair.public_key);
            CHECK((*out)[0].prefixes.size() == 2);
            CHECK((*out)[0].prefixes[0] == std::make_pair(pt_ip(10, 30, 0, 0), (uint8_t)24));
            CHECK((*out)[0].prefixes[1] == std::make_pair(pt_ip(10, 30, 0, 2), (uint8_t)32));
            CHECK((*out)[1].prefixes.empty());
            CHECK((*out)[1].path.size() == 3);
            CHECK((*out)[1].path[0] == bob.node_id);
            CHECK((*out)[1].path[1] == charlie.node_id);
            CHECK((*out)[1].path[2] == dave.node_id);
        }
    }

    // ---- 2. Truncated / bad-version input is rejected ------------------------
    {
        std::vector<uint8_t> bad = {0x00, 0x00, 0x01};
        CHECK(!deserialize_peer_table(bad.data(), bad.size()).has_value());
        std::vector<uint8_t> truncated = {0x02, 0x00, 0x02, 0xAA};
        CHECK(!deserialize_peer_table(truncated.data(), truncated.size()).has_value());
        std::vector<uint8_t> bad_version = {0x01, 0x00, 0x00};
        CHECK(!deserialize_peer_table(bad_version.data(), bad_version.size()).has_value());

        std::vector<uint8_t> trailing = {0x02, 0x00, 0x00, 0xFF};
        CHECK(!deserialize_peer_table(
            trailing.data(), trailing.size()).has_value());

        std::vector<uint8_t> nonzero_reserved(70, 0);
        nonzero_reserved[0] = 0x02;
        nonzero_reserved[2] = 0x01;
        nonzero_reserved[68] = 0x01;
        CHECK(!deserialize_peer_table(
            nonzero_reserved.data(), nonzero_reserved.size()).has_value());
        CHECK(!deserialize_peer_table(nullptr, 0).has_value());
    }

    // ---- 2b. Peer-table resource limits are enforced ------------------------
    {
        const uint16_t excessive_peer_count = PEER_TABLE_MAX_PEERS + 1;
        std::vector<uint8_t> excessive_peers = {
            0x02,
            static_cast<uint8_t>(excessive_peer_count >> 8),
            static_cast<uint8_t>(excessive_peer_count & 0xFF)
        };
        CHECK(!deserialize_peer_table(
            excessive_peers.data(), excessive_peers.size()).has_value());

        std::vector<uint8_t> excessive_path(68, 0);
        excessive_path[0] = 0x02;
        excessive_path[2] = 0x01;
        excessive_path[67] = PEER_TABLE_MAX_PATH_HOPS + 1;
        CHECK(!deserialize_peer_table(
            excessive_path.data(), excessive_path.size()).has_value());

        std::vector<uint8_t> excessive_prefixes(70, 0);
        excessive_prefixes[0] = 0x02;
        excessive_prefixes[2] = 0x01;
        excessive_prefixes[69] = PEER_TABLE_MAX_PREFIXES + 1;
        CHECK(!deserialize_peer_table(
            excessive_prefixes.data(), excessive_prefixes.size()).has_value());

        std::vector<uint8_t> oversized(PEER_TABLE_MAX_WIRE_BYTES + 1, 0);
        oversized[0] = 0x02;
        CHECK(!deserialize_peer_table(
            oversized.data(), oversized.size()).has_value());

        std::vector<AdvertisedPeer> too_many_peers(
            PEER_TABLE_MAX_PEERS + 1);
        CHECK(!serialize_peer_table(too_many_peers).has_value());

        AdvertisedPeer bounded;
        bounded.path.resize(PEER_TABLE_MAX_PATH_HOPS);
        bounded.prefixes.resize(PEER_TABLE_MAX_PREFIXES);
        auto boundary_wire = serialize_peer_table({bounded});
        CHECK(boundary_wire.has_value());
        CHECK(boundary_wire && deserialize_peer_table(
            boundary_wire->data(), boundary_wire->size()).has_value());

        bounded.path.emplace_back();
        CHECK(!serialize_peer_table({bounded}).has_value());
        bounded.path.resize(PEER_TABLE_MAX_PATH_HOPS);
        bounded.prefixes.emplace_back();
        CHECK(!serialize_peer_table({bounded}).has_value());
    }

    // ---- 3. Merge learns new peers as untrusted relay-only -------------------
    {
        PeerManager pm;
        RoutingEngine re;

        std::vector<AdvertisedPeer> advertised;
        AdvertisedPeer c;
        c.node_id = charlie.node_id;
        c.public_key = charlie.keypair.public_key;
        c.prefixes.emplace_back(pt_ip(10, 30, 0, 0), 24);
        advertised.push_back(c);
        AdvertisedPeer d;
        d.node_id = dave.node_id;
        d.public_key = dave.keypair.public_key;
        d.path = { charlie.node_id, dave.node_id };  // bob -> charlie -> dave
        d.prefixes.emplace_back(pt_ip(10, 40, 0, 0), 24);
        advertised.push_back(d);

        const auto stats = merge_peer_table(
            pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(stats.accepted == 2);
        CHECK(stats.peers_changed == 2);
        CHECK(stats.routes_installed == 2);
        CHECK(stats.malformed == 0);
        CHECK(stats.conflicting == 0);
        CHECK(stats.capacity_rejected == 0);
        CHECK(stats.changed());
        CHECK(pm.size() == 2);

        const Peer* pc = pm.get_peer(charlie.node_id);
        CHECK(pc != nullptr);
        if (pc) {
            CHECK(!pc->trusted);
            CHECK(!pc->endpoint.has_value());
            CHECK(pc->public_key == charlie.keypair.public_key);
        }

        // Routes: prefix 10.30.0.0/24 -> next_hop bob -> destination charlie,
        // with a full hop path [bob, charlie] from the advertised list.
        auto nh = re.find_next_hop(pt_ip(10, 30, 0, 5));
        auto dst = re.find_peer(pt_ip(10, 30, 0, 5));
        CHECK(nh.has_value() && *nh == bob.node_id);
        CHECK(dst.has_value() && *dst == charlie.node_id);
        auto rc = re.find_route(pt_ip(10, 30, 0, 5));
        CHECK(rc.has_value());
        if (rc) {
            CHECK(rc->path.size() == 2);
            CHECK(rc->path[0] == bob.node_id);
            CHECK(rc->path[1] == charlie.node_id);
        }

        // A multi-hop advertised path reconstructs to [bob, charlie, dave].
        auto rd = re.find_route(pt_ip(10, 40, 0, 7));
        CHECK(rd.has_value());
        if (rd) {
            CHECK(rd->path.size() == 3);
            CHECK(rd->path[0] == bob.node_id);
            CHECK(rd->path[1] == charlie.node_id);
            CHECK(rd->path[2] == dave.node_id);
        }

        // No endpoint was learned — real IPs never travel in gossip.
        CHECK(!pm.get_peer(charlie.node_id)->endpoint.has_value());
    }

    // ---- 3b. Paths that loop back through the receiver are rejected ----------
    {
        PeerManager pm;
        RoutingEngine re;
        std::vector<AdvertisedPeer> advertised;
        AdvertisedPeer d;
        d.node_id = dave.node_id;
        d.public_key = dave.keypair.public_key;
        // Advertiser (bob) claims a path that passes through us (alice) —
        // installing it would let the onion loop forever.
        d.path = { alice.node_id, dave.node_id };
        d.prefixes.emplace_back(pt_ip(10, 40, 0, 0), 24);
        advertised.push_back(d);

        const auto stats = merge_peer_table(
            pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(stats.accepted == 1);      // peer identity itself is still valid
        CHECK(stats.peers_changed == 1);
        CHECK(stats.routes_installed == 0);
        CHECK(stats.malformed == 1);     // the advertised path is invalid
        CHECK(re.empty());              // but no routable path is installed
        CHECK(re.find_route(pt_ip(10, 40, 0, 9)).has_value() == false);
    }

    // ---- 4. Re-merge of identical table learns nothing -----------------------
    {
        PeerManager pm;
        RoutingEngine re;
        std::vector<AdvertisedPeer> advertised;
        AdvertisedPeer c;
        c.node_id = charlie.node_id;
        c.public_key = charlie.keypair.public_key;
        c.prefixes.emplace_back(pt_ip(10, 30, 0, 0), 24);
        advertised.push_back(c);

        merge_peer_table(pm, re, advertised, bob.node_id, alice.node_id);
        const auto again = merge_peer_table(
            pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(again.accepted == 1);
        CHECK(again.peers_changed == 0);
        CHECK(again.routes_installed == 0);
        CHECK(!again.changed());
        CHECK(re.size() == 1);  // route refreshed, not duplicated
    }

    // ---- 5. Self and sender entries are ignored ------------------------------
    {
        PeerManager pm;
        RoutingEngine re;
        std::vector<AdvertisedPeer> advertised;
        AdvertisedPeer self;
        self.node_id = alice.node_id;      // our own NodeID
        self.prefixes.emplace_back(pt_ip(10, 10, 0, 0), 24);
        AdvertisedPeer sender;
        sender.node_id = bob.node_id;      // the sender — already directly connected
        sender.prefixes.emplace_back(pt_ip(10, 20, 0, 0), 24);
        advertised.push_back(self);
        advertised.push_back(sender);

        const auto stats = merge_peer_table(
            pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(stats.accepted == 0);
        CHECK(stats.peers_changed == 0);
        CHECK(stats.malformed == 0);
        CHECK(pm.size() == 0);
        CHECK(re.empty());
    }

    // ---- 6. Existing direct route is preserved (no downgrade to relay) -------
    {
        PeerManager pm;
        RoutingEngine re;
        Route direct;
        direct.prefix = pt_ip(10, 30, 0, 0);
        direct.prefix_length = 24;
        direct.type = NextHopType::Direct;
        direct.next_hop = charlie.node_id;
        direct.destination = charlie.node_id;
        direct.path = { charlie.node_id };
        re.add_route(direct);

        std::vector<AdvertisedPeer> advertised;
        AdvertisedPeer c;
        c.node_id = charlie.node_id;
        c.public_key = charlie.keypair.public_key;
        c.prefixes.emplace_back(pt_ip(10, 30, 0, 0), 24);
        advertised.push_back(c);

        merge_peer_table(pm, re, advertised, bob.node_id, alice.node_id);
        auto route = re.find_route(pt_ip(10, 30, 0, 9));
        CHECK(route.has_value());
        if (route)
            CHECK(route->type == NextHopType::Direct);
    }

    // ---- 7. Forged NodeID/public-key bindings are rejected ------------------
    {
        PeerManager pm;
        RoutingEngine re;

        AdvertisedPeer forged;
        forged.node_id = charlie.node_id;
        forged.public_key = dave.keypair.public_key;
        forged.prefixes.emplace_back(pt_ip(10, 66, 0, 0), 24);

        const auto stats = merge_peer_table(
            pm, re, {forged}, bob.node_id, alice.node_id);

        CHECK(stats.accepted == 0);
        CHECK(stats.peers_changed == 0);
        CHECK(stats.routes_installed == 0);
        CHECK(stats.malformed == 1);
        CHECK(stats.conflicting == 0);
        CHECK(!pm.has_peer(charlie.node_id));
        CHECK(pm.size() == 0);
        CHECK(re.empty());
        CHECK(!re.find_route(pt_ip(10, 66, 0, 1)).has_value());
    }

    // ---- 8. All-zero public keys are rejected explicitly -------------------
    {
        PeerManager pm;
        RoutingEngine re;

        AdvertisedPeer zero_key_peer;
        zero_key_peer.public_key = Key{};
        // This binding passes a hash-only check. The key itself must still be
        // rejected because an all-zero X25519 public key is not a peer identity.
        zero_key_peer.node_id = hash_public_key(zero_key_peer.public_key);
        zero_key_peer.prefixes.emplace_back(pt_ip(10, 67, 0, 0), 24);

        const auto stats = merge_peer_table(
            pm, re, {zero_key_peer}, bob.node_id, alice.node_id);

        CHECK(stats.accepted == 0);
        CHECK(stats.peers_changed == 0);
        CHECK(stats.routes_installed == 0);
        CHECK(stats.malformed == 1);
        CHECK(stats.conflicting == 0);
        CHECK(!pm.has_peer(zero_key_peer.node_id));
        CHECK(pm.size() == 0);
        CHECK(re.empty());
        CHECK(!re.find_route(pt_ip(10, 67, 0, 1)).has_value());
    }

    // ---- 9. Persistent table capacity rejects state and counters ------------
    {
        AdvertisedPeer c;
        c.node_id = charlie.node_id;
        c.public_key = charlie.keypair.public_key;
        c.prefixes.emplace_back(pt_ip(10, 68, 0, 0), 24);

        PeerManager full_peers(/*max_peers=*/0);
        RoutingEngine routes;
        const auto peer_capacity = merge_peer_table(
            full_peers, routes, {c}, bob.node_id, alice.node_id);
        CHECK(peer_capacity.accepted == 0);
        CHECK(peer_capacity.peers_changed == 0);
        CHECK(peer_capacity.routes_installed == 0);
        CHECK(peer_capacity.capacity_rejected == 1);
        CHECK(full_peers.size() == 0);
        CHECK(routes.empty());

        PeerManager peers;
        RoutingEngine full_routes(/*max_routes=*/0);
        const auto route_capacity = merge_peer_table(
            peers, full_routes, {c}, bob.node_id, alice.node_id);
        CHECK(route_capacity.accepted == 1);
        CHECK(route_capacity.peers_changed == 1);
        CHECK(route_capacity.routes_installed == 0);
        CHECK(route_capacity.capacity_rejected == 1);
        CHECK(peers.has_peer(charlie.node_id));
        CHECK(full_routes.empty());
    }

    // ---- 10. Existing identity conflicts are reported -----------------------
    {
        PeerManager pm;
        RoutingEngine re;

        CHECK(pm.upsert(charlie.node_id, dave.keypair.public_key) ==
              PeerUpsertResult::Inserted);

        AdvertisedPeer c;
        c.node_id = charlie.node_id;
        c.public_key = charlie.keypair.public_key;
        c.prefixes.emplace_back(pt_ip(10, 69, 0, 0), 24);

        const auto stats = merge_peer_table(
            pm, re, {c}, bob.node_id, alice.node_id);
        CHECK(stats.accepted == 0);
        CHECK(stats.peers_changed == 0);
        CHECK(stats.routes_installed == 0);
        CHECK(stats.malformed == 0);
        CHECK(stats.conflicting == 1);
        CHECK(stats.capacity_rejected == 0);
        CHECK(!stats.changed());
        CHECK(re.empty());
    }

    // ---- 11. Binding a placeholder is reported as changed state -------------
    {
        PeerManager pm;
        RoutingEngine re;
        CHECK(pm.upsert(charlie.node_id, Key{}) ==
              PeerUpsertResult::Inserted);

        AdvertisedPeer c;
        c.node_id = charlie.node_id;
        c.public_key = charlie.keypair.public_key;

        const auto stats = merge_peer_table(
            pm, re, {c}, bob.node_id, alice.node_id);
        CHECK(stats.accepted == 1);
        CHECK(stats.peers_changed == 1);
        CHECK(stats.routes_installed == 0);
        CHECK(stats.malformed == 0);
        CHECK(stats.conflicting == 0);
        CHECK(stats.capacity_rejected == 0);
        CHECK(stats.changed());
        CHECK(pm.get_peer(charlie.node_id)->public_key ==
              charlie.keypair.public_key);
    }

    printf("--- peer table: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
