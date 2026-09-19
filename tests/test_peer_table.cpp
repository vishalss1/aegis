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
        CHECK(wire.size() >= 3);
        auto out = deserialize_peer_table(wire.data(), wire.size());
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
        CHECK(!deserialize_peer_table(nullptr, 0).has_value());
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

        size_t learned = merge_peer_table(pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(learned == 2);
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

        size_t learned = merge_peer_table(pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(learned == 1);            // peer itself is still learned
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
        size_t again = merge_peer_table(pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(again == 0);
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

        size_t learned = merge_peer_table(pm, re, advertised, bob.node_id, alice.node_id);
        CHECK(learned == 0);
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

        size_t routes_installed = 99;
        size_t learned = merge_peer_table(
            pm, re, {forged}, bob.node_id, alice.node_id,
            &routes_installed);

        CHECK(learned == 0);
        CHECK(routes_installed == 0);
        CHECK(!pm.has_peer(charlie.node_id));
        CHECK(pm.size() == 0);
        CHECK(re.empty());
        CHECK(!re.find_route(pt_ip(10, 66, 0, 1)).has_value());
    }

    printf("--- peer table: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
