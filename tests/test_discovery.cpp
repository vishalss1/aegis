#include "aegis/discovery/discovery.hpp"
#include "aegis/identity/identity.hpp"
#include <cstdio>
#include <vector>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- discovery tests ---\n");

    NetworkId net1{};
    net1[0] = 0x01;
    NetworkId net2{};
    net2[0] = 0x02;

    Identity alice = Identity::create(net1);
    Identity bob = Identity::create(net1);
    Identity mallory = Identity::create(net2);

    Endpoint ep_alice = Endpoint::from_parts(10, 10, 0, 1, 45120);
    Endpoint ep_bob = Endpoint::from_parts(10, 10, 0, 2, 45121);
    Endpoint ep_mallory = Endpoint::from_parts(10, 90, 0, 1, 45190);

    // ---- 1. Build/parse round-trip ------------------------------------------
    {
        auto frame = Discovery::build_presence(alice, ep_alice);
        CHECK(frame.size() == DISCOVERY_FRAME_SIZE);

        auto p = Discovery::parse_presence(frame.data(), frame.size());
        CHECK(p.has_value());
        CHECK(p->node_id == alice.node_id);
        CHECK(p->network_id == net1);
        CHECK(p->endpoint == ep_alice);

        // Presence parsing is network-agnostic by design.
        auto f2 = Discovery::build_presence(mallory, ep_mallory);
        auto p2 = Discovery::parse_presence(f2.data(), f2.size());
        CHECK(p2.has_value());
        CHECK(p2->node_id == mallory.node_id);
        CHECK(p2->network_id == net2);
    }

    // ---- 2. Malformed input is rejected -------------------------------------
    {
        auto frame = Discovery::build_presence(alice, ep_alice);
        CHECK(!Discovery::parse_presence(frame.data(), frame.size() - 1).has_value());

        std::vector<uint8_t> bad_type = frame;
        bad_type[1] = 0xFF;
        CHECK(!Discovery::parse_presence(bad_type.data(), bad_type.size()).has_value());

        std::vector<uint8_t> bad_version = frame;
        bad_version[0] = 0x02;
        CHECK(!Discovery::parse_presence(
            bad_version.data(), bad_version.size()).has_value());
    }

    // ---- 3. Received presences are resolved without live socket timing ------
    {
        const Endpoint sender = Endpoint::from_parts(192, 0, 2, 25, 45950);
        constexpr int64_t observed_at_ms = 123456;

        auto bob_frame = Discovery::build_presence(bob, ep_bob);
        auto same_network = Discovery::parse_received_presence(
            bob_frame.data(), bob_frame.size(), sender,
            alice.node_id, observed_at_ms);
        CHECK(same_network.has_value());
        CHECK(same_network->node_id == bob.node_id);
        CHECK(same_network->network_id == net1);
        CHECK(same_network->reachable_endpoint.ip == sender.ip);
        CHECK(same_network->reachable_endpoint.port == ep_bob.port);
        CHECK(same_network->last_seen_ms == observed_at_ms);

        // Cross-network presence remains visible; session setup gates it later.
        auto mallory_frame = Discovery::build_presence(mallory, ep_mallory);
        auto cross_network = Discovery::parse_received_presence(
            mallory_frame.data(), mallory_frame.size(), sender,
            alice.node_id, observed_at_ms);
        CHECK(cross_network.has_value());
        CHECK(cross_network->node_id == mallory.node_id);
        CHECK(cross_network->network_id == net2);
        CHECK(cross_network->reachable_endpoint.ip == sender.ip);
        CHECK(cross_network->reachable_endpoint.port == ep_mallory.port);

        // A node never records its own broadcast as a peer.
        auto alice_frame = Discovery::build_presence(alice, ep_alice);
        CHECK(!Discovery::parse_received_presence(
            alice_frame.data(), alice_frame.size(), sender,
            alice.node_id, observed_at_ms).has_value());

        CHECK(!Discovery::parse_received_presence(
            mallory_frame.data(), mallory_frame.size() - 1, sender,
            alice.node_id, observed_at_ms).has_value());
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
