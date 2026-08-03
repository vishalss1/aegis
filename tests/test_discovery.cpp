#include "aegis/discovery/discovery.hpp"
#include "aegis/identity/identity.hpp"
#include "aegis/platform/platform.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>

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
    if (!platform_init_winsock()) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    NetworkId net1{};
    net1[0] = 0x01;
    NetworkId net2{};
    net2[0] = 0x02;

    Identity alice = Identity::create(net1);
    Identity mallory = Identity::create(net2);

    Endpoint ep_alice = Endpoint::from_parts(10, 10, 0, 1, 45120);
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

        // Another network's presence parses identically — presence is
        // network-agnostic by design (the receiver still sees it).
        auto f2 = Discovery::build_presence(mallory, ep_mallory);
        auto p2 = Discovery::parse_presence(f2.data(), f2.size());
        CHECK(p2.has_value());
        CHECK(p2->node_id == mallory.node_id);
        CHECK(p2->network_id == net2);
    }

    // ---- 2. Malformed input is rejected -------------------------------------
    {
        auto frame = Discovery::build_presence(alice, ep_alice);
        // Truncated frame.
        CHECK(!Discovery::parse_presence(frame.data(), frame.size() - 1).has_value());
        // Wrong packet type.
        std::vector<uint8_t> bad = frame;
        bad[1] = 0xFF;
        CHECK(!Discovery::parse_presence(bad.data(), bad.size()).has_value());
        // Wrong version.
        std::vector<uint8_t> bad2 = frame;
        bad2[0] = 0x02;
        CHECK(!Discovery::parse_presence(bad2.data(), bad2.size()).has_value());
    }

    // ---- 3. Two nodes on one host see each other (same + cross network) -----
    {
        Discovery d_a;
        Discovery d_m;
        // Both bind the shared discovery port (SO_REUSEADDR); presence is
        // network-agnostic so alice and mallory must see each other even though
        // they are on different networks.
        CHECK(d_a.start(alice, ep_alice));
        CHECK(d_m.start(mallory, ep_mallory));

        bool saw = false;
        for (int i = 0; i < 30 && !saw; i++) {
            auto pa = d_a.presences();
            auto pm = d_m.presences();
            if (pa.count(mallory.node_id) && pm.count(alice.node_id))
                saw = true;
            else
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        CHECK(saw);

        auto pa = d_a.presences();
        auto pm = d_m.presences();
        CHECK(pa.count(alice.node_id) == 0);    // never record self
        CHECK(pm.count(mallory.node_id) == 0);  // never record self
        CHECK(pa.count(mallory.node_id) == 1);
        CHECK(pm.count(alice.node_id) == 1);
        CHECK(pa[mallory.node_id].network_id == net2);  // cross-network visible
        CHECK(pm[alice.node_id].network_id == net1);

        // reachable_endpoint = transport sender IP + announced listen port.
        // Loopback test: sender is 127.0.0.1, announced port is 45190.
        CHECK(pa[mallory.node_id].reachable_endpoint.ip == htonl(0x7F000001u));
        CHECK(pa[mallory.node_id].reachable_endpoint.port == htons(45190));
        CHECK(pm[alice.node_id].reachable_endpoint.ip == htonl(0x7F000001u));
        CHECK(pm[alice.node_id].reachable_endpoint.port == htons(45120));

        d_a.stop();
        d_m.stop();
    }

    printf("\n%d / %d passed\n", passed, tests);
    platform_cleanup_winsock();
    return (passed == tests) ? 0 : 1;
}
