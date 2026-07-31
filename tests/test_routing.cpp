#include "aegis/routing/routing.hpp"
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

static uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
           static_cast<uint32_t>(d);
}

static NodeId make_id(uint8_t tag) {
    NodeId n{};
    n[0] = tag;
    return n;
}

static Route make_direct(uint32_t prefix, uint8_t plen, const NodeId& peer) {
    Route r;
    r.prefix = prefix;
    r.prefix_length = plen;
    r.type = NextHopType::Direct;
    r.next_hop = peer;
    r.destination = peer;
    return r;
}

static Route make_relay(uint32_t prefix, uint8_t plen,
                        const NodeId& next_hop, const NodeId& destination) {
    Route r;
    r.prefix = prefix;
    r.prefix_length = plen;
    r.type = NextHopType::Relay;
    r.next_hop = next_hop;
    r.destination = destination;
    return r;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- routing engine tests ---\n");

    NodeId p1 = make_id(1);
    NodeId p2 = make_id(2);
    NodeId d  = make_id(9);

    // ---- 1. Longest-prefix match + direct route abstraction -----------------
    {
        RoutingEngine re;
        re.add_route(make_direct(make_ip(10,10,0,0), 24, p1));
        re.add_route(make_direct(make_ip(10,10,0,2), 32, p2));

        CHECK(re.size() == 2);

        // /32 beats /24
        auto f1 = re.find_peer(make_ip(10,10,0,2));
        CHECK(f1.has_value());
        CHECK(*f1 == p2);

        // /24 fallback
        auto f2 = re.find_peer(make_ip(10,10,0,99));
        CHECK(f2.has_value());
        CHECK(*f2 == p1);

        // no route
        CHECK(!re.find_peer(make_ip(10,20,0,1)).has_value());
        CHECK(!re.find_route(make_ip(10,20,0,1)).has_value());

        // direct: next_hop == destination == peer
        auto nh = re.find_next_hop(make_ip(10,10,0,2));
        CHECK(nh.has_value());
        CHECK(*nh == p2);
        auto fp = re.find_peer(make_ip(10,10,0,2));
        CHECK(fp.has_value());
        CHECK(*fp == *nh);
    }

    // ---- 2. Relay next-hop abstraction --------------------------------------
    {
        RoutingEngine re;
        re.add_route(make_direct(make_ip(10,0,0,1), 32, p1));
        re.add_route(make_relay(make_ip(10,30,0,0), 24, p1, d));

        // final destination differs from the next hop we must forward to
        auto peer = re.find_peer(make_ip(10,30,0,5));
        CHECK(peer.has_value());
        CHECK(*peer == d);
        auto nh = re.find_next_hop(make_ip(10,30,0,5));
        CHECK(nh.has_value());
        CHECK(*nh == p1);
    }

    // ---- 3. Upsert: same prefix replaces the old entry ----------------------
    {
        RoutingEngine re;
        re.add_route(make_direct(make_ip(10,10,0,1), 32, p1));
        CHECK(re.add_route(make_direct(make_ip(10,10,0,1), 32, p2)));
        CHECK(re.size() == 1);
        auto f = re.find_peer(make_ip(10,10,0,1));
        CHECK(f.has_value());
        CHECK(*f == p2);
    }

    // ---- 4. Loop avoidance --------------------------------------------------
    {
        NodeId A = make_id(10);
        NodeId D = make_id(12);

        // D via A, A via D -> forwarding would loop
        RoutingEngine re;
        re.add_route(make_relay(make_ip(10,50,0,1), 32, A, D));
        re.add_route(make_relay(make_ip(10,50,0,2), 32, D, A));
        CHECK(!re.find_peer(make_ip(10,50,0,1)).has_value());
        CHECK(!re.find_peer(make_ip(10,50,0,2)).has_value());

        // Multi-hop chain that terminates at a direct route is fine
        RoutingEngine ok;
        ok.add_route(make_direct(make_ip(10,0,0,10), 32, A));
        ok.add_route(make_relay(make_ip(10,0,0,12), 32, A, D));      // D via A
        ok.add_route(make_relay(make_ip(10,60,0,0), 24, A, make_id(13))); // net via A
        auto peer = ok.find_peer(make_ip(10,60,0,5));
        CHECK(peer.has_value());
        auto nh = ok.find_next_hop(make_ip(10,60,0,5));
        CHECK(nh.has_value());
        CHECK(*nh == A);
    }

    // ---- 5. Self-relay rejected at insert -----------------------------------
    {
        RoutingEngine re;
        NodeId X = make_id(30);
        CHECK(!re.add_route(make_relay(make_ip(10,80,0,1), 32, X, X)));
        CHECK(re.empty());
    }

    // ---- 6. Route withdrawal through a dead peer ----------------------------
    {
        RoutingEngine re;
        re.add_route(make_direct(make_ip(10,10,0,1), 32, p1));
        re.add_route(make_relay(make_ip(10,30,0,0), 24, p1, d));
        re.add_route(make_direct(make_ip(10,20,0,1), 32, p2));
        CHECK(re.size() == 3);

        re.remove_route(p1);
        CHECK(re.size() == 1);
        CHECK(!re.find_peer(make_ip(10,10,0,1)).has_value());
        CHECK(!re.find_peer(make_ip(10,30,0,1)).has_value());
        auto left = re.find_peer(make_ip(10,20,0,1));
        CHECK(left.has_value());
        CHECK(*left == p2);
    }

    // ---- 7. clear / empty / accessor ----------------------------------------
    {
        RoutingEngine re;
        CHECK(re.empty());
        CHECK(re.routes().empty());
        re.add_route(make_direct(make_ip(10,10,0,0), 24, p1));
        CHECK(!re.empty());
        CHECK(re.size() == 1);
        CHECK(re.routes().size() == 1);
        re.clear();
        CHECK(re.empty());
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
