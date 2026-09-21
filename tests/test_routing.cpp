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
    r.path = { peer };
    return r;
}

static Route make_relay(uint32_t prefix, uint8_t plen,
                        const NodeId& next_hop, const NodeId& destination,
                        std::vector<NodeId> path = {}) {
    Route r;
    r.prefix = prefix;
    r.prefix_length = plen;
    r.type = NextHopType::Relay;
    r.next_hop = next_hop;
    r.destination = destination;
    if (path.empty())
        path = { next_hop, destination };
    r.path = std::move(path);
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

    // ---- 4. New routes are rejected at capacity; replacements still work ----
    {
        RoutingEngine re(/*max_routes=*/2);
        CHECK(re.add_route(make_direct(make_ip(10,10,0,1), 32, p1)));
        CHECK(re.add_route(make_direct(make_ip(10,10,0,2), 32, p2)));
        CHECK(!re.add_route(make_direct(make_ip(10,10,0,3), 32, d)));
        CHECK(re.size() == 2);
        CHECK(!re.find_route(make_ip(10,10,0,3)).has_value());

        CHECK(re.add_route(make_direct(make_ip(10,10,0,1), 32, d)));
        CHECK(re.size() == 2);
        auto replaced = re.find_peer(make_ip(10,10,0,1));
        CHECK(replaced.has_value());
        CHECK(replaced && *replaced == d);
    }

    // ---- 5. Loop avoidance is enforced on the hop path ----------------------
    {
        NodeId A = make_id(10);
        NodeId D = make_id(12);

        RoutingEngine re;

        // A path that revisits a node would loop the onion forever.
        CHECK(!re.add_route(make_relay(make_ip(10,50,0,1), 32, A, D,
                                       { A, D, A })));

        // next_hop must be the first hop of the path.
        CHECK(!re.add_route(make_relay(make_ip(10,50,0,2), 32, A, D,
                                       { D, A, D })));

        // The path must end at the destination.
        CHECK(!re.add_route(make_relay(make_ip(10,50,0,3), 32, A, D,
                                       { A, A })));

        // A relay with next_hop == destination is rejected outright.
        CHECK(!re.add_route(make_relay(make_ip(10,50,0,4), 32, A, A)));

        // A direct route must name its destination.
        Route no_path;
        no_path.prefix = make_ip(10,50,0,5);
        no_path.prefix_length = 32;
        no_path.type = NextHopType::Direct;
        no_path.next_hop = A;
        no_path.destination = A;
        CHECK(!re.add_route(no_path));

        CHECK(re.empty());

        // A valid multi-hop path resolves: forward to A, final dest D.
        re.add_route(make_direct(make_ip(10,0,0,10), 32, A));
        re.add_route(make_relay(make_ip(10,60,0,0), 24, A, D,
                                { A, D }));
        auto peer = re.find_peer(make_ip(10,60,0,5));
        CHECK(peer.has_value());
        CHECK(*peer == D);
        auto nh = re.find_next_hop(make_ip(10,60,0,5));
        CHECK(nh.has_value());
        CHECK(*nh == A);
        auto r4 = re.find_route(make_ip(10,60,0,5));
        CHECK(r4.has_value());
        if (r4) {
            CHECK(r4->path.size() == 2);
            CHECK(r4->path[0] == A);
            CHECK(r4->path[1] == D);
        }
    }

    // ---- 6. Self-relay rejected at insert -----------------------------------
    {
        RoutingEngine re;
        NodeId X = make_id(30);
        CHECK(!re.add_route(make_relay(make_ip(10,80,0,1), 32, X, X)));
        CHECK(re.empty());
    }

    // ---- 7. Route withdrawal through a dead peer ----------------------------
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

    // ---- 8. Path precedence and routes_to -----------------------------------
    {
        RoutingEngine re;
        NodeId A = make_id(10);
        NodeId B = make_id(11);
        NodeId D = make_id(12);

        // Add 3-hop relay route
        re.add_route(make_relay(make_ip(10,90,0,0), 24, A, D, { A, B, D }));
        auto r1 = re.find_route(make_ip(10,90,0,5));
        CHECK(r1.has_value());
        CHECK(r1->path.size() == 3);

        // Shorter 2-hop relay route to same prefix should win
        re.add_route(make_relay(make_ip(10,90,0,0), 24, A, D, { A, D }));
        auto r2 = re.find_route(make_ip(10,90,0,5));
        CHECK(r2.has_value());
        CHECK(r2->path.size() == 2);

        // Direct route should win over Relay route
        re.add_route(make_direct(make_ip(10,90,0,0), 24, D));
        auto r3 = re.find_route(make_ip(10,90,0,5));
        CHECK(r3.has_value());
        CHECK(r3->type == NextHopType::Direct);

        // routes_to check
        auto r_to_D = re.routes_to(D);
        CHECK(r_to_D.size() == 1);
        CHECK(r_to_D[0].destination == D);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
