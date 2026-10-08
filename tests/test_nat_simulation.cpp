#include "aegis/packet/relay.hpp"
#include "aegis/protocol/endpoint_punch.hpp"
#include "aegis/routing/routing.hpp"
#include <cstdio>
#include <vector>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    ++tests; \
    const bool ok = !!(cond); \
    passed += ok; \
    std::printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

static NodeId make_id(uint8_t value) {
    NodeId id{};
    id[0] = value;
    return id;
}

class NatSimulator {
public:
    NatSimulator(bool endpoint_independent, uint8_t public_ip,
                 uint16_t first_port)
        : endpoint_independent_(endpoint_independent),
          public_ip_(public_ip), next_port_(first_port) {}

    Endpoint outbound(Endpoint internal, Endpoint remote) {
        for (const auto& mapping : mappings_) {
            if (mapping.internal == internal &&
                (endpoint_independent_ || mapping.remote == remote))
                return mapping.external;
        }
        const auto external = Endpoint::from_parts(
            198, 51, 100, public_ip_, next_port_++);
        mappings_.push_back({internal, remote, external});
        return external;
    }

    bool deliver(Endpoint target, Endpoint source) const {
        for (const auto& mapping : mappings_) {
            if (mapping.external != target)
                continue;
            return endpoint_independent_ || mapping.remote == source;
        }
        return false;
    }

private:
    struct Mapping {
        Endpoint internal;
        Endpoint remote;
        Endpoint external;
    };

    bool endpoint_independent_;
    uint8_t public_ip_;
    uint16_t next_port_;
    std::vector<Mapping> mappings_;
};

static Route direct_route(uint32_t prefix, const NodeId& peer) {
    Route route;
    route.prefix = prefix;
    route.prefix_length = 24;
    route.type = NextHopType::Direct;
    route.next_hop = peer;
    route.destination = peer;
    route.path = {peer};
    return route;
}

static Route relay_route(uint32_t prefix, const NodeId& relay,
                         const NodeId& destination) {
    Route route;
    route.prefix = prefix;
    route.prefix_length = 24;
    route.type = NextHopType::Relay;
    route.next_hop = relay;
    route.destination = destination;
    route.path = {relay, destination};
    return route;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("--- deterministic NAT path simulation ---\n");

    const Endpoint stun = Endpoint::from_parts(192, 0, 2, 1, 3478);
    const Endpoint internal_a = Endpoint::from_parts(10, 0, 0, 1, 40000);
    const Endpoint internal_b = Endpoint::from_parts(10, 0, 0, 2, 40000);
    const NodeId id_b = make_id(2);
    const auto now = ProtocolClock::time_point{} + std::chrono::seconds(10);

    // Endpoint-independent (cone) mappings reuse the STUN-discovered public
    // socket for traffic to the other peer, so simultaneous punches reach it.
    {
        NatSimulator nat_a(true, 10, 41000);
        NatSimulator nat_b(true, 11, 42000);
        const auto public_a = nat_a.outbound(internal_a, stun);
        const auto public_b = nat_b.outbound(internal_b, stun);
        const auto a_to_b = nat_a.outbound(internal_a, public_b);
        const auto b_to_a = nat_b.outbound(internal_b, public_a);
        CHECK(a_to_b == public_a);
        CHECK(b_to_a == public_b);
        CHECK(nat_b.deliver(public_b, a_to_b));
        CHECK(nat_a.deliver(public_a, b_to_a));

        EndpointPunchTracker pending;
        CHECK(pending.begin(101, {id_b, public_b}, now));
        const auto response = serialize_endpoint_punch(
            {EndpointPunchKind::Response, 101});
        CHECK(response.has_value());
        const auto decoded = response
            ? deserialize_endpoint_punch(*response) : std::nullopt;
        CHECK(decoded && decoded->transaction_id == 101);
        const auto validated = pending.acknowledge(
            101, id_b, b_to_a, now + std::chrono::seconds(1));
        CHECK(validated && validated->endpoint == public_b);
    }

    // Symmetric mappings are destination-specific: the address learned from
    // STUN is not the mapping allocated for the other peer, so direct punches
    // cannot reach either advertised endpoint in this model.
    {
        NatSimulator nat_a(false, 20, 43000);
        NatSimulator nat_b(false, 21, 44000);
        const auto public_a = nat_a.outbound(internal_a, stun);
        const auto public_b = nat_b.outbound(internal_b, stun);
        const auto a_to_b = nat_a.outbound(internal_a, public_b);
        const auto b_to_a = nat_b.outbound(internal_b, public_a);
        CHECK(a_to_b != public_a);
        CHECK(b_to_a != public_b);
        CHECK(!nat_b.deliver(public_b, a_to_b));
        CHECK(!nat_a.deliver(public_a, b_to_a));

        EndpointPunchTracker pending;
        CHECK(pending.begin(202, {id_b, public_b}, now));
        CHECK(pending.size() == 1);
        const auto expired = pending.expire(now + ENDPOINT_PUNCH_TIMEOUT);
        CHECK(expired.size() == 1 && expired.front() == 202);
        CHECK(pending.size() == 0);
    }

    // With the direct candidate suppressed after its bounded probe failure,
    // routing selects the already reachable relay circuit. Onion layers are
    // still cryptographically opened by each hop before delivery.
    {
        NetworkId network{};
        network[0] = 7;
        const auto source = Identity::create(network);
        const auto relay = Identity::create(network);
        const auto destination = Identity::create(network);
        constexpr uint32_t prefix = 0x0A640000;
        RoutingEngine routes;
        CHECK(routes.add_route(direct_route(prefix, destination.node_id)));
        CHECK(routes.add_route(relay_route(
            prefix, relay.node_id, destination.node_id)));
        auto selected = routes.find_route(0x0A640001);
        CHECK(selected && selected->type == NextHopType::Direct);

        const auto failed_at = now + std::chrono::seconds(5);
        CHECK(routes.mark_probe_sent(
            destination.node_id, destination.node_id, prefix, 24, 1, now));
        CHECK(routes.record_probe_failure(
            destination.node_id, destination.node_id, prefix, 24, 1,
            failed_at));
        selected = routes.find_route(0x0A640001);
        CHECK(selected && selected->type == NextHopType::Relay);

        const uint8_t packet[] = {0x45, 0x00, 0x00, 0x14, 0x0a, 0x64};
        const std::vector<NodeId> path{
            relay.node_id, destination.node_id};
        const std::vector<Key> keys{
            relay.keypair.public_key, destination.keypair.public_key};
        const auto onion = build_onion(
            source.keypair, path, keys, packet, sizeof(packet));
        CHECK(onion.has_value());
        if (onion) {
            const auto first = peel_onion(
                relay.keypair, source.keypair.public_key,
                onion->data(), onion->size());
            CHECK(first && first->next_hop == destination.node_id);
            const auto final = first ? peel_onion(
                destination.keypair, source.keypair.public_key,
                first->inner.data(), first->inner.size()) : std::nullopt;
            CHECK(final && final->next_hop == NodeId{});
            CHECK(final && final->inner ==
                std::vector<uint8_t>(packet, packet + sizeof(packet)));
        }
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
