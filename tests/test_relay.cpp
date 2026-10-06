#include "aegis/packet/relay.hpp"
#include "aegis/packet/relay_limiter.hpp"
#include "aegis/packet/mtu.hpp"
#include "aegis/identity/identity.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

static int tests  = 0;
static int passed = 0;

class ManualClock final : public ProtocolClock {
public:
    [[nodiscard]] time_point now() const noexcept override { return now_; }
    void advance(std::chrono::milliseconds duration) { now_ += duration; }

private:
    time_point now_{};
};

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- relay / onion tests ---\n");

    NetworkId net{};
    net[0] = 0x01;
    Identity src = Identity::create(net);
    Identity b   = Identity::create(net);
    Identity c   = Identity::create(net);
    Identity d   = Identity::create(net);

    const uint8_t packet[] = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        0x0a, 0x0a, 0x00, 0x01, 0x0a, 0x28, 0x00, 0x01
    };
    const size_t packet_len = sizeof(packet);

    std::vector<NodeId> path = { b.node_id, c.node_id, d.node_id };
    std::vector<Key> keys   = { b.keypair.public_key, c.keypair.public_key,
                                d.keypair.public_key };

    // ---- 1. Full 3-hop onion: each relay sees only its own layer ------------
    {
        auto onion = build_onion(src.keypair, path, keys, packet, packet_len);
        CHECK(onion.has_value());
        CHECK(onion->size() == packet_len + 3 * ONION_OVERHEAD);
        if (!onion) return 1;

        // B opens the outer layer: next hop is C, inner is NOT the packet.
        auto pb = peel_onion(b.keypair, src.keypair.public_key,
                             onion->data(), onion->size());
        CHECK(pb.has_value());
        if (pb) {
            CHECK(pb->next_hop == c.node_id);
            CHECK(pb->inner.size() == packet_len + 2 * ONION_OVERHEAD);
            CHECK(!(pb->inner.size() == packet_len &&
                    std::memcmp(pb->inner.data(), packet, packet_len) == 0));
        }

        // C opens the next layer: next hop is D.
        auto pc = peel_onion(c.keypair, src.keypair.public_key,
                             pb->inner.data(), pb->inner.size());
        CHECK(pc.has_value());
        if (pc) {
            CHECK(pc->next_hop == d.node_id);
            CHECK(pc->inner.size() == packet_len + ONION_OVERHEAD);
        }

        // D opens the final layer: all-zero next hop, plaintext packet back.
        auto pd = peel_onion(d.keypair, src.keypair.public_key,
                             pc->inner.data(), pc->inner.size());
        CHECK(pd.has_value());
        if (pd) {
            bool zero = true;
            for (auto byte : pd->next_hop)
                if (byte != 0) { zero = false; break; }
            CHECK(zero);
            CHECK(pd->inner.size() == packet_len);
            CHECK(std::memcmp(pd->inner.data(), packet, packet_len) == 0);
        }
    }

    // ---- 2. A relay without the right key cannot open the layer ------------
    {
        auto onion = build_onion(src.keypair, path, keys, packet, packet_len);
        CHECK(onion.has_value());
        if (!onion) return 1;
        // C's key cannot open the layer meant for B (different static secret).
        auto wrong = peel_onion(c.keypair, src.keypair.public_key,
                                onion->data(), onion->size());
        CHECK(!wrong.has_value());
    }

    // ---- 3. Wrong source key cannot open the layer --------------------------
    {
        auto onion = build_onion(src.keypair, path, keys, packet, packet_len);
        CHECK(onion.has_value());
        if (!onion) return 1;
        Identity impersonator = Identity::create(net);
        // B's layer is keyed to src; an impostor's public key fails auth.
        auto wrong = peel_onion(b.keypair, impersonator.keypair.public_key,
                                onion->data(), onion->size());
        CHECK(!wrong.has_value());
    }

    // ---- 4. Tampered blob is rejected ---------------------------------------
    {
        auto onion = build_onion(src.keypair, path, keys, packet, packet_len);
        CHECK(onion.has_value());
        if (!onion) return 1;

        auto extended_blob = *onion;
        extended_blob.push_back(0x00);
        auto extended = peel_onion(b.keypair, src.keypair.public_key,
                                   extended_blob.data(), extended_blob.size());
        CHECK(!extended.has_value());

        onion->at(onion->size() - 1) ^= 0xFF;  // corrupt the outer tag
        auto tampered = peel_onion(b.keypair, src.keypair.public_key,
                                   onion->data(), onion->size());
        CHECK(!tampered.has_value());
    }

    // ---- 5. Too-short / malformed inputs ------------------------------------
    {
        uint8_t tiny[ONION_OVERHEAD - 1] = {};
        bool all_prefixes_rejected = true;
        for (size_t length = 0; length < ONION_OVERHEAD; ++length) {
            all_prefixes_rejected &= !peel_onion(
                b.keypair, src.keypair.public_key, tiny, length).has_value();
        }
        CHECK(all_prefixes_rejected);
        CHECK(!peel_onion(b.keypair, src.keypair.public_key, nullptr, 0).has_value());
        std::vector<NodeId> empty;
        std::vector<Key> empty_keys;
        CHECK(!build_onion(src.keypair, empty, empty_keys, packet, packet_len).has_value());
        CHECK(!build_onion(src.keypair, path, keys, nullptr, 0).has_value());
    }

    // ---- 6. Single-hop onion (direct packet to the destination) -------------
    {
        std::vector<NodeId> one = { d.node_id };
        std::vector<Key> one_keys = { d.keypair.public_key };
        auto onion = build_onion(src.keypair, one, one_keys, packet, packet_len);
        CHECK(onion.has_value());
        if (onion) {
            CHECK(onion->size() == packet_len + ONION_OVERHEAD);
            auto pd = peel_onion(d.keypair, src.keypair.public_key,
                                 onion->data(), onion->size());
            CHECK(pd.has_value());
            if (pd) {
                bool zero = true;
                for (auto byte : pd->next_hop)
                    if (byte != 0) { zero = false; break; }
                CHECK(zero);
                CHECK(pd->inner.size() == packet_len);
                CHECK(std::memcmp(pd->inner.data(), packet, packet_len) == 0);
            }
        }
    }

    // ---- 7. Oversized path is refused ---------------------------------------
    {
        std::vector<NodeId> many;
        std::vector<Key> many_keys;
        for (int i = 0; i <= ONION_MAX_HOPS; ++i) {
            Identity hop = Identity::create(net);
            many.push_back(hop.node_id);
            many_keys.push_back(hop.keypair.public_key);
        }
        CHECK(!build_onion(src.keypair, many, many_keys, packet, packet_len).has_value());
    }

    // ---- 8. Calculated wire budgets match real onions at every relay depth --
    {
        std::vector<NodeId> all_hops;
        std::vector<Key> all_keys;
        for (size_t index = 0; index < ONION_MAX_HOPS; ++index) {
            Identity hop = Identity::create(net);
            all_hops.push_back(hop.node_id);
            all_keys.push_back(hop.keypair.public_key);
        }

        for (size_t depth = 2; depth <= ONION_MAX_HOPS; ++depth) {
            const auto end_offset =
                static_cast<std::vector<NodeId>::difference_type>(depth);
            std::vector<NodeId> depth_hops(
                all_hops.begin(), all_hops.begin() + end_offset);
            std::vector<Key> depth_keys(
                all_keys.begin(), all_keys.begin() + end_offset);
            const auto onion = build_onion(
                src.keypair, depth_hops, depth_keys, packet, packet_len);
            const auto overhead = wire_overhead_for_route_depth(depth);

            CHECK(onion.has_value());
            CHECK(overhead.has_value());
            if (onion && overhead) {
                const size_t relay_payload_size = NODE_ID_SIZE + onion->size();
                const size_t encrypted_datagram_size =
                    SESSION_FRAME_OVERHEAD + relay_payload_size;
                const size_t physical_wire_size =
                    OUTER_IPV4_UDP_OVERHEAD + encrypted_datagram_size;
                CHECK(physical_wire_size == packet_len + *overhead);
            }
        }
    }

    // ---- 9. Relay forwarding uses per-peer and global token buckets --------
    {
        ManualClock clock;
        RelayQuotaConfig config;
        config.per_peer_packets_per_second = 2.0;
        config.per_peer_packet_burst = 2;
        config.per_peer_bytes_per_second = 100.0;
        config.per_peer_byte_burst = 100;
        config.global_packets_per_second = 10.0;
        config.global_packet_burst = 3;
        config.global_bytes_per_second = 100.0;
        config.global_byte_burst = 150;
        config.max_peers = 2;
        config.idle_ttl = std::chrono::milliseconds(1000);
        RelayForwardLimiter limiter(clock, config);

        CHECK(limiter.allow(b.node_id, 60) == RelayQuotaResult::Allowed);
        CHECK(limiter.allow(b.node_id, 41) ==
              RelayQuotaResult::PeerLimited);
        CHECK(limiter.allow(b.node_id, 40) == RelayQuotaResult::Allowed);
        CHECK(limiter.allow(b.node_id, 1) ==
              RelayQuotaResult::PeerLimited);

        // Failed peer admission consumed no global capacity: C can still use
        // the exact 50 bytes left in the global bucket.
        CHECK(limiter.allow(c.node_id, 51) ==
              RelayQuotaResult::GlobalLimited);
        CHECK(limiter.allow(c.node_id, 50) == RelayQuotaResult::Allowed);
        CHECK(limiter.tracked_peers() == 2);

        clock.advance(std::chrono::milliseconds(100));
        CHECK(limiter.allow(d.node_id, 1) ==
              RelayQuotaResult::CapacityLimited);

        // Idle state expires, and both packet and byte tokens refill.
        clock.advance(std::chrono::milliseconds(900));
        CHECK(limiter.allow(d.node_id, 1) == RelayQuotaResult::Allowed);
        CHECK(limiter.tracked_peers() == 1);

        const auto stats = limiter.stats();
        CHECK(stats.admitted_packets == 4);
        CHECK(stats.admitted_bytes == 151);
        CHECK(stats.peer_drops == 2);
        CHECK(stats.global_drops == 1);
        CHECK(stats.capacity_drops == 1);
        CHECK(stats.total_drops() == 4);

        limiter.reset();
        CHECK(limiter.tracked_peers() == 0);
        CHECK(limiter.stats().admitted_packets == 0);
        CHECK(limiter.allow(b.node_id, 100) == RelayQuotaResult::Allowed);
    }

    // ---- 10. Invalid relay quota configurations fail closed ----------------
    {
        ManualClock clock;
        RelayQuotaConfig invalid;
        invalid.per_peer_packets_per_second = 0.0;
        RelayForwardLimiter limiter(clock, invalid);
        CHECK(limiter.allow(b.node_id, 1) == RelayQuotaResult::Invalid);
        CHECK(limiter.tracked_peers() == 0);
    }

    printf("--- relay / onion: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
