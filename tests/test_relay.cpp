#include "aegis/packet/relay.hpp"
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
        onion->at(onion->size() - 1) ^= 0xFF;  // corrupt the outer tag
        auto tampered = peel_onion(b.keypair, src.keypair.public_key,
                                   onion->data(), onion->size());
        CHECK(!tampered.has_value());
    }

    // ---- 5. Too-short / malformed inputs ------------------------------------
    {
        uint8_t tiny[ONION_OVERHEAD - 1] = {};
        CHECK(!peel_onion(b.keypair, src.keypair.public_key, tiny, sizeof(tiny)).has_value());
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

    printf("--- relay / onion: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
