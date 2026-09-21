#include "aegis/peer/peer.hpp"
#include "aegis/session/session.hpp"
#include "aegis/identity/identity.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
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
    printf("--- peer manager tests ---\n");

    NetworkId net{};
    net[0] = 0x01;
    Identity alice = Identity::create(net);
    Identity bob   = Identity::create(net);
    Identity charlie = Identity::create(net);

    Endpoint ep_alice = Endpoint::from_parts(127, 0, 0, 1, 51820);
    Endpoint ep_bob   = Endpoint::from_parts(127, 0, 0, 1, 51821);

    // ---- 1. Multi-peer table ops --------------------------------------------
    {
        PeerManager pm;

        pm.upsert(alice.node_id, alice.keypair.public_key, ep_alice, /*trusted=*/true);
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        pm.upsert(charlie.node_id, charlie.keypair.public_key);

        CHECK(pm.size() == 3);
        CHECK(pm.has_peer(alice.node_id));
        CHECK(pm.has_peer(bob.node_id));
        CHECK(pm.has_peer(charlie.node_id));

        Peer* a = pm.get_peer(alice.node_id);
        CHECK(a != nullptr);
        CHECK(a->node_id == alice.node_id);
        CHECK(a->public_key == alice.keypair.public_key);
        CHECK(a->endpoint.has_value());
        CHECK(a->endpoint->port == ep_alice.port);
        CHECK(a->trusted);

        Peer* b = pm.get_peer(bob.node_id);
        CHECK(b != nullptr);
        CHECK(!b->trusted);

        // Relay-only peer: no endpoint
        Peer* c = pm.get_peer(charlie.node_id);
        CHECK(c != nullptr);
        CHECK(!c->endpoint.has_value());

        // Unknown peer lookup
        NodeId unknown{};
        unknown[0] = 0xFF;
        CHECK(pm.get_peer(unknown) == nullptr);
        CHECK(!pm.has_peer(unknown));

        // Remove
        pm.remove_peer(bob.node_id);
        CHECK(pm.size() == 2);
        CHECK(!pm.has_peer(bob.node_id));
        CHECK(pm.get_peer(bob.node_id) == nullptr);
    }

    // ---- 2. State transitions and endpoint update ---------------------------
    {
        PeerManager pm;
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);

        pm.mark_connecting(bob.node_id);
        Peer* b = pm.get_peer(bob.node_id);
        CHECK(b->state == PeerState::Connecting);
        CHECK(b->connect_attempts == 1);

        auto before = std::chrono::steady_clock::now();
        pm.mark_seen(bob.node_id);
        b = pm.get_peer(bob.node_id);
        CHECK(b->state == PeerState::Established);
        CHECK(b->last_seen >= before);
        CHECK(b->connected_since >= before);

        // Endpoint update
        Endpoint ep_new = Endpoint::from_parts(192, 168, 1, 50, 51830);
        pm.update_endpoint(bob.node_id, ep_new);
        b = pm.get_peer(bob.node_id);
        CHECK(b->endpoint.has_value());
        CHECK(b->endpoint->ip == ep_new.ip);
        CHECK(b->endpoint->port == ep_new.port);

        pm.mark_dead(bob.node_id);
        b = pm.get_peer(bob.node_id);
        CHECK(b->state == PeerState::Dead);
    }

    // ---- 2b. Static identity keys are immutable after binding ---------------
    {
        PeerManager pm;
        CHECK(pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob) ==
              PeerUpsertResult::Inserted);

        Endpoint ep_new = Endpoint::from_parts(192, 168, 1, 51, 51831);
        CHECK(pm.upsert(bob.node_id, charlie.keypair.public_key, ep_new) ==
              PeerUpsertResult::IdentityConflict);

        const Peer* existing = pm.get_peer(bob.node_id);
        CHECK(existing != nullptr);
        if (existing) {
            CHECK(existing->public_key == bob.keypair.public_key);
            CHECK(existing->endpoint.has_value());
            CHECK(existing->endpoint->ip == ep_bob.ip);
            CHECK(existing->endpoint->port == ep_bob.port);
        }

        CHECK(pm.upsert(bob.node_id, bob.keypair.public_key, ep_new) ==
              PeerUpsertResult::Updated);
        existing = pm.get_peer(bob.node_id);
        CHECK(existing != nullptr);
        if (existing) {
            CHECK(existing->endpoint.has_value());
            CHECK(existing->endpoint->ip == ep_new.ip);
            CHECK(existing->endpoint->port == ep_new.port);
        }

        // The unauthenticated v1 handshake currently creates an empty-key
        // placeholder. It may acquire its first real binding, but that binding
        // becomes immutable immediately.
        NodeId placeholder_id = charlie.node_id;
        CHECK(pm.upsert(placeholder_id, Key{}) ==
              PeerUpsertResult::Inserted);
        CHECK(pm.get_peer(placeholder_id)->public_key == Key{});
        CHECK(pm.upsert(placeholder_id, charlie.keypair.public_key) ==
              PeerUpsertResult::IdentityBound);
        CHECK(pm.get_peer(placeholder_id)->public_key ==
              charlie.keypair.public_key);
        CHECK(pm.upsert(placeholder_id, alice.keypair.public_key) ==
              PeerUpsertResult::IdentityConflict);
        CHECK(pm.get_peer(placeholder_id)->public_key ==
              charlie.keypair.public_key);
    }

    // ---- 3. Capacity rejects growth but permits existing-peer updates --------
    {
        PeerManager pm(/*max_peers=*/2);
        CHECK(pm.upsert(alice.node_id, alice.keypair.public_key) ==
              PeerUpsertResult::Inserted);
        CHECK(pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob) ==
              PeerUpsertResult::Inserted);
        CHECK(pm.upsert(charlie.node_id, charlie.keypair.public_key) ==
              PeerUpsertResult::CapacityRejected);
        CHECK(pm.size() == 2);
        CHECK(!pm.has_peer(charlie.node_id));

        Endpoint ep_new = Endpoint::from_parts(192, 168, 1, 52, 51832);
        CHECK(pm.upsert(bob.node_id, bob.keypair.public_key, ep_new) ==
              PeerUpsertResult::Updated);
        const Peer* updated = pm.get_peer(bob.node_id);
        CHECK(updated != nullptr);
        CHECK(updated && updated->endpoint.has_value());
        CHECK(updated && updated->endpoint && updated->endpoint->ip == ep_new.ip);
        CHECK(updated && updated->endpoint && updated->endpoint->port == ep_new.port);

        Peer replacement = *pm.get_peer(alice.node_id);
        replacement.trusted = true;
        CHECK(pm.add_peer(replacement));
        Peer extra;
        extra.node_id = charlie.node_id;
        extra.public_key = charlie.keypair.public_key;
        CHECK(!pm.add_peer(extra));
        CHECK(pm.size() == 2);
    }

    // ---- 4. Session lookup delegates to Session Manager ---------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xA0000001;
        auto init_msg = sm_a.create_handshake_init(session_id);
        CHECK(init_msg.size() == HANDSHAKE_PAYLOAD_SIZE);
        auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
        CHECK(resp_msg.has_value());
        CHECK(sm_a.handle_handshake_resp(*resp_msg, session_id));

        PeerManager pm;
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        CHECK(!pm.get_session(bob.node_id).has_value());

        pm.set_session_manager(&sm_a);
        auto sess = pm.get_session(bob.node_id);
        CHECK(sess.has_value());
        CHECK((*sess)->established);
        CHECK((*sess)->id == session_id);

        NodeId unknown{};
        unknown[0] = 0xEE;
        CHECK(!pm.get_session(unknown).has_value());
    }

    // ---- 5. Stale peer detection with dead timeout --------------------------
    {
        PeerManager pm;
        pm.set_dead_timeout(std::chrono::milliseconds(1000));
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        pm.mark_seen(bob.node_id);

        CHECK(pm.stale_peers().empty());

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));

        auto stale = pm.stale_peers();
        CHECK(stale.size() == 1);
        CHECK(stale[0]->node_id == bob.node_id);

        // Dead peers are excluded from stale detection
        pm.mark_dead(bob.node_id);
        CHECK(pm.stale_peers().empty());
    }

    // ---- 6. Keepalive-needed detection --------------------------------------
    {
        PeerManager pm;
        pm.set_keepalive_interval(std::chrono::milliseconds(1000));
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        pm.mark_seen(bob.node_id);

        CHECK(pm.peers_needing_keepalive().empty());

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));

        auto need = pm.peers_needing_keepalive();
        CHECK(need.size() == 1);
        CHECK(need[0]->node_id == bob.node_id);

        // Marking last_keepalive fresh removes it from the list
        Peer* b = pm.get_peer(bob.node_id);
        b->last_keepalive = std::chrono::steady_clock::now();
        CHECK(pm.peers_needing_keepalive().empty());
    }

    // ---- 7. Step 15: mark_seen on an established peer advances keepalive -----
    // The keep-alive sender relies on last_keepalive being advanced on EVERY
    // received packet, not just on the transition into Established — otherwise
    // a busy peer would keep receiving keep-alives forever. (Regression for
    // the mark_seen fix.)
    {
        PeerManager pm;
        pm.set_keepalive_interval(std::chrono::milliseconds(1000));
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);

        // Transition into Established advances last_keepalive once...
        pm.mark_seen(bob.node_id);
        CHECK(pm.peers_needing_keepalive().empty());

        // ...then it must be advanced again by subsequent traffic even though
        // the peer was already Established.
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        CHECK(pm.peers_needing_keepalive().size() == 1);

        pm.mark_seen(bob.node_id);  // already-established peer sends traffic
        CHECK(pm.peers_needing_keepalive().empty());

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        CHECK(pm.peers_needing_keepalive().size() == 1);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
