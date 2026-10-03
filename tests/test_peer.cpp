#include "aegis/peer/peer.hpp"
#include "aegis/session/session.hpp"
#include "aegis/identity/identity.hpp"
#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>

static int tests  = 0;
static int passed = 0;

class ManualClock final : public ProtocolClock {
public:
    time_point now() const noexcept override {
        return time_point(std::chrono::milliseconds(
            current_ms_.load(std::memory_order_relaxed)));
    }
    void advance(std::chrono::milliseconds duration) {
        current_ms_.fetch_add(duration.count(), std::memory_order_relaxed);
    }

private:
    std::atomic<int64_t> current_ms_{0};
};

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
        ManualClock clock;
        PeerManager pm(PEER_MANAGER_MAX_PEERS, clock);

        pm.upsert(alice.node_id, alice.keypair.public_key, ep_alice, /*trusted=*/true);
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        pm.upsert(charlie.node_id, charlie.keypair.public_key);

        CHECK(pm.size() == 3);
        CHECK(pm.has_peer(alice.node_id));
        CHECK(pm.has_peer(bob.node_id));
        CHECK(pm.has_peer(charlie.node_id));

        auto a = pm.get_peer(alice.node_id);
        CHECK(a.has_value());
        CHECK(a->node_id == alice.node_id);
        CHECK(a->public_key == alice.keypair.public_key);
        CHECK(a->endpoint.has_value());
        CHECK(a->endpoint->port == ep_alice.port);
        CHECK(a->trusted);

        // Read results are owned snapshots: caller mutation cannot escape
        // back into PeerManager after its lock has been released.
        a->trusted = false;
        a->endpoint.reset();
        const auto fresh_a = pm.get_peer(alice.node_id);
        CHECK(fresh_a && fresh_a->trusted);
        CHECK(fresh_a && fresh_a->endpoint.has_value());

        auto snapshots = pm.all_peers();
        const auto snapshot_a = std::find_if(
            snapshots.begin(), snapshots.end(),
            [&](const Peer& peer) { return peer.node_id == alice.node_id; });
        CHECK(snapshot_a != snapshots.end());
        if (snapshot_a != snapshots.end())
            snapshot_a->state = PeerState::Dead;
        const auto unchanged_a = pm.get_peer(alice.node_id);
        CHECK(unchanged_a && unchanged_a->state == PeerState::Unknown);

        auto b = pm.get_peer(bob.node_id);
        CHECK(b.has_value());
        CHECK(!b->trusted);

        // Relay-only peer: no endpoint
        auto c = pm.get_peer(charlie.node_id);
        CHECK(c.has_value());
        CHECK(!c->endpoint.has_value());

        // Unknown peer lookup
        NodeId unknown{};
        unknown[0] = 0xFF;
        CHECK(!pm.get_peer(unknown).has_value());
        CHECK(!pm.has_peer(unknown));

        // Remove
        pm.remove_peer(bob.node_id);
        CHECK(pm.size() == 2);
        CHECK(!pm.has_peer(bob.node_id));
        CHECK(!pm.get_peer(bob.node_id).has_value());
    }

    // ---- 2. State transitions and endpoint update ---------------------------
    {
        PeerManager pm;
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);

        pm.mark_connecting(bob.node_id);
        auto b = pm.get_peer(bob.node_id);
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

        auto existing = pm.get_peer(bob.node_id);
        CHECK(existing.has_value());
        if (existing) {
            CHECK(existing->public_key == bob.keypair.public_key);
            CHECK(existing->endpoint.has_value());
            CHECK(existing->endpoint->ip == ep_bob.ip);
            CHECK(existing->endpoint->port == ep_bob.port);
        }

        CHECK(pm.upsert(bob.node_id, bob.keypair.public_key, ep_new) ==
              PeerUpsertResult::Updated);
        existing = pm.get_peer(bob.node_id);
        CHECK(existing.has_value());
        if (existing) {
            CHECK(existing->endpoint.has_value());
            CHECK(existing->endpoint->ip == ep_new.ip);
            CHECK(existing->endpoint->port == ep_new.port);
        }

        CHECK(pm.upsert(alice.node_id, alice.keypair.public_key, ep_alice,
                        /*trusted=*/true) == PeerUpsertResult::Inserted);
        CHECK(pm.upsert(alice.node_id, alice.keypair.public_key,
                        std::nullopt, /*trusted=*/false) ==
              PeerUpsertResult::Updated);
        CHECK(pm.get_peer(alice.node_id)->trusted);

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
        auto updated = pm.get_peer(bob.node_id);
        CHECK(updated.has_value());
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
        auto init_msg = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        CHECK(init_msg && init_msg->size() == HANDSHAKE_V2_INIT_FRAME_SIZE);
        auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
        CHECK(resp_msg.has_value());
        CHECK(sm_a.handle_handshake_resp(resp_msg->message, session_id));

        PeerManager pm;
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        CHECK(!pm.get_session(bob.node_id).has_value());

        pm.set_session_manager(&sm_a);
        auto sess = pm.get_session(bob.node_id);
        CHECK(sess.has_value());
        CHECK(sess->established);
        CHECK(sess->id == session_id);

        NodeId unknown{};
        unknown[0] = 0xEE;
        CHECK(!pm.get_session(unknown).has_value());
    }

    // ---- 5. Stale peer detection with dead timeout --------------------------
    {
        ManualClock clock;
        PeerManager pm(PEER_MANAGER_MAX_PEERS, clock);
        pm.set_dead_timeout(std::chrono::milliseconds(1000));
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        pm.mark_seen(bob.node_id);

        CHECK(pm.stale_peers().empty());

        clock.advance(std::chrono::milliseconds(1100));

        auto stale = pm.stale_peers();
        CHECK(stale.size() == 1);
        CHECK(stale[0].node_id == bob.node_id);

        // Dead peers are excluded from stale detection
        pm.mark_dead(bob.node_id);
        CHECK(pm.stale_peers().empty());
    }

    // ---- 6. Keepalive-needed detection --------------------------------------
    {
        ManualClock clock;
        PeerManager pm(PEER_MANAGER_MAX_PEERS, clock);
        pm.set_keepalive_interval(std::chrono::milliseconds(1000));
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
        pm.mark_seen(bob.node_id);

        CHECK(pm.peers_needing_keepalive().empty());

        clock.advance(std::chrono::milliseconds(1100));

        auto need = pm.peers_needing_keepalive();
        CHECK(need.size() == 1);
        CHECK(need[0].node_id == bob.node_id);

        // Receiving traffic refreshes last_keepalive under the manager lock.
        pm.mark_seen(bob.node_id);
        CHECK(pm.peers_needing_keepalive().empty());
    }

    // ---- 7. Step 15: mark_seen on an established peer advances keepalive -----
    // The keep-alive sender relies on last_keepalive being advanced on EVERY
    // received packet, not just on the transition into Established — otherwise
    // a busy peer would keep receiving keep-alives forever. (Regression for
    // the mark_seen fix.)
    {
        ManualClock clock;
        PeerManager pm(PEER_MANAGER_MAX_PEERS, clock);
        pm.set_keepalive_interval(std::chrono::milliseconds(1000));
        pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);

        // Transition into Established advances last_keepalive once...
        pm.mark_seen(bob.node_id);
        CHECK(pm.peers_needing_keepalive().empty());

        // ...then it must be advanced again by subsequent traffic even though
        // the peer was already Established.
        clock.advance(std::chrono::milliseconds(1100));
        CHECK(pm.peers_needing_keepalive().size() == 1);

        pm.mark_seen(bob.node_id);  // already-established peer sends traffic
        CHECK(pm.peers_needing_keepalive().empty());

        clock.advance(std::chrono::milliseconds(1100));
        CHECK(pm.peers_needing_keepalive().size() == 1);
    }

    // ---- 8. Concurrent peer lifecycle keeps snapshots self-contained --------
    {
        ManualClock clock;
        PeerManager pm(PEER_MANAGER_MAX_PEERS, clock);
        pm.set_keepalive_interval(std::chrono::milliseconds(5));
        pm.set_dead_timeout(std::chrono::milliseconds(10));
        CHECK(pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob) ==
              PeerUpsertResult::Inserted);

        constexpr int iterations = 1000;
        std::atomic<bool> consistent{true};
        std::barrier start_line(4);

        std::thread lifecycle([&] {
            start_line.arrive_and_wait();
            for (int i = 0; i < iterations; ++i) {
                pm.remove_peer(bob.node_id);
                const auto result = pm.upsert(
                    bob.node_id, bob.keypair.public_key, ep_bob,
                    (i % 2) == 0);
                if (result != PeerUpsertResult::Inserted)
                    consistent.store(false, std::memory_order_relaxed);
            }
        });

        std::thread state_updates([&] {
            start_line.arrive_and_wait();
            for (int i = 0; i < iterations; ++i) {
                pm.mark_connecting(bob.node_id);
                pm.mark_seen(bob.node_id, ep_bob);
                pm.update_endpoint(bob.node_id, ep_bob);
                pm.mark_dead(bob.node_id);
            }
        });

        std::thread snapshot_reads([&] {
            start_line.arrive_and_wait();
            for (int i = 0; i < iterations; ++i) {
                const auto peer = pm.get_peer(bob.node_id);
                if (peer && (peer->node_id != bob.node_id ||
                             peer->public_key != bob.keypair.public_key)) {
                    consistent.store(false, std::memory_order_relaxed);
                }

                const auto peers = pm.all_peers();
                if (peers.size() > 1 ||
                    (!peers.empty() &&
                     (peers.front().node_id != bob.node_id ||
                      peers.front().public_key != bob.keypair.public_key))) {
                    consistent.store(false, std::memory_order_relaxed);
                }
                (void)pm.stale_peers();
                (void)pm.peers_needing_keepalive();
            }
        });

        start_line.arrive_and_wait();
        for (int i = 0; i < iterations; ++i)
            clock.advance(std::chrono::milliseconds(1));

        lifecycle.join();
        state_updates.join();
        snapshot_reads.join();

        const auto final_result = pm.upsert(
            bob.node_id, bob.keypair.public_key, ep_bob, true);
        CHECK(final_result == PeerUpsertResult::Inserted ||
              final_result == PeerUpsertResult::Updated);
        pm.mark_seen(bob.node_id, ep_bob);
        const auto final_peer = pm.get_peer(bob.node_id);
        CHECK(consistent.load(std::memory_order_relaxed));
        CHECK(pm.size() == 1);
        CHECK(final_peer && final_peer->node_id == bob.node_id);
        CHECK(final_peer && final_peer->public_key == bob.keypair.public_key);
        CHECK(final_peer && final_peer->state == PeerState::Established);
        CHECK(final_peer && final_peer->trusted);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
