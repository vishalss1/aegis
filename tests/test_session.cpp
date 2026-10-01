#include "aegis/session/session.hpp"
#include "aegis/identity/identity.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>
#include <thread>

static int tests  = 0;
static int passed = 0;

class ManualClock final : public ProtocolClock {
public:
    time_point current{};
    time_point now() const noexcept override { return current; }
    void advance(std::chrono::milliseconds duration) { current += duration; }
};

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- session tests ---\n");

    // Create two identities
    NetworkId net{};
    net[0] = 0x01;
    Identity alice = Identity::create(net);
    Identity bob   = Identity::create(net);

    // ---- 1. Handshake round-trip: init -> resp -> keys established ----------
    {
        ManualClock clock;
        SessionManager sm_a(alice, clock);
        SessionManager sm_b(bob, clock);

        uint32_t session_id = 0xABCD0001;

        // A creates handshake init for B
        auto init_msg = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        CHECK(init_msg.has_value());
        CHECK(init_msg && init_msg->size() == HANDSHAKE_V2_INIT_FRAME_SIZE);

        // B handles the init
        auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
        CHECK(resp_msg.has_value());
        CHECK(resp_msg &&
              resp_msg->message.size() == HANDSHAKE_V2_RESPONSE_FRAME_SIZE);
        CHECK(resp_msg && resp_msg->peer_id == alice.node_id);
        CHECK(resp_msg && resp_msg->peer_static_public_key ==
              alice.keypair.public_key);

        // A handles the response
        bool ok = sm_a.handle_handshake_resp(resp_msg->message, session_id);
        CHECK(ok);

        // Both sides should have established sessions
        auto sess_a = sm_a.get_session(bob.node_id);
        auto sess_b = sm_b.get_session(alice.node_id);
        CHECK(sess_a.has_value());
        CHECK(sess_b.has_value());
        CHECK((*sess_a)->established);
        CHECK((*sess_b)->established);
        CHECK((*sess_a)->id == session_id);
        CHECK((*sess_b)->id == session_id);

        // Session keys should be non-zero
        bool a_send_nonzero = false;
        for (auto b : (*sess_a)->send_key)
            if (b != 0) { a_send_nonzero = true; break; }
        CHECK(a_send_nonzero);

        bool a_recv_nonzero = false;
        for (auto b : (*sess_a)->recv_key)
            if (b != 0) { a_recv_nonzero = true; break; }
        CHECK(a_recv_nonzero);

        // A's send key should equal B's recv key (opposite directions)
        CHECK((*sess_a)->send_key == (*sess_b)->recv_key);
        CHECK((*sess_b)->send_key == (*sess_a)->recv_key);

        // Replaying either handshake frame cannot replace an established
        // session or recreate consumed initiator state.
        CHECK(!sm_b.handle_handshake_init(*init_msg, session_id).has_value());
        CHECK(!sm_a.handle_handshake_resp(
            resp_msg->message, session_id));
        CHECK(sm_a.get_session(bob.node_id).has_value());
        CHECK(sm_b.get_session(alice.node_id).has_value());
    }

    // ---- 1b. Handshake payloads require exact canonical lengths -------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);
        const uint32_t session_id = 0xABCD0009;
        const auto init = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        CHECK(init.has_value());

        auto short_init = *init;
        short_init.pop_back();
        CHECK(!sm_b.handle_handshake_init(short_init, session_id).has_value());
        CHECK(!sm_b.get_session(alice.node_id).has_value());

        auto trailing_init = *init;
        trailing_init.push_back(0);
        CHECK(!sm_b.handle_handshake_init(trailing_init, session_id).has_value());
        CHECK(!sm_b.get_session(alice.node_id).has_value());

        const auto response = sm_b.handle_handshake_init(*init, session_id);
        CHECK(response.has_value());
        if (response) {
            auto short_response = response->message;
            short_response.pop_back();
            CHECK(!sm_a.handle_handshake_resp(short_response, session_id));
            CHECK(!sm_a.get_session(bob.node_id).has_value());

            auto trailing_response = response->message;
            trailing_response.push_back(0);
            CHECK(!sm_a.handle_handshake_resp(trailing_response, session_id));
            CHECK(!sm_a.get_session(bob.node_id).has_value());
            CHECK(!sm_a.handle_handshake_resp(
                response->message, session_id));
        }
    }

    // ---- 2. Encrypt/decrypt round-trip --------------------------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0002;
        auto init_msg = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
        sm_a.handle_handshake_resp(resp_msg->message, session_id);

        const uint8_t plaintext[] = {0x45, 0x00, 0x00, 0x14,
                                     0x08, 0x00, 0x00, 0x00,
                                     0x40, 0x11, 0x00, 0x00,
                                     0x0a, 0x0a, 0x00, 0x01,
                                     0x0a, 0x0a, 0x00, 0x02};
        size_t pt_len = sizeof(plaintext);

        // A encrypts
        auto enc = sm_a.encrypt_data(bob.node_id, plaintext, pt_len);
        CHECK(enc.has_value());

        // Wire format: [16 header][12 nonce][ct][16 tag]
        CHECK(enc->size() == 16 + 12 + pt_len + 16);

        // B decrypts
        auto dec = sm_b.decrypt_data(enc->data(), enc->size());
        CHECK(dec.has_value());
        CHECK(dec->size() == pt_len);
        CHECK(std::memcmp(dec->data(), plaintext, pt_len) == 0);

        // Also test B -> A direction
        const uint8_t reply[] = {0x45, 0x00, 0x00, 0x14,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x40, 0x01, 0x00, 0x00,
                                 0x0a, 0x0a, 0x00, 0x02,
                                 0x0a, 0x0a, 0x00, 0x01};
        auto enc2 = sm_b.encrypt_data(alice.node_id, reply, sizeof(reply));
        CHECK(enc2.has_value());

        auto dec2 = sm_a.decrypt_data(enc2->data(), enc2->size());
        CHECK(dec2.has_value());
        CHECK(std::memcmp(dec2->data(), reply, sizeof(reply)) == 0);

        std::vector<uint8_t> oversized(4097, 0x5a);
        CHECK(!sm_a.encrypt_data(
            bob.node_id, oversized.data(), oversized.size()).has_value());
    }

    // ---- 3. Replay rejection ------------------------------------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0003;
        auto init_msg = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
        sm_a.handle_handshake_resp(resp_msg->message, session_id);

        const uint8_t pt[] = {0x45, 0x00, 0x00, 0x14};
        auto enc = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(enc.has_value());

        // First decrypt should succeed
        auto dec1 = sm_b.decrypt_data(enc->data(), enc->size());
        CHECK(dec1.has_value());

        // Second decrypt of same packet should fail (replay)
        auto dec2 = sm_b.decrypt_data(enc->data(), enc->size());
        CHECK(!dec2.has_value());

        // A new packet should still work
        auto enc3 = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(enc3.has_value());
        auto dec3 = sm_b.decrypt_data(enc3->data(), enc3->size());
        CHECK(dec3.has_value());
    }

    // ---- 4. Tamper rejection ------------------------------------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0004;
        auto init_msg = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
        sm_a.handle_handshake_resp(resp_msg->message, session_id);

        const uint8_t pt[] = {0x45, 0x00, 0x00, 0x14};
        auto enc = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(enc.has_value());

        // Corrupt a byte in the ciphertext area (after header + nonce)
        if (enc->size() > 30) {
            (*enc)[28] ^= 0xFF;
        }

        auto dec = sm_b.decrypt_data(enc->data(), enc->size());
        CHECK(!dec.has_value());
    }

    // ---- 5. Wrong identity cannot establish session -------------------------
    {
        Identity charlie = Identity::create(net);

        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0005;
        auto init_msg = sm_a.create_handshake_init(
            session_id, bob.node_id, bob.keypair.public_key);
        auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
        CHECK(resp_msg.has_value());
        CHECK(resp_msg && resp_msg->peer_id == alice.node_id);
        CHECK(resp_msg && resp_msg->peer_id != charlie.node_id);

        CHECK(!sm_a.create_handshake_init(
            session_id + 1, charlie.node_id,
            bob.keypair.public_key).has_value());
    }

    // ---- 6. Step 14: NetworkID gating ---------------------------------------
    {
        // Two networks on a shared LAN: net1 = {alice, bob}, net2 = {mallory}.
        NetworkId net2{};
        net2[0] = 0x02;
        Identity mallory = Identity::create(net2);

        // Same-network handshake still works (init carries net1, responder agrees).
        {
            SessionManager sm_a(alice);
            SessionManager sm_b(bob);
            uint32_t session_id = 0xABCD0010;
            auto init_msg = sm_a.create_handshake_init(
                session_id, bob.node_id, bob.keypair.public_key);
            auto resp_msg = sm_b.handle_handshake_init(*init_msg, session_id);
            CHECK(resp_msg.has_value());
            CHECK(sm_a.handle_handshake_resp(
                resp_msg->message, session_id));
            CHECK(sm_a.get_session(bob.node_id).has_value());
            CHECK(sm_b.get_session(alice.node_id).has_value());
        }

        // Responder gate: alice (net1) initiates toward mallory (net2) — the
        // handshake must be refused BEFORE any session is created.
        {
            SessionManager sm_a(alice);
            SessionManager sm_m(mallory);
            uint32_t session_id = 0xABCD0011;
            auto init_msg = sm_a.create_handshake_init(
                session_id, mallory.node_id, mallory.keypair.public_key);
            auto resp_msg = sm_m.handle_handshake_init(*init_msg, session_id);
            CHECK(!resp_msg.has_value());
            CHECK(!sm_m.get_session(alice.node_id).has_value());
        }

        // Initiator gate (defense in depth): mallory initiates toward alice —
        // same refusal path.
        {
            SessionManager sm_a(alice);
            SessionManager sm_m(mallory);
            uint32_t session_id = 0xABCD0012;
            auto init_msg = sm_m.create_handshake_init(
                session_id, alice.node_id, alice.keypair.public_key);
            auto resp_msg = sm_a.handle_handshake_init(*init_msg, session_id);
            CHECK(!resp_msg.has_value());
            CHECK(!sm_a.get_session(mallory.node_id).has_value());
        }
    }

    // ---- 7. Step 15: rekey via a fresh handshake -----------------------------
    {
        ManualClock clock;
        SessionManager sm_a(alice, clock);
        SessionManager sm_b(bob, clock);
        sm_a.set_retired_grace(std::chrono::milliseconds(60));
        sm_b.set_retired_grace(std::chrono::milliseconds(60));

        // Establish the first session (sid1).
        uint32_t sid1 = 0xABCD0100;
        auto init1 = sm_a.create_handshake_init(
            sid1, bob.node_id, bob.keypair.public_key);
        auto resp1 = sm_b.handle_handshake_init(*init1, sid1);
        CHECK(sm_a.handle_handshake_resp(resp1->message, sid1));
        auto sess_a1 = sm_a.get_session(bob.node_id);
        CHECK(sess_a1.has_value());
        CHECK((*sess_a1)->id == sid1);

        // A packet sent under sid1 but still in flight when the rekey happens.
        const uint8_t pt[] = {0x45, 0x00, 0x00, 0x14, 0x00, 0x00,
                              0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
                              0x0a, 0x0a, 0x00, 0x01, 0x0a, 0x0a, 0x00, 0x02};
        auto in_flight = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(in_flight.has_value());

        // Rekey: fresh handshake with a new session_id. Same deterministic role
        // rules apply; here A drives it on both sides for the round-trip.
        uint32_t sid2 = 0xABCD0200;
        auto init2 = sm_a.create_handshake_init(
            sid2, bob.node_id, bob.keypair.public_key);
        auto resp2 = sm_b.handle_handshake_init(*init2, sid2);
        CHECK(sm_a.handle_handshake_resp(resp2->message, sid2));

        // Both sides now hold sid2 as the active session...
        auto sess_a2 = sm_a.get_session(bob.node_id);
        auto sess_b2 = sm_b.get_session(alice.node_id);
        CHECK(sess_a2.has_value());
        CHECK(sess_b2.has_value());
        CHECK((*sess_a2)->id == sid2);
        CHECK((*sess_b2)->id == sid2);

        // ...while sid1 is retired but still resolving for in-flight packets.
        // The in-flight packet from before the rekey must still decrypt on B.
        auto dec_inflight = sm_b.decrypt_data(in_flight->data(), in_flight->size());
        CHECK(dec_inflight.has_value());
        CHECK(std::memcmp(dec_inflight->data(), pt, sizeof(pt)) == 0);

        // Fresh traffic under the new keys works in both directions.
        auto enc_new = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(enc_new.has_value());
        auto dec_new = sm_b.decrypt_data(enc_new->data(), enc_new->size());
        CHECK(dec_new.has_value());
        auto enc_back = sm_b.encrypt_data(alice.node_id, pt, sizeof(pt));
        auto dec_back = sm_a.decrypt_data(enc_back->data(), enc_back->size());
        CHECK(dec_back.has_value());

        // After the grace window, purge drops the retired session: the old
        // in-flight frame must no longer decrypt (keys gone).
        clock.advance(std::chrono::milliseconds(120));
        sm_b.purge_retired();
        auto dec_stale = sm_b.decrypt_data(in_flight->data(), in_flight->size());
        CHECK(!dec_stale.has_value());
        // New session is untouched by the purge.
        CHECK(sm_b.get_session(alice.node_id).has_value());
    }

    // ---- 8. Step 15: remove_session tears down active + retired keys ---------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t sid1 = 0xABCD0300;
        auto init1 = sm_a.create_handshake_init(
            sid1, bob.node_id, bob.keypair.public_key);
        auto resp1 = sm_b.handle_handshake_init(*init1, sid1);
        sm_a.handle_handshake_resp(resp1->message, sid1);

        // Rekey once so B has a retired sid1 plus an active sid2.
        uint32_t sid2 = 0xABCD0400;
        auto init2 = sm_a.create_handshake_init(
            sid2, bob.node_id, bob.keypair.public_key);
        auto resp2 = sm_b.handle_handshake_init(*init2, sid2);
        sm_a.handle_handshake_resp(resp2->message, sid2);

        // A removes its session with B.
        sm_a.remove_session(bob.node_id);
        CHECK(!sm_a.get_session(bob.node_id).has_value());
        // Encryption toward the removed peer fails on A (active keys gone).
        const uint8_t pt[] = {0x45, 0x00, 0x00, 0x14};
        auto enc = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(!enc.has_value());
    }

    // ---- 9. Handshake-v2 integration attack matrix -------------------------
    {
        Identity charlie = Identity::create(net);

        // A claimed NodeID cannot be paired with another static key, and an IK
        // message encrypted for Charlie cannot be accepted by Bob.
        SessionManager sm_claim(alice);
        CHECK(!sm_claim.create_handshake_init(
            0xAC000001, charlie.node_id,
            bob.keypair.public_key).has_value());
        auto for_charlie = sm_claim.create_handshake_init(
            0xAC000002, charlie.node_id,
            charlie.keypair.public_key);
        SessionManager sm_bob(bob);
        CHECK(for_charlie.has_value());
        CHECK(!sm_bob.handle_handshake_init(
            *for_charlie, 0xAC000002).has_value());
        CHECK(!sm_bob.get_session(alice.node_id).has_value());

        // Header/session and Noise-message tampering fail before any responder
        // session is installed.
        SessionManager sm_tamper_i(alice);
        SessionManager sm_tamper_r(bob);
        auto canonical = sm_tamper_i.create_handshake_init(
            0xAC000010, bob.node_id, bob.keypair.public_key);
        CHECK(canonical.has_value());
        auto wrong_inner_session = *canonical;
        wrong_inner_session[6] ^= 0x01;
        CHECK(!sm_tamper_r.handle_handshake_init(
            wrong_inner_session, 0xAC000010).has_value());
        CHECK(!sm_tamper_r.handle_handshake_init(
            *canonical, 0xAC000011).has_value());
        auto tampered_noise = *canonical;
        tampered_noise.back() ^= 0x80;
        CHECK(!sm_tamper_r.handle_handshake_init(
            tampered_noise, 0xAC000010).has_value());
        auto old_version = *canonical;
        old_version[0] = 0x01;
        CHECK(!sm_tamper_r.handle_handshake_init(
            old_version, 0xAC000010).has_value());
        CHECK(!sm_tamper_r.handle_handshake_init(
            std::vector<uint8_t>(100, 0), 0xAC000010).has_value());

        // Changing a cross-network routing selector to the responder's network
        // still fails because the original network is bound into the Noise
        // transcript.
        NetworkId other_net{};
        other_net[0] = 0x7f;
        Identity outsider = Identity::create(other_net);
        SessionManager sm_outsider(outsider);
        SessionManager sm_network_bob(bob);
        auto cross_network = sm_outsider.create_handshake_init(
            0xAC000020, bob.node_id, bob.keypair.public_key);
        CHECK(cross_network.has_value());
        std::copy(net.begin(), net.end(),
                  cross_network->begin() + HANDSHAKE_V2_HEADER_SIZE);
        CHECK(!sm_network_bob.handle_handshake_init(
            *cross_network, 0xAC000020).has_value());

        // INIT cannot be reflected as RESP or processed with the responder
        // role, and the failed response consumes the pending initiator state.
        SessionManager sm_reflect_i(alice);
        SessionManager sm_reflect_r(alice);
        auto reflected = sm_reflect_i.create_handshake_init(
            0xAC000030, bob.node_id, bob.keypair.public_key);
        CHECK(reflected.has_value());
        CHECK(!sm_reflect_i.handle_handshake_resp(
            *reflected, 0xAC000030));
        CHECK(!sm_reflect_r.handle_handshake_init(
            *reflected, 0xAC000030).has_value());

        // A valid response from an unrelated Charlie handshake cannot satisfy
        // Alice's pending handshake with Bob.
        SessionManager sm_expect_bob(alice);
        SessionManager sm_expect_charlie(alice);
        SessionManager sm_charlie(charlie);
        auto init_for_bob = sm_expect_bob.create_handshake_init(
            0xAC000040, bob.node_id, bob.keypair.public_key);
        auto init_for_charlie = sm_expect_charlie.create_handshake_init(
            0xAC000040, charlie.node_id, charlie.keypair.public_key);
        auto charlie_response = sm_charlie.handle_handshake_init(
            *init_for_charlie, 0xAC000040);
        CHECK(init_for_bob.has_value());
        CHECK(charlie_response.has_value());
        CHECK(!sm_expect_bob.handle_handshake_resp(
            charlie_response->message, 0xAC000040));
        CHECK(!sm_expect_bob.get_session(bob.node_id).has_value());

        // Response header/version and ciphertext tampering are fail-closed.
        SessionManager sm_resp_i(alice);
        SessionManager sm_resp_r(bob);
        auto resp_init = sm_resp_i.create_handshake_init(
            0xAC000050, bob.node_id, bob.keypair.public_key);
        auto response = sm_resp_r.handle_handshake_init(
            *resp_init, 0xAC000050);
        CHECK(response.has_value());
        auto bad_response_version = response->message;
        bad_response_version[0] = 0x01;
        CHECK(!sm_resp_i.handle_handshake_resp(
            bad_response_version, 0xAC000050));
        CHECK(!sm_resp_i.handle_handshake_resp(
            response->message, 0xAC000050));

        SessionManager sm_resp_tamper_i(alice);
        SessionManager sm_resp_tamper_r(bob);
        auto tamper_init = sm_resp_tamper_i.create_handshake_init(
            0xAC000051, bob.node_id, bob.keypair.public_key);
        auto tamper_response = sm_resp_tamper_r.handle_handshake_init(
            *tamper_init, 0xAC000051);
        CHECK(tamper_response.has_value());
        tamper_response->message.back() ^= 0x01;
        CHECK(!sm_resp_tamper_i.handle_handshake_resp(
            tamper_response->message, 0xAC000051));
    }

    // ---- 10. Simultaneous reconnect converges on lower-NodeID initiation ----
    {
        const Identity& lower = alice.node_id < bob.node_id ? alice : bob;
        const Identity& higher = alice.node_id < bob.node_id ? bob : alice;
        SessionManager sm_lower(lower);
        SessionManager sm_higher(higher);
        const uint32_t lower_session_id = 0xAC001000;
        const uint32_t higher_session_id = 0xAC002000;

        auto lower_init = sm_lower.create_handshake_init(
            lower_session_id, higher.node_id, higher.keypair.public_key);
        auto higher_init = sm_higher.create_handshake_init(
            higher_session_id, lower.node_id, lower.keypair.public_key);
        CHECK(lower_init.has_value());
        CHECK(higher_init.has_value());

        auto response_to_lower = sm_higher.handle_handshake_init(
            *lower_init, lower_session_id);
        auto response_to_higher = sm_lower.handle_handshake_init(
            *higher_init, higher_session_id);
        CHECK(response_to_lower.has_value());
        CHECK(!response_to_higher.has_value());
        CHECK(sm_lower.handle_handshake_resp(
            response_to_lower->message, lower_session_id));

        auto lower_session = sm_lower.get_session(higher.node_id);
        auto higher_session = sm_higher.get_session(lower.node_id);
        CHECK(lower_session.has_value());
        CHECK(higher_session.has_value());
        CHECK((*lower_session)->id == lower_session_id);
        CHECK((*higher_session)->id == lower_session_id);

        // Repeat the collision while that session is active: simultaneous
        // rekey also converges without either side retaining the losing keys.
        const uint32_t lower_rekey_id = 0xAC003000;
        const uint32_t higher_rekey_id = 0xAC004000;
        auto lower_rekey = sm_lower.create_handshake_init(
            lower_rekey_id, higher.node_id, higher.keypair.public_key);
        auto higher_rekey = sm_higher.create_handshake_init(
            higher_rekey_id, lower.node_id, lower.keypair.public_key);
        CHECK(lower_rekey.has_value());
        CHECK(higher_rekey.has_value());
        auto rekey_response_to_lower = sm_higher.handle_handshake_init(
            *lower_rekey, lower_rekey_id);
        auto rekey_response_to_higher = sm_lower.handle_handshake_init(
            *higher_rekey, higher_rekey_id);
        CHECK(rekey_response_to_lower.has_value());
        CHECK(!rekey_response_to_higher.has_value());
        CHECK(sm_lower.handle_handshake_resp(
            rekey_response_to_lower->message, lower_rekey_id));
        lower_session = sm_lower.get_session(higher.node_id);
        higher_session = sm_higher.get_session(lower.node_id);
        CHECK(lower_session.has_value());
        CHECK(higher_session.has_value());
        CHECK((*lower_session)->id == lower_rekey_id);
        CHECK((*higher_session)->id == lower_rekey_id);
    }

    // ---- 11. Incomplete initiator handshakes expire ------------------------
    {
        ManualClock clock;
        SessionManager sm_i(alice, clock);
        SessionManager sm_r(bob, clock);
        sm_i.set_handshake_timeout(std::chrono::milliseconds(50));
        CHECK(sm_i.handshake_timeout() == std::chrono::milliseconds(50));

        const uint32_t expired_id = 0xAC005000;
        auto init = sm_i.create_handshake_init(
            expired_id, bob.node_id, bob.keypair.public_key);
        auto response = sm_r.handle_handshake_init(*init, expired_id);
        CHECK(init.has_value());
        CHECK(response.has_value());

        clock.advance(std::chrono::milliseconds(51));
        sm_i.purge_incomplete_handshakes();
        CHECK(!sm_i.handle_handshake_resp(
            response->message, expired_id));
        CHECK(!sm_i.get_session(bob.node_id).has_value());

        // Entry points also purge lazily. Reusing the expired session ID
        // creates fresh Noise state, so a response to the old INIT cannot
        // complete the replacement attempt.
        SessionManager sm_lazy_i(alice, clock);
        SessionManager sm_lazy_r(bob, clock);
        sm_lazy_i.set_handshake_timeout(std::chrono::milliseconds(50));
        const uint32_t reused_id = 0xAC005001;
        auto old_init = sm_lazy_i.create_handshake_init(
            reused_id, bob.node_id, bob.keypair.public_key);
        auto old_response = sm_lazy_r.handle_handshake_init(
            *old_init, reused_id);
        CHECK(old_response.has_value());
        clock.advance(std::chrono::milliseconds(51));
        auto replacement_init = sm_lazy_i.create_handshake_init(
            reused_id, bob.node_id, bob.keypair.public_key);
        CHECK(replacement_init.has_value());
        CHECK(*replacement_init != *old_init);
        CHECK(!sm_lazy_i.handle_handshake_resp(
            old_response->message, reused_id));
        CHECK(!sm_lazy_i.get_session(bob.node_id).has_value());
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
