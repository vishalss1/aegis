#include "aegis/session/session.hpp"
#include "aegis/identity/identity.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
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
    printf("--- session tests ---\n");

    // Create two identities
    NetworkId net{};
    net[0] = 0x01;
    Identity alice = Identity::create(net);
    Identity bob   = Identity::create(net);

    // ---- 1. Handshake round-trip: init -> resp -> keys established ----------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0001;

        // A creates handshake init for B
        auto init_msg = sm_a.create_handshake_init(session_id);
        CHECK(init_msg.size() == HANDSHAKE_PAYLOAD_SIZE);

        // B handles the init
        auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
        CHECK(resp_msg.has_value());
        CHECK(resp_msg->size() == HANDSHAKE_PAYLOAD_SIZE);

        // A handles the response
        bool ok = sm_a.handle_handshake_resp(*resp_msg, session_id);
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
    }

    // ---- 2. Encrypt/decrypt round-trip --------------------------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0002;
        auto init_msg = sm_a.create_handshake_init(session_id);
        auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
        sm_a.handle_handshake_resp(*resp_msg, session_id);

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
    }

    // ---- 3. Replay rejection ------------------------------------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);

        uint32_t session_id = 0xABCD0003;
        auto init_msg = sm_a.create_handshake_init(session_id);
        auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
        sm_a.handle_handshake_resp(*resp_msg, session_id);

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
        auto init_msg = sm_a.create_handshake_init(session_id);
        auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
        sm_a.handle_handshake_resp(*resp_msg, session_id);

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
        auto init_msg = sm_a.create_handshake_init(session_id);

        // B tries to handle init but claims it's from charlie (wrong node_id)
        auto resp_msg = sm_b.handle_handshake_init(init_msg, charlie.node_id);
        CHECK(!resp_msg.has_value());
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
            auto init_msg = sm_a.create_handshake_init(session_id);
            auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
            CHECK(resp_msg.has_value());
            CHECK(sm_a.handle_handshake_resp(*resp_msg, session_id));
            CHECK(sm_a.get_session(bob.node_id).has_value());
            CHECK(sm_b.get_session(alice.node_id).has_value());
        }

        // Responder gate: alice (net1) initiates toward mallory (net2) — the
        // handshake must be refused BEFORE any session is created.
        {
            SessionManager sm_a(alice);
            SessionManager sm_m(mallory);
            uint32_t session_id = 0xABCD0011;
            auto init_msg = sm_a.create_handshake_init(session_id);
            auto resp_msg = sm_m.handle_handshake_init(init_msg, alice.node_id);
            CHECK(!resp_msg.has_value());
            CHECK(!sm_m.get_session(alice.node_id).has_value());
        }

        // Initiator gate (defense in depth): mallory initiates toward alice —
        // same refusal path.
        {
            SessionManager sm_a(alice);
            SessionManager sm_m(mallory);
            uint32_t session_id = 0xABCD0012;
            auto init_msg = sm_m.create_handshake_init(session_id);
            auto resp_msg = sm_a.handle_handshake_init(init_msg, mallory.node_id);
            CHECK(!resp_msg.has_value());
            CHECK(!sm_a.get_session(mallory.node_id).has_value());
        }
    }

    // ---- 7. Step 15: rekey via a fresh handshake -----------------------------
    {
        SessionManager sm_a(alice);
        SessionManager sm_b(bob);
        sm_a.set_retired_grace(std::chrono::milliseconds(60));
        sm_b.set_retired_grace(std::chrono::milliseconds(60));

        // Establish the first session (sid1).
        uint32_t sid1 = 0xABCD0100;
        auto init1 = sm_a.create_handshake_init(sid1);
        auto resp1 = sm_b.handle_handshake_init(init1, alice.node_id);
        CHECK(sm_a.handle_handshake_resp(*resp1, sid1));
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
        auto init2 = sm_a.create_handshake_init(sid2);
        auto resp2 = sm_b.handle_handshake_init(init2, alice.node_id);
        CHECK(sm_a.handle_handshake_resp(*resp2, sid2));

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
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
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
        auto init1 = sm_a.create_handshake_init(sid1);
        auto resp1 = sm_b.handle_handshake_init(init1, alice.node_id);
        sm_a.handle_handshake_resp(*resp1, sid1);

        // Rekey once so B has a retired sid1 plus an active sid2.
        uint32_t sid2 = 0xABCD0400;
        auto init2 = sm_a.create_handshake_init(sid2);
        auto resp2 = sm_b.handle_handshake_init(init2, alice.node_id);
        sm_a.handle_handshake_resp(*resp2, sid2);

        // A removes its session with B.
        sm_a.remove_session(bob.node_id);
        CHECK(!sm_a.get_session(bob.node_id).has_value());
        // Encryption toward the removed peer fails on A (active keys gone).
        const uint8_t pt[] = {0x45, 0x00, 0x00, 0x14};
        auto enc = sm_a.encrypt_data(bob.node_id, pt, sizeof(pt));
        CHECK(!enc.has_value());
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
