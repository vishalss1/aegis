#include "aegis/session/session.hpp"
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

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
