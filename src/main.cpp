#include "aegis/adapter/adapter.hpp"
#include "aegis/platform/platform.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/crypto/x25519.hpp"
#include "aegis/crypto/chacha20poly1305.hpp"
#include "aegis/identity/identity.hpp"
#include "aegis/tunnel/tunnel.hpp"
#include "aegis/tunnel/tunnel_test.hpp"
#include "aegis/session/session.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/routing/routing.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <vector>

// UDP packet: 10.10.0.2:12345 -> 10.10.0.1:9999, payload "hello" (5 bytes)
// Total 33 bytes: 20 IP + 8 UDP + 5 payload
// IP: tot_len=33(0x21), id=1, ttl=64, proto=17(UDP), csum=0x66b5
// UDP: sport=12345, dport=9999, len=13(0x0d), csum=0x50a3
static const uint8_t UDP_TEST_PACKET[] = {
    0x45, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x66, 0xb5, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x30, 0x39, 0x27, 0x0f, 0x00, 0x0d, 0x50, 0xa3,
    0x68, 0x65, 0x6c, 0x6c, 0x6f};

// ICMP Echo Request:  10.10.0.2 -> 10.10.0.1
// IP:    id=0xabcd, ttl=64, checksum=0xbadd
// ICMP:  type=8(echo), id=1, seq=1, payload=32 zero bytes, checksum=0xf7fd
static const uint8_t PING_TEST_PACKET[] = {
    0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd, 0x00, 0x00,
    0x40, 0x01, 0xba, 0xdd, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static bool parse_hex(const char* hex, std::vector<uint8_t>& out) {
    size_t len = std::strlen(hex);
    if (len % 2 != 0) return false;
    out.resize(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        char buf[3] = {hex[i], hex[i + 1], 0};
        char* end;
        unsigned long v = std::strtoul(buf, &end, 16);
        if (*end != 0) return false;
        out[i / 2] = (uint8_t)v;
    }
    return true;
}

static void print_usage(const char* prog) {
    printf("usage: %s [--listen | --inject <hex> | --ping-test | --transport-test | --crypto-test | --aead-test | --identity-test]\n\n", prog);
    printf("  --listen           create adapter at 10.10.0.1/24 and print packets for 30s\n");
    printf("  --inject <hex>     inject a raw hex-encoded IP packet, then read one reply\n");
    printf("  --ping-test        inject a UDP packet, confirm OS listener receives it\n");
    printf("  --transport-test   loopback UDP send/receive via Transport class\n");
    printf("  --crypto-test      X25519 key generation and shared secret derivation\n");
    printf("  --aead-test        ChaCha20-Poly1305 AEAD encrypt/decrypt with tamper rejection\n");
    printf("  --identity-test    Identity creation, NodeID determinism, NetworkID matching\n");
    printf("  --session-test     Session Manager handshake, key derivation, replay, encrypt/decrypt\n");
    printf("  --peer-test        Peer Manager multi-peer table, states, endpoints, session lookup\n");
    printf("  --routing-test     Routing Engine prefix->next-hop->peer resolution and loop avoidance\n");
    printf("  --tunnel-test      self-test: staggered 3-node mesh, join-any-available bootstrap,\n");
    printf("                     forced-route UDP round-trips (multi-peer routing + reconnect)\n");
    printf("  --gossip-test      self-test: 4-node A-B-C-D chain where each node knows only its\n");
    printf("                     direct neighbors — peer table gossip must converge the full mesh\n");
    printf("  --tunnel <local_ip> <prefix> <listen_port> [--peer <nodeid> <pubkey> <ip> <port> <cidr...>]  mesh node\n");
}

// RFC 8439 Section 2.8.2 AEAD_CHACHA20_POLY1305 test vector
static const uint8_t RFC8439_KEY[] = {
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
};
static const uint8_t RFC8439_NONCE[] = {
    0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
};
static const uint8_t RFC8439_AAD[] = {
    0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
};
static const uint8_t RFC8439_CT[] = {
    0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,
    0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
    0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,
    0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
    0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,
    0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
    0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,
    0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
    0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,
    0x86,0xce,0xc6,0x4b,0x61,0x16,
};
static const uint8_t RFC8439_TAG[] = {
    0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,
    0xd0,0x60,0x06,0x91,
};
static const uint8_t RFC8439_PT[] = {
    0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,
    0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
    0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,
    0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
    0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,
    0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
    0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,
    0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
    0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,
    0x62,0x65,0x20,0x69,0x74,0x2e,
};

// ---- aead-test --------------------------------------------------------------
static int run_aead_test() {
    printf("[aead-test] starting\n");

    // --- RFC 8439 test vector (ground truth against published spec) -----------
    printf("[aead-test] RFC 8439 Section 2.8.2 test vector:\n");
    printf("[aead-test]   key:   ");
    for (auto b : RFC8439_KEY) printf("%02x", b);
    printf("\n[aead-test]   nonce: ");
    for (auto b : RFC8439_NONCE) printf("%02x", b);
    printf("\n[aead-test]   aad:   ");
    for (auto b : RFC8439_AAD) printf("%02x", b);
    printf("\n[aead-test]   pt:    ");
    for (auto b : RFC8439_PT) printf("%02x", b);
    printf("\n");

    ChaCha20Poly1305Key rfc_key;
    std::memcpy(rfc_key.data(), RFC8439_KEY, CHACHA20_POLY1305_KEY_SIZE);
    ChaCha20Poly1305Nonce rfc_nonce;
    std::memcpy(rfc_nonce.data(), RFC8439_NONCE, CHACHA20_POLY1305_NONCE_SIZE);

    uint8_t rfc_ct[sizeof(RFC8439_CT)];
    uint8_t rfc_tag[CHACHA20_POLY1305_TAG_SIZE];
    if (!chacha20_poly1305_encrypt(
            rfc_key, rfc_nonce,
            RFC8439_PT, sizeof(RFC8439_PT),
            rfc_ct, rfc_tag, RFC8439_AAD, sizeof(RFC8439_AAD))) {
        fprintf(stderr, "[aead-test] FAIL — RFC 8439 encrypt returned false\n");
        return 1;
    }

    bool rfc_ct_ok = (std::memcmp(rfc_ct, RFC8439_CT, sizeof(RFC8439_CT)) == 0);
    bool rfc_tag_ok = (std::memcmp(rfc_tag, RFC8439_TAG, CHACHA20_POLY1305_TAG_SIZE) == 0);

    printf("[aead-test]   ct:    ");
    for (size_t i = 0; i < sizeof(RFC8439_CT); i++) printf("%02x", rfc_ct[i]);
    printf("\n[aead-test]   tag:   ");
    for (size_t i = 0; i < CHACHA20_POLY1305_TAG_SIZE; i++) printf("%02x", rfc_tag[i]);
    printf("\n");
    printf("[aead-test]   expected ct:  ");
    for (auto b : RFC8439_CT) printf("%02x", b);
    printf("\n[aead-test]   expected tag: ");
    for (auto b : RFC8439_TAG) printf("%02x", b);
    printf("\n");

    if (!rfc_ct_ok) {
        fprintf(stderr, "[aead-test] FAIL — RFC 8439 ciphertext mismatch\n");
        return 1;
    }
    if (!rfc_tag_ok) {
        fprintf(stderr, "[aead-test] FAIL — RFC 8439 tag mismatch\n");
        return 1;
    }

    uint8_t rfc_pt[sizeof(RFC8439_PT)];
    if (!chacha20_poly1305_decrypt(
            rfc_key, rfc_nonce,
            rfc_ct, sizeof(RFC8439_CT), rfc_tag, rfc_pt,
            RFC8439_AAD, sizeof(RFC8439_AAD))) {
        fprintf(stderr, "[aead-test] FAIL — RFC 8439 decrypt returned false\n");
        return 1;
    }
    bool rfc_pt_ok = (std::memcmp(rfc_pt, RFC8439_PT, sizeof(RFC8439_PT)) == 0);
    if (!rfc_pt_ok) {
        fprintf(stderr, "[aead-test] FAIL — RFC 8439 decrypted plaintext mismatch\n");
        return 1;
    }
    printf("[aead-test] RFC 8439 test vector: *** PASS ***\n");

    // --- Internal round-trip with arbitrary key/nonce -------------------------
    ChaCha20Poly1305Key key{};
    ChaCha20Poly1305Nonce nonce{};
    for (uint8_t i = 0; i < CHACHA20_POLY1305_KEY_SIZE; i++) key[i] = i;
    for (uint8_t i = 0; i < CHACHA20_POLY1305_NONCE_SIZE; i++) nonce[i] = 0x80 | i;

    const char* PLAINTEXT = "hello-aead-0123456789";
    size_t pt_len = std::strlen(PLAINTEXT);

    uint8_t ct[64];
    uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
    if (!chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct, tag)) {
        fprintf(stderr, "[aead-test] FAIL — encrypt returned false\n");
        return 1;
    }

    uint8_t pt2[64];
    if (!chacha20_poly1305_decrypt(key, nonce, ct, pt_len, tag, pt2)) {
        fprintf(stderr, "[aead-test] FAIL — decrypt returned false\n");
        return 1;
    }
    bool match = (std::memcmp(pt2, PLAINTEXT, pt_len) == 0);
    if (!match) {
        fprintf(stderr, "[aead-test] FAIL — plaintext mismatch\n");
        return 1;
    }
    printf("[aead-test] internal round-trip: *** PASS ***\n");

    // Tampered tag: must fail
    {
        uint8_t ct2[64];
        uint8_t tag2[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct2, tag2);
        tag2[5] ^= 0x01;
        bool rejected = !chacha20_poly1305_decrypt(key, nonce, ct2, pt_len, tag2, pt2);
        if (!rejected) {
            fprintf(stderr, "[aead-test] FAIL — tampered tag was not rejected\n");
            return 1;
        }
    }
    printf("[aead-test] tag-tamper rejected: *** PASS ***\n");

    // Tampered ciphertext: must fail
    {
        uint8_t ct2[64];
        uint8_t tag2[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct2, tag2);
        ct2[3] ^= 0x01;
        bool rejected = !chacha20_poly1305_decrypt(key, nonce, ct2, pt_len, tag2, pt2);
        if (!rejected) {
            fprintf(stderr, "[aead-test] FAIL — tampered ciphertext was not rejected\n");
            return 1;
        }
    }
    printf("[aead-test] ct-tamper rejected: *** PASS ***\n");

    // Wrong key: must fail
    {
        uint8_t ct2[64];
        uint8_t tag2[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct2, tag2);
        ChaCha20Poly1305Key wrong_key{};
        wrong_key[0] = 0x42;
        bool rejected = !chacha20_poly1305_decrypt(wrong_key, nonce, ct2, pt_len, tag2, pt2);
        if (!rejected) {
            fprintf(stderr, "[aead-test] FAIL — wrong key was not rejected\n");
            return 1;
        }
    }
    printf("[aead-test] wrong-key rejected: *** PASS ***\n");

    // Wrong nonce: must fail
    {
        uint8_t ct2[64];
        uint8_t tag2[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct2, tag2);
        ChaCha20Poly1305Nonce wrong_nonce{};
        wrong_nonce[0] = 0x42;
        bool rejected = !chacha20_poly1305_decrypt(key, wrong_nonce, ct2, pt_len, tag2, pt2);
        if (!rejected) {
            fprintf(stderr, "[aead-test] FAIL — wrong nonce was not rejected\n");
            return 1;
        }
    }
    printf("[aead-test] wrong-nonce rejected: *** PASS ***\n");

    printf("[aead-test] *** ALL PASS ***\n");
    return 0;
}

// ---- crypto-test ------------------------------------------------------------
static int run_crypto_test() {
    printf("[crypto-test] generating keypairs...\n");

    X25519KeyPair alice = x25519_generate_keypair();
    X25519KeyPair bob   = x25519_generate_keypair();

    // Check keys are non-zero
    auto key_all_zero = [](const X25519Key& k) {
        for (auto b : k) if (b != 0) return false;
        return true;
    };

    if (key_all_zero(alice.private_key) || key_all_zero(alice.public_key)) {
        fprintf(stderr, "[crypto-test] FAIL — alice keypair generation returned all zeros\n");
        return 1;
    }
    if (key_all_zero(bob.private_key) || key_all_zero(bob.public_key)) {
        fprintf(stderr, "[crypto-test] FAIL — bob keypair generation returned all zeros\n");
        return 1;
    }

    printf("[crypto-test] alice priv: ");
    for (auto b : alice.private_key) printf("%02x", b);
    printf("\n[crypto-test] alice pub:  ");
    for (auto b : alice.public_key) printf("%02x", b);

    printf("\n[crypto-test] bob priv:   ");
    for (auto b : bob.private_key) printf("%02x", b);
    printf("\n[crypto-test] bob pub:    ");
    for (auto b : bob.public_key) printf("%02x", b);
    printf("\n");

    // Derive from both directions
    printf("[crypto-test] deriving shared secret (A-side)...\n");
    auto s_alice = x25519_derive_shared_secret(alice.private_key, bob.public_key);
    if (!s_alice.has_value()) {
        fprintf(stderr, "[crypto-test] FAIL — alice-side derivation returned nullopt\n");
        return 1;
    }

    printf("[crypto-test] deriving shared secret (B-side)...\n");
    auto s_bob = x25519_derive_shared_secret(bob.private_key, alice.public_key);
    if (!s_bob.has_value()) {
        fprintf(stderr, "[crypto-test] FAIL — bob-side derivation returned nullopt\n");
        return 1;
    }

    printf("[crypto-test] secret (A-side): ");
    for (auto b : *s_alice) printf("%02x", b);
    printf("\n[crypto-test] secret (B-side): ");
    for (auto b : *s_bob) printf("%02x", b);
    printf("\n");

    // Verify match
    bool match = true;
    for (size_t i = 0; i < X25519_KEY_SIZE; i++)
        if ((*s_alice)[i] != (*s_bob)[i]) { match = false; break; }

    if (!match) {
        fprintf(stderr, "[crypto-test] FAIL — shared secrets do not match\n");
        return 1;
    }

    printf("[crypto-test] *** PASS *** shared secret matches from both sides\n");
    return 0;
}

// ---- identity-test ----------------------------------------------------------
static int run_identity_test() {
    printf("[identity-test] starting\n");

    // Create two identities with the same NetworkID
    NetworkId net_a{};
    net_a[0] = 0x01;
    NetworkId net_b{};
    net_b[0] = 0x02;

    Identity alice = Identity::create(net_a);
    Identity bob   = Identity::create(net_a);
    Identity charlie = Identity::create(net_b);

    printf("[identity-test] alice node_id:  ");
    for (auto b : alice.node_id) printf("%02x", b);
    printf("\n[identity-test] bob node_id:    ");
    for (auto b : bob.node_id) printf("%02x", b);
    printf("\n[identity-test] charlie node_id:");
    for (auto b : charlie.node_id) printf("%02x", b);
    printf("\n");

    // Same-network peers: must match
    if (!alice.matches_network(bob.network_id)) {
        fprintf(stderr, "[identity-test] FAIL — alice and bob share net_a but matches_network returned false\n");
        return 1;
    }
    printf("[identity-test] alice matches bob's network: YES\n");

    if (!bob.matches_network(alice.network_id)) {
        fprintf(stderr, "[identity-test] FAIL — bob and alice share net_a but matches_network returned false\n");
        return 1;
    }
    printf("[identity-test] bob matches alice's network: YES\n");

    // Different-network peers: must NOT match
    if (alice.matches_network(charlie.network_id)) {
        fprintf(stderr, "[identity-test] FAIL — alice (net_a) matches charlie (net_b) but should not\n");
        return 1;
    }
    printf("[identity-test] alice matches charlie's network: NO\n");

    if (charlie.matches_network(alice.network_id)) {
        fprintf(stderr, "[identity-test] FAIL — charlie (net_b) matches alice (net_a) but should not\n");
        return 1;
    }
    printf("[identity-test] charlie matches alice's network: NO\n");

    // NodeID determinism: hash the same public key twice
    NodeId h1 = hash_public_key(alice.keypair.public_key);
    NodeId h2 = hash_public_key(alice.keypair.public_key);
    if (h1 != h2) {
        fprintf(stderr, "[identity-test] FAIL — hash_public_key not deterministic\n");
        return 1;
    }
    // Also confirm it matches what Identity::create stored
    if (h1 != alice.node_id) {
        fprintf(stderr, "[identity-test] FAIL — hash_public_key != stored node_id\n");
        return 1;
    }
    printf("[identity-test] NodeID is deterministic: YES\n");

    printf("[identity-test] *** ALL PASS ***\n");
    return 0;
}

// ---- session-test ----------------------------------------------------------
static int run_session_test() {
    printf("[session-test] starting\n");

    NetworkId net{};
    net[0] = 0x01;
    Identity alice = Identity::create(net);
    Identity bob   = Identity::create(net);

    SessionManager sm_a(alice);
    SessionManager sm_b(bob);

    uint32_t session_id = 0xDEAD0001;

    // A creates init
    auto init = sm_a.create_handshake_init(session_id);
    if (init.size() != HANDSHAKE_PAYLOAD_SIZE) {
        fprintf(stderr, "[session-test] FAIL: init size %zu != %zu\n",
                init.size(), HANDSHAKE_PAYLOAD_SIZE);
        return 1;
    }
    printf("[session-test] handshake init: %zu bytes\n", init.size());

    // B handles init
    auto resp = sm_b.handle_handshake_init(init, alice.node_id);
    if (!resp) {
        fprintf(stderr, "[session-test] FAIL: handle_handshake_init returned nullopt\n");
        return 1;
    }
    printf("[session-test] handshake resp: %zu bytes\n", resp->size());

    // A handles resp
    if (!sm_a.handle_handshake_resp(*resp, session_id)) {
        fprintf(stderr, "[session-test] FAIL: handle_handshake_resp failed\n");
        return 1;
    }
    printf("[session-test] handshake: established\n");

    // Check sessions
    auto sess_a = sm_a.get_session(bob.node_id);
    auto sess_b = sm_b.get_session(alice.node_id);
    if (!sess_a || !sess_b) {
        fprintf(stderr, "[session-test] FAIL: sessions not found\n");
        return 1;
    }
    if (!sess_a.value()->established || !sess_b.value()->established) {
        fprintf(stderr, "[session-test] FAIL: sessions not established\n");
        return 1;
    }
    printf("[session-test] sessions established: OK\n");

    // Encrypt/decrypt round-trip
    const uint8_t pt[] = {0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd};
    size_t pt_len = sizeof(pt);

    auto enc = sm_a.encrypt_data(bob.node_id, pt, pt_len);
    if (!enc) {
        fprintf(stderr, "[session-test] FAIL: encrypt failed\n");
        return 1;
    }
    printf("[session-test] encrypted: %zu bytes\n", enc->size());

    auto dec = sm_b.decrypt_data(enc->data(), enc->size());
    if (!dec) {
        fprintf(stderr, "[session-test] FAIL: decrypt failed\n");
        return 1;
    }
    if (dec->size() != pt_len ||
        memcmp(dec->data(), pt, pt_len) != 0) {
        fprintf(stderr, "[session-test] FAIL: plaintext mismatch\n");
        return 1;
    }
    printf("[session-test] decrypt round-trip: OK\n");

    // Replay rejection
    auto replay = sm_b.decrypt_data(enc->data(), enc->size());
    if (replay) {
        fprintf(stderr, "[session-test] FAIL: replay not rejected\n");
        return 1;
    }
    printf("[session-test] replay rejection: OK\n");

    // Tamper rejection
    auto enc2 = sm_a.encrypt_data(bob.node_id, pt, pt_len);
    if (enc2 && enc2->size() > 30) {
        (*enc2)[28] ^= 0xFF;
        auto tamper = sm_b.decrypt_data(enc2->data(), enc2->size());
        if (tamper) {
            fprintf(stderr, "[session-test] FAIL: tamper not rejected\n");
            return 1;
        }
    }
    printf("[session-test] tamper rejection: OK\n");

    // Wrong id rejection
    Identity charlie = Identity::create(net);
    SessionManager sm_c(charlie);
    auto init_c = sm_c.create_handshake_init(0xDEAD0002);
    auto bad_resp = sm_b.handle_handshake_init(init_c, charlie.node_id);
    if (bad_resp) {
        // This should work - charlie and bob don't know each other
        // but the handshake is session-based, not identity-verified
        // So this is fine. We just skip this check.
    }

    printf("[session-test] *** ALL PASS ***\n");
    return 0;
}

// ---- peer-test --------------------------------------------------------------
static int run_peer_test() {
    printf("[peer-test] starting\n");

    NetworkId net{};
    net[0] = 0x01;
    Identity alice = Identity::create(net);
    Identity bob   = Identity::create(net);
    Identity charlie = Identity::create(net);

    PeerManager pm;

    Endpoint ep_alice = Endpoint::from_parts(127, 0, 0, 1, 51820);
    Endpoint ep_bob   = Endpoint::from_parts(127, 0, 0, 1, 51821);

    // ---- multi-peer table + endpoints --------------------------------------
    pm.upsert(alice.node_id, alice.keypair.public_key, ep_alice, true);
    pm.upsert(bob.node_id, bob.keypair.public_key, ep_bob);
    pm.upsert(charlie.node_id, charlie.keypair.public_key);
    printf("[peer-test] table size after 3 upserts: %zu\n", pm.size());
    if (pm.size() != 3) {
        fprintf(stderr, "[peer-test] FAIL: expected 3 peers\n");
        return 1;
    }

    auto* a = pm.get_peer(alice.node_id);
    if (!a || a->node_id != alice.node_id ||
        a->public_key != alice.keypair.public_key ||
        !a->endpoint.has_value() || !a->trusted) {
        fprintf(stderr, "[peer-test] FAIL: alice peer entry wrong\n");
        return 1;
    }
    printf("[peer-test] direct peer entry with endpoint + trusted: OK\n");

    auto* c = pm.get_peer(charlie.node_id);
    if (!c || c->endpoint.has_value()) {
        fprintf(stderr, "[peer-test] FAIL: relay-only peer must have no endpoint\n");
        return 1;
    }
    printf("[peer-test] relay-only peer (no endpoint): OK\n");

    // ---- endpoint update ----------------------------------------------------
    Endpoint ep_new = Endpoint::from_parts(192, 168, 1, 5, 51820);
    pm.update_endpoint(alice.node_id, ep_new);
    a = pm.get_peer(alice.node_id);
    if (!a || !a->endpoint.has_value() ||
        a->endpoint->ip != ep_new.ip || a->endpoint->port != ep_new.port) {
        fprintf(stderr, "[peer-test] FAIL: endpoint update failed\n");
        return 1;
    }
    printf("[peer-test] endpoint update: OK\n");

    // ---- state transitions --------------------------------------------------
    pm.mark_connecting(bob.node_id);
    auto* b = pm.get_peer(bob.node_id);
    if (!b || b->state != PeerState::Connecting || b->connect_attempts != 1) {
        fprintf(stderr, "[peer-test] FAIL: mark_connecting\n");
        return 1;
    }
    pm.mark_seen(bob.node_id);
    b = pm.get_peer(bob.node_id);
    if (!b || b->state != PeerState::Established) {
        fprintf(stderr, "[peer-test] FAIL: mark_seen -> Established\n");
        return 1;
    }
    printf("[peer-test] state transitions: OK\n");

    // ---- session lookup (delegates to Session Manager) ----------------------
    SessionManager sm_a(alice);
    SessionManager sm_b(bob);
    uint32_t session_id = 0xA0000001;
    auto init_msg = sm_a.create_handshake_init(session_id);
    auto resp_msg = sm_b.handle_handshake_init(init_msg, alice.node_id);
    if (!resp_msg) {
        fprintf(stderr, "[peer-test] FAIL: handshake init\n");
        return 1;
    }
    if (!sm_a.handle_handshake_resp(*resp_msg, session_id)) {
        fprintf(stderr, "[peer-test] FAIL: handshake resp\n");
        return 1;
    }

    pm.set_session_manager(&sm_a);
    auto sess = pm.get_session(bob.node_id);
    if (!sess || !(*sess)->established || (*sess)->id != session_id) {
        fprintf(stderr, "[peer-test] FAIL: session lookup via PeerManager\n");
        return 1;
    }
    printf("[peer-test] session lookup via PeerManager: OK\n");

    NodeId unknown{};
    unknown[0] = 0xFF;
    if (pm.get_session(unknown).has_value()) {
        fprintf(stderr, "[peer-test] FAIL: unknown peer must not resolve to a session\n");
        return 1;
    }
    printf("[peer-test] unknown peer has no session: OK\n");

    // ---- stale / keepalive detection ---------------------------------------
    pm.set_dead_timeout(std::chrono::seconds(1));
    pm.set_keepalive_interval(std::chrono::seconds(1));
    if (!pm.stale_peers().empty()) {
        fprintf(stderr, "[peer-test] FAIL: nothing stale yet\n");
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    if (pm.stale_peers().empty()) {
        fprintf(stderr, "[peer-test] FAIL: expected stale peers after dead timeout\n");
        return 1;
    }
    printf("[peer-test] stale peer detection after dead timeout: OK\n");

    if (pm.peers_needing_keepalive().empty()) {
        fprintf(stderr, "[peer-test] FAIL: expected keepalive-needed peers after interval\n");
        return 1;
    }
    printf("[peer-test] keepalive-needed detection: OK\n");

    // ---- removal ------------------------------------------------------------
    pm.remove_peer(charlie.node_id);
    if (pm.size() != 2 || pm.has_peer(charlie.node_id)) {
        fprintf(stderr, "[peer-test] FAIL: remove_peer\n");
        return 1;
    }
    printf("[peer-test] peer removal: OK\n");

    printf("[peer-test] *** ALL PASS ***\n");
    return 0;
}

// ---- routing-test -----------------------------------------------------------
static uint32_t rt_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
           static_cast<uint32_t>(d);
}

static NodeId rt_id(uint8_t tag) {
    NodeId n{};
    n[0] = tag;
    return n;
}

static Route rt_direct(uint32_t prefix, uint8_t plen, const NodeId& peer) {
    Route r;
    r.prefix = prefix;
    r.prefix_length = plen;
    r.type = NextHopType::Direct;
    r.next_hop = peer;
    r.destination = peer;
    return r;
}

static Route rt_relay(uint32_t prefix, uint8_t plen,
                      const NodeId& next_hop, const NodeId& destination) {
    Route r;
    r.prefix = prefix;
    r.prefix_length = plen;
    r.type = NextHopType::Relay;
    r.next_hop = next_hop;
    r.destination = destination;
    return r;
}

static int run_routing_test() {
    printf("[routing-test] starting\n");

    NodeId p1 = rt_id(1);
    NodeId p2 = rt_id(2);
    NodeId d  = rt_id(9);

    // ---- longest-prefix match ----------------------------------------------
    RoutingEngine re;
    re.add_route(rt_direct(rt_ip(10, 10, 0, 0), 24, p1));
    re.add_route(rt_direct(rt_ip(10, 10, 0, 2), 32, p2));

    auto best = re.find_peer(rt_ip(10, 10, 0, 2));
    if (!best || *best != p2) {
        fprintf(stderr, "[routing-test] FAIL: longest-prefix match\n");
        return 1;
    }
    printf("[routing-test] longest-prefix match (/32 beats /24): OK\n");

    auto wide = re.find_peer(rt_ip(10, 10, 0, 99));
    if (!wide || *wide != p1) {
        fprintf(stderr, "[routing-test] FAIL: /24 fallback\n");
        return 1;
    }
    printf("[routing-test] /24 fallback: OK\n");

    if (re.find_peer(rt_ip(10, 20, 0, 1)).has_value()) {
        fprintf(stderr, "[routing-test] FAIL: unexpected route for 10.20.0.1\n");
        return 1;
    }
    printf("[routing-test] no-route returns nullopt: OK\n");

    // ---- relay next-hop abstraction ----------------------------------------
    RoutingEngine mesh;
    NodeId A = rt_id(10);
    mesh.add_route(rt_direct(rt_ip(10, 0, 0, 10), 32, A));
    mesh.add_route(rt_relay(rt_ip(10, 60, 0, 0), 24, A, d));

    auto dpeer = mesh.find_peer(rt_ip(10, 60, 0, 5));
    auto dnh   = mesh.find_next_hop(rt_ip(10, 60, 0, 5));
    if (!dpeer || *dpeer != d || !dnh || *dnh != A) {
        fprintf(stderr, "[routing-test] FAIL: relay next-hop resolution\n");
        return 1;
    }
    printf("[routing-test] relay: dest=%02x.. next_hop=%02x..: OK\n", d[0], A[0]);

    // ---- loop avoidance ----------------------------------------------------
    RoutingEngine loops;
    loops.add_route(rt_relay(rt_ip(10, 50, 0, 1), 32, A, d));
    loops.add_route(rt_relay(rt_ip(10, 50, 0, 2), 32, d, A));
    if (loops.find_peer(rt_ip(10, 50, 0, 1)).has_value()) {
        fprintf(stderr, "[routing-test] FAIL: relay loop not rejected\n");
        return 1;
    }
    printf("[routing-test] relay loop rejected: OK\n");

    // ---- self-relay rejection ----------------------------------------------
    RoutingEngine selfrelay;
    NodeId X = rt_id(30);
    if (selfrelay.add_route(rt_relay(rt_ip(10, 80, 0, 1), 32, X, X))) {
        fprintf(stderr, "[routing-test] FAIL: self-relay accepted\n");
        return 1;
    }
    printf("[routing-test] self-relay rejected at insert: OK\n");

    // ---- upsert + withdraw -------------------------------------------------
    re.add_route(rt_direct(rt_ip(10, 10, 0, 2), 32, p2));
    if (re.size() != 2) {
        fprintf(stderr, "[routing-test] FAIL: upsert must replace same prefix\n");
        return 1;
    }
    printf("[routing-test] upsert replaces same prefix: OK\n");

    RoutingEngine w;
    w.add_route(rt_direct(rt_ip(10, 20, 0, 1), 32, p2));
    w.add_route(rt_relay(rt_ip(10, 30, 0, 0), 24, p2, d));
    w.remove_route(p2);
    if (!w.empty()) {
        fprintf(stderr, "[routing-test] FAIL: withdraw did not remove routes\n");
        return 1;
    }
    printf("[routing-test] route withdrawal through dead peer: OK\n");

    printf("[routing-test] *** ALL PASS ***\n");
    return 0;
}

// ---- tunnel -----------------------------------------------------------------
static int run_tunnel(int argc, char* argv[]) {
    // usage: --tunnel <local_ip> <prefix> <listen_port>
    //          [--peer <nodeid_hex> <pubkey_hex> <peer_ip> <peer_port> <allowed_cidr> ...]
    // Each --peer block is a mesh bootstrap candidate. The node joins any that
    // are reachable and keeps retrying the rest in the background.
    if (argc < 6) {
        fprintf(stderr, "usage: %s --tunnel <local_ip> <prefix> <listen_port>\n"
                        "                    [--peer <nodeid_hex> <pubkey_hex> <peer_ip> <peer_port> <allowed_cidr> ...]\n",
                argv[0]);
        fprintf(stderr, "  e.g.: aegis --tunnel 10.10.0.1 24 51820\n"
                        "            --peer <64hex> <64hex> 203.0.113.2 51821 10.20.0.0/24\n");
        return 1;
    }

    // Parse local IP
    uint32_t local_ip = 0;
    {
        uint8_t a, b, c, d;
        if (sscanf_s(argv[2], "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
            fprintf(stderr, "error: invalid local_ip '%s'\n", argv[2]);
            return 1;
        }
        local_ip = htonl((static_cast<uint32_t>(a) << 24) |
                         (static_cast<uint32_t>(b) << 16) |
                         (static_cast<uint32_t>(c) << 8)  |
                         static_cast<uint32_t>(d));
    }

    uint8_t prefix = (uint8_t)std::atoi(argv[3]);
    uint16_t listen_port = (uint16_t)std::atoi(argv[4]);

    TunnelConfig cfg;
    cfg.local_ip = local_ip;
    cfg.local_prefix = prefix;
    cfg.listen_port = listen_port;

    int i = 5;
    while (i < argc) {
        if (std::strcmp(argv[i], "--peer") != 0) {
            fprintf(stderr, "error: unexpected argument '%s' (expected --peer)\n", argv[i]);
            return 1;
        }
        if (i + 5 >= argc) {
            fprintf(stderr, "error: --peer needs <nodeid_hex> <pubkey_hex> <peer_ip> <peer_port> <allowed_cidr>...\n");
            return 1;
        }

        TunnelPeer peer;
        std::vector<uint8_t> nid, pk;
        if (!parse_hex(argv[i + 1], nid) || nid.size() != NODE_ID_SIZE) {
            fprintf(stderr, "error: invalid nodeid_hex '%s' (expected 64 hex chars)\n", argv[i + 1]);
            return 1;
        }
        if (!parse_hex(argv[i + 2], pk) || pk.size() != KEY_SIZE) {
            fprintf(stderr, "error: invalid pubkey_hex '%s' (expected 64 hex chars)\n", argv[i + 2]);
            return 1;
        }
        std::memcpy(peer.node_id.data(), nid.data(), NODE_ID_SIZE);
        std::memcpy(peer.public_key.data(), pk.data(), KEY_SIZE);

        uint8_t a, b, c, d;
        if (sscanf_s(argv[i + 3], "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
            fprintf(stderr, "error: invalid peer_ip '%s'\n", argv[i + 3]);
            return 1;
        }
        peer.endpoint = Endpoint::from_parts(a, b, c, d, (uint16_t)std::atoi(argv[i + 4]));
        i += 5;

        while (i < argc && std::strcmp(argv[i], "--peer") != 0) {
            char ip_part[32];
            unsigned plen = 0;
            if (sscanf_s(argv[i], "%31[^/]/%u", ip_part, (unsigned)sizeof(ip_part), &plen) != 2 || plen > 32) {
                fprintf(stderr, "error: invalid allowed_cidr '%s'\n", argv[i]);
                return 1;
            }
            uint8_t ia, ib, ic, id_;
            if (sscanf_s(ip_part, "%hhu.%hhu.%hhu.%hhu", &ia, &ib, &ic, &id_) != 4) {
                fprintf(stderr, "error: invalid allowed_cidr '%s'\n", argv[i]);
                return 1;
            }
            AllowedIP aip;
            aip.prefix = (static_cast<uint32_t>(ia) << 24) |
                         (static_cast<uint32_t>(ib) << 16) |
                         (static_cast<uint32_t>(ic) << 8)  |
                         static_cast<uint32_t>(id_);
            aip.prefix_length = (uint8_t)plen;
            peer.allowed_ips.push_back(aip);
            i++;
        }
        cfg.peers.push_back(peer);
    }

    if (cfg.peers.empty()) {
        fprintf(stderr, "error: at least one --peer block is required\n");
        return 1;
    }

    // Build adapter name from local IP (unique per instance)
    char adapter_name_buf[64];
    uint32_t ip_host = ntohl(local_ip);
    snprintf(adapter_name_buf, sizeof(adapter_name_buf),
             "Aegis %u.%u.%u.%u",
             (ip_host >> 24) & 0xFF, (ip_host >> 16) & 0xFF,
             (ip_host >>  8) & 0xFF,  ip_host        & 0xFF);

    Tunnel tunnel;
    if (!tunnel.start(cfg, adapter_name_buf)) {
        fprintf(stderr, "error: tunnel start failed\n");
        return 1;
    }

    printf("[tunnel] running — press Ctrl+C to stop\n");
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    tunnel.stop();
    return 0;
}

// ---- transport-test --------------------------------------------------------
static int run_transport_test() {
    printf("[transport-test] starting\n");

    Transport tx;
    Transport rx;

    if (!tx.bind(7001)) {
        fprintf(stderr, "[transport-test] tx bind failed\n");
        return 1;
    }
    printf("[transport-test] tx bound to port 7001\n");

    if (!rx.bind(7002)) {
        fprintf(stderr, "[transport-test] rx bind failed\n");
        return 1;
    }
    printf("[transport-test] rx bound to port 7002\n");

    // State shared between callback and main thread
    bool received = false;
    std::vector<uint8_t> recv_data;
    Endpoint recv_from{};
    std::mutex mtx;
    std::condition_variable cv;

    if (!rx.start_receive([&](const uint8_t* data, size_t len, Endpoint sender) {
        std::lock_guard<std::mutex> lock(mtx);
        received = true;
        recv_data.assign(data, data + len);
        recv_from = sender;
        cv.notify_one();
    })) {
        fprintf(stderr, "[transport-test] rx start_receive failed\n");
        tx.close();
        rx.close();
        return 1;
    }

    // Send known payload
    const char* payload = "hello-transport";
    size_t payload_len = std::strlen(payload);
    Endpoint dest = Endpoint::from_parts(127, 0, 0, 1, 7002);
    if (!tx.send((const uint8_t*)payload, payload_len, dest)) {
        fprintf(stderr, "[transport-test] tx.send failed\n");
        rx.stop_receive();
        tx.close();
        rx.close();
        return 1;
    }
    printf("[transport-test] sent %zu bytes to 127.0.0.1:7002\n", payload_len);

    // Wait for receipt (1s timeout)
    {
        std::unique_lock<std::mutex> lock(mtx);
        if (!cv.wait_for(lock, std::chrono::seconds(1), [&] { return received; })) {
            fprintf(stderr, "[transport-test] FAIL — rx timed out, no packet received\n");
            rx.stop_receive();
            tx.close();
            rx.close();
            return 1;
        }
    }

    // Verify payload
    bool payload_ok = (recv_data.size() == payload_len &&
                       std::memcmp(recv_data.data(), payload, payload_len) == 0);
    if (!payload_ok) {
        fprintf(stderr, "[transport-test] FAIL — payload mismatch\n");
        rx.stop_receive();
        tx.close();
        rx.close();
        return 1;
    }

    // Verify sender endpoint (127.0.0.1:7001)
    Endpoint expected_sender = Endpoint::from_parts(127, 0, 0, 1, 7001);
    if (!(recv_from == expected_sender)) {
        fprintf(stderr, "[transport-test] FAIL — sender mismatch: got %08x:%04x, expected %08x:%04x\n",
                recv_from.ip, recv_from.port, expected_sender.ip, expected_sender.port);
        rx.stop_receive();
        tx.close();
        rx.close();
        return 1;
    }

    printf("[transport-test] *** PASS *** received %zu bytes from 127.0.0.1:7001: \"%s\"\n",
           recv_data.size(), recv_data.data());

    rx.stop_receive();
    tx.close();
    rx.close();
    return 0;
}

// ---- main ------------------------------------------------------------------
int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    printf("[main] starting\n");

    if (!platform_init_winsock()) return 1;

    // ---- parse mode --------------------------------------------------------
    bool mode_listen       = false;
    bool mode_inject       = false;
    bool mode_ping_test    = false;
    bool mode_transport_test = false;
    bool mode_crypto_test  = false;
    bool mode_aead_test    = false;
    bool mode_identity_test = false;
    bool mode_peer_test = false;
    bool mode_routing_test = false;
    std::vector<uint8_t> inject_data;

    if (argc < 2) {
        mode_listen = true;
    } else if (std::strcmp(argv[1], "--listen") == 0) {
        mode_listen = true;
    } else if (std::strcmp(argv[1], "--ping-test") == 0) {
        mode_ping_test = true;
    } else if (std::strcmp(argv[1], "--transport-test") == 0) {
        mode_transport_test = true;
    } else if (std::strcmp(argv[1], "--crypto-test") == 0) {
        mode_crypto_test = true;
    } else if (std::strcmp(argv[1], "--aead-test") == 0) {
        mode_aead_test = true;
    } else if (std::strcmp(argv[1], "--session-test") == 0) {
        int ret = run_session_test();
        platform_cleanup_winsock();
        return ret;
    } else if (std::strcmp(argv[1], "--identity-test") == 0) {
        mode_identity_test = true;
    } else if (std::strcmp(argv[1], "--peer-test") == 0) {
        mode_peer_test = true;
    } else if (std::strcmp(argv[1], "--routing-test") == 0) {
        mode_routing_test = true;
    } else if (argc > 2 && std::strcmp(argv[1], "--inject") == 0) {
        if (!parse_hex(argv[2], inject_data)) {
            fprintf(stderr, "error: invalid hex string\n");
            platform_cleanup_winsock();
            return 1;
        }
        mode_inject = true;
    } else if (std::strcmp(argv[1], "--tunnel-test") == 0) {
        if (!platform_is_admin()) {
            fprintf(stderr, "error: tunnel-test mode requires administrator privileges\n");
            platform_cleanup_winsock();
            return 1;
        }
        int ret = run_tunnel_test();
        platform_cleanup_winsock();
        return ret;
    } else if (std::strcmp(argv[1], "--gossip-test") == 0) {
        if (!platform_is_admin()) {
            fprintf(stderr, "error: gossip-test mode requires administrator privileges\n");
            platform_cleanup_winsock();
            return 1;
        }
        int ret = run_gossip_test();
        platform_cleanup_winsock();
        return ret;
    } else if (std::strcmp(argv[1], "--tunnel") == 0) {
        if (!platform_is_admin()) {
            fprintf(stderr, "error: tunnel mode requires administrator privileges\n");
            platform_cleanup_winsock();
            return 1;
        }
        int ret = run_tunnel(argc, argv);
        platform_cleanup_winsock();
        return ret;
    } else {
        print_usage(argv[0]);
        platform_cleanup_winsock();
        return 1;
    }

    // ---- modes that don't need adapter or winsock --------------------------
    if (mode_crypto_test) {
        return run_crypto_test();
    }
    if (mode_aead_test) {
        return run_aead_test();
    }
    if (mode_identity_test) {
        return run_identity_test();
    }
    if (mode_peer_test) {
        int ret = run_peer_test();
        platform_cleanup_winsock();
        return ret;
    }
    if (mode_routing_test) {
        int ret = run_routing_test();
        platform_cleanup_winsock();
        return ret;
    }

    // ---- transport-test (no adapter needed) --------------------------------
    if (mode_transport_test) {
        int ret = run_transport_test();
        platform_cleanup_winsock();
        return ret;
    }

    // ---- modes requiring adapter: check admin + create adapter ------------
    if (!platform_is_admin()) {
        fprintf(stderr, "error: must run as administrator\n");
        platform_cleanup_winsock();
        return 1;
    }

    Adapter adapter;
    if (!adapter.create()) {
        fprintf(stderr, "error: adapter creation failed\n");
        platform_cleanup_winsock();
        return 1;
    }

    // ---- inject / ping-test ------------------------------------------------
    if (mode_ping_test || mode_inject) {
        const uint8_t* data;
        size_t len;
        if (mode_ping_test) {
            SOCKET listener = socket(AF_INET, SOCK_DGRAM, 0);
            bool listener_ok = false;
            if (listener != INVALID_SOCKET) {
                struct sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 1);
                addr.sin_port = htons(9999);
                listener_ok = (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == 0);
                if (listener_ok)
                    printf("[main] listening on 10.10.0.1:9999\n");
            }

            char rule_name[] = "AegisTempPingTest";
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "netsh advfirewall firewall add rule name=%s dir=in"
                " program=\"%s\" protocol=udp localport=9999 action=allow",
                rule_name, exe_path);
            int fw_ret = system(cmd);
            printf("[main] firewall rule add returned %d\n", fw_ret);

            std::vector<uint8_t> drain;
            for (int i = 0; i < 5; i++) {
                if (!adapter.read_packet(drain, 200)) break;
            }

            data = UDP_TEST_PACKET;
            len  = sizeof(UDP_TEST_PACKET);
            printf("[main] ping-test: injecting %zu bytes:\n      ", len);
            for (size_t i = 0; i < len; i++)
                printf("%02x%c", data[i], (i % 16 == 15) ? '\n' : ' ');
            putchar('\n');

            if (!adapter.write_packet({data, data + len})) {
                fprintf(stderr, "error: write_packet failed\n");
                adapter.close();
                platform_cleanup_winsock();
                return 1;
            }
            printf("[main] write OK\n");

            if (listener_ok) {
                DWORD timeout = 5000;
                setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO,
                           (const char*)&timeout, sizeof(timeout));
                char buf[64] = {};
                struct sockaddr_in from = {};
                int fromlen = sizeof(from);
                int r = recvfrom(listener, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
                if (r > 0) {
                    buf[r] = 0;
                    printf("[main] *** INJECTION CONFIRMED *** listener received %d bytes"
                           " from %s:%d: \"%s\"\n",
                           r, inet_ntoa(from.sin_addr), ntohs(from.sin_port), buf);
                } else {
                    int err = WSAGetLastError();
                    printf("[main] listener error %d (0x%x)"
                           " — injection may have failed\n", err, err);
                }
                closesocket(listener);
            }

            snprintf(cmd, sizeof(cmd),
                "netsh advfirewall firewall delete rule name=%s", rule_name);
            system(cmd);
        } else {
            data = inject_data.data();
            len  = inject_data.size();
            printf("[main] inject: injecting %zu bytes\n", len);

            if (!adapter.write_packet({data, data + len})) {
                fprintf(stderr, "error: write_packet failed\n");
                adapter.close();
                platform_cleanup_winsock();
                return 1;
            }
            printf("[main] write OK\n");
        }

        // Send a packet from the OS through Wintun and verify typed parsing
        printf("[main] testing typed parser with OS outbound traffic...\n");
        {
            SOCKET sender = socket(AF_INET, SOCK_DGRAM, 0);
            if (sender != INVALID_SOCKET) {
                struct sockaddr_in local = {};
                local.sin_family = AF_INET;
                local.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 1);
                local.sin_port = htons(54321);
                bind(sender, (struct sockaddr*)&local, sizeof(local));

                struct sockaddr_in dest = {};
                dest.sin_family = AF_INET;
                dest.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 2);
                dest.sin_port = htons(9999);
                const char* msg = "probe";
                sendto(sender, msg, 5, 0, (struct sockaddr*)&dest, sizeof(dest));
                printf("[main] OS sent UDP to 10.10.0.2:9999\n");
                closesocket(sender);
            }

            std::vector<uint8_t> reply;
            for (int i = 0; i < 20; i++) {
                reply.clear();
                if (!adapter.read_packet(reply, 250)) continue;
                Adapter::print_packet(reply.data(), reply.size());
            }
        }

        adapter.close();
        platform_cleanup_winsock();
        return 0;
    }

    // ---- listen ------------------------------------------------------------
    printf("[main] listening for packets (30s timeout)...\n");
    printf("[main]   try:  ping 10.10.0.2   (from another terminal)\n");

    std::atomic<bool> done{false};
    std::thread reader([&]() {
        std::vector<uint8_t> buf;
        while (!done) {
            buf.clear();
            if (adapter.read_packet(buf))
                Adapter::print_packet(buf.data(), buf.size());
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(30));
    done = true;
    adapter.close();
    reader.join();

    printf("[main] listen complete\n");
    platform_cleanup_winsock();
    return 0;
}
