#include "aegis/identity/identity.hpp"
#include "aegis/crypto/x25519.hpp"
#include <cstdio>
#include <cstring>

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
    printf("--- identity tests ---\n");

    // ---- 1. Identity::create produces non-zero keypair and node_id ----------
    {
        NetworkId net{};
        net[0] = 0xAA;
        Identity id = Identity::create(net);

        bool priv_nonzero = false;
        for (auto b : id.keypair.private_key)
            if (b != 0) { priv_nonzero = true; break; }
        CHECK(priv_nonzero);

        bool pub_nonzero = false;
        for (auto b : id.keypair.public_key)
            if (b != 0) { pub_nonzero = true; break; }
        CHECK(pub_nonzero);

        bool signing_pub_nonzero = false;
        for (auto b : id.signing_keypair.public_key)
            if (b != 0) { signing_pub_nonzero = true; break; }
        CHECK(signing_pub_nonzero);
        CHECK(id.signing_keypair.public_key != id.keypair.public_key);
        CHECK(verify_key_agreement_binding(id));

        bool nid_nonzero = false;
        for (auto b : id.node_id)
            if (b != 0) { nid_nonzero = true; break; }
        CHECK(nid_nonzero);

        CHECK(id.network_id == net);
    }

    // ---- 1b. Binding signature commits to the Noise key -------------------
    {
        NetworkId net{};
        Identity id = Identity::create(net);
        Identity tampered_key = id;
        tampered_key.keypair.public_key[0] ^= 0x01;
        CHECK(!verify_key_agreement_binding(tampered_key));

        Identity tampered_signer = id;
        tampered_signer.signing_keypair.public_key[0] ^= 0x01;
        CHECK(!verify_key_agreement_binding(tampered_signer));

        Identity tampered_signature = id;
        tampered_signature.key_agreement_binding[0] ^= 0x01;
        CHECK(!verify_key_agreement_binding(tampered_signature));

        const NodeId legacy_node_id = id.node_id;
        CHECK(legacy_node_id == hash_public_key(id.keypair.public_key));
    }

    // ---- 1c. Rotation certificate links two bound identities --------------
    {
        NetworkId net{};
        Identity previous = Identity::create(net);
        Identity next = Identity::create(net);
        const auto certificate = create_identity_rotation_certificate(
            previous, next, 1'850'000'000);
        CHECK(certificate.has_value());
        CHECK(certificate && verify_identity_rotation_certificate(
            *certificate, previous.signing_keypair.public_key));
        CHECK(certificate && !verify_identity_rotation_certificate(
            *certificate, next.signing_keypair.public_key));
        if (certificate) {
            auto tampered = *certificate;
            tampered.next_key_agreement_public_key[0] ^= 1;
            CHECK(!verify_identity_rotation_certificate(
                tampered, previous.signing_keypair.public_key));
            tampered = *certificate;
            tampered.issued_at++;
            CHECK(!verify_identity_rotation_certificate(
                tampered, previous.signing_keypair.public_key));
        }
        Identity invalid_next = next;
        invalid_next.key_agreement_binding[0] ^= 1;
        CHECK(!create_identity_rotation_certificate(
            previous, invalid_next, 1'850'000'000).has_value());
    }

    // ---- 2. NodeID is deterministic for a given public key ------------------
    {
        X25519KeyPair kp = x25519_generate_keypair();

        NodeId h1 = hash_public_key(kp.public_key);
        NodeId h2 = hash_public_key(kp.public_key);

        CHECK(h1 == h2);
    }

    // ---- 3. Different public keys produce different NodeIDs -----------------
    {
        X25519KeyPair kp1 = x25519_generate_keypair();
        X25519KeyPair kp2 = x25519_generate_keypair();

        NodeId h1 = hash_public_key(kp1.public_key);
        NodeId h2 = hash_public_key(kp2.public_key);

        CHECK(h1 != h2);
    }

    // ---- 4. Identity matches_network true for same NetworkID ----------------
    {
        NetworkId net{};
        net[0] = 0xBB;

        Identity a = Identity::create(net);
        Identity b = Identity::create(net);

        CHECK(a.matches_network(b.network_id));
        CHECK(b.matches_network(a.network_id));
    }

    // ---- 5. Identity matches_network false for different NetworkID ----------
    {
        NetworkId net_a{};
        net_a[0] = 0xCC;
        NetworkId net_b{};
        net_b[0] = 0xDD;

        Identity a = Identity::create(net_a);
        Identity b = Identity::create(net_b);

        CHECK(!a.matches_network(b.network_id));
        CHECK(!b.matches_network(a.network_id));
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
