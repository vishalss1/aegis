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

    printf("--- crypto tests ---\n");

    // ---- 1. Keypair generation produces non-zero 32-byte keys ----------------
    {
        X25519KeyPair kp = x25519_generate_keypair();

        bool priv_nonzero = false;
        for (auto b : kp.private_key)
            if (b != 0) { priv_nonzero = true; break; }
        CHECK(priv_nonzero);

        bool pub_nonzero = false;
        for (auto b : kp.public_key)
            if (b != 0) { pub_nonzero = true; break; }
        CHECK(pub_nonzero);

        // Keys are 32 bytes
        CHECK(kp.private_key.size() == X25519_KEY_SIZE);
        CHECK(kp.public_key.size() == X25519_KEY_SIZE);
    }

    // ---- 2. Two independent keypairs derive the same shared secret ----------
    {
        X25519KeyPair alice = x25519_generate_keypair();
        X25519KeyPair bob   = x25519_generate_keypair();

        auto s1 = x25519_derive_shared_secret(alice.private_key, bob.public_key);
        auto s2 = x25519_derive_shared_secret(bob.private_key, alice.public_key);

        CHECK(s1.has_value());
        CHECK(s2.has_value());

        if (s1.has_value() && s2.has_value()) {
            bool match = true;
            for (size_t i = 0; i < X25519_KEY_SIZE; i++)
                if ((*s1)[i] != (*s2)[i]) { match = false; break; }
            CHECK(match);
        }
    }

    // ---- 3. Wrong public key produces a different secret --------------------
    {
        X25519KeyPair alice  = x25519_generate_keypair();
        X25519KeyPair bob    = x25519_generate_keypair();
        X25519KeyPair mallory = x25519_generate_keypair();

        // Alice derives with Bob's key
        auto s_ab = x25519_derive_shared_secret(alice.private_key, bob.public_key);
        // Alice derives with Mallory's key (wrong peer)
        auto s_am = x25519_derive_shared_secret(alice.private_key, mallory.public_key);

        CHECK(s_ab.has_value());
        CHECK(s_am.has_value());

        if (s_ab.has_value() && s_am.has_value()) {
            bool different = false;
            for (size_t i = 0; i < X25519_KEY_SIZE; i++)
                if ((*s_ab)[i] != (*s_am)[i]) { different = true; break; }
            CHECK(different);
        }
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
