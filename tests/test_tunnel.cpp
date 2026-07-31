#include "aegis/crypto/chacha20poly1305.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static constexpr size_t WIRE_NONCE_SIZE = 12;
static constexpr size_t WIRE_TAG_SIZE   = 16;

static void increment_nonce(std::array<uint8_t, WIRE_NONCE_SIZE>& nonce) {
    for (int i = WIRE_NONCE_SIZE - 1; i >= 0; i--) {
        if (++nonce[i] != 0) break;
    }
}

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
    printf("--- tunnel tests ---\n");

    // ---- 1. Nonce counter starts at 0 and increments correctly --------------
    {
        std::array<uint8_t, WIRE_NONCE_SIZE> nonce{};

        // Start at all zeros
        bool all_zero = true;
        for (auto b : nonce) if (b != 0) { all_zero = false; break; }
        CHECK(all_zero);

        // Increment once → last byte becomes 1
        increment_nonce(nonce);
        CHECK(nonce[WIRE_NONCE_SIZE - 1] == 1);
        CHECK(nonce[WIRE_NONCE_SIZE - 2] == 0);
    }

    // ---- 2. Nonce counter wraps byte correctly (carry propagation) ----------
    {
        std::array<uint8_t, WIRE_NONCE_SIZE> nonce{};
        nonce[WIRE_NONCE_SIZE - 1] = 0xFF;

        increment_nonce(nonce);
        CHECK(nonce[WIRE_NONCE_SIZE - 1] == 0);
        CHECK(nonce[WIRE_NONCE_SIZE - 2] == 1);
    }

    // ---- 3. Nonce counter carries across multiple bytes ----------------------
    {
        std::array<uint8_t, WIRE_NONCE_SIZE> nonce{};
        nonce[WIRE_NONCE_SIZE - 2] = 0xFF;
        nonce[WIRE_NONCE_SIZE - 1] = 0xFF;

        increment_nonce(nonce);
        CHECK(nonce[WIRE_NONCE_SIZE - 1] == 0);
        CHECK(nonce[WIRE_NONCE_SIZE - 2] == 0);
        CHECK(nonce[WIRE_NONCE_SIZE - 3] == 1);
    }

    // ---- 4. Wire format round-trip: build and parse an encrypted packet -----
    {
        ChaCha20Poly1305Key key{};
        key[0] = 0x01;

        std::array<uint8_t, WIRE_NONCE_SIZE> nonce{};
        nonce[0] = 0xAA;

        const uint8_t plaintext[] = {0x45, 0x00, 0x00, 0x14, 0x08, 0x00};
        size_t pt_len = sizeof(plaintext);

        uint8_t ct_buf[64];
        uint8_t tag_buf[WIRE_TAG_SIZE];

        ChaCha20Poly1305Nonce chacha_nonce{};
        std::memcpy(chacha_nonce.data(), nonce.data(), WIRE_NONCE_SIZE);

        bool enc_ok = chacha20_poly1305_encrypt(key, chacha_nonce,
            plaintext, pt_len, ct_buf, tag_buf);
        CHECK(enc_ok);

        // Build wire packet: [nonce][ciphertext][tag]
        std::vector<uint8_t> wire;
        wire.insert(wire.end(), nonce.begin(), nonce.end());
        wire.insert(wire.end(), ct_buf, ct_buf + pt_len);
        wire.insert(wire.end(), tag_buf, tag_buf + WIRE_TAG_SIZE);

        // Parse wire packet
        CHECK(wire.size() == WIRE_NONCE_SIZE + pt_len + WIRE_TAG_SIZE);

        // Extract nonce
        ChaCha20Poly1305Nonce parsed_nonce{};
        std::memcpy(parsed_nonce.data(), wire.data(), WIRE_NONCE_SIZE);
        CHECK(std::memcmp(parsed_nonce.data(), nonce.data(), WIRE_NONCE_SIZE) == 0);

        // Extract ciphertext and tag
        const uint8_t* parsed_ct = wire.data() + WIRE_NONCE_SIZE;
        const uint8_t* parsed_tag = wire.data() + WIRE_NONCE_SIZE + pt_len;

        // Decrypt
        uint8_t pt2[64];
        bool dec_ok = chacha20_poly1305_decrypt(key, parsed_nonce,
            parsed_ct, pt_len, parsed_tag, pt2);
        CHECK(dec_ok);

        bool pt_match = (std::memcmp(pt2, plaintext, pt_len) == 0);
        CHECK(pt_match);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
