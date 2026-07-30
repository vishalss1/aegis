#include "aegis/crypto/chacha20poly1305.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

// RFC 8439 Section 2.8.2 AEAD_CHACHA20_POLY1305 test vector
static const uint8_t RFC8439_KEY[] = {
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
};
static const uint8_t RFC8439_NONCE[] = {
    0x07,0x00,0x00,0x00,
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
};
static const uint8_t RFC8439_AAD[] = {
    0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
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
static const uint8_t RFC8439_CT[] = {
    0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
    0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
    0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
    0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
    0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
    0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
    0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
    0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
    0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
    0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
    0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
    0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
    0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
    0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
    0x61,0x16,
};
static const uint8_t RFC8439_TAG[] = {
    0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
    0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
};

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- aead tests ---\n");

    // ---- 0. RFC 8439 test vector (ground truth) ----------------------------
    {
        ChaCha20Poly1305Key rfc_key;
        std::memcpy(rfc_key.data(), RFC8439_KEY, CHACHA20_POLY1305_KEY_SIZE);
        ChaCha20Poly1305Nonce rfc_nonce;
        std::memcpy(rfc_nonce.data(), RFC8439_NONCE, CHACHA20_POLY1305_NONCE_SIZE);

        uint8_t ct[sizeof(RFC8439_CT)];
        uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
        bool enc_ok = chacha20_poly1305_encrypt(
            rfc_key, rfc_nonce,
            RFC8439_PT, sizeof(RFC8439_PT),
            ct, tag, RFC8439_AAD, sizeof(RFC8439_AAD));
        CHECK(enc_ok);

        bool ct_match = std::memcmp(ct, RFC8439_CT, sizeof(RFC8439_CT)) == 0;
        CHECK(ct_match);

        bool tag_match = std::memcmp(tag, RFC8439_TAG, CHACHA20_POLY1305_TAG_SIZE) == 0;
        CHECK(tag_match);

        uint8_t pt[sizeof(RFC8439_PT)];
        bool dec_ok = chacha20_poly1305_decrypt(
            rfc_key, rfc_nonce,
            ct, sizeof(RFC8439_CT), tag, pt,
            RFC8439_AAD, sizeof(RFC8439_AAD));
        CHECK(dec_ok);

        bool pt_match = std::memcmp(pt, RFC8439_PT, sizeof(RFC8439_PT)) == 0;
        CHECK(pt_match);
    }

    // Fixed key and nonce for reproducible tests
    ChaCha20Poly1305Key key{};
    ChaCha20Poly1305Nonce nonce{};
    for (uint8_t i = 0; i < CHACHA20_POLY1305_KEY_SIZE; i++) key[i] = i;
    for (uint8_t i = 0; i < CHACHA20_POLY1305_NONCE_SIZE; i++) nonce[i] = 0x80 | i;

    const char* PLAINTEXT = "hello-aead-0123456789";
    size_t pt_len = std::strlen(PLAINTEXT);

    // ---- 1. Round-trip encrypt/decrypt correctness -------------------------
    {
        uint8_t ct[64];
        uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
        bool enc_ok = chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct, tag);
        CHECK(enc_ok);

        uint8_t pt2[64];
        bool dec_ok = chacha20_poly1305_decrypt(key, nonce, ct, pt_len, tag, pt2);
        CHECK(dec_ok);

        bool match = (std::memcmp(pt2, PLAINTEXT, pt_len) == 0);
        CHECK(match);
    }

    // ---- 2. Tag tamper rejection -------------------------------------------
    {
        uint8_t ct[64];
        uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct, tag);

        tag[5] ^= 0x01;

        uint8_t pt2[64];
        bool dec_ok = chacha20_poly1305_decrypt(key, nonce, ct, pt_len, tag, pt2);
        CHECK(!dec_ok);
    }

    // ---- 3. Ciphertext tamper rejection ------------------------------------
    {
        uint8_t ct[64];
        uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct, tag);

        ct[3] ^= 0x01;

        uint8_t pt2[64];
        bool dec_ok = chacha20_poly1305_decrypt(key, nonce, ct, pt_len, tag, pt2);
        CHECK(!dec_ok);
    }

    // ---- 4. Wrong-key rejection --------------------------------------------
    {
        uint8_t ct[64];
        uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct, tag);

        ChaCha20Poly1305Key wrong_key{};
        wrong_key[0] = 0x42;

        uint8_t pt2[64];
        bool dec_ok = chacha20_poly1305_decrypt(wrong_key, nonce, ct, pt_len, tag, pt2);
        CHECK(!dec_ok);
    }

    // ---- 5. Wrong-nonce rejection ------------------------------------------
    {
        uint8_t ct[64];
        uint8_t tag[CHACHA20_POLY1305_TAG_SIZE];
        chacha20_poly1305_encrypt(key, nonce,
            (const uint8_t*)PLAINTEXT, pt_len, ct, tag);

        ChaCha20Poly1305Nonce wrong_nonce{};
        wrong_nonce[0] = 0x42;

        uint8_t pt2[64];
        bool dec_ok = chacha20_poly1305_decrypt(key, wrong_nonce, ct, pt_len, tag, pt2);
        CHECK(!dec_ok);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
