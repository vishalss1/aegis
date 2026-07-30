#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

static constexpr size_t CHACHA20_POLY1305_KEY_SIZE   = 32;
static constexpr size_t CHACHA20_POLY1305_NONCE_SIZE  = 12;
static constexpr size_t CHACHA20_POLY1305_TAG_SIZE    = 16;

using ChaCha20Poly1305Key   = std::array<uint8_t, CHACHA20_POLY1305_KEY_SIZE>;
using ChaCha20Poly1305Nonce = std::array<uint8_t, CHACHA20_POLY1305_NONCE_SIZE>;

bool chacha20_poly1305_encrypt(
    const ChaCha20Poly1305Key& key,
    const ChaCha20Poly1305Nonce& nonce,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out,
    const uint8_t* aad = nullptr,
    size_t aad_len = 0
);

bool chacha20_poly1305_decrypt(
    const ChaCha20Poly1305Key& key,
    const ChaCha20Poly1305Nonce& nonce,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext_out,
    const uint8_t* aad = nullptr,
    size_t aad_len = 0
);
