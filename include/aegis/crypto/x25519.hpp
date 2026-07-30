#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

static constexpr size_t X25519_KEY_SIZE = 32;

using X25519Key = std::array<uint8_t, X25519_KEY_SIZE>;

struct X25519KeyPair {
    X25519Key private_key;
    X25519Key public_key;
};

X25519KeyPair x25519_generate_keypair();

std::optional<X25519Key> x25519_derive_shared_secret(
    const X25519Key& my_private,
    const X25519Key& their_public
);
