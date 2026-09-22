#pragma once

#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>

enum class CryptoHashAlgorithm {
    Sha256,
    Blake2s256,
};

using CryptoHash = std::array<uint8_t, 32>;

// Hash ordered transcript fragments without requiring callers to concatenate
// them first. An empty list hashes the empty string.
[[nodiscard]] std::optional<CryptoHash> transcript_hash(
    CryptoHashAlgorithm algorithm,
    std::initializer_list<std::span<const uint8_t>> fragments);

// RFC 5869 HKDF using the selected 256-bit digest. Output is left unchanged
// if OpenSSL rejects an input or any operation fails.
[[nodiscard]] bool hkdf(
    CryptoHashAlgorithm algorithm,
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    std::span<uint8_t> output);

// Compare equal-length byte strings without data-dependent early exit.
[[nodiscard]] bool constant_time_equal(
    std::span<const uint8_t> left,
    std::span<const uint8_t> right);
