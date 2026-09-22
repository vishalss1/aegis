#pragma once

#include <cstdint>
#include <optional>
#include <span>

class RandomSource {
public:
    virtual ~RandomSource() = default;
    [[nodiscard]] virtual bool fill(std::span<uint8_t> output) = 0;
    [[nodiscard]] std::optional<uint32_t> u32();
    [[nodiscard]] std::optional<uint64_t> u64();
};

RandomSource& system_random_source();

// Fill a caller-owned buffer from OpenSSL's operating-system-seeded CSPRNG.
// Returns false without producing a usable result when the request is too
// large for RAND_bytes or OpenSSL reports a failure.
[[nodiscard]] bool secure_random_bytes(std::span<uint8_t> output);

// Generate a uniformly random 32-bit value. Zero is a valid result; protocol
// callers that reserve zero must reject it explicitly.
[[nodiscard]] std::optional<uint32_t> secure_random_u32();

// Generate a uniformly random 64-bit value. Zero is a valid result; protocol
// callers that reserve zero must reject it explicitly.
[[nodiscard]] std::optional<uint64_t> secure_random_u64();
