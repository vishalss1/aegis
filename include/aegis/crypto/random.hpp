#pragma once

#include <cstdint>
#include <optional>
#include <span>

// Fill a caller-owned buffer from OpenSSL's operating-system-seeded CSPRNG.
// Returns false without producing a usable result when the request is too
// large for RAND_bytes or OpenSSL reports a failure.
[[nodiscard]] bool secure_random_bytes(std::span<uint8_t> output);

// Generate a uniformly random 32-bit value. Zero is a valid result; protocol
// callers that reserve zero must reject it explicitly.
[[nodiscard]] std::optional<uint32_t> secure_random_u32();
