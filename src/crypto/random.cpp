#include "aegis/crypto/random.hpp"
#include <array>
#include <limits>
#include <openssl/rand.h>

bool secure_random_bytes(std::span<uint8_t> output) {
    if (output.empty())
        return true;
    if (output.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

std::optional<uint32_t> secure_random_u32() {
    std::array<uint8_t, sizeof(uint32_t)> bytes{};
    if (!secure_random_bytes(bytes))
        return std::nullopt;
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}

std::optional<uint64_t> secure_random_u64() {
    std::array<uint8_t, sizeof(uint64_t)> bytes{};
    if (!secure_random_bytes(bytes))
        return std::nullopt;

    uint64_t value = 0;
    for (const auto byte : bytes)
        value = (value << 8) | static_cast<uint64_t>(byte);
    return value;
}
