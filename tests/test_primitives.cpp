#include "aegis/crypto/primitives.hpp"

#include <array>
#include <cstdio>
#include <string_view>
#include <vector>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    std::printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while (0)

static uint8_t hex_nibble(char value) {
    if (value >= '0' && value <= '9')
        return static_cast<uint8_t>(value - '0');
    return static_cast<uint8_t>(value - 'a' + 10);
}

static std::vector<uint8_t> from_hex(std::string_view hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(
            (hex_nibble(hex[i]) << 4) | hex_nibble(hex[i + 1])));
    }
    return bytes;
}

int main() {
    std::printf("--- cryptographic primitive tests ---\n");

    {
        const std::array<uint8_t, 1> first{'a'};
        const std::array<uint8_t, 2> second{'b', 'c'};
        const auto expected = from_hex(
            "508c5e8c327c14e2e1a72ba34eeb452f"
            "37458b209ed63a294d999b4c86675982");
        const auto actual = transcript_hash(
            CryptoHashAlgorithm::Blake2s256, {first, second});
        CHECK(actual.has_value());
        CHECK(actual && constant_time_equal(*actual, expected));
    }

    {
        // RFC 5869, SHA-256 test case 1.
        const std::vector<uint8_t> ikm(22, 0x0b);
        const auto salt = from_hex("000102030405060708090a0b0c");
        const auto info = from_hex("f0f1f2f3f4f5f6f7f8f9");
        const auto expected = from_hex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865");
        std::array<uint8_t, 42> actual{};
        CHECK(hkdf(CryptoHashAlgorithm::Sha256, ikm, salt, info, actual));
        CHECK(constant_time_equal(actual, expected));
    }

    {
        // Independent HMAC-BLAKE2s HKDF vector for the Noise v2 digest.
        std::array<uint8_t, 32> ikm{};
        std::array<uint8_t, 16> salt{};
        for (size_t i = 0; i < ikm.size(); ++i)
            ikm[i] = static_cast<uint8_t>(i);
        for (size_t i = 0; i < salt.size(); ++i)
            salt[i] = static_cast<uint8_t>(i);
        const std::array<uint8_t, 14> info{
            'a','e','g','i','s','-','n','o','i','s','e','-','v','2'};
        const auto expected = from_hex(
            "dcc5d4c200617df61f8cb9bafbe128cc"
            "9c82299b0068f81738908e98d3985c16"
            "18c10cfaad999f2fad117a63dff8c1fe"
            "6e700e65962dbc35571efa7f97282c4f");
        std::array<uint8_t, 64> actual{};
        CHECK(hkdf(
            CryptoHashAlgorithm::Blake2s256, ikm, salt, info, actual));
        CHECK(constant_time_equal(actual, expected));
    }

    {
        const std::array<uint8_t, 3> same_a{1, 2, 3};
        const std::array<uint8_t, 3> same_b{1, 2, 3};
        const std::array<uint8_t, 3> different{1, 2, 4};
        const std::array<uint8_t, 2> shorter{1, 2};
        const std::span<const uint8_t> empty{};
        CHECK(constant_time_equal(same_a, same_b));
        CHECK(!constant_time_equal(same_a, different));
        CHECK(!constant_time_equal(same_a, shorter));
        CHECK(constant_time_equal(empty, empty));
    }

    {
        const std::array<uint8_t, 1> ikm{0x01};
        std::vector<uint8_t> oversized(255u * 32u + 1u, 0x5a);
        CHECK(!hkdf(
            CryptoHashAlgorithm::Blake2s256, ikm, {}, {}, oversized));
        CHECK(oversized.front() == 0x5a && oversized.back() == 0x5a);
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
