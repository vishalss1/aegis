#include "aegis/crypto/secret.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <memory>
#include <new>
#include <utility>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    std::printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    std::printf("--- cleansing secret storage tests ---\n");
    static_assert(sizeof(SecretBytes<32>) == 32);

    {
        SecretBytes<32> source;
        source.fill(0xa5);
        SecretBytes<32> destination(std::move(source));
        CHECK(std::all_of(
            source.begin(), source.end(), [](uint8_t byte) { return byte == 0; }));
        CHECK(std::all_of(
            destination.begin(), destination.end(),
            [](uint8_t byte) { return byte == 0xa5; }));
    }

    {
        alignas(SecretBytes<32>)
            std::array<unsigned char, sizeof(SecretBytes<32>)> storage{};
        auto* secret = std::construct_at(
            reinterpret_cast<SecretBytes<32>*>(storage.data()));
        secret->fill(0x7b);
        CHECK(std::any_of(
            storage.begin(), storage.end(),
            [](unsigned char byte) { return byte != 0; }));
        std::destroy_at(secret);
        CHECK(std::all_of(
            storage.begin(), storage.end(),
            [](unsigned char byte) { return byte == 0; }));
    }

    {
        SecretBytes<32> first;
        SecretBytes<32> same;
        SecretBytes<32> different;
        first.fill(0x11);
        same.fill(0x11);
        different.fill(0x12);
        CHECK(first == same);
        CHECK(!(first == different));
        first.clear();
        CHECK(std::all_of(
            first.begin(), first.end(), [](uint8_t byte) { return byte == 0; }));
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
