#include "aegis/crypto/random.hpp"
#include <array>
#include <cstdio>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    std::printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    std::printf("--- secure random tests ---\n");

    {
        std::array<uint8_t, 64> bytes{};
        CHECK(secure_random_bytes(bytes));
    }

    {
        std::array<uint8_t, 0> empty{};
        CHECK(secure_random_bytes(empty));
    }

    {
        const auto value = secure_random_u32();
        CHECK(value.has_value());
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
