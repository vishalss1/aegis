#include "aegis/crypto/random.hpp"
#include <array>
#include <cstdio>

static int tests = 0;
static int passed = 0;

class FixedRandomSource final : public RandomSource {
public:
    bool fill(std::span<uint8_t> output) override {
        for (size_t i = 0; i < output.size(); ++i)
            output[i] = static_cast<uint8_t>(i + 1);
        return true;
    }
};

class FailingRandomSource final : public RandomSource {
public:
    bool fill(std::span<uint8_t>) override { return false; }
};

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

    {
        const auto value = secure_random_u64();
        CHECK(value.has_value());
    }

    {
        FixedRandomSource source;
        CHECK(source.u32() == 0x01020304u);
        CHECK(source.u64() == 0x0102030405060708ull);
    }

    {
        FailingRandomSource source;
        CHECK(!source.u32().has_value());
        CHECK(!source.u64().has_value());
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
