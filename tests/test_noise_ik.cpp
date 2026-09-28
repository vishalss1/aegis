#include "aegis/session/noise_ik.hpp"
#include "aegis/session/handshake_v2.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <string_view>
#include <vector>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    const bool ok = !!(cond); \
    passed += ok; \
    std::printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

namespace {

uint8_t hex_digit(char value) {
    if (value >= '0' && value <= '9')
        return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f')
        return static_cast<uint8_t>(value - 'a' + 10);
    return 0xFF;
}

std::vector<uint8_t> from_hex(std::string_view text) {
    std::vector<uint8_t> bytes;
    if ((text.size() % 2) != 0)
        return bytes;
    bytes.reserve(text.size() / 2);
    for (size_t index = 0; index < text.size(); index += 2) {
        const uint8_t high = hex_digit(text[index]);
        const uint8_t low = hex_digit(text[index + 1]);
        if (high == 0xFF || low == 0xFF)
            return {};
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

bool bytes_equal(std::span<const uint8_t> left,
                 std::span<const uint8_t> right) {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

template <typename Container>
bool assign_hex(Container& output, std::string_view text) {
    const auto bytes = from_hex(text);
    if (bytes.size() != output.size())
        return false;
    std::copy(bytes.begin(), bytes.end(), output.begin());
    return true;
}

class FixedRandom final : public RandomSource {
public:
    explicit FixedRandom(std::span<const uint8_t> bytes)
        : bytes_(bytes.begin(), bytes.end()) {}

    bool fill(std::span<uint8_t> output) override {
        if (used_ || output.size() != bytes_.size())
            return false;
        std::copy(bytes_.begin(), bytes_.end(), output.begin());
        used_ = true;
        return true;
    }

private:
    std::vector<uint8_t> bytes_;
    bool used_ = false;
};

class FailingRandom final : public RandomSource {
public:
    bool fill(std::span<uint8_t>) override { return false; }
};

} // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("--- Noise IK wrapper tests ---\n");

    // Independent Cacophony vector published by the pinned Noise-C revision:
    // tests/vector/cacophony.txt, Noise_IK_25519_ChaChaPoly_BLAKE2s.
    X25519PrivateKey initiator_static;
    X25519PrivateKey responder_static;
    X25519Key responder_public{};
    const auto initiator_ephemeral = from_hex(
        "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
    const auto responder_ephemeral = from_hex(
        "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
    const auto prologue = from_hex("4a6f686e2047616c74");
    const auto first_payload = from_hex("4c756477696720766f6e204d69736573");
    const auto second_payload = from_hex("4d757272617920526f746862617264");
    const auto expected_first = from_hex(
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440"
        "b03ddc7aac5123d06a1b23b71670e32e76c28239a7ca4ac8f784de7e44c1adbf"
        "c6e83fef7352a58d9d56157400c0a737b1d171ce368229c7b752ac25b8faf4ec"
        "a690f6d896f543be02c996ab2b86b76");
    const auto expected_second = from_hex(
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
        "d9b5a8927f0ac9655ef76833bc7e5561f42e691ac8404efd6fbd6308b6a27c");

    CHECK(assign_hex(initiator_static,
        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
    CHECK(assign_hex(responder_static,
        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
    CHECK(assign_hex(responder_public,
        "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"));

    FixedRandom initiator_random(initiator_ephemeral);
    FixedRandom responder_random(responder_ephemeral);
    auto initiator = NoiseIkHandshake::create_initiator(
        initiator_static, responder_public, prologue, initiator_random);
    auto responder = NoiseIkHandshake::create_responder(
        responder_static, prologue, responder_random);
    CHECK(initiator != nullptr);
    CHECK(responder != nullptr);
    if (!initiator || !responder)
        return 1;

    std::array<uint8_t, 256> first_message{};
    const auto first_write = initiator->write_message(
        first_payload, first_message);
    CHECK(first_write);
    CHECK(bytes_equal(
        std::span<const uint8_t>(first_message.data(), first_write.bytes),
        expected_first));

    std::array<uint8_t, 64> received_first_payload{};
    const auto first_read = responder->read_message(
        std::span<const uint8_t>(first_message.data(), first_write.bytes),
        received_first_payload);
    CHECK(first_read);
    CHECK(bytes_equal(
        std::span<const uint8_t>(received_first_payload.data(),
                                 first_read.bytes),
        first_payload));
    CHECK(responder->remote_static_public_key().has_value());

    std::array<uint8_t, 128> second_message{};
    const auto second_write = responder->write_message(
        second_payload, second_message);
    CHECK(second_write);
    CHECK(bytes_equal(
        std::span<const uint8_t>(second_message.data(), second_write.bytes),
        expected_second));

    std::array<uint8_t, 64> received_second_payload{};
    const auto second_read = initiator->read_message(
        std::span<const uint8_t>(second_message.data(), second_write.bytes),
        received_second_payload);
    CHECK(second_read);
    CHECK(bytes_equal(
        std::span<const uint8_t>(received_second_payload.data(),
                                 second_read.bytes),
        second_payload));
    CHECK(initiator->handshake_hash().has_value());
    CHECK(responder->handshake_hash().has_value());
    CHECK(initiator->handshake_hash() == responder->handshake_hash());

    FixedRandom empty_initiator_random(initiator_ephemeral);
    FixedRandom empty_responder_random(responder_ephemeral);
    auto empty_initiator = NoiseIkHandshake::create_initiator(
        initiator_static, responder_public, prologue,
        empty_initiator_random);
    auto empty_responder = NoiseIkHandshake::create_responder(
        responder_static, prologue, empty_responder_random);
    CHECK(empty_initiator != nullptr);
    CHECK(empty_responder != nullptr);
    if (!empty_initiator || !empty_responder)
        return 1;

    HandshakeV2InitNoise empty_first{};
    const auto empty_first_write = empty_initiator->write_message(
        {}, empty_first);
    CHECK(empty_first_write);
    CHECK(empty_first_write.bytes == HANDSHAKE_V2_INIT_NOISE_SIZE);
    CHECK(empty_responder->read_message(empty_first, {}));

    HandshakeV2ResponseNoise empty_second{};
    const auto empty_second_write = empty_responder->write_message(
        {}, empty_second);
    CHECK(empty_second_write);
    CHECK(empty_second_write.bytes == HANDSHAKE_V2_RESPONSE_NOISE_SIZE);
    CHECK(empty_initiator->read_message(empty_second, {}));

    FailingRandom failing_random;
    CHECK(NoiseIkHandshake::create_initiator(
        initiator_static, responder_public, prologue, failing_random) ==
        nullptr);

    std::printf("--- Noise IK wrapper: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
