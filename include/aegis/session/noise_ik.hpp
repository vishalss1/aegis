#pragma once

#include "aegis/crypto/random.hpp"
#include "aegis/crypto/x25519.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

static constexpr size_t NOISE_IK_HASH_SIZE = 32;

enum class NoiseIkError {
    none,
    invalid_argument,
    invalid_state,
    buffer_too_small,
    authentication_failed,
    dependency_failure,
};

struct NoiseIkOperationResult {
    NoiseIkError error = NoiseIkError::dependency_failure;
    size_t bytes = 0;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == NoiseIkError::none;
    }
};

// A narrow ownership and policy boundary around the pinned Noise-C library.
// Only Noise_IK_25519_ChaChaPoly_BLAKE2s can be instantiated. Each factory
// obtains a fresh ephemeral private key from the caller-provided RandomSource
// before the handshake starts.
class NoiseIkHandshake {
public:
    static std::unique_ptr<NoiseIkHandshake> create_initiator(
        const X25519PrivateKey& local_static_private,
        const X25519Key& expected_responder_static,
        std::span<const uint8_t> prologue,
        RandomSource& random);

    static std::unique_ptr<NoiseIkHandshake> create_responder(
        const X25519PrivateKey& local_static_private,
        std::span<const uint8_t> prologue,
        RandomSource& random);

    NoiseIkHandshake(const NoiseIkHandshake&) = delete;
    NoiseIkHandshake& operator=(const NoiseIkHandshake&) = delete;
    NoiseIkHandshake(NoiseIkHandshake&&) noexcept;
    NoiseIkHandshake& operator=(NoiseIkHandshake&&) noexcept;
    ~NoiseIkHandshake();

    [[nodiscard]] NoiseIkOperationResult write_message(
        std::span<const uint8_t> payload,
        std::span<uint8_t> output);

    [[nodiscard]] NoiseIkOperationResult read_message(
        std::span<const uint8_t> message,
        std::span<uint8_t> payload_output);

    [[nodiscard]] std::optional<X25519Key> remote_static_public_key() const;
    [[nodiscard]] std::optional<std::array<uint8_t, NOISE_IK_HASH_SIZE>>
    handshake_hash() const;

private:
    struct Impl;
    explicit NoiseIkHandshake(std::unique_ptr<Impl> impl);

    static std::unique_ptr<NoiseIkHandshake> create(
        int role,
        const X25519PrivateKey& local_static_private,
        const X25519Key* expected_responder_static,
        std::span<const uint8_t> prologue,
        RandomSource& random);

    std::unique_ptr<Impl> impl_;
};
