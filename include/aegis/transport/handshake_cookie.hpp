#pragma once

#include "aegis/crypto/random.hpp"
#include "aegis/crypto/secret.hpp"
#include "aegis/protocol/sources.hpp"
#include "aegis/transport/transport.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>

inline constexpr size_t HANDSHAKE_COOKIE_SIZE = 32;
using HandshakeCookie = std::array<uint8_t, HANDSHAKE_COOKIE_SIZE>;

struct HandshakeCookieConfig {
    std::chrono::milliseconds rotation_interval{std::chrono::minutes(2)};
};

// Issues stateless retry tokens that prove a sender can receive packets at the
// claimed UDP endpoint before the responder performs Noise DH or stores peer
// state. The current and immediately previous rotating secrets are accepted.
class HandshakeCookieManager {
public:
    HandshakeCookieManager(
        ProtocolClock& clock,
        RandomSource& random,
        HandshakeCookieConfig config = {});

    [[nodiscard]] std::optional<HandshakeCookie> issue(
        const Endpoint& source,
        uint32_t session_id,
        std::span<const uint8_t> init_frame);

    [[nodiscard]] bool verify(
        const HandshakeCookie& cookie,
        const Endpoint& source,
        uint32_t session_id,
        std::span<const uint8_t> init_frame);

private:
    using CookieSecret = SecretBytes<HANDSHAKE_COOKIE_SIZE>;

    [[nodiscard]] bool rotate_if_needed(ProtocolClock::time_point now);
    [[nodiscard]] std::optional<HandshakeCookie> derive(
        const CookieSecret& secret,
        const Endpoint& source,
        uint32_t session_id,
        std::span<const uint8_t> init_frame) const;

    ProtocolClock& clock_;
    RandomSource& random_;
    HandshakeCookieConfig config_;
    CookieSecret current_secret_;
    CookieSecret previous_secret_;
    ProtocolClock::time_point rotated_at_{};
    bool has_current_ = false;
    bool has_previous_ = false;
    std::mutex mutex_;
};
