#include "aegis/transport/handshake_cookie.hpp"

#include "aegis/crypto/primitives.hpp"
#include "aegis/protocol/wire.hpp"

#include <algorithm>

namespace {

constexpr std::array<uint8_t, 21> COOKIE_DOMAIN{
    'a','e','g','i','s','-','r','e','t','r','y','-','c','o','o','k','i','e','-','v','1'};

} // namespace

HandshakeCookieManager::HandshakeCookieManager(
    ProtocolClock& clock,
    RandomSource& random,
    HandshakeCookieConfig config)
    : clock_(clock), random_(random), config_(config) {
    if (config_.rotation_interval <= std::chrono::milliseconds::zero())
        config_.rotation_interval = std::chrono::milliseconds(1);
}

bool HandshakeCookieManager::rotate_if_needed(
    ProtocolClock::time_point now) {
    if (has_current_ && now >= rotated_at_ &&
        now - rotated_at_ < config_.rotation_interval)
        return true;

    CookieSecret replacement;
    if (!random_.fill(
            std::span<uint8_t>(replacement.data(), replacement.size())))
        return false;

    if (has_current_ && now >= rotated_at_ &&
        now - rotated_at_ < 2 * config_.rotation_interval) {
        previous_secret_ = std::move(current_secret_);
        has_previous_ = true;
    } else {
        previous_secret_.clear();
        has_previous_ = false;
    }

    current_secret_ = std::move(replacement);
    rotated_at_ = now;
    has_current_ = true;
    return true;
}

std::optional<HandshakeCookie> HandshakeCookieManager::derive(
    const CookieSecret& secret,
    const Endpoint& source,
    uint32_t session_id,
    std::span<const uint8_t> init_frame) const {
    const auto init_hash = transcript_hash(
        CryptoHashAlgorithm::Blake2s256, {init_frame});
    if (!init_hash)
        return std::nullopt;

    std::array<uint8_t,
        COOKIE_DOMAIN.size() + 4 + 2 + 4 + CryptoHash{}.size()> context{};
    WireWriter writer(context);
    if (!writer.write_bytes(COOKIE_DOMAIN) ||
        !writer.write_u32(ntohl(source.ip)) ||
        !writer.write_u16(ntohs(source.port)) ||
        !writer.write_u32(session_id) ||
        !writer.write_bytes(*init_hash) || !writer.finished())
        return std::nullopt;

    return hmac_hash(
        CryptoHashAlgorithm::Blake2s256,
        std::span<const uint8_t>(secret.data(), secret.size()),
        context);
}

std::optional<HandshakeCookie> HandshakeCookieManager::issue(
    const Endpoint& source,
    uint32_t session_id,
    std::span<const uint8_t> init_frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!rotate_if_needed(clock_.now()))
        return std::nullopt;
    return derive(current_secret_, source, session_id, init_frame);
}

bool HandshakeCookieManager::verify(
    const HandshakeCookie& cookie,
    const Endpoint& source,
    uint32_t session_id,
    std::span<const uint8_t> init_frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!rotate_if_needed(clock_.now()))
        return false;

    const auto current = derive(
        current_secret_, source, session_id, init_frame);
    if (current && constant_time_equal(cookie, *current))
        return true;
    if (!has_previous_)
        return false;
    const auto previous = derive(
        previous_secret_, source, session_id, init_frame);
    return previous && constant_time_equal(cookie, *previous);
}
