#include "aegis/transport/handshake_rate_limiter.hpp"

HandshakeRateLimiter::HandshakeRateLimiter(
    ProtocolClock& clock,
    HandshakeRateLimitConfig config)
    : clock_(clock), config_(config), global_window_start_(clock.now()) {
    if (config_.window <= std::chrono::milliseconds::zero())
        config_.window = std::chrono::milliseconds(1);
}

bool HandshakeRateLimiter::expired(
    ProtocolClock::time_point start,
    ProtocolClock::time_point now) const {
    return now < start || now - start >= config_.window;
}

void HandshakeRateLimiter::reset_global_if_expired(
    ProtocolClock::time_point now) {
    if (!expired(global_window_start_, now)) return;
    global_window_start_ = now;
    global_count_ = 0;
}

void HandshakeRateLimiter::purge_expired_sources(
    ProtocolClock::time_point now) {
    for (auto it = sources_.begin(); it != sources_.end();) {
        if (expired(it->second.window_start, now))
            it = sources_.erase(it);
        else
            ++it;
    }
}

bool HandshakeRateLimiter::allow(const Endpoint& source) {
    const auto now = clock_.now();
    std::lock_guard<std::mutex> lock(mutex_);

    reset_global_if_expired(now);
    purge_expired_sources(now);

    auto source_it = sources_.find(source.ip);
    if (source_it != sources_.end() &&
        source_it->second.count >= config_.per_source_limit)
        return false;
    if (global_count_ >= config_.global_limit)
        return false;

    if (source_it == sources_.end()) {
        if (sources_.size() >= config_.max_sources)
            return false;
        source_it = sources_.emplace(source.ip, Bucket{now, 0}).first;
    }

    ++source_it->second.count;
    ++global_count_;
    return true;
}

size_t HandshakeRateLimiter::tracked_sources() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sources_.size();
}
