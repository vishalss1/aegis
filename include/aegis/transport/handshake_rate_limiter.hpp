#pragma once

#include "aegis/protocol/sources.hpp"
#include "aegis/transport/transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <utility>

struct HandshakeRateLimitConfig {
    size_t per_source_limit = 8;
    size_t global_limit = 64;
    size_t max_sources = 1024;
    std::chrono::milliseconds window{1000};
};

// Bounds unauthenticated handshake work before payload allocation and Noise
// processing. Sources are keyed by IP rather than Endpoint so changing the UDP
// source port cannot evade the per-source budget.
class HandshakeRateLimiter {
public:
    explicit HandshakeRateLimiter(
        ProtocolClock& clock,
        HandshakeRateLimitConfig config = {});

    [[nodiscard]] bool allow(const Endpoint& source);
    [[nodiscard]] size_t tracked_sources() const;

private:
    struct Bucket {
        ProtocolClock::time_point window_start;
        size_t count = 0;
    };

    void reset_global_if_expired(ProtocolClock::time_point now);
    void purge_expired_sources(ProtocolClock::time_point now);
    [[nodiscard]] bool expired(
        ProtocolClock::time_point start,
        ProtocolClock::time_point now) const;

    ProtocolClock& clock_;
    HandshakeRateLimitConfig config_;
    ProtocolClock::time_point global_window_start_;
    size_t global_count_ = 0;
    // IPv4 sources are tracked per address; IPv6 per /64, since a single
    // subscriber normally controls an entire /64.
    using SourceKey = std::pair<uint8_t, std::array<uint8_t, 16>>;
    [[nodiscard]] static SourceKey source_key(const Endpoint& source);

    std::map<SourceKey, Bucket> sources_;
    mutable std::mutex mutex_;
};
