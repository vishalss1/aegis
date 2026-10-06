#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/protocol/sources.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>

inline constexpr size_t RELAY_QUOTA_MAX_PEERS = 256;

struct RelayQuotaConfig {
    double per_peer_packets_per_second = 200.0;
    size_t per_peer_packet_burst = 400;
    double per_peer_bytes_per_second = 512.0 * 1024.0;
    size_t per_peer_byte_burst = 1024 * 1024;
    double global_packets_per_second = 1000.0;
    size_t global_packet_burst = 2000;
    double global_bytes_per_second = 4.0 * 1024.0 * 1024.0;
    size_t global_byte_burst = 8 * 1024 * 1024;
    size_t max_peers = RELAY_QUOTA_MAX_PEERS;
    std::chrono::milliseconds idle_ttl{300000};
};

enum class RelayQuotaResult {
    Allowed,
    Invalid,
    PeerLimited,
    GlobalLimited,
    CapacityLimited
};

struct RelayQuotaStats {
    uint64_t admitted_packets = 0;
    uint64_t admitted_bytes = 0;
    uint64_t peer_drops = 0;
    uint64_t global_drops = 0;
    uint64_t capacity_drops = 0;

    [[nodiscard]] uint64_t total_drops() const noexcept {
        return peer_drops + global_drops + capacity_drops;
    }
};

// Limits forwarding by authenticated adjacent sender. Both the sender's
// packet/byte buckets and the global packet/byte buckets must have capacity;
// rejection never consumes tokens from either scope.
class RelayForwardLimiter {
public:
    explicit RelayForwardLimiter(
        ProtocolClock& clock = system_protocol_clock(),
        RelayQuotaConfig config = {});

    [[nodiscard]] RelayQuotaResult allow(
        const NodeId& authenticated_sender, size_t forwarded_bytes);
    void reset();

    [[nodiscard]] RelayQuotaStats stats() const;
    [[nodiscard]] size_t tracked_peers() const;

private:
    struct Bucket {
        double packet_tokens = 0.0;
        double byte_tokens = 0.0;
        ProtocolClock::time_point updated_at{};
    };

    struct PeerBucket {
        Bucket bucket;
        ProtocolClock::time_point last_seen{};
    };

    ProtocolClock& clock_;
    RelayQuotaConfig config_;
    bool valid_config_ = false;
    Bucket global_;
    std::map<NodeId, PeerBucket> peers_;
    RelayQuotaStats stats_;
    mutable std::mutex mutex_;

    [[nodiscard]] bool valid_config() const noexcept;
    [[nodiscard]] Bucket make_bucket(
        double packet_burst, double byte_burst,
        ProtocolClock::time_point now) const;
    static void refill(Bucket& bucket, ProtocolClock::time_point now,
                       double packets_per_second, double packet_burst,
                       double bytes_per_second, double byte_burst);
    void purge_idle(ProtocolClock::time_point now);
};
