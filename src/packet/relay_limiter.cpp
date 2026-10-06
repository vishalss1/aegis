#include "aegis/packet/relay_limiter.hpp"
#include <algorithm>
#include <cmath>

RelayForwardLimiter::RelayForwardLimiter(
    ProtocolClock& clock, RelayQuotaConfig config)
    : clock_(clock), config_(config), valid_config_(valid_config()) {
    reset();
}

bool RelayForwardLimiter::valid_config() const noexcept {
    return std::isfinite(config_.per_peer_packets_per_second) &&
           config_.per_peer_packets_per_second > 0.0 &&
           config_.per_peer_packet_burst > 0 &&
           std::isfinite(config_.per_peer_bytes_per_second) &&
           config_.per_peer_bytes_per_second > 0.0 &&
           config_.per_peer_byte_burst > 0 &&
           std::isfinite(config_.global_packets_per_second) &&
           config_.global_packets_per_second > 0.0 &&
           config_.global_packet_burst > 0 &&
           std::isfinite(config_.global_bytes_per_second) &&
           config_.global_bytes_per_second > 0.0 &&
           config_.global_byte_burst > 0 &&
           config_.max_peers > 0 &&
           config_.idle_ttl.count() > 0;
}

RelayForwardLimiter::Bucket RelayForwardLimiter::make_bucket(
    double packet_burst, double byte_burst,
    ProtocolClock::time_point now) const {
    Bucket bucket;
    bucket.packet_tokens = packet_burst;
    bucket.byte_tokens = byte_burst;
    bucket.updated_at = now;
    return bucket;
}

void RelayForwardLimiter::refill(
    Bucket& bucket, ProtocolClock::time_point now,
    double packets_per_second, double packet_burst,
    double bytes_per_second, double byte_burst) {
    if (now <= bucket.updated_at)
        return;
    const double elapsed =
        std::chrono::duration<double>(now - bucket.updated_at).count();
    bucket.packet_tokens = std::min(
        packet_burst,
        bucket.packet_tokens + elapsed * packets_per_second);
    bucket.byte_tokens = std::min(
        byte_burst,
        bucket.byte_tokens + elapsed * bytes_per_second);
    bucket.updated_at = now;
}

void RelayForwardLimiter::purge_idle(ProtocolClock::time_point now) {
    for (auto peer = peers_.begin(); peer != peers_.end();) {
        if (now >= peer->second.last_seen &&
            now - peer->second.last_seen >= config_.idle_ttl) {
            peer = peers_.erase(peer);
        } else {
            ++peer;
        }
    }
}

RelayQuotaResult RelayForwardLimiter::allow(
    const NodeId& authenticated_sender, size_t forwarded_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!valid_config_ || forwarded_bytes == 0)
        return RelayQuotaResult::Invalid;

    const double byte_cost = static_cast<double>(forwarded_bytes);
    if (byte_cost > static_cast<double>(config_.global_byte_burst)) {
        ++stats_.global_drops;
        return RelayQuotaResult::GlobalLimited;
    }
    if (byte_cost > static_cast<double>(config_.per_peer_byte_burst)) {
        ++stats_.peer_drops;
        return RelayQuotaResult::PeerLimited;
    }

    const auto now = clock_.now();
    refill(global_, now,
           config_.global_packets_per_second,
           static_cast<double>(config_.global_packet_burst),
           config_.global_bytes_per_second,
           static_cast<double>(config_.global_byte_burst));
    if (global_.packet_tokens < 1.0 || global_.byte_tokens < byte_cost) {
        ++stats_.global_drops;
        return RelayQuotaResult::GlobalLimited;
    }

    auto peer = peers_.find(authenticated_sender);
    if (peer == peers_.end()) {
        if (peers_.size() >= config_.max_peers)
            purge_idle(now);
        if (peers_.size() >= config_.max_peers) {
            ++stats_.capacity_drops;
            return RelayQuotaResult::CapacityLimited;
        }
        PeerBucket created;
        created.bucket = make_bucket(
            static_cast<double>(config_.per_peer_packet_burst),
            static_cast<double>(config_.per_peer_byte_burst), now);
        created.last_seen = now;
        peer = peers_.emplace(authenticated_sender, created).first;
    } else {
        refill(peer->second.bucket, now,
               config_.per_peer_packets_per_second,
               static_cast<double>(config_.per_peer_packet_burst),
               config_.per_peer_bytes_per_second,
               static_cast<double>(config_.per_peer_byte_burst));
        peer->second.last_seen = now;
    }

    if (peer->second.bucket.packet_tokens < 1.0 ||
        peer->second.bucket.byte_tokens < byte_cost) {
        ++stats_.peer_drops;
        return RelayQuotaResult::PeerLimited;
    }

    global_.packet_tokens -= 1.0;
    global_.byte_tokens -= byte_cost;
    peer->second.bucket.packet_tokens -= 1.0;
    peer->second.bucket.byte_tokens -= byte_cost;
    ++stats_.admitted_packets;
    stats_.admitted_bytes += static_cast<uint64_t>(forwarded_bytes);
    return RelayQuotaResult::Allowed;
}

void RelayForwardLimiter::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = clock_.now();
    global_ = make_bucket(
        static_cast<double>(config_.global_packet_burst),
        static_cast<double>(config_.global_byte_burst), now);
    peers_.clear();
    stats_ = {};
}

RelayQuotaStats RelayForwardLimiter::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

size_t RelayForwardLimiter::tracked_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peers_.size();
}
