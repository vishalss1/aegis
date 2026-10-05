#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

inline constexpr size_t TRANSPORT_QUEUE_MAX_ITEMS_PER_PEER = 64;
inline constexpr size_t TRANSPORT_QUEUE_MAX_BYTES_PER_PEER = 256 * 1024;
inline constexpr size_t TRANSPORT_QUEUE_MAX_ITEMS_GLOBAL = 1024;
inline constexpr size_t TRANSPORT_QUEUE_MAX_BYTES_GLOBAL = 4 * 1024 * 1024;

struct SendQueueLimits {
    size_t max_items_per_peer = TRANSPORT_QUEUE_MAX_ITEMS_PER_PEER;
    size_t max_bytes_per_peer = TRANSPORT_QUEUE_MAX_BYTES_PER_PEER;
    size_t max_items_global = TRANSPORT_QUEUE_MAX_ITEMS_GLOBAL;
    size_t max_bytes_global = TRANSPORT_QUEUE_MAX_BYTES_GLOBAL;
};

enum class SendQueueResult {
    Queued,
    Invalid,
    PerPeerItemLimit,
    PerPeerByteLimit,
    GlobalItemLimit,
    GlobalByteLimit
};

struct QueuedDatagram {
    uint64_t peer_key = 0;
    std::vector<uint8_t> bytes;
};

// A bounded collection of FIFO queues drained one datagram per peer in
// round-robin order. The owner provides synchronization so it can combine the
// empty check, wait, and pop operation under one condition-variable mutex.
class BoundedSendQueue {
public:
    explicit BoundedSendQueue(SendQueueLimits limits = {})
        : limits_(limits) {}

    [[nodiscard]] SendQueueResult enqueue(
        uint64_t peer_key, const uint8_t* data, size_t len) {
        if ((len > 0 && !data) || !valid_limits())
            return SendQueueResult::Invalid;

        auto existing = peers_.find(peer_key);
        const size_t peer_items =
            existing == peers_.end() ? 0 : existing->second.items.size();
        const size_t peer_bytes =
            existing == peers_.end() ? 0 : existing->second.bytes;

        if (peer_items >= limits_.max_items_per_peer)
            return SendQueueResult::PerPeerItemLimit;
        if (len > limits_.max_bytes_per_peer - peer_bytes)
            return SendQueueResult::PerPeerByteLimit;
        if (total_items_ >= limits_.max_items_global)
            return SendQueueResult::GlobalItemLimit;
        if (len > limits_.max_bytes_global - total_bytes_)
            return SendQueueResult::GlobalByteLimit;

        std::vector<uint8_t> bytes;
        if (len > 0)
            bytes.assign(data, data + len);

        auto [peer, inserted] = peers_.try_emplace(peer_key);
        if (inserted)
            active_peers_.push_back(peer_key);
        peer->second.items.push_back(std::move(bytes));
        peer->second.bytes += len;
        ++total_items_;
        total_bytes_ += len;
        return SendQueueResult::Queued;
    }

    [[nodiscard]] std::optional<QueuedDatagram> pop() {
        if (active_peers_.empty())
            return std::nullopt;

        const uint64_t peer_key = active_peers_.front();
        active_peers_.pop_front();
        auto peer = peers_.find(peer_key);
        if (peer == peers_.end() || peer->second.items.empty())
            return std::nullopt;

        QueuedDatagram datagram;
        datagram.peer_key = peer_key;
        datagram.bytes = std::move(peer->second.items.front());
        peer->second.items.pop_front();
        peer->second.bytes -= datagram.bytes.size();
        --total_items_;
        total_bytes_ -= datagram.bytes.size();

        if (peer->second.items.empty())
            peers_.erase(peer);
        else
            active_peers_.push_back(peer_key);
        return datagram;
    }

    void clear() {
        peers_.clear();
        active_peers_.clear();
        total_items_ = 0;
        total_bytes_ = 0;
    }

    [[nodiscard]] bool empty() const noexcept { return total_items_ == 0; }
    [[nodiscard]] size_t size() const noexcept { return total_items_; }
    [[nodiscard]] size_t bytes() const noexcept { return total_bytes_; }
    [[nodiscard]] size_t peer_count() const noexcept { return peers_.size(); }

private:
    struct PeerQueue {
        std::deque<std::vector<uint8_t>> items;
        size_t bytes = 0;
    };

    [[nodiscard]] bool valid_limits() const noexcept {
        return limits_.max_items_per_peer > 0 &&
               limits_.max_bytes_per_peer > 0 &&
               limits_.max_items_global > 0 &&
               limits_.max_bytes_global > 0;
    }

    SendQueueLimits limits_;
    std::unordered_map<uint64_t, PeerQueue> peers_;
    std::deque<uint64_t> active_peers_;
    size_t total_items_ = 0;
    size_t total_bytes_ = 0;
};
