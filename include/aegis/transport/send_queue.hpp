#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

inline constexpr size_t TRANSPORT_DATA_QUEUE_MAX_ITEMS_PER_PEER = 48;
inline constexpr size_t TRANSPORT_DATA_QUEUE_MAX_BYTES_PER_PEER = 192 * 1024;
inline constexpr size_t TRANSPORT_DATA_QUEUE_MAX_ITEMS_GLOBAL = 768;
inline constexpr size_t TRANSPORT_DATA_QUEUE_MAX_BYTES_GLOBAL = 3 * 1024 * 1024;
inline constexpr size_t TRANSPORT_CONTROL_QUEUE_MAX_ITEMS_PER_PEER = 16;
inline constexpr size_t TRANSPORT_CONTROL_QUEUE_MAX_BYTES_PER_PEER = 64 * 1024;
inline constexpr size_t TRANSPORT_CONTROL_QUEUE_MAX_ITEMS_GLOBAL = 256;
inline constexpr size_t TRANSPORT_CONTROL_QUEUE_MAX_BYTES_GLOBAL =
    1024 * 1024;
inline constexpr size_t TRANSPORT_QUEUE_MAX_ITEMS_PER_PEER =
    TRANSPORT_DATA_QUEUE_MAX_ITEMS_PER_PEER +
    TRANSPORT_CONTROL_QUEUE_MAX_ITEMS_PER_PEER;
inline constexpr size_t TRANSPORT_QUEUE_MAX_BYTES_PER_PEER =
    TRANSPORT_DATA_QUEUE_MAX_BYTES_PER_PEER +
    TRANSPORT_CONTROL_QUEUE_MAX_BYTES_PER_PEER;
inline constexpr size_t TRANSPORT_QUEUE_MAX_ITEMS_GLOBAL =
    TRANSPORT_DATA_QUEUE_MAX_ITEMS_GLOBAL +
    TRANSPORT_CONTROL_QUEUE_MAX_ITEMS_GLOBAL;
inline constexpr size_t TRANSPORT_QUEUE_MAX_BYTES_GLOBAL =
    TRANSPORT_DATA_QUEUE_MAX_BYTES_GLOBAL +
    TRANSPORT_CONTROL_QUEUE_MAX_BYTES_GLOBAL;

struct SendQueueClassLimits {
    size_t max_items_per_peer;
    size_t max_bytes_per_peer;
    size_t max_items_global;
    size_t max_bytes_global;
};

struct SendQueueLimits {
    SendQueueClassLimits data{
        TRANSPORT_DATA_QUEUE_MAX_ITEMS_PER_PEER,
        TRANSPORT_DATA_QUEUE_MAX_BYTES_PER_PEER,
        TRANSPORT_DATA_QUEUE_MAX_ITEMS_GLOBAL,
        TRANSPORT_DATA_QUEUE_MAX_BYTES_GLOBAL};
    SendQueueClassLimits control{
        TRANSPORT_CONTROL_QUEUE_MAX_ITEMS_PER_PEER,
        TRANSPORT_CONTROL_QUEUE_MAX_BYTES_PER_PEER,
        TRANSPORT_CONTROL_QUEUE_MAX_ITEMS_GLOBAL,
        TRANSPORT_CONTROL_QUEUE_MAX_BYTES_GLOBAL};
};

enum class SendPriority { Data, Control };

enum class SendQueueResult {
    Queued,
    Invalid,
    PerPeerItemLimit,
    PerPeerByteLimit,
    GlobalItemLimit,
    GlobalByteLimit
};

template <class Key>
struct BasicQueuedDatagram {
    Key peer_key{};
    SendPriority priority = SendPriority::Data;
    std::vector<uint8_t> bytes;
};

// Bounded control and data FIFOs. Control traffic has reserved capacity and is
// always selected first; peers within each priority drain round-robin. The
// owner provides synchronization so it can combine empty checks, waits, and
// pops under one condition-variable mutex.
template <class Key>
class BasicBoundedSendQueue {
public:
    using QueuedDatagram = BasicQueuedDatagram<Key>;

    explicit BasicBoundedSendQueue(SendQueueLimits limits = {})
        : limits_(limits) {}

    [[nodiscard]] SendQueueResult enqueue(
        const Key& peer_key, const uint8_t* data, size_t len,
        SendPriority priority = SendPriority::Data) {
        if ((len > 0 && !data) || !valid_limits())
            return SendQueueResult::Invalid;

        auto existing = peers_.find(peer_key);
        const QueueLane* existing_lane = nullptr;
        if (existing != peers_.end()) {
            existing_lane = priority == SendPriority::Control
                ? &existing->second.control
                : &existing->second.data;
        }
        const size_t peer_items =
            existing_lane ? existing_lane->items.size() : 0;
        const size_t peer_bytes = existing_lane ? existing_lane->bytes : 0;
        const auto& class_limits = priority == SendPriority::Control
            ? limits_.control
            : limits_.data;
        const size_t global_items = priority == SendPriority::Control
            ? control_items_
            : data_items_;
        const size_t global_bytes = priority == SendPriority::Control
            ? control_bytes_
            : data_bytes_;

        if (peer_items >= class_limits.max_items_per_peer)
            return SendQueueResult::PerPeerItemLimit;
        if (len > class_limits.max_bytes_per_peer - peer_bytes)
            return SendQueueResult::PerPeerByteLimit;
        if (global_items >= class_limits.max_items_global)
            return SendQueueResult::GlobalItemLimit;
        if (len > class_limits.max_bytes_global - global_bytes)
            return SendQueueResult::GlobalByteLimit;

        std::vector<uint8_t> bytes;
        if (len > 0)
            bytes.assign(data, data + len);

        auto [peer, inserted] = peers_.try_emplace(peer_key);
        (void)inserted;
        QueueLane& lane = priority == SendPriority::Control
            ? peer->second.control
            : peer->second.data;
        if (lane.items.empty()) {
            auto& active = priority == SendPriority::Control
                ? active_control_peers_
                : active_data_peers_;
            active.push_back(peer_key);
        }
        lane.items.push_back(std::move(bytes));
        lane.bytes += len;
        if (priority == SendPriority::Control) {
            ++control_items_;
            control_bytes_ += len;
        } else {
            ++data_items_;
            data_bytes_ += len;
        }
        return SendQueueResult::Queued;
    }

    [[nodiscard]] std::optional<QueuedDatagram> pop() {
        if (!active_control_peers_.empty())
            return pop(SendPriority::Control);
        if (!active_data_peers_.empty())
            return pop(SendPriority::Data);
        return std::nullopt;
    }

    void clear() {
        peers_.clear();
        active_control_peers_.clear();
        active_data_peers_.clear();
        control_items_ = 0;
        control_bytes_ = 0;
        data_items_ = 0;
        data_bytes_ = 0;
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] size_t size() const noexcept {
        return control_items_ + data_items_;
    }
    [[nodiscard]] size_t bytes() const noexcept {
        return control_bytes_ + data_bytes_;
    }
    [[nodiscard]] size_t control_size() const noexcept {
        return control_items_;
    }
    [[nodiscard]] size_t data_size() const noexcept { return data_items_; }
    [[nodiscard]] size_t peer_count() const noexcept { return peers_.size(); }

private:
    struct QueueLane {
        std::deque<std::vector<uint8_t>> items;
        size_t bytes = 0;
    };

    struct PeerQueue {
        QueueLane control;
        QueueLane data;
    };

    [[nodiscard]] std::optional<QueuedDatagram> pop(SendPriority priority) {
        auto& active = priority == SendPriority::Control
            ? active_control_peers_
            : active_data_peers_;
        const Key peer_key = active.front();
        active.pop_front();
        auto peer = peers_.find(peer_key);
        if (peer == peers_.end())
            return std::nullopt;

        QueueLane& lane = priority == SendPriority::Control
            ? peer->second.control
            : peer->second.data;
        if (lane.items.empty())
            return std::nullopt;

        QueuedDatagram datagram;
        datagram.peer_key = peer_key;
        datagram.priority = priority;
        datagram.bytes = std::move(lane.items.front());
        lane.items.pop_front();
        lane.bytes -= datagram.bytes.size();
        if (priority == SendPriority::Control) {
            --control_items_;
            control_bytes_ -= datagram.bytes.size();
        } else {
            --data_items_;
            data_bytes_ -= datagram.bytes.size();
        }

        if (!lane.items.empty())
            active.push_back(peer_key);
        if (peer->second.control.items.empty() &&
            peer->second.data.items.empty()) {
            peers_.erase(peer);
        }
        return datagram;
    }

    [[nodiscard]] bool valid_limits() const noexcept {
        const auto valid_class = [](const SendQueueClassLimits& limits) {
            return limits.max_items_per_peer > 0 &&
                   limits.max_bytes_per_peer > 0 &&
                   limits.max_items_global > 0 &&
                   limits.max_bytes_global > 0;
        };
        return valid_class(limits_.control) && valid_class(limits_.data);
    }

    SendQueueLimits limits_;
    std::unordered_map<Key, PeerQueue> peers_;
    std::deque<Key> active_control_peers_;
    std::deque<Key> active_data_peers_;
    size_t control_items_ = 0;
    size_t control_bytes_ = 0;
    size_t data_items_ = 0;
    size_t data_bytes_ = 0;
};

using QueuedDatagram = BasicQueuedDatagram<uint64_t>;
using BoundedSendQueue = BasicBoundedSendQueue<uint64_t>;
