#pragma once

#include "aegis/transport/send_queue.hpp"
#include <cstdint>
#include <cstddef>
#include <functional>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <vector>
#include <winsock2.h>

inline constexpr size_t IPV4_UDP_MAX_DATAGRAM_SIZE = 65507;

struct Endpoint {
    uint32_t ip;       // Network byte order
    uint16_t port;     // Network byte order

    bool operator==(const Endpoint& other) const {
        return ip == other.ip && port == other.port;
    }

    static Endpoint from_parts(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
        Endpoint e;
        e.ip = htonl((static_cast<uint32_t>(a) << 24) |
                      (static_cast<uint32_t>(b) << 16) |
                      (static_cast<uint32_t>(c) << 8) |
                      static_cast<uint32_t>(d));
        e.port = htons(port);
        return e;
    }
};

using OnReceiveCallback = std::function<void(const uint8_t* data, size_t len, Endpoint sender)>;

struct TransportQueueDropStats {
    uint64_t data = 0;
    uint64_t control = 0;

    [[nodiscard]] uint64_t total() const noexcept {
        return data + control;
    }
};

// Thread-safe accounting kept separate from the socket worker so queue-drop
// classification and lifecycle reset behavior remain deterministic to test.
class TransportQueueMetrics {
public:
    void record_drop(SendPriority priority) noexcept {
        if (priority == SendPriority::Control)
            control_drops_.fetch_add(1, std::memory_order_relaxed);
        else
            data_drops_.fetch_add(1, std::memory_order_relaxed);
    }

    void reset() noexcept {
        data_drops_.store(0, std::memory_order_relaxed);
        control_drops_.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] TransportQueueDropStats stats() const noexcept {
        return {
            data_drops_.load(std::memory_order_relaxed),
            control_drops_.load(std::memory_order_relaxed)
        };
    }

private:
    std::atomic<uint64_t> data_drops_{0};
    std::atomic<uint64_t> control_drops_{0};
};

// Socket options for bind(). `broadcast` enables sending to the network
// broadcast address; `reuseaddr` allows multiple sockets (e.g. every Aegis
// node on a LAN) to bind the same discovery port — broadcast datagrams are
// then delivered to all of them (standard Windows SO_REUSEADDR semantics).
struct SocketOptions {
    bool broadcast = false;
    bool reuseaddr = false;
};

struct ReceivedDatagram {
    std::vector<uint8_t> bytes;
    Endpoint sender{};
};

class Transport {
public:
    Transport();
    ~Transport();

    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    bool bind(uint16_t local_port, const SocketOptions& opts = {});
    void close();

    // Copies a datagram into the destination's bounded priority FIFO. Returns
    // false if the socket is closed, the datagram is invalid/oversized, or its
    // queue class is full. Control capacity is reserved from data traffic and
    // drains first; peers within each class drain round-robin.
    bool send(const uint8_t* data, size_t len, const Endpoint& dest,
              SendPriority priority = SendPriority::Data);

    // Sends immediately through this transport's bound socket and waits for a
    // datagram from the same endpoint. This startup-only exchange is rejected
    // while the asynchronous receive loop owns the socket.
    [[nodiscard]] std::optional<ReceivedDatagram> exchange(
        const uint8_t* data, size_t len, const Endpoint& dest,
        int timeout_ms);

    // Maximum UDP payload permitted by the configured physical IPv4 MTU.
    // The default is the protocol maximum so non-tunnel users remain usable;
    // Tunnel narrows it before binding.
    bool set_max_datagram_size(size_t maximum);
    size_t max_datagram_size() const {
        return max_datagram_size_.load(std::memory_order_relaxed);
    }
    uint64_t oversize_send_drops() const {
        return oversize_send_drops_.load(std::memory_order_relaxed);
    }
    uint64_t oversize_receive_drops() const {
        return oversize_receive_drops_.load(std::memory_order_relaxed);
    }
    TransportQueueDropStats queue_drop_stats() const {
        return queue_metrics_.stats();
    }
    uint64_t send_queue_drops() const {
        return queue_metrics_.stats().total();
    }

    bool start_receive(OnReceiveCallback callback);
    void stop_receive();

    uint16_t local_port() const { return local_port_; }
    bool is_open() const { return sock_ != INVALID_SOCKET; }

private:
    SOCKET sock_ = INVALID_SOCKET;
    uint16_t local_port_ = 0;
    std::thread send_thread_;
    std::thread recv_thread_;
    bool send_running_ = false;
    std::atomic<bool> running_{false};
    std::atomic<size_t> max_datagram_size_{IPV4_UDP_MAX_DATAGRAM_SIZE};
    std::atomic<uint64_t> oversize_send_drops_{0};
    std::atomic<uint64_t> oversize_receive_drops_{0};
    TransportQueueMetrics queue_metrics_;
    std::mutex send_mutex_;
    std::mutex socket_send_mutex_;
    std::condition_variable send_cv_;
    BoundedSendQueue send_queue_;

    void send_loop();
    void recv_loop(OnReceiveCallback callback);
};
