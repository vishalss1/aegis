#include "aegis/transport/transport.hpp"
#include "aegis/platform/platform.hpp"
#include <winsock2.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

Transport::Transport() = default;

Transport::~Transport() { close(); }

bool Transport::bind(uint16_t port, const SocketOptions& opts) {
    if (sock_ != INVALID_SOCKET) close();
    oversize_send_drops_.store(0, std::memory_order_relaxed);
    oversize_receive_drops_.store(0, std::memory_order_relaxed);
    queue_metrics_.reset();

    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ == INVALID_SOCKET) {
        fprintf(stderr, "[transport] socket: error %d\n", platform_last_error());
        return false;
    }

    if (opts.broadcast) {
        BOOL bcast = TRUE;
        setsockopt(sock_, SOL_SOCKET, SO_BROADCAST, (const char*)&bcast, sizeof(bcast));
    }
    if (opts.reuseaddr) {
        BOOL reuse = TRUE;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sock_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[transport] bind: error %d\n", platform_last_error());
        close();
        return false;
    }

    local_port_ = port;
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        send_queue_.clear();
        send_running_ = true;
    }
    send_thread_ = std::thread(&Transport::send_loop, this);
    return true;
}

void Transport::close() {
    stop_receive();
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        send_running_ = false;
        send_queue_.clear();
    }
    send_cv_.notify_all();
    if (send_thread_.joinable())
        send_thread_.join();
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
    local_port_ = 0;
}

bool Transport::set_max_datagram_size(size_t maximum) {
    if (maximum == 0 || maximum > IPV4_UDP_MAX_DATAGRAM_SIZE)
        return false;
    max_datagram_size_.store(maximum, std::memory_order_relaxed);
    return true;
}

bool Transport::send(const uint8_t* data, size_t len, const Endpoint& dest,
                     SendPriority priority) {
    if (len > max_datagram_size_.load(std::memory_order_relaxed)) {
        oversize_send_drops_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (len > 0 && !data) return false;
    const uint64_t peer_key =
        (static_cast<uint64_t>(dest.ip) << 16) |
        static_cast<uint64_t>(dest.port);
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        if (sock_ == INVALID_SOCKET || !send_running_)
            return false;
        if (send_queue_.enqueue(peer_key, data, len, priority) !=
            SendQueueResult::Queued) {
            queue_metrics_.record_drop(priority);
            return false;
        }
    }
    send_cv_.notify_one();
    return true;
}

std::optional<ReceivedDatagram> Transport::exchange(
    const uint8_t* data, size_t len, const Endpoint& dest,
    int timeout_ms) {
    const size_t maximum = max_datagram_size_.load(std::memory_order_relaxed);
    if (sock_ == INVALID_SOCKET || running_.load(std::memory_order_relaxed) ||
        !data || len == 0 || timeout_ms <= 0)
        return std::nullopt;
    if (len > maximum) {
        oversize_send_drops_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = dest.ip;
    destination.sin_port = dest.port;
    {
        std::lock_guard<std::mutex> lock(socket_send_mutex_);
        const int sent = sendto(
            sock_, reinterpret_cast<const char*>(data),
            static_cast<int>(len), 0,
            reinterpret_cast<const sockaddr*>(&destination),
            sizeof(destination));
        if (sent != static_cast<int>(len))
            return std::nullopt;
    }

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(timeout_ms);
    std::vector<uint8_t> buffer(maximum);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<
            std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
        const DWORD receive_timeout = static_cast<DWORD>((std::max)(
            int64_t{1}, static_cast<int64_t>(remaining.count())));
        if (setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&receive_timeout),
                       sizeof(receive_timeout)) == SOCKET_ERROR)
            return std::nullopt;

        sockaddr_in sender{};
        int sender_length = sizeof(sender);
        const int received = recvfrom(
            sock_, reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(buffer.size()), 0,
            reinterpret_cast<sockaddr*>(&sender), &sender_length);
        if (received == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAETIMEDOUT)
                return std::nullopt;
            if (error == WSAECONNRESET || error == WSAENETRESET ||
                error == WSAEMSGSIZE)
                continue;
            return std::nullopt;
        }

        const Endpoint source{sender.sin_addr.s_addr, sender.sin_port};
        if (!(source == dest))
            continue;
        buffer.resize(static_cast<size_t>(received));
        return ReceivedDatagram{std::move(buffer), source};
    }
    return std::nullopt;
}

void Transport::send_loop() {
    while (true) {
        std::optional<QueuedDatagram> datagram;
        {
            std::unique_lock<std::mutex> lock(send_mutex_);
            send_cv_.wait(lock, [this] {
                return !send_running_ || !send_queue_.empty();
            });
            if (!send_running_)
                return;
            datagram = send_queue_.pop();
        }
        if (!datagram)
            continue;

        Endpoint dest{};
        dest.ip = static_cast<uint32_t>(datagram->peer_key >> 16);
        dest.port = static_cast<uint16_t>(datagram->peer_key & 0xFFFFu);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = dest.ip;
        addr.sin_port = dest.port;
        const int length = static_cast<int>(datagram->bytes.size());
        int ret = SOCKET_ERROR;
        {
            std::lock_guard<std::mutex> lock(socket_send_mutex_);
            ret = sendto(
                sock_, reinterpret_cast<const char*>(datagram->bytes.data()),
                length, 0, reinterpret_cast<const sockaddr*>(&addr),
                sizeof(addr));
        }
        if (ret == SOCKET_ERROR)
            fprintf(stderr, "[transport] sendto %08x:%04x failed: %d\n",
                    ntohl(dest.ip), ntohs(dest.port), platform_last_error());
    }
}

bool Transport::start_receive(OnReceiveCallback callback) {
    if (sock_ == INVALID_SOCKET || running_) return false;

    running_ = true;
    recv_thread_ = std::thread(&Transport::recv_loop, this, std::move(callback));
    return true;
}

void Transport::stop_receive() {
    running_ = false;
    if (recv_thread_.joinable())
        recv_thread_.join();
}

void Transport::recv_loop(OnReceiveCallback callback) {
    DWORD timeout = 100;
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeout, sizeof(timeout));

    char buf[65536];
    while (running_) {
        sockaddr_in sender{};
        int from_len = sizeof(sender);
        int ret = recvfrom(sock_, buf, sizeof(buf), 0,
                           (sockaddr*)&sender, &from_len);
        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            // WSAETIMEDOUT: normal poll timeout, keep looping.
            // WSAECONNRESET / WSAENETRESET: a prior sendto to an unreachable
            // port produced an ICMP error queued on this UDP socket (classic
            // Windows behavior). The socket is still valid - just swallow the
            // error and continue receiving.
            if (err == WSAETIMEDOUT || err == WSAECONNRESET ||
                err == WSAENETRESET)
                continue;
            break;
        }

        if (static_cast<size_t>(ret) >
            max_datagram_size_.load(std::memory_order_relaxed)) {
            oversize_receive_drops_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        Endpoint ep{sender.sin_addr.s_addr, sender.sin_port};
        callback((const uint8_t*)buf, (size_t)ret, ep);
    }
}
