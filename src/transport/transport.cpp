#include "aegis/transport/transport.hpp"
#include "aegis/platform/platform.hpp"
#include <winsock2.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>

std::optional<Endpoint> endpoint_from_sockaddr(
    const sockaddr* address, size_t length) noexcept {
    if (!address) return std::nullopt;
    if (address->sa_family == AF_INET && length >= sizeof(sockaddr_in)) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
        return Endpoint(v4->sin_addr.s_addr, v4->sin_port);
    }
    if (address->sa_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
        std::array<uint8_t, 16> bytes{};
        std::memcpy(bytes.data(), &v6->sin6_addr, bytes.size());
        static constexpr std::array<uint8_t, 12> mapped_prefix{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (std::equal(mapped_prefix.begin(), mapped_prefix.end(),
                       bytes.begin())) {
            uint32_t ipv4 = 0;
            std::memcpy(&ipv4, bytes.data() + 12, sizeof(ipv4));
            return Endpoint(ipv4, v6->sin6_port);
        }
        return Endpoint(IPAddress::from_ipv6(bytes), v6->sin6_port);
    }
    return std::nullopt;
}

int endpoint_to_sockaddr(const Endpoint& endpoint, bool ipv6_socket,
                         sockaddr_storage& out) noexcept {
    std::memset(&out, 0, sizeof(out));
    if (endpoint.is_ipv4() && !ipv6_socket) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&out);
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = endpoint.ipv4_network();
        v4->sin_port = endpoint.port;
        return sizeof(sockaddr_in);
    }
    if (!ipv6_socket) return 0;
    if (!endpoint.is_ipv4() && !endpoint.is_ipv6()) return 0;
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&out);
    v6->sin6_family = AF_INET6;
    v6->sin6_port = endpoint.port;
    if (endpoint.is_ipv4()) {
        v6->sin6_addr.u.Byte[10] = 0xff;
        v6->sin6_addr.u.Byte[11] = 0xff;
        std::memcpy(&v6->sin6_addr.u.Byte[12], &endpoint.address.bytes[0], 4);
    } else {
        std::memcpy(&v6->sin6_addr, endpoint.address.bytes.data(), 16);
    }
    return sizeof(sockaddr_in6);
}

Transport::Transport() = default;

Transport::~Transport() { close(); }

bool Transport::bind(uint16_t port, const SocketOptions& opts) {
    if (sock_ != INVALID_SOCKET) close();
    oversize_send_drops_.store(0, std::memory_order_relaxed);
    oversize_receive_drops_.store(0, std::memory_order_relaxed);
    queue_metrics_.reset();

    ipv6_socket_ = false;
    if (opts.dual_stack && !opts.broadcast) {
        sock_ = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock_ != INVALID_SOCKET) {
            DWORD v6only = 0;
            sockaddr_in6 any6{};
            any6.sin6_family = AF_INET6;
            any6.sin6_port = htons(port);
            const bool configured =
                setsockopt(sock_, IPPROTO_IPV6, IPV6_V6ONLY,
                           reinterpret_cast<const char*>(&v6only),
                           sizeof(v6only)) != SOCKET_ERROR &&
                ::bind(sock_, reinterpret_cast<sockaddr*>(&any6),
                       sizeof(any6)) != SOCKET_ERROR;
            if (configured) {
                ipv6_socket_ = true;
            } else {
                closesocket(sock_);
                sock_ = INVALID_SOCKET;
            }
        }
    }

    if (!ipv6_socket_) {
        sock_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ == INVALID_SOCKET) {
            fprintf(stderr, "[transport] socket: error %d\n",
                    platform_last_error());
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
    ipv6_socket_ = false;
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
    if (dest.is_ipv6() && !ipv6_socket_) return false;
    {
        std::lock_guard<std::mutex> lock(send_mutex_);
        if (sock_ == INVALID_SOCKET || !send_running_)
            return false;
        if (send_queue_.enqueue(dest, data, len, priority) !=
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

    sockaddr_storage destination{};
    const int destination_length =
        endpoint_to_sockaddr(dest, ipv6_socket_, destination);
    if (destination_length == 0)
        return std::nullopt;
    {
        std::lock_guard<std::mutex> lock(socket_send_mutex_);
        const int sent = sendto(
            sock_, reinterpret_cast<const char*>(data),
            static_cast<int>(len), 0,
            reinterpret_cast<const sockaddr*>(&destination),
            destination_length);
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

        sockaddr_storage sender{};
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

        const auto source = endpoint_from_sockaddr(
            reinterpret_cast<const sockaddr*>(&sender), sender_length);
        if (!source || !(*source == dest))
            continue;
        buffer.resize(static_cast<size_t>(received));
        return ReceivedDatagram{std::move(buffer), *source};
    }
    return std::nullopt;
}

void Transport::send_loop() {
    while (true) {
        std::optional<BasicQueuedDatagram<Endpoint>> datagram;
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

        const Endpoint& dest = datagram->peer_key;
        sockaddr_storage addr{};
        const int addr_length =
            endpoint_to_sockaddr(dest, ipv6_socket_, addr);
        if (addr_length == 0)
            continue;
        const int length = static_cast<int>(datagram->bytes.size());
        int ret = SOCKET_ERROR;
        {
            std::lock_guard<std::mutex> lock(socket_send_mutex_);
            ret = sendto(
                sock_, reinterpret_cast<const char*>(datagram->bytes.data()),
                length, 0, reinterpret_cast<const sockaddr*>(&addr),
                addr_length);
        }
        if (ret == SOCKET_ERROR)
            fprintf(stderr, "[transport] sendto port %u failed: %d\n",
                    ntohs(dest.port), platform_last_error());
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
        sockaddr_storage sender{};
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

        const auto ep = endpoint_from_sockaddr(
            reinterpret_cast<const sockaddr*>(&sender), from_len);
        if (!ep)
            continue;
        callback((const uint8_t*)buf, (size_t)ret, *ep);
    }
}
