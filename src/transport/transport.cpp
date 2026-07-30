#include "aegis/transport/transport.hpp"
#include "aegis/platform/platform.hpp"
#include <winsock2.h>
#include <cstdio>
#include <cstring>

Transport::Transport() = default;

Transport::~Transport() { close(); }

bool Transport::bind(uint16_t port) {
    if (sock_ != INVALID_SOCKET) close();

    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ == INVALID_SOCKET) {
        fprintf(stderr, "[transport] socket: error %d\n", platform_last_error());
        return false;
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
    return true;
}

void Transport::close() {
    stop_receive();
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
    local_port_ = 0;
}

bool Transport::send(const uint8_t* data, size_t len, const Endpoint& dest) {
    if (sock_ == INVALID_SOCKET) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dest.ip;
    addr.sin_port = dest.port;
    int ret = sendto(sock_, (const char*)data, (int)len, 0,
                     (const sockaddr*)&addr, sizeof(addr));
    return ret != SOCKET_ERROR;
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
            if (err == WSAETIMEDOUT)
                continue;
            break;
        }

        Endpoint ep{sender.sin_addr.s_addr, sender.sin_port};
        callback((const uint8_t*)buf, (size_t)ret, ep);
    }
}
