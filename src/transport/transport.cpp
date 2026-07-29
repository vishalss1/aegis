#include "aegis/transport.hpp"
#include "aegis/platform.hpp"
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

    int opt = 1;
    setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sock_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[transport] bind: error %d\n", platform_last_error());
        close();
        return false;
    }

    return true;
}

void Transport::close() {
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool Transport::send_to(const sockaddr_in& dest, const std::vector<uint8_t>& data) {
    int ret = sendto(sock_, (const char*)data.data(), (int)data.size(), 0,
                     (const sockaddr*)&dest, sizeof(dest));
    return ret != SOCKET_ERROR;
}

bool Transport::recv_from(sockaddr_in& sender, std::vector<uint8_t>& data) {
    int from_len = sizeof(sender);
    char buf[65536];
    int ret = recvfrom(sock_, buf, sizeof(buf), 0,
                       (sockaddr*)&sender, &from_len);
    if (ret == SOCKET_ERROR) return false;
    data.assign(buf, buf + ret);
    return true;
}

bool Transport::send_to_peer(const PeerEndpoint& peer, const std::vector<uint8_t>& data) {
    return send_to(peer.addr, data);
}
