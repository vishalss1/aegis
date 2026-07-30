#pragma once

#include "aegis/identity/identity.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <winsock2.h>

struct PeerEndpoint {
    NodeId node_id;
    sockaddr_in addr;
};

class Transport {
public:
    Transport();
    ~Transport();

    bool bind(uint16_t port);
    void close();

    bool send_to(const sockaddr_in& dest, const std::vector<uint8_t>& data);
    bool recv_from(sockaddr_in& sender, std::vector<uint8_t>& data);

    bool send_to_peer(const PeerEndpoint& peer, const std::vector<uint8_t>& data);

    SOCKET handle() const { return sock_; }

private:
    SOCKET sock_ = INVALID_SOCKET;
};
