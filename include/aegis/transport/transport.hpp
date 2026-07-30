#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <thread>
#include <atomic>
#include <winsock2.h>

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

class Transport {
public:
    Transport();
    ~Transport();

    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    bool bind(uint16_t local_port);
    void close();

    bool send(const uint8_t* data, size_t len, const Endpoint& dest);

    bool start_receive(OnReceiveCallback callback);
    void stop_receive();

    uint16_t local_port() const { return local_port_; }
    bool is_open() const { return sock_ != INVALID_SOCKET; }

private:
    SOCKET sock_ = INVALID_SOCKET;
    uint16_t local_port_ = 0;
    std::thread recv_thread_;
    std::atomic<bool> running_{false};

    void recv_loop(OnReceiveCallback callback);
};
