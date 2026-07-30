#pragma once

#include "aegis/crypto/chacha20poly1305.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/adapter/adapter.hpp"
#include "aegis/packet/packet.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <atomic>
#include <thread>
#include <vector>

static constexpr size_t WIRE_NONCE_SIZE = CHACHA20_POLY1305_NONCE_SIZE;
static constexpr size_t WIRE_TAG_SIZE   = CHACHA20_POLY1305_TAG_SIZE;

void increment_nonce(std::array<uint8_t, WIRE_NONCE_SIZE>& nonce);

struct TunnelConfig {
    uint32_t local_ip;         // Network byte order
    uint8_t  local_prefix;     // e.g. 24
    uint16_t listen_port;      // Host byte order
    Endpoint peer_endpoint;
    ChaCha20Poly1305Key psk;
};

class Tunnel {
public:
    Tunnel();
    ~Tunnel();

    Tunnel(const Tunnel&) = delete;
    Tunnel& operator=(const Tunnel&) = delete;

    bool start(const TunnelConfig& config, const std::string& adapter_name);
    void stop();

private:
    Adapter adapter_;
    Transport transport_;
    TunnelConfig config_;

    std::array<uint8_t, WIRE_NONCE_SIZE> tx_nonce_{};

    std::thread tx_thread_;
    std::thread rx_thread_;
    std::atomic<bool> running_{false};

    void tx_loop();
    void rx_loop();
};
