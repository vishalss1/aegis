#pragma once

#include "aegis/session/session.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/adapter/adapter.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>

struct TunnelConfig {
    uint32_t local_ip;         // Network byte order
    uint8_t  local_prefix;     // e.g. 24
    uint16_t listen_port;      // Host byte order
    Endpoint peer_endpoint;
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

    Identity identity_;
    SessionManager session_manager_;
    NodeId peer_id_{};

    std::thread tx_thread_;
    std::atomic<bool> running_{false};

    void tx_loop();
    void rx_callback(const uint8_t* data, size_t len, Endpoint sender);

    std::mutex hs_mtx_;
    std::condition_variable hs_cv_;
    bool hs_done_ = false;
    uint32_t pending_session_id_ = 0;
};
