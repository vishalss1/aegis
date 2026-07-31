#pragma once

#include "aegis/session/session.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/routing/routing.hpp"
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
#include <map>
#include <memory>
#include <optional>

// One routable prefix this peer is responsible for.
// `prefix` uses the same representation as IPPacket::dest_ip (big-endian
// value, e.g. 10.20.0.0/24 -> 0x0A140000).
struct AllowedIP {
    uint32_t prefix;
    uint8_t  prefix_length;
};

// A statically-configured direct peer (mesh bootstrap joins later).
struct TunnelPeer {
    NodeId node_id{};
    Key public_key{};
    Endpoint endpoint{};
    std::vector<AllowedIP> allowed_ips;
};

struct TunnelConfig {
    std::optional<Identity> identity;   // nullopt -> generate a fresh one
    uint32_t local_ip;                  // network byte order (adapter convention)
    uint8_t  local_prefix;              // e.g. 24
    uint16_t listen_port;               // host byte order
    std::vector<TunnelPeer> peers;
};

class Tunnel {
public:
    Tunnel();
    ~Tunnel();

    Tunnel(const Tunnel&) = delete;
    Tunnel& operator=(const Tunnel&) = delete;

    bool start(const TunnelConfig& config, const std::string& adapter_name);
    void stop();

    const Identity& identity() const { return identity_; }
    const PeerManager& peers() const { return peers_; }
    const RoutingEngine& routing() const { return routing_; }

private:
    Adapter adapter_;
    Transport transport_;
    TunnelConfig config_;

    Identity identity_;
    std::unique_ptr<SessionManager> session_manager_;
    PeerManager peers_;
    RoutingEngine routing_;

    std::thread tx_thread_;
    std::atomic<bool> running_{false};
    uint32_t unrouted_count_ = 0;

    // Per-peer handshake state. `session_id` is ours (initiator picks it, the
    // responder adopts it from the received INIT).
    struct PendingHandshake {
        NodeId peer_id{};
        uint32_t session_id = 0;
        bool done = false;
    };
    std::map<NodeId, PendingHandshake> pending_handshakes_;
    std::mutex hs_mtx_;
    std::condition_variable hs_cv_;

    bool handshake_peer(const TunnelPeer& peer);
    void tx_loop();
    void rx_callback(const uint8_t* data, size_t len, Endpoint sender);
};
