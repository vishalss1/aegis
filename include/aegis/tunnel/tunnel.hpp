#pragma once

#include "aegis/session/session.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/peer/peer_table.hpp"
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

// A bootstrap candidate. The node joins the mesh by connecting to any of the
// configured candidates that is reachable (availability-based join) — a
// candidate that is down is retried in the background, not treated as fatal.
// Endpoint is only the bootstrap address; the peer's identity is its NodeID.
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
    std::vector<TunnelPeer> peers;      // bootstrap candidates
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
    uint32_t interface_index() const { return adapter_.interface_index(); }

    // True once the encrypted session with `node_id` is established. start()
    // returns before any session exists; background connect loops establish
    // them as the peers become available.
    bool session_established(const NodeId& node_id) const;

private:
    Adapter adapter_;
    Transport transport_;
    TunnelConfig config_;

    Identity identity_;
    std::unique_ptr<SessionManager> session_manager_;
    PeerManager peers_;
    RoutingEngine routing_;

    std::thread tx_thread_;
    std::thread gossip_thread_;
    std::vector<std::thread> connect_threads_;
    std::atomic<bool> running_{false};
    uint32_t unrouted_count_ = 0;
    static constexpr int GOSSIP_INTERVAL_MS = 3000;

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
    void connect_loop(const TunnelPeer& peer);
    void tx_loop();
    void gossip_loop();
    void rx_callback(const uint8_t* data, size_t len, Endpoint sender);
    // Step 13: peel one onion layer off a relayed frame and either deliver the
    // final packet or forward the inner layer to the revealed next hop.
    void handle_relay(const uint8_t* data, size_t len, uint32_t session_id);

    // Peer table propagation (step 12): after a session is established the
    // current table is sent to the new peer; on learning new peers the table
    // is re-announced to all other established peers so knowledge fans out.
    std::vector<AdvertisedPeer> build_advertised_peers() const;
    void send_peer_table(const NodeId& to_peer);
    void announce_peer_table(const std::optional<NodeId>& exclude);
    void handle_peer_table(const NodeId& sender, const uint8_t* data, size_t len);
};
