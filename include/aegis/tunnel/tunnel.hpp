#pragma once

#include "aegis/session/session.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/peer/peer_table.hpp"
#include "aegis/routing/routing.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/adapter/adapter.hpp"
#include "aegis/discovery/discovery.hpp"
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
    std::optional<std::string> stun_server; // e.g. "stun.l.google.com:19302"
    std::vector<TunnelPeer> peers;      // bootstrap candidates

    // Step 15 lifecycle tuning (ms). Zero values fall back to the defaults.
    // Tests set short values to exercise keep-alive / dead-detection / rekey
    // quickly; the CLI uses the defaults.
    uint32_t keepalive_interval_ms = 0;
    uint32_t dead_timeout_ms = 0;
    uint32_t rekey_interval_ms = 0;
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
    PeerManager& peers() { return peers_; }
    const RoutingEngine& routing() const { return routing_; }
    uint32_t interface_index() const { return adapter_.interface_index(); }
    // Observability: the current session (and its id / established_at) for a
    // peer, so tests can prove a rekey replaced the keys.
    SessionManager* session_manager() const { return session_manager_.get(); }
    std::optional<Endpoint> stun_public_endpoint() const { return stun_public_endpoint_; }

    // Step 14: presences seen via LAN-wide discovery. Deliberately
    // network-agnostic — every node on the LAN is visible regardless of
    // NetworkID; session/data stays isolated by the handshake gate.
    std::map<NodeId, Presence> presences() const { return discovery_.presences(); }

    // True once the encrypted session with `node_id` is established. start()
    // returns before any session exists; background connect loops establish
    // them as the peers become available.
    bool session_established(const NodeId& node_id) const;

    // Messaging & File Sharing over active sessions
    bool broadcast_chat(const std::string& text);
    bool send_file(const std::string& filepath, const std::optional<NodeId>& target_peer = std::nullopt);


private:
    Adapter adapter_;
    Transport transport_;
    Discovery discovery_;
    TunnelConfig config_;
    std::optional<Endpoint> stun_public_endpoint_;

    Identity identity_;
    std::unique_ptr<SessionManager> session_manager_;
    PeerManager peers_;
    RoutingEngine routing_;


    std::thread tx_thread_;
    std::thread gossip_thread_;
    std::thread maintenance_thread_;
    std::vector<std::thread> connect_threads_;
    std::atomic<bool> running_{false};
    uint32_t unrouted_count_ = 0;
    static constexpr int GOSSIP_INTERVAL_MS = 3000;

    // Step 15 lifecycle defaults (used when TunnelConfig leaves them at 0).
    static constexpr int KEEPALIVE_INTERVAL_MS = 25000;
    static constexpr int DEAD_TIMEOUT_MS = 180000;
    static constexpr int REKEY_INTERVAL_MS = 120000;
    static constexpr int MAINTENANCE_TICK_MS = 1000;
    static constexpr int CONNECT_BACKOFF_BASE_MS = 1000;
    static constexpr int CONNECT_BACKOFF_CAP_MS = 30000;

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

    // Step 15: last rekey attempt per peer, so a failed rekey is throttled to
    // one attempt per rekey interval instead of spamming handshakes. Guarded by
    // hs_mtx_.
    std::map<NodeId, std::chrono::steady_clock::time_point> rekey_attempts_;

    bool handshake_peer(const TunnelPeer& peer, bool force = false);
    void connect_loop(const TunnelPeer& peer);
    void install_configured_routes(const TunnelPeer& peer);
    void tx_loop();
    void gossip_loop();
    // Step 15: keep-alive + dead detection + rekey on a 1 s tick.
    void maintenance_loop();
    // Discovery: fold same-network presences for known peers into their
    // endpoint, so a peer that changed IP (DHCP/NAT rebinding) is re-joinable
    // without reconfiguring. Presence alone never creates a peer — a handshake
    // still requires an out-of-band-known public key.
    void refresh_endpoints_from_discovery();
    void send_keepalive(const Peer& peer);
    void rekey_peer(const NodeId& node_id);
    void rekey_due();
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
