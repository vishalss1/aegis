#pragma once

#include "aegis/session/session.hpp"
#include "aegis/identity/revocation.hpp"
#include "aegis/peer/peer.hpp"
#include "aegis/peer/peer_table.hpp"
#include "aegis/peer/gossip.hpp"
#include "aegis/routing/routing.hpp"
#include "aegis/routing/path_probe.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/transport/handshake_rate_limiter.hpp"
#include "aegis/transport/handshake_cookie.hpp"
#include "aegis/adapter/adapter.hpp"
#include "aegis/discovery/discovery.hpp"
#include "aegis/crypto/random.hpp"
#include "aegis/protocol/sources.hpp"
#include "aegis/protocol/endpoint_candidate.hpp"
#include "aegis/protocol/endpoint_punch.hpp"
#include "aegis/packet/mtu.hpp"
#include "aegis/packet/relay_limiter.hpp"
#include "aegis/file/transfer.hpp"
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
    std::string network_name;           // Human-readable network name
    uint32_t local_ip;                  // network byte order (adapter convention)
    uint8_t  local_prefix;              // e.g. 24
    uint16_t listen_port;               // host byte order
    uint32_t underlay_mtu = static_cast<uint32_t>(DEFAULT_UNDERLAY_MTU);
    uint8_t max_relay_depth = static_cast<uint8_t>(ONION_MAX_HOPS);
    uint16_t padding_bucket_size =
        static_cast<uint16_t>(SESSION_PADDING_BUCKET_SIZE);
    std::optional<std::string> stun_server; // e.g. "stun.l.google.com:19302"
    std::optional<Key> trusted_membership_issuer;
    std::vector<TunnelPeer> peers;      // bootstrap candidates

    // Step 15 lifecycle tuning (ms). Zero values fall back to the defaults.
    // Tests set short values to exercise keep-alive / dead-detection / rekey
    // quickly; the CLI uses the defaults.
    uint32_t keepalive_interval_ms = 0;
    uint32_t dead_timeout_ms = 0;
    uint32_t rekey_interval_ms = 0;
};

struct TunnelDropStats {
    uint64_t oversize_outbound = 0;
    uint64_t oversize_inbound = 0;
    uint64_t invalid_inbound = 0;
    uint64_t transport_oversize_send = 0;
    uint64_t transport_oversize_receive = 0;
    uint64_t transport_data_queue_drops = 0;
    uint64_t transport_control_queue_drops = 0;
    uint64_t relay_admitted_packets = 0;
    uint64_t relay_admitted_bytes = 0;
    uint64_t relay_peer_drops = 0;
    uint64_t relay_global_drops = 0;
    uint64_t relay_capacity_drops = 0;
};

class Tunnel {
public:
    Tunnel();
    Tunnel(ProtocolClock& clock, RandomSource& random);
    ~Tunnel();

    Tunnel(const Tunnel&) = delete;
    Tunnel& operator=(const Tunnel&) = delete;

    bool start(const TunnelConfig& config, const std::string& adapter_name);
    void stop();

    const Identity& identity() const { return identity_; }
    const std::string& network_name() const { return network_name_; }
    void set_network_name(const std::string& name) { network_name_ = name; }
    const PeerManager& peers() const { return peers_; }
    PeerManager& peers() { return peers_; }
    const RoutingEngine& routing() const { return routing_; }
    uint32_t interface_index() const { return adapter_.interface_index(); }
    uint32_t overlay_mtu() const { return overlay_mtu_; }
    TunnelDropStats drop_stats() const;
    // Observability: the current session (and its id / established_at) for a
    // peer, so tests can prove a rekey replaced the keys.
    SessionManager* session_manager() const { return session_manager_.get(); }
    std::optional<Endpoint> stun_public_endpoint() const { return stun_public_endpoint_; }
    std::vector<EndpointCandidate> local_endpoint_candidates() const;

    // Step 14: presences seen via LAN-wide discovery. Deliberately
    // network-agnostic — every node on the LAN is visible regardless of
    // NetworkID; session/data stays isolated by the handshake gate.
    std::map<NodeId, Presence> presences() const { return discovery_.presences(); }

    // True once the encrypted session with `node_id` is established. start()
    // returns before any session exists; background connect loops establish
    // them as the peers become available.
    bool session_established(const NodeId& node_id) const;
    [[nodiscard]] bool add_membership_revocation(
        const MembershipRevocation& revocation);
    [[nodiscard]] std::vector<MembershipRevocation>
    membership_revocations() const { return membership_revocations_.snapshot(); }

    // Messaging & File Sharing over active sessions
    bool broadcast_chat(const std::string& text);
    bool send_file(const std::string& filepath, const std::optional<NodeId>& target_peer = std::nullopt);

    // Network Ownership & Teardown
    bool is_creator() const { return is_creator_; }
    const NodeId& creator_node_id() const { return creator_node_id_; }
    void set_creator_node_id(const NodeId& cid, bool is_creator = false) {
        creator_node_id_ = cid;
        is_creator_ = is_creator;
        identity_.creator_node_id = cid;
    }

    bool delete_network();
    void leave_network();


private:
    Adapter adapter_;
    Transport transport_;
    Discovery discovery_;
    TunnelConfig config_;
    std::optional<Endpoint> stun_public_endpoint_;

    Identity identity_;
    std::string network_name_;
    NodeId creator_node_id_{};
    bool is_creator_ = false;
    ProtocolClock& clock_;
    RandomSource& random_;
    RelayForwardLimiter relay_forward_limiter_;
    HandshakeRateLimiter handshake_rate_limiter_;
    HandshakeCookieManager handshake_cookie_manager_;
    std::unique_ptr<SessionManager> session_manager_;
    PeerManager peers_;
    RoutingEngine routing_;
    GossipDeltaTracker gossip_delta_tracker_;
    MembershipRevocationStore membership_revocations_;
    PathProbeTracker path_probe_tracker_;
    EndpointPunchTracker endpoint_punch_tracker_;
    std::map<NodeId, ProtocolClock::time_point> endpoint_punch_attempts_;
    std::map<NodeId, ProtocolClock::time_point> endpoint_binding_refreshes_;
    mutable std::mutex endpoint_punch_attempts_mtx_;
    std::vector<EndpointCandidate> local_endpoint_candidates_;
    mutable std::mutex endpoint_candidates_mtx_;


    std::thread tx_thread_;
    std::thread gossip_thread_;
    std::thread maintenance_thread_;
    std::vector<std::thread> connect_threads_;
    std::atomic<bool> running_{false};
    uint32_t overlay_mtu_ = 0;
    std::atomic<uint64_t> oversize_outbound_drops_{0};
    std::atomic<uint64_t> oversize_inbound_drops_{0};
    std::atomic<uint64_t> invalid_inbound_drops_{0};
    uint32_t unrouted_count_ = 0;
    size_t gossip_round_ = 0;
    std::mutex gossip_send_mtx_;

    // Step 15 lifecycle defaults (used when TunnelConfig leaves them at 0).
    static constexpr int KEEPALIVE_INTERVAL_MS = 25000;
    static constexpr int DEAD_TIMEOUT_MS = 180000;
    static constexpr int REKEY_INTERVAL_MS = 120000;
    static constexpr int ENDPOINT_BINDING_REFRESH_MS = 30000;
    static constexpr int MAINTENANCE_TICK_MS = 1000;
    static constexpr int CONNECT_BACKOFF_BASE_MS = 1000;
    static constexpr int CONNECT_BACKOFF_CAP_MS = 30000;

    // Per-peer handshake state. `session_id` is ours (initiator picks it, the
    // responder adopts it from the received INIT).
    struct PendingHandshake {
        NodeId peer_id{};
        uint32_t session_id = 0;
        bool done = false;
        Endpoint endpoint{};
        std::optional<HandshakeCookie> cookie;
        bool cookie_updated = false;
    };
    std::map<NodeId, PendingHandshake> pending_handshakes_;
    std::mutex hs_mtx_;
    std::condition_variable hs_cv_;

    struct IncomingFileTransfer {
        std::string filename;
        uint64_t file_size = 0;
        uint32_t chunk_size = 0;
        uint32_t total_chunks = 0;
        CryptoHash content_hash{};
        std::string output_path;
        std::string final_path;
        FileChunkTracker chunks;
        bool completion_reported = false;
        ProtocolClock::time_point last_activity{};
    };
    std::map<FileTransferKey, IncomingFileTransfer> incoming_transfers_;
    std::mutex incoming_transfers_mtx_;
    std::map<FileTransferKey, FileSendWindow> outgoing_transfers_;
    std::mutex outgoing_transfers_mtx_;
    std::condition_variable outgoing_transfers_cv_;

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
    bool packet_fits_route(size_t packet_size, size_t route_depth);
    bool inject_inner_packet(const std::vector<uint8_t>& packet);
    void rx_callback(const uint8_t* data, size_t len, Endpoint sender);
    void handle_data_frame(const uint8_t* data, size_t len,
                           const PacketHeader& header, Endpoint sender);
    void handle_relay_frame(const uint8_t* data, size_t len,
                            const PacketHeader& header);
    void handle_keepalive_frame(const uint8_t* data, size_t len,
                                const PacketHeader& header, Endpoint sender);
    void handle_peer_table_frame(const uint8_t* data, size_t len,
                                 const PacketHeader& header, Endpoint sender);
    void handle_membership_revocation_frame(
        const uint8_t* data, size_t len, const PacketHeader& header,
        Endpoint sender);
    void handle_endpoint_candidates_frame(
        const uint8_t* data, size_t len, const PacketHeader& header,
        Endpoint sender);
    void handle_endpoint_punch_frame(
        const uint8_t* data, size_t len, const PacketHeader& header,
        Endpoint sender);
    void handle_chat_frame(const uint8_t* data, size_t len,
                           const PacketHeader& header, Endpoint sender);
    void handle_file_header_frame(const uint8_t* data, size_t len,
                                  const PacketHeader& header, Endpoint sender);
    void handle_file_chunk_frame(const uint8_t* data, size_t len,
                                 const PacketHeader& header, Endpoint sender);
    void handle_file_ack_frame(const uint8_t* data, size_t len,
                               const PacketHeader& header, Endpoint sender);
    void handle_file_cancel_frame(const uint8_t* data, size_t len,
                                  const PacketHeader& header,
                                  Endpoint sender);
    void send_file_ack(const NodeId& peer_id, Endpoint endpoint,
                       const FileTransferAck& ack);
    void send_file_cancel(const NodeId& peer_id, Endpoint endpoint,
                          uint64_t transfer_id, FileCancelReason reason);
    void expire_file_transfers();
    void probe_due_routes();
    bool send_path_probe(const Route& route, const PathProbeMessage& probe);
    void handle_path_probe(const NodeId& source, const PathProbeMessage& probe);
    void handle_path_probe_frame(const uint8_t* data, size_t len,
                                 const PacketHeader& header,
                                 Endpoint sender);
    void handle_network_teardown_frame(const uint8_t* data, size_t len,
                                       const PacketHeader& header);
    void handle_handshake_response_frame(const uint8_t* data, size_t len,
                                         const PacketHeader& header);
    void handle_handshake_cookie_frame(const uint8_t* data, size_t len,
                                       const PacketHeader& header,
                                       Endpoint sender);
    void handle_handshake_init_frame(const uint8_t* data, size_t len,
                                     const PacketHeader& header,
                                     Endpoint sender);
    // Step 13: peel one onion layer off a relayed frame and either deliver the
    // final packet or forward the inner layer to the revealed next hop.
    void handle_relay(const uint8_t* data, size_t len, uint32_t session_id);

    // Peer table propagation (step 12): after a session is established the
    // current table is sent to the new peer; on learning new peers the table
    // is re-announced to all other established peers so knowledge fans out.
    std::vector<AdvertisedPeer> build_advertised_peers() const;
    void send_peer_table(const NodeId& to_peer, bool force_full = false);
    void announce_peer_table(const std::optional<NodeId>& exclude,
                             bool force_full = false);
    void announce_membership_revocations(
        const std::optional<NodeId>& exclude = std::nullopt);
    void handle_peer_table(const NodeId& sender, const uint8_t* data, size_t len);
    void announce_endpoint_candidates(
        const NodeId& peer_id, Endpoint observed_peer);
    void send_endpoint_candidate_update(
        const NodeId& peer_id,
        const EndpointCandidateMessage& update);
    void record_local_endpoint_candidate(const EndpointCandidate& candidate);
    bool send_endpoint_punch(
        const NodeId& peer_id, Endpoint endpoint,
        const EndpointPunchMessage& message);
    void begin_endpoint_punching(const NodeId& peer_id);
    void refresh_endpoint_bindings();
};
