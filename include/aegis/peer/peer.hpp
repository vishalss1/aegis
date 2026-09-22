#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/protocol/sources.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

class SessionManager;
struct Session;

enum class PeerState {
    Unknown,
    Discovering,
    Connecting,
    Established,
    Dead
};

enum class PeerUpsertResult {
    Inserted,          // A new peer record was created.
    Updated,           // Existing non-identity fields were accepted.
    IdentityBound,     // An empty-key placeholder acquired its first key.
    IdentityConflict,  // A non-empty key differed from the existing binding.
    CapacityRejected   // A new record would exceed the configured limit.
};

inline constexpr size_t PEER_MANAGER_MAX_PEERS = 256;

struct Peer {
    NodeId node_id{};
    Key public_key{};
    std::optional<Endpoint> endpoint;   // nullopt for relay-only / not-yet-known peers
    PeerState state = PeerState::Unknown;
    std::chrono::steady_clock::time_point created_at{};
    std::chrono::steady_clock::time_point last_seen{};
    std::chrono::steady_clock::time_point last_keepalive{};
    std::chrono::steady_clock::time_point connected_since{};
    uint32_t connect_attempts = 0;
    bool trusted = false;   // statically configured vs learned via peer gossip
};

class PeerManager {
public:
    explicit PeerManager(
        size_t max_peers = PEER_MANAGER_MAX_PEERS,
        ProtocolClock& clock = system_protocol_clock());

    void set_session_manager(SessionManager* session_manager);

    // A non-empty public key is an identity binding and is immutable. An empty
    // placeholder may be populated once. A conflicting non-empty key rejects
    // the complete update and returns IdentityConflict. Trust is monotonic.
    // This method does not hash the key; network boundaries must first verify
    // hash_public_key(public_key) == node_id.
    PeerUpsertResult upsert(const NodeId& node_id, const Key& public_key,
                            std::optional<Endpoint> endpoint = std::nullopt,
                            bool trusted = false);
    // Inserts or replaces prevalidated local state. Returns false only when a
    // new record would exceed capacity; callers own identity validation.
    bool add_peer(const Peer& peer);
    void remove_peer(const NodeId& node_id);

    Peer* get_peer(const NodeId& node_id);
    const Peer* get_peer(const NodeId& node_id) const;
    bool has_peer(const NodeId& node_id) const;
    size_t size() const;

    std::vector<Peer*> all_peers();
    std::vector<const Peer*> all_peers() const;

    void mark_seen(const NodeId& node_id, std::optional<Endpoint> endpoint = std::nullopt);
    void mark_connecting(const NodeId& node_id);
    void mark_dead(const NodeId& node_id);
    void update_endpoint(const NodeId& node_id, const Endpoint& endpoint);

    std::optional<Session*> get_session(const NodeId& node_id) const;

    void set_keepalive_interval(std::chrono::milliseconds interval);
    void set_dead_timeout(std::chrono::milliseconds timeout);
    std::chrono::milliseconds keepalive_interval() const { return keepalive_interval_; }
    std::chrono::milliseconds dead_timeout() const { return dead_timeout_; }

    std::vector<Peer*> stale_peers();
    std::vector<Peer*> peers_needing_keepalive();

private:
    std::map<NodeId, Peer> peers_;
    size_t max_peers_;
    ProtocolClock& clock_;
    SessionManager* session_manager_ = nullptr;
    std::chrono::milliseconds keepalive_interval_{25000};
    std::chrono::milliseconds dead_timeout_{180000};
    mutable std::mutex mtx_;
};
