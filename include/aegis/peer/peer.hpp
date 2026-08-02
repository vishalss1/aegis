#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/transport/transport.hpp"
#include <chrono>
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
    PeerManager();

    void set_session_manager(SessionManager* session_manager);

    Peer& upsert(const NodeId& node_id, const Key& public_key,
                 std::optional<Endpoint> endpoint = std::nullopt,
                 bool trusted = false);
    void add_peer(const Peer& peer);
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
    SessionManager* session_manager_ = nullptr;
    std::chrono::milliseconds keepalive_interval_{25000};
    std::chrono::milliseconds dead_timeout_{180000};
    mutable std::mutex mtx_;
};
