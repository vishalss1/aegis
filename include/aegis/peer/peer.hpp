#pragma once

#include "aegis/identity/identity.hpp"
#include <cstdint>
#include <string>
#include <chrono>
#include <map>
#include <optional>
#include <winsock2.h>

enum class PeerState {
    Unknown,
    Discovering,
    Connecting,
    Established,
    Dead
};

struct Peer {
    NodeId node_id;
    Key public_key;
    sockaddr_in endpoint;
    PeerState state = PeerState::Unknown;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point last_keepalive;
};

class PeerManager {
public:
    PeerManager();

    void add_peer(const Peer& peer);
    void remove_peer(const NodeId& node_id);
    std::optional<Peer*> get_peer(const NodeId& node_id);

    void mark_seen(const NodeId& node_id);
    void mark_dead(const NodeId& node_id);

    std::vector<const Peer*> all_peers() const;

    bool has_peer(const NodeId& node_id) const;

    void set_keepalive_interval(std::chrono::seconds interval);
    void set_dead_timeout(std::chrono::seconds timeout);

    std::vector<Peer*> stale_peers();

private:
    std::map<NodeId, Peer> peers_;
    std::chrono::seconds keepalive_interval_{25};
    std::chrono::seconds dead_timeout_{180};
};
