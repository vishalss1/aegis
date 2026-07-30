#include "aegis/peer/peer.hpp"
#include <algorithm>
#include <cstdio>

PeerManager::PeerManager() = default;

void PeerManager::add_peer(const Peer& peer) {
    peers_[peer.node_id] = peer;
}

void PeerManager::remove_peer(const NodeId& node_id) {
    peers_.erase(node_id);
}

std::optional<Peer*> PeerManager::get_peer(const NodeId& node_id) {
    auto it = peers_.find(node_id);
    if (it != peers_.end()) return &it->second;
    return std::nullopt;
}

void PeerManager::mark_seen(const NodeId& node_id) {
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        it->second.last_seen = std::chrono::steady_clock::now();
        it->second.state = PeerState::Established;
    }
}

void PeerManager::mark_dead(const NodeId& node_id) {
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        it->second.state = PeerState::Dead;
    }
}

std::vector<const Peer*> PeerManager::all_peers() const {
    std::vector<const Peer*> result;
    result.reserve(peers_.size());
    for (const auto& [_, peer] : peers_)
        result.push_back(&peer);
    return result;
}

bool PeerManager::has_peer(const NodeId& node_id) const {
    return peers_.contains(node_id);
}

void PeerManager::set_keepalive_interval(std::chrono::seconds interval) {
    keepalive_interval_ = interval;
}

void PeerManager::set_dead_timeout(std::chrono::seconds timeout) {
    dead_timeout_ = timeout;
}

std::vector<Peer*> PeerManager::stale_peers() {
    std::vector<Peer*> stale;
    auto now = std::chrono::steady_clock::now();
    for (auto& [_, peer] : peers_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - peer.last_seen);
        if (age > dead_timeout_) {
            stale.push_back(&peer);
        }
    }
    return stale;
}
