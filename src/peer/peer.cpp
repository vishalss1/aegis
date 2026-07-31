#include "aegis/peer/peer.hpp"
#include "aegis/session/session.hpp"
#include <algorithm>
#include <cstdio>

PeerManager::PeerManager() = default;

void PeerManager::set_session_manager(SessionManager* session_manager) {
    std::lock_guard<std::mutex> lock(mtx_);
    session_manager_ = session_manager;
}

Peer& PeerManager::upsert(const NodeId& node_id, const Key& public_key,
                          std::optional<Endpoint> endpoint, bool trusted) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        it->second.public_key = public_key;
        if (endpoint) it->second.endpoint = endpoint;
        it->second.trusted = trusted;
        return it->second;
    }
    Peer peer;
    peer.node_id = node_id;
    peer.public_key = public_key;
    peer.endpoint = endpoint;
    peer.trusted = trusted;
    peer.created_at = std::chrono::steady_clock::now();
    auto res = peers_.emplace(node_id, peer);
    return res.first->second;
}

void PeerManager::add_peer(const Peer& peer) {
    std::lock_guard<std::mutex> lock(mtx_);
    peers_[peer.node_id] = peer;
}

void PeerManager::remove_peer(const NodeId& node_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    peers_.erase(node_id);
}

Peer* PeerManager::get_peer(const NodeId& node_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it != peers_.end()) return &it->second;
    return nullptr;
}

const Peer* PeerManager::get_peer(const NodeId& node_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it != peers_.end()) return &it->second;
    return nullptr;
}

bool PeerManager::has_peer(const NodeId& node_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return peers_.contains(node_id);
}

size_t PeerManager::size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return peers_.size();
}

std::vector<Peer*> PeerManager::all_peers() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Peer*> result;
    result.reserve(peers_.size());
    for (auto& [_, peer] : peers_)
        result.push_back(&peer);
    return result;
}

std::vector<const Peer*> PeerManager::all_peers() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<const Peer*> result;
    result.reserve(peers_.size());
    for (const auto& [_, peer] : peers_)
        result.push_back(&peer);
    return result;
}

void PeerManager::mark_seen(const NodeId& node_id, std::optional<Endpoint> endpoint) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it == peers_.end()) return;
    auto& peer = it->second;
    auto now = std::chrono::steady_clock::now();
    if (endpoint) peer.endpoint = endpoint;
    if (peer.state != PeerState::Established) {
        peer.connected_since = now;
        peer.last_keepalive = now;
    }
    peer.last_seen = now;
    peer.state = PeerState::Established;
}

void PeerManager::mark_connecting(const NodeId& node_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it == peers_.end()) return;
    it->second.state = PeerState::Connecting;
    it->second.connect_attempts++;
}

void PeerManager::mark_dead(const NodeId& node_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it == peers_.end()) return;
    it->second.state = PeerState::Dead;
}

void PeerManager::update_endpoint(const NodeId& node_id, const Endpoint& endpoint) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = peers_.find(node_id);
    if (it == peers_.end()) return;
    it->second.endpoint = endpoint;
    it->second.last_seen = std::chrono::steady_clock::now();
}

std::optional<Session*> PeerManager::get_session(const NodeId& node_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!session_manager_ || !peers_.contains(node_id))
        return std::nullopt;
    return session_manager_->get_session(node_id);
}

void PeerManager::set_keepalive_interval(std::chrono::seconds interval) {
    std::lock_guard<std::mutex> lock(mtx_);
    keepalive_interval_ = interval;
}

void PeerManager::set_dead_timeout(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lock(mtx_);
    dead_timeout_ = timeout;
}

std::vector<Peer*> PeerManager::stale_peers() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Peer*> stale;
    auto now = std::chrono::steady_clock::now();
    for (auto& [_, peer] : peers_) {
        if (peer.state == PeerState::Dead) continue;
        auto reference = (peer.last_seen != decltype(peer.last_seen){})
            ? peer.last_seen : peer.created_at;
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - reference);
        if (age >= dead_timeout_)
            stale.push_back(&peer);
    }
    return stale;
}

std::vector<Peer*> PeerManager::peers_needing_keepalive() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Peer*> result;
    auto now = std::chrono::steady_clock::now();
    for (auto& [_, peer] : peers_) {
        if (peer.state != PeerState::Established) continue;
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - peer.last_keepalive);
        if (age >= keepalive_interval_)
            result.push_back(&peer);
    }
    return result;
}
