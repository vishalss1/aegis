#include "aegis/session/session.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

SessionManager::SessionManager(const Identity& identity)
    : identity_(identity) {}

bool SessionManager::start_handshake(const NodeId& peer_id) {
    (void)peer_id;
    fprintf(stderr, "[session] start_handshake: not implemented\n");
    return false;
}

bool SessionManager::handle_handshake_message(
    const NodeId& peer_id, const std::vector<uint8_t>& message
) {
    (void)peer_id;
    (void)message;
    fprintf(stderr, "[session] handle_handshake_message: not implemented\n");
    return false;
}

bool SessionManager::is_network_match(const NetworkId& peer_network) const {
    return identity_.network_id == peer_network;
}

std::optional<Session*> SessionManager::get_session(const NodeId& peer_id) {
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end())
        return &it->second;
    return std::nullopt;
}

bool SessionManager::encrypt(
    const NodeId& peer_id,
    const std::vector<uint8_t>& plaintext,
    std::vector<uint8_t>& out
) {
    (void)peer_id; (void)plaintext; (void)out;
    fprintf(stderr, "[session] encrypt: not implemented\n");
    return false;
}

bool SessionManager::decrypt(
    const NodeId& peer_id,
    const std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& plaintext
) {
    (void)peer_id; (void)ciphertext; (void)plaintext;
    fprintf(stderr, "[session] decrypt: not implemented\n");
    return false;
}

bool SessionManager::check_replay(const Session& session, uint32_t seq) {
    (void)session;
    (void)seq;
    return true;
}

Session& SessionManager::create_session(const NodeId& peer_id) {
    auto [it, _] = sessions_.try_emplace(peer_id);
    return it->second;
}
