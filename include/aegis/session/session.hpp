#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/crypto/crypto.hpp"
#include <cstdint>
#include <vector>
#include <map>
#include <optional>

struct Session {
    uint32_t id;
    Key shared_secret;
    std::vector<uint8_t> send_key;
    std::vector<uint8_t> recv_key;
    uint32_t send_seq = 0;
    uint32_t recv_seq = 0;
    NodeId peer_id;
    bool established = false;
};

class SessionManager {
public:
    SessionManager(const Identity& identity);

    bool start_handshake(const NodeId& peer_id);
    bool handle_handshake_message(
        const NodeId& peer_id,
        const std::vector<uint8_t>& message
    );
    bool is_network_match(const NetworkId& peer_network) const;

    std::optional<Session*> get_session(const NodeId& peer_id);

    bool encrypt(const NodeId& peer_id,
                 const std::vector<uint8_t>& plaintext,
                 std::vector<uint8_t>& out);
    bool decrypt(const NodeId& peer_id,
                 const std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& plaintext);

private:
    const Identity& identity_;
    std::map<NodeId, Session> sessions_;

    bool check_replay(const Session& session, uint32_t seq);
    Session& create_session(const NodeId& peer_id);
};
