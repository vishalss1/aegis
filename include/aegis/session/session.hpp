#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/crypto/chacha20poly1305.hpp"
#include "aegis/packet/header.hpp"
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

static constexpr size_t HANDSHAKE_PAYLOAD_SIZE = 68;

struct Session {
    uint32_t id;
    ChaCha20Poly1305Key send_key{};
    ChaCha20Poly1305Key recv_key{};
    uint64_t send_seq = 0;
    uint64_t recv_last = 0;
    uint64_t recv_window = 0;
    NodeId peer_id{};
    bool established = false;
};

class SessionManager {
public:
    SessionManager(const Identity& identity);

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    std::vector<uint8_t> create_handshake_init(uint32_t session_id);

    std::optional<std::vector<uint8_t>> handle_handshake_init(
        const std::vector<uint8_t>& message, const NodeId& sender_id);

    bool handle_handshake_resp(
        const std::vector<uint8_t>& message, uint32_t session_id);

    std::optional<std::vector<uint8_t>> encrypt_data(
        const NodeId& peer_id, const uint8_t* plaintext, size_t pt_len);

    std::optional<std::vector<uint8_t>> decrypt_data(
        const uint8_t* data, size_t len);

    std::optional<Session*> get_session(const NodeId& peer_id);
    std::optional<Session*> get_session_by_id(uint32_t session_id);

    static std::array<uint8_t, 16> serialize_header(const PacketHeader& hdr);

private:
    const Identity& identity_;
    std::map<NodeId, Session> sessions_;
    std::map<uint32_t, NodeId> session_to_peer_;

    X25519KeyPair ephemeral_;

    std::vector<uint8_t> build_handshake_message(
        uint8_t type, uint32_t session_id) const;

    Session& create_session(const NodeId& peer_id, uint32_t session_id);
    void derive_keys(Session& session, const X25519Key& shared_secret,
                     uint32_t session_id, bool initiator);

    bool check_replay(Session& session, uint64_t seq);
    void update_replay(Session& session, uint64_t seq);

    static X25519Key derive_master_secret(
        const X25519Key& our_priv, const X25519Key& their_pub);

    static std::array<uint8_t, 32> sha256(
        const uint8_t* data, size_t len);
    static std::array<uint8_t, 32> sha256(
        const uint8_t* d1, size_t l1,
        const uint8_t* d2, size_t l2);

    static constexpr size_t REPLAY_BITS = 64;
};
