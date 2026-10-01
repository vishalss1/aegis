#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/crypto/chacha20poly1305.hpp"
#include "aegis/crypto/random.hpp"
#include "aegis/packet/header.hpp"
#include "aegis/protocol/sources.hpp"
#include "aegis/session/handshake_v2.hpp"
#include "aegis/session/noise_ik.hpp"
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

struct Session {
    uint32_t id;
    ChaCha20Poly1305Key send_key{};
    ChaCha20Poly1305Key recv_key{};
    uint64_t send_seq = 0;
    uint64_t recv_last = 0;
    std::bitset<2048> recv_window{};
    NodeId peer_id{};
    bool established = false;
    // When the session's keys were established. Rekey (step 15) replaces a
    // session once it has lived past the rekey interval, so the age lives on
    // the session itself (a peer's connected_since is not reset by rekey).
    std::chrono::steady_clock::time_point established_at{};
};

class SessionManager {
public:
    explicit SessionManager(
        const Identity& identity,
        ProtocolClock& clock = system_protocol_clock(),
        RandomSource& random = system_random_source());

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    [[nodiscard]] std::optional<std::vector<uint8_t>> create_handshake_init(
        uint32_t session_id, const NodeId& expected_peer_id,
        const X25519Key& expected_peer_static);

    struct HandshakeResponse {
        std::vector<uint8_t> message;
        NodeId peer_id{};
        X25519Key peer_static_public_key{};
    };

    [[nodiscard]] std::optional<HandshakeResponse> handle_handshake_init(
        const std::vector<uint8_t>& message, uint32_t outer_session_id);

    bool handle_handshake_resp(
        const std::vector<uint8_t>& message, uint32_t session_id);

    // Encrypt a payload under the session's keys and return the wire frame
    // (16-byte header + 12-byte nonce + ciphertext + 16-byte tag). `packet_type`
    // is stamped into the plaintext header and becomes authenticated data.
    // `flags` is copied into the wire header (e.g. FLAG_RELAY on relayed frames).
    std::optional<std::vector<uint8_t>> encrypt_message(
        const NodeId& peer_id, uint8_t packet_type,
        const uint8_t* plaintext, size_t pt_len,
        uint8_t flags = 0);

    std::optional<std::vector<uint8_t>> encrypt_data(
        const NodeId& peer_id, const uint8_t* plaintext, size_t pt_len) {
        return encrypt_message(peer_id, TYPE_DATA, plaintext, pt_len);
    }

    struct DecryptedMessage {
        uint8_t packet_type;
        std::vector<uint8_t> payload;
    };

    // Verify and decrypt any session message (TYPE_DATA, TYPE_PEER_TABLE, ...).
    std::optional<DecryptedMessage> decrypt_message(
        const uint8_t* data, size_t len);

    std::optional<std::vector<uint8_t>> decrypt_data(
        const uint8_t* data, size_t len);

    std::optional<Session*> get_session(const NodeId& peer_id);
    std::optional<Session*> get_session_by_id(uint32_t session_id);

    // Step 15: tear down every session with `peer_id` (active and retired) and
    // drop any in-flight authenticated initiator state for it. Used when a peer
    // is judged dead so stale keys can never be used again.
    void remove_session(const NodeId& peer_id);

    // Step 15: drop retired sessions whose grace window has expired. Called by
    // the tunnel's maintenance loop; safe to call from anywhere.
    void purge_retired();

    // Step 15: how long a rekeyed-away session keeps decrypting in-flight
    // packets (default 10 s). Tests shorten this so the purge path is
    // exercisable without sleeping through the production grace window.
    void set_retired_grace(std::chrono::milliseconds grace);
    std::chrono::milliseconds retired_grace() const { return retired_grace_; }

    static std::array<uint8_t, 16> serialize_header(const PacketHeader& hdr);

private:
    const Identity& identity_;
    ProtocolClock& clock_;
    RandomSource& random_;
    std::map<NodeId, Session> sessions_;
    std::map<uint32_t, NodeId> session_to_peer_;

    // Sessions superseded by a rekey, kept briefly so packets that were in
    // flight under the old keys still decrypt. Keyed by session_id so
    // get_session_by_id finds them. Expired entries are purged by purge_retired.
    struct RetiredSession {
        Session session;
        std::chrono::steady_clock::time_point expires;
    };
    static constexpr std::chrono::seconds RETIRED_GRACE = std::chrono::seconds(10);
    std::chrono::milliseconds retired_grace_{RETIRED_GRACE};
    std::map<uint32_t, RetiredSession> retired_;

    struct PendingInitiator {
        NodeId expected_peer_id{};
        X25519Key expected_peer_static{};
        std::unique_ptr<NoiseIkHandshake> handshake;
    };
    std::map<uint32_t, PendingInitiator> pending_initiators_;
    std::mutex mtx_;

    Session& create_session(const NodeId& peer_id, uint32_t session_id);
    void install_noise_keys(Session& session, NoiseIkSplitResult&& split);

    bool check_replay(Session& session, uint64_t seq);
    void update_replay(Session& session, uint64_t seq);

    static constexpr size_t REPLAY_BITS = 2048;
};
