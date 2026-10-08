#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/crypto/chacha20poly1305.hpp"
#include "aegis/crypto/primitives.hpp"
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

struct SessionSnapshot {
    uint32_t id = 0;
    NodeId peer_id{};
    bool established = false;
    bool initiated_locally = false;
    std::chrono::steady_clock::time_point established_at{};
};

inline constexpr size_t SESSION_MAX_ACTIVE = 256;
inline constexpr size_t SESSION_MAX_RETIRED = 256;
inline constexpr size_t SESSION_MAX_PENDING = 256;

struct SessionCapacityLimits {
    size_t active = SESSION_MAX_ACTIVE;
    size_t retired = SESSION_MAX_RETIRED;
    size_t pending = SESSION_MAX_PENDING;
};

class SessionManager {
public:
    explicit SessionManager(
        const Identity& identity,
        ProtocolClock& clock = system_protocol_clock(),
        RandomSource& random = system_random_source(),
        SessionCapacityLimits capacity = {},
        size_t padding_bucket_size = SESSION_PADDING_BUCKET_SIZE);

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

    // Read APIs expose metadata snapshots only. Keys, counters, and replay
    // windows remain private and are accessed under the manager mutex.
    std::optional<SessionSnapshot> get_session(const NodeId& peer_id) const;
    std::optional<SessionSnapshot> get_session_by_id(
        uint32_t session_id) const;

    // Step 15: tear down every session with `peer_id` (active and retired) and
    // drop any in-flight authenticated initiator state for it. Used when a peer
    // is judged dead so stale keys can never be used again.
    void remove_session(const NodeId& peer_id);

    // Step 15: drop retired sessions whose grace window has expired. Called by
    // the tunnel's maintenance loop; safe to call from anywhere.
    void purge_retired();

    // Incomplete initiator handshakes retain Noise ephemeral state only until
    // this deadline (15 s by default). Maintenance and handshake entry points
    // purge expired state before it can participate in collision handling.
    void purge_incomplete_handshakes();
    void set_handshake_timeout(std::chrono::milliseconds timeout);
    std::chrono::milliseconds handshake_timeout() const;

    // Successfully authenticated INIT transcripts remain in a replay cache
    // for two minutes by default, independent of active-session teardown.
    void purge_handshake_replays();
    void set_handshake_replay_ttl(std::chrono::milliseconds ttl);
    std::chrono::milliseconds handshake_replay_ttl() const;

    // Step 15: how long a rekeyed-away session keeps decrypting in-flight
    // packets (default 10 s). Tests shorten this so the purge path is
    // exercisable without sleeping through the production grace window.
    void set_retired_grace(std::chrono::milliseconds grace);
    std::chrono::milliseconds retired_grace() const;

    [[nodiscard]] size_t active_session_count() const;
    [[nodiscard]] size_t retired_session_count() const;
    [[nodiscard]] size_t pending_handshake_count() const;

    static std::array<uint8_t, 16> serialize_header(const PacketHeader& hdr);

private:
    struct SessionState {
        uint32_t id = 0;
        ChaCha20Poly1305Key send_key{};
        ChaCha20Poly1305Key recv_key{};
        uint64_t send_seq = 0;
        uint64_t recv_last = 0;
        std::bitset<2048> recv_window{};
        NodeId peer_id{};
        bool established = false;
        bool initiated_locally = false;
        std::chrono::steady_clock::time_point established_at{};
    };

    const Identity& identity_;
    ProtocolClock& clock_;
    RandomSource& random_;
    SessionCapacityLimits capacity_;
    size_t padding_bucket_size_ = SESSION_PADDING_BUCKET_SIZE;
    std::map<NodeId, SessionState> sessions_;
    std::map<uint32_t, NodeId> session_to_peer_;

    // Sessions superseded by a rekey, kept briefly so packets that were in
    // flight under the old keys still decrypt. Keyed by session_id so
    // get_session_by_id finds them. Expired entries are purged by purge_retired.
    struct RetiredSession {
        SessionState session;
        std::chrono::steady_clock::time_point expires;
    };
    static constexpr std::chrono::seconds RETIRED_GRACE = std::chrono::seconds(10);
    std::chrono::milliseconds retired_grace_{RETIRED_GRACE};
    std::map<uint32_t, RetiredSession> retired_;

    struct PendingInitiator {
        NodeId expected_peer_id{};
        X25519Key expected_peer_static{};
        std::unique_ptr<NoiseIkHandshake> handshake;
        std::chrono::steady_clock::time_point expires{};
    };
    static constexpr std::chrono::seconds HANDSHAKE_TIMEOUT =
        std::chrono::seconds(15);
    std::chrono::milliseconds handshake_timeout_{HANDSHAKE_TIMEOUT};
    std::map<uint32_t, PendingInitiator> pending_initiators_;

    static constexpr std::chrono::minutes HANDSHAKE_REPLAY_TTL =
        std::chrono::minutes(2);
    std::chrono::milliseconds handshake_replay_ttl_{HANDSHAKE_REPLAY_TTL};
    std::map<CryptoHash, std::chrono::steady_clock::time_point>
        handshake_replays_;
    mutable std::mutex mtx_;

    SessionState& create_session(
        const NodeId& peer_id, uint32_t session_id);
    void install_noise_keys(
        SessionState& session, NoiseIkSplitResult&& split,
        bool initiated_locally);
    [[nodiscard]] SessionState* find_session_locked(
        const NodeId& peer_id);
    [[nodiscard]] SessionState* find_session_by_id_locked(
        uint32_t session_id);
    [[nodiscard]] static SessionSnapshot snapshot(
        const SessionState& session);
    void purge_incomplete_handshakes_locked(
        std::chrono::steady_clock::time_point now);
    void purge_retired_locked(std::chrono::steady_clock::time_point now);
    void retire_session_locked(
        const SessionState& session,
        std::chrono::steady_clock::time_point now);
    void purge_handshake_replays_locked(
        std::chrono::steady_clock::time_point now);

    bool check_replay(SessionState& session, uint64_t seq);
    void update_replay(SessionState& session, uint64_t seq);

    static constexpr size_t REPLAY_BITS = 2048;
};
