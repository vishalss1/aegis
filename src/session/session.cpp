#include "aegis/session/session.hpp"
#include "aegis/platform/logger.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <limits>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4242 4244)
static uint32_t bswap32(uint32_t x) {
    return _byteswap_ulong(x);
}
#pragma warning(pop)
#else
static uint32_t bswap32(uint32_t x) {
    return __builtin_bswap32(x);
}
#endif

SessionManager::SessionManager(
    const Identity& identity, ProtocolClock& clock, RandomSource& random)
    : identity_(identity), clock_(clock), random_(random) {}

std::array<uint8_t, 16> SessionManager::serialize_header(const PacketHeader& hdr) {
    return serialize_packet_header(hdr);
}

void SessionManager::install_noise_keys(
    Session& session, NoiseIkSplitResult&& split,
    bool initiated_locally) {
    session.send_key = std::move(split.send_key);
    session.recv_key = std::move(split.receive_key);
    session.established_at = clock_.now();
    session.established = true;
    session.initiated_locally = initiated_locally;
}

void SessionManager::set_retired_grace(std::chrono::milliseconds grace) {
    std::lock_guard<std::mutex> lock(mtx_);
    retired_grace_ = grace;
}

Session& SessionManager::create_session(
    const NodeId& peer_id, uint32_t session_id)
{
    // A rekey (or a fresh handshake replacing a dead session) supersedes the
    // prior established session. Keep the old one in the retired buffer for a
    // short grace window so packets already in flight under its keys still
    // decrypt; it is dropped by purge_retired once the window expires.
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end() && it->second.established) {
        retired_[it->second.id] = { it->second,
            clock_.now() + retired_grace_ };
        session_to_peer_.erase(it->second.id);
    }

    auto [n, _] = sessions_.try_emplace(peer_id);
    n->second.peer_id = peer_id;
    n->second.id = session_id;
    n->second.send_seq = 0;
    n->second.recv_last = 0;
    n->second.recv_window.reset();
    n->second.established = false;
    session_to_peer_[session_id] = peer_id;
    return n->second;
}

std::optional<Session*> SessionManager::get_session(const NodeId& peer_id) {
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end() && it->second.established)
        return &it->second;
    return std::nullopt;
}

std::optional<Session*> SessionManager::get_session_by_id(uint32_t session_id) {
    // Active session first...
    auto it = session_to_peer_.find(session_id);
    if (it != session_to_peer_.end())
        return get_session(it->second);
    // ...then sessions superseded by a rekey, still inside the grace window.
    // This lets in-flight packets that were encrypted under the old keys
    // decrypt until purge_retired drops them.
    auto rit = retired_.find(session_id);
    if (rit != retired_.end() && rit->second.session.established)
        return &rit->second.session;
    return std::nullopt;
}

void SessionManager::remove_session(const NodeId& peer_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end()) {
        session_to_peer_.erase(it->second.id);
        retired_.erase(it->second.id);
        sessions_.erase(it);
    }
    // Any retired sessions for this peer go too (only one session id per peer
    // is ever active, so the active removal above already covers it; kept for
    // symmetry in case a stale entry lingers).
    for (auto r = retired_.begin(); r != retired_.end();) {
        if (r->second.session.peer_id == peer_id)
            r = retired_.erase(r);
        else
            ++r;
    }
    // Drop any in-flight authenticated initiator state for this peer.
    for (auto pending = pending_initiators_.begin();
         pending != pending_initiators_.end();) {
        if (pending->second.expected_peer_id == peer_id) {
            pending = pending_initiators_.erase(pending);
        } else {
            ++pending;
        }
    }
}

void SessionManager::purge_retired() {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = clock_.now();
    for (auto it = retired_.begin(); it != retired_.end();) {
        if (it->second.expires <= now)
            it = retired_.erase(it);
        else
            ++it;
    }
}

void SessionManager::purge_incomplete_handshakes_locked(
    std::chrono::steady_clock::time_point now) {
    for (auto it = pending_initiators_.begin();
         it != pending_initiators_.end();) {
        if (it->second.expires <= now)
            it = pending_initiators_.erase(it);
        else
            ++it;
    }
}

void SessionManager::purge_incomplete_handshakes() {
    std::lock_guard<std::mutex> lock(mtx_);
    purge_incomplete_handshakes_locked(clock_.now());
}

void SessionManager::set_handshake_timeout(
    std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lock(mtx_);
    handshake_timeout_ = (std::max)(timeout, std::chrono::milliseconds::zero());
    purge_incomplete_handshakes_locked(clock_.now());
}

void SessionManager::purge_handshake_replays_locked(
    std::chrono::steady_clock::time_point now) {
    for (auto it = handshake_replays_.begin();
         it != handshake_replays_.end();) {
        if (it->second <= now)
            it = handshake_replays_.erase(it);
        else
            ++it;
    }
}

void SessionManager::purge_handshake_replays() {
    std::lock_guard<std::mutex> lock(mtx_);
    purge_handshake_replays_locked(clock_.now());
}

void SessionManager::set_handshake_replay_ttl(
    std::chrono::milliseconds ttl) {
    std::lock_guard<std::mutex> lock(mtx_);
    handshake_replay_ttl_ =
        (std::max)(ttl, std::chrono::milliseconds::zero());
    purge_handshake_replays_locked(clock_.now());
}

std::optional<std::vector<uint8_t>> SessionManager::create_handshake_init(
    uint32_t session_id, const NodeId& expected_peer_id,
    const X25519Key& expected_peer_static) {
    if (session_id == 0 ||
        std::all_of(expected_peer_static.begin(),
                    expected_peer_static.end(),
                    [](uint8_t value) { return value == 0; }) ||
        expected_peer_id !=
            hash_public_key(expected_peer_static)) {
        return std::nullopt;
    }

    const auto prologue = make_handshake_v2_prologue(
        identity_.network_id, session_id);
    if (!prologue)
        return std::nullopt;

    auto handshake = NoiseIkHandshake::create_initiator(
        identity_.keypair.private_key, expected_peer_static,
        *prologue, random_);
    if (!handshake)
        return std::nullopt;

    HandshakeV2InitFrame frame;
    frame.session_id = session_id;
    frame.network_id = identity_.network_id;
    const auto written = handshake->write_message({}, frame.noise_message);
    if (!written || written.bytes != frame.noise_message.size())
        return std::nullopt;

    const auto encoded = serialize_handshake_v2_init(frame);
    if (!encoded)
        return std::nullopt;

    std::lock_guard<std::mutex> lock(mtx_);
    const auto now = clock_.now();
    purge_incomplete_handshakes_locked(now);
    if (pending_initiators_.contains(session_id) ||
        session_to_peer_.contains(session_id) || retired_.contains(session_id)) {
        return std::nullopt;
    }
    pending_initiators_[session_id] = {
        expected_peer_id, expected_peer_static, std::move(handshake),
        now + handshake_timeout_};
    return std::vector<uint8_t>(encoded->begin(), encoded->end());
}

std::optional<SessionManager::HandshakeResponse>
SessionManager::handle_handshake_init(
    const std::vector<uint8_t>& message, uint32_t outer_session_id) {
    const auto frame = parse_handshake_v2_init(message);
    if (!frame || frame->session_id != outer_session_id ||
        frame->network_id != identity_.network_id) {
        aegis_log("[session] rejected non-canonical handshake-v2 init\n");
        return std::nullopt;
    }
    const auto replay_key = transcript_hash(
        CryptoHashAlgorithm::Blake2s256,
        {std::span<const uint8_t>(message)});
    if (!replay_key)
        return std::nullopt;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        const auto now = clock_.now();
        purge_incomplete_handshakes_locked(now);
        purge_handshake_replays_locked(now);
        if (handshake_replays_.contains(*replay_key))
            return std::nullopt;
        if (session_to_peer_.contains(frame->session_id) ||
            retired_.contains(frame->session_id) ||
            pending_initiators_.contains(frame->session_id)) {
            return std::nullopt;
        }
    }

    const auto prologue = make_handshake_v2_prologue(
        identity_.network_id, frame->session_id);
    if (!prologue)
        return std::nullopt;
    auto handshake = NoiseIkHandshake::create_responder(
        identity_.keypair.private_key, *prologue, random_);
    if (!handshake || !handshake->read_message(frame->noise_message, {}))
        return std::nullopt;

    const auto peer_static = handshake->remote_static_public_key();
    if (!peer_static ||
        std::all_of(peer_static->begin(), peer_static->end(),
                    [](uint8_t value) { return value == 0; }))
        return std::nullopt;
    const NodeId peer_id = hash_public_key(*peer_static);

    {
        std::lock_guard<std::mutex> lock(mtx_);
        const auto now = clock_.now();
        purge_incomplete_handshakes_locked(now);
        purge_handshake_replays_locked(now);
        if (handshake_replays_.contains(*replay_key))
            return std::nullopt;
        handshake_replays_[*replay_key] = now + handshake_replay_ttl_;
        const bool local_has_priority = identity_.node_id < peer_id;
        const auto active = sessions_.find(peer_id);
        const bool active_local_initiation =
            active != sessions_.end() && active->second.established &&
            active->second.initiated_locally;
        const auto pending = std::find_if(
            pending_initiators_.begin(), pending_initiators_.end(),
            [&](const auto& entry) {
                return entry.second.expected_peer_id == peer_id;
            });
        if (local_has_priority &&
            (pending != pending_initiators_.end() ||
             active_local_initiation)) {
            return std::nullopt;
        }
        if (!local_has_priority && pending != pending_initiators_.end())
            pending_initiators_.erase(pending);
    }

    HandshakeV2ResponseFrame response_frame;
    response_frame.session_id = frame->session_id;
    const auto written = handshake->write_message(
        {}, response_frame.noise_message);
    if (!written || written.bytes != response_frame.noise_message.size())
        return std::nullopt;
    auto split = handshake->split();
    const auto encoded = serialize_handshake_v2_response(response_frame);
    if (!split || !encoded)
        return std::nullopt;

    std::lock_guard<std::mutex> lock(mtx_);
    purge_incomplete_handshakes_locked(clock_.now());
    if (session_to_peer_.contains(frame->session_id) ||
        retired_.contains(frame->session_id) ||
        pending_initiators_.contains(frame->session_id)) {
        return std::nullopt;
    }
    Session& session = create_session(peer_id, frame->session_id);
    install_noise_keys(session, std::move(*split), false);

    HandshakeResponse response;
    response.message.assign(encoded->begin(), encoded->end());
    response.peer_id = peer_id;
    response.peer_static_public_key = *peer_static;
    return response;
}

bool SessionManager::handle_handshake_resp(
    const std::vector<uint8_t>& message, uint32_t session_id) {
    const auto frame = parse_handshake_v2_response(message);
    std::lock_guard<std::mutex> lock(mtx_);
    purge_incomplete_handshakes_locked(clock_.now());
    auto pending = pending_initiators_.find(session_id);
    if (pending == pending_initiators_.end())
        return false;
    if (!frame || frame->session_id != session_id) {
        pending_initiators_.erase(pending);
        return false;
    }

    PendingInitiator state = std::move(pending->second);
    pending_initiators_.erase(pending);
    if (!state.handshake ||
        !state.handshake->read_message(frame->noise_message, {})) {
        return false;
    }
    const auto remote = state.handshake->remote_static_public_key();
    if (!remote || *remote != state.expected_peer_static ||
        hash_public_key(*remote) != state.expected_peer_id) {
        return false;
    }
    auto split = state.handshake->split();
    if (!split)
        return false;

    const auto active = sessions_.find(state.expected_peer_id);
    if (active != sessions_.end() && active->second.established &&
        !active->second.initiated_locally &&
        state.expected_peer_id < identity_.node_id) {
        return false;
    }

    Session& session = create_session(state.expected_peer_id, session_id);
    install_noise_keys(session, std::move(*split), true);
    return true;
}

bool SessionManager::check_replay(Session& session, uint64_t seq) {
    if (session.recv_last >= REPLAY_BITS &&
        seq <= session.recv_last - REPLAY_BITS)
        return false;

    if (seq > session.recv_last)
        return true;

    if (seq + REPLAY_BITS <= session.recv_last)
        return false;

    if (session.recv_window.test(session.recv_last - seq))
        return false;

    return true;
}

void SessionManager::update_replay(Session& session, uint64_t seq) {
    if (seq > session.recv_last) {
        uint64_t shift = seq - session.recv_last;
        if (shift < REPLAY_BITS)
            session.recv_window <<= shift;
        else
            session.recv_window.reset();
        session.recv_last = seq;
    }

    session.recv_window.set(session.recv_last - seq);
}

std::optional<std::vector<uint8_t>> SessionManager::encrypt_message(
    const NodeId& peer_id, uint8_t packet_type,
    const uint8_t* plaintext, size_t pt_len, uint8_t flags)
{
    auto sess_opt = get_session(peer_id);
    if (!sess_opt)
        return std::nullopt;
    if ((pt_len > 0 && !plaintext) || pt_len > 4096 ||
        pt_len > static_cast<size_t>((std::numeric_limits<uint32_t>::max)()))
        return std::nullopt;

    Session& sess = *sess_opt.value();

    uint64_t send_seq = sess.send_seq++;

    // Nonce from session_id + send_seq
    ChaCha20Poly1305Nonce nonce{};
    uint32_t sid_be = bswap32(sess.id);
    uint32_t seq_hi = (uint32_t)(send_seq >> 32);
    uint32_t seq_lo = (uint32_t)(send_seq);
    std::memcpy(nonce.data(), &sid_be, 4);
    std::memcpy(nonce.data() + 4, &seq_hi, 4);
    std::memcpy(nonce.data() + 8, &seq_lo, 4);

    // 4096: enough for an MTU-sized IP packet plus onion layers (up to
    // ONION_MAX_HOPS layers of AEAD overhead) and the relay source NodeID.
    uint8_t ct_buf[4096];
    uint8_t tag_buf[CHACHA20_POLY1305_TAG_SIZE];

    PacketHeader hdr{};
    hdr.version = PACKET_VERSION;
    hdr.packet_type = packet_type;
    hdr.flags = flags;
    hdr.reserved = 0;
    hdr.session_id = sess.id;
    hdr.sequence_number = (uint32_t)(send_seq & 0xFFFFFFFF);
    hdr.payload_length = (uint32_t)pt_len;

    auto hdr_bytes = serialize_header(hdr);

    if (!chacha20_poly1305_encrypt(
            sess.send_key, nonce,
            plaintext, pt_len, ct_buf, tag_buf,
            hdr_bytes.data(), hdr_bytes.size())) {
        aegis_log( "[session] encrypt failed\n");
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    out.reserve(16 + 12 + pt_len + 16);
    out.insert(out.end(), hdr_bytes.begin(), hdr_bytes.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct_buf, ct_buf + pt_len);
    out.insert(out.end(), tag_buf, tag_buf + CHACHA20_POLY1305_TAG_SIZE);

    return out;
}

std::optional<SessionManager::DecryptedMessage> SessionManager::decrypt_message(
    const uint8_t* data, size_t len)
{
    if (len < 16 + 12 + CHACHA20_POLY1305_TAG_SIZE) {
        aegis_log( "[session] decrypt: packet too small (%zu)\n", len);
        return std::nullopt;
    }

    const auto parsed_header = parse_packet_header(
        std::span<const uint8_t>(data, PACKET_HEADER_SIZE));
    if (!parsed_header)
        return std::nullopt;
    const PacketHeader& hdr = *parsed_header;

    if (hdr.version != PACKET_VERSION || hdr.reserved != 0 ||
        (hdr.flags & static_cast<uint8_t>(~PACKET_KNOWN_FLAGS)) != 0) {
        aegis_log( "[session] decrypt: bad header\n");
        return std::nullopt;
    }

    size_t ct_len = hdr.payload_length;
    if (16 + 12 + ct_len + 16 != len) {
        aegis_log( "[session] decrypt: length mismatch (hdr=%u, wire=%zu)\n",
                hdr.payload_length, len);
        return std::nullopt;
    }

    auto sess_opt = get_session_by_id(hdr.session_id);
    if (!sess_opt)
        return std::nullopt;

    Session& sess = *sess_opt.value();

    uint64_t wire_seq = ((uint64_t)hdr.sequence_number);

    if (!check_replay(sess, wire_seq)) {
        aegis_log( "[session] drop: replay (seq=%llu)\n",
                (unsigned long long)wire_seq);
        return std::nullopt;
    }

    const uint8_t* nonce_ptr = data + 16;
    const uint8_t* ct_ptr = data + 16 + 12;
    const uint8_t* tag_ptr = data + 16 + 12 + ct_len;

    ChaCha20Poly1305Nonce nonce{};
    std::memcpy(nonce.data(), nonce_ptr, 12);

    std::array<uint8_t, 16> hdr_bytes;
    std::memcpy(hdr_bytes.data(), data, 16);

    uint8_t pt_buf[4096];
    if (ct_len > sizeof(pt_buf)) {
        aegis_log( "[session] drop: payload too large (%zu)\n", ct_len);
        return std::nullopt;
    }
    if (!chacha20_poly1305_decrypt(
            sess.recv_key, nonce,
            ct_ptr, ct_len, tag_ptr, pt_buf,
            hdr_bytes.data(), hdr_bytes.size())) {
        aegis_log( "[session] drop: decrypt/auth failure\n");
        return std::nullopt;
    }

    update_replay(sess, wire_seq);

    DecryptedMessage out;
    out.packet_type = hdr.packet_type;
    out.payload.assign(pt_buf, pt_buf + ct_len);
    return out;
}

std::optional<std::vector<uint8_t>> SessionManager::decrypt_data(
    const uint8_t* data, size_t len)
{
    auto msg = decrypt_message(data, len);
    if (!msg || msg->packet_type != TYPE_DATA)
        return std::nullopt;
    return std::move(msg->payload);
}
