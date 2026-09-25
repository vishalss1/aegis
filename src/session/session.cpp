#include "aegis/session/session.hpp"
#include "aegis/platform/logger.hpp"
#include "aegis/protocol/wire.hpp"
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cstdlib>
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

SessionManager::SessionManager(const Identity& identity, ProtocolClock& clock)
    : identity_(identity), clock_(clock) {}

SecretBytes<32> SessionManager::sha256(
    const uint8_t* data, size_t len)
{
    SecretBytes<32> hash{};
    unsigned int out_len = 32;
    EVP_Digest(data, len, hash.data(), &out_len, EVP_sha256(), nullptr);
    return hash;
}

SecretBytes<32> SessionManager::sha256(
    const uint8_t* d1, size_t l1,
    const uint8_t* d2, size_t l2)
{
    SecretBytes<32> hash{};
    unsigned int out_len = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, d1, l1);
        EVP_DigestUpdate(ctx, d2, l2);
        EVP_DigestFinal_ex(ctx, hash.data(), &out_len);
        EVP_MD_CTX_free(ctx);
    }
    return hash;
}

std::array<uint8_t, 16> SessionManager::serialize_header(const PacketHeader& hdr) {
    return serialize_packet_header(hdr);
}

std::vector<uint8_t> SessionManager::build_handshake_message(
    uint32_t session_id,
    const X25519KeyPair& ephemeral) const
{
    std::vector<uint8_t> msg(HANDSHAKE_PAYLOAD_SIZE);
    WireWriter writer(msg);
    if (!writer.write_u32(session_id) ||
        !writer.write_bytes(ephemeral.public_key) ||
        !writer.write_bytes(identity_.node_id) ||
        !writer.write_bytes(identity_.network_id) || !writer.finished())
        return {};
    return msg;
}

std::optional<SessionManager::HandshakeMessage>
SessionManager::parse_handshake_message(
    const std::vector<uint8_t>& message) {
    WireReader reader(message);
    HandshakeMessage parsed;
    const auto session_id = reader.read_u32();
    const auto ephemeral_public = reader.read_bytes(X25519_KEY_SIZE);
    const auto node_id = reader.read_bytes(NODE_ID_SIZE);
    const auto network_id = reader.read_bytes(NETWORK_ID_SIZE);
    if (!session_id || !ephemeral_public || !node_id || !network_id ||
        !reader.finished())
        return std::nullopt;

    parsed.session_id = *session_id;
    std::copy(ephemeral_public->begin(), ephemeral_public->end(),
              parsed.ephemeral_public.begin());
    std::copy(node_id->begin(), node_id->end(), parsed.node_id.begin());
    std::copy(network_id->begin(), network_id->end(),
              parsed.network_id.begin());
    return parsed;
}

X25519SharedSecret SessionManager::derive_master_secret(
    const X25519PrivateKey& our_priv, const X25519Key& their_pub)
{
    auto opt = x25519_derive_shared_secret(our_priv, their_pub);
    if (!opt) {
        aegis_log( "[session] derive_master_secret failed\n");
        return X25519SharedSecret{};
    }
    return *opt;
}

void SessionManager::derive_keys(
    Session& session, const X25519SharedSecret& shared_secret,
    uint32_t session_id, bool initiator)
{
    // send_key = SHA-256(shared_secret || session_id_be || "send")
    // recv_key = SHA-256(shared_secret || session_id_be || "recv")
    uint32_t sid_be = bswap32(session_id);
    const char label_send[] = "send";
    const char label_recv[] = "recv";

    auto k1 = sha256(shared_secret.data(), shared_secret.size(),
                     (const uint8_t*)&sid_be, 4);
    auto k1b = sha256(k1.data(), k1.size(),
                      (const uint8_t*)label_send, 4);
    std::memcpy(session.send_key.data(), k1b.data(), 32);

    auto k2 = sha256(shared_secret.data(), shared_secret.size(),
                     (const uint8_t*)&sid_be, 4);
    auto k2b = sha256(k2.data(), k2.size(),
                      (const uint8_t*)label_recv, 4);
    std::memcpy(session.recv_key.data(), k2b.data(), 32);

    if (!initiator) {
        std::swap(session.send_key, session.recv_key);
    }

    // The session becomes active (and its rekey timer starts) only once both
    // sides have the derived keys. Time is captured here rather than at
    // create_session so a failed handshake never leaves a "fresh" timestamp.
    session.established_at = clock_.now();
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
    // Drop any in-flight handshake ephemeral keyed by a session we just killed.
    for (auto e = ephemerals_.begin(); e != ephemerals_.end();) {
        auto s2p = session_to_peer_.find(e->first);
        if (s2p == session_to_peer_.end() ||
            sessions_.find(s2p->second) == sessions_.end()) {
            e = ephemerals_.erase(e);
        } else {
            ++e;
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

std::vector<uint8_t> SessionManager::create_handshake_init(uint32_t session_id) {
    X25519KeyPair ephemeral = x25519_generate_keypair();
    auto message = build_handshake_message(session_id, ephemeral);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        ephemerals_[session_id] = std::move(ephemeral);
    }
    return message;
}

std::optional<std::vector<uint8_t>> SessionManager::handle_handshake_init(
    const std::vector<uint8_t>& message, const NodeId& sender_id)
{
    std::lock_guard<std::mutex> lock(mtx_);

    const auto parsed = parse_handshake_message(message);
    if (!parsed) {
        aegis_log( "[session] handle_handshake_init: invalid message (%zu)\n",
                message.size());
        return std::nullopt;
    }

    const uint32_t session_id = parsed->session_id;
    const X25519Key& peer_eph = parsed->ephemeral_public;
    const NodeId& received_id = parsed->node_id;

    if (received_id != sender_id) {
        aegis_log( "[session] handle_handshake_init: NodeID mismatch\n");
        return std::nullopt;
    }

    // Step 14: NetworkID gating. The responder refuses the handshake before
    // any keys are derived or a session is created — a cross-network peer is
    // visible (discovery) but unreachable. This is what makes independent
    // meshes on a shared LAN stay isolated.
    const NetworkId& peer_network = parsed->network_id;
    if (peer_network != identity_.network_id) {
        aegis_log( "[session] reject handshake init: network mismatch "
                        "(peer %02x%02x..., expected net %02x...)\n",
                received_id[0], received_id[1], identity_.network_id[0]);
        return std::nullopt;
    }

    X25519KeyPair ephemeral = x25519_generate_keypair();

    X25519SharedSecret secret = derive_master_secret(
        ephemeral.private_key, peer_eph);
    if (std::all_of(secret.begin(), secret.end(), [](uint8_t b) { return b == 0; }))
        return std::nullopt;

    Session& sess = create_session(sender_id, session_id);
    derive_keys(sess, secret, session_id, false);
    sess.established = true;

    aegis_log( "[session] session %08x established with ",
            session_id);
    for (auto b : sender_id) aegis_log( "%02x", b);
    aegis_log( "\n");

    return build_handshake_message(session_id, ephemeral);
}

bool SessionManager::handle_handshake_resp(
    const std::vector<uint8_t>& message, uint32_t session_id)
{
    std::lock_guard<std::mutex> lock(mtx_);

    const auto parsed = parse_handshake_message(message);
    if (!parsed) {
        aegis_log( "[session] handle_handshake_resp: invalid message (%zu)\n",
                message.size());
        return false;
    }

    const uint32_t resp_session_id = parsed->session_id;

    if (resp_session_id != session_id) {
        aegis_log( "[session] handle_handshake_resp: session_id mismatch "
                "(got %08x, expected %08x)\n", resp_session_id, session_id);
        return false;
    }

    const X25519Key& peer_eph = parsed->ephemeral_public;
    const NodeId& peer_id = parsed->node_id;

    // Step 14: initiator-side gate. The responder gates first, so this should
    // never fire; kept as defense in depth so a forged/misconfigured response
    // from a different network can never establish a session.
    const NetworkId& peer_network = parsed->network_id;
    if (peer_network != identity_.network_id) {
        aegis_log( "[session] reject handshake resp: network mismatch "
                        "(peer %02x%02x...)\n",
                peer_id[0], peer_id[1]);
        ephemerals_.erase(session_id);
        return false;
    }

    auto eit = ephemerals_.find(session_id);
    if (eit == ephemerals_.end()) {
        aegis_log( "[session] handle_handshake_resp: no ephemeral for "
                "session %08x\n", session_id);
        return false;
    }

    X25519SharedSecret secret = derive_master_secret(
        eit->second.private_key, peer_eph);
    ephemerals_.erase(eit);
    if (std::all_of(secret.begin(), secret.end(), [](uint8_t b) { return b == 0; }))
        return false;

    Session& sess = create_session(peer_id, session_id);
    derive_keys(sess, secret, session_id, true);
    sess.established = true;

    aegis_log( "[session] session %08x established with ",
            session_id);
    for (auto b : peer_id) aegis_log( "%02x", b);
    aegis_log( "\n");

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
