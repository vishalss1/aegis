#include "aegis/session/session.hpp"
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cstdlib>

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

SessionManager::SessionManager(const Identity& identity)
    : identity_(identity) {}

std::array<uint8_t, 32> SessionManager::sha256(
    const uint8_t* data, size_t len)
{
    std::array<uint8_t, 32> hash{};
    unsigned int out_len = 32;
    EVP_Digest(data, len, hash.data(), &out_len, EVP_sha256(), nullptr);
    return hash;
}

std::array<uint8_t, 32> SessionManager::sha256(
    const uint8_t* d1, size_t l1,
    const uint8_t* d2, size_t l2)
{
    std::array<uint8_t, 32> hash{};
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
    std::array<uint8_t, 16> buf{};
    buf[0] = hdr.version;
    buf[1] = hdr.packet_type;
    buf[2] = hdr.flags;
    buf[3] = hdr.reserved;
    buf[4] = (uint8_t)(hdr.session_id >> 24);
    buf[5] = (uint8_t)(hdr.session_id >> 16);
    buf[6] = (uint8_t)(hdr.session_id >> 8);
    buf[7] = (uint8_t)(hdr.session_id);
    buf[8] = (uint8_t)(hdr.sequence_number >> 24);
    buf[9] = (uint8_t)(hdr.sequence_number >> 16);
    buf[10] = (uint8_t)(hdr.sequence_number >> 8);
    buf[11] = (uint8_t)(hdr.sequence_number);
    buf[12] = (uint8_t)(hdr.payload_length >> 24);
    buf[13] = (uint8_t)(hdr.payload_length >> 16);
    buf[14] = (uint8_t)(hdr.payload_length >> 8);
    buf[15] = (uint8_t)(hdr.payload_length);
    return buf;
}

std::vector<uint8_t> SessionManager::build_handshake_message(
    uint8_t type, uint32_t session_id,
    const X25519KeyPair& ephemeral) const
{
    std::vector<uint8_t> msg;
    msg.reserve(HANDSHAKE_PAYLOAD_SIZE);

    uint32_t sid_be = bswap32(session_id);
    msg.insert(msg.end(), (uint8_t*)&sid_be, (uint8_t*)&sid_be + 4);

    msg.insert(msg.end(), ephemeral.public_key.begin(),
               ephemeral.public_key.end());

    msg.insert(msg.end(), identity_.node_id.begin(),
               identity_.node_id.end());

    return msg;
}

X25519Key SessionManager::derive_master_secret(
    const X25519Key& our_priv, const X25519Key& their_pub)
{
    auto opt = x25519_derive_shared_secret(our_priv, their_pub);
    if (!opt) {
        fprintf(stderr, "[session] derive_master_secret failed\n");
        return X25519Key{};
    }
    return *opt;
}

void SessionManager::derive_keys(
    Session& session, const X25519Key& shared_secret,
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
}

Session& SessionManager::create_session(
    const NodeId& peer_id, uint32_t session_id)
{
    auto [it, _] = sessions_.try_emplace(peer_id);
    it->second.peer_id = peer_id;
    it->second.id = session_id;
    it->second.send_seq = 0;
    it->second.recv_last = 0;
    it->second.recv_window = 0;
    session_to_peer_[session_id] = peer_id;
    return it->second;
}

std::optional<Session*> SessionManager::get_session(const NodeId& peer_id) {
    auto it = sessions_.find(peer_id);
    if (it != sessions_.end() && it->second.established)
        return &it->second;
    return std::nullopt;
}

std::optional<Session*> SessionManager::get_session_by_id(uint32_t session_id) {
    auto it = session_to_peer_.find(session_id);
    if (it == session_to_peer_.end())
        return std::nullopt;
    return get_session(it->second);
}

std::vector<uint8_t> SessionManager::create_handshake_init(uint32_t session_id) {
    X25519KeyPair ephemeral = x25519_generate_keypair();
    {
        std::lock_guard<std::mutex> lock(mtx_);
        ephemerals_[session_id] = ephemeral;
    }
    return build_handshake_message(TYPE_HANDSHAKE_INIT, session_id, ephemeral);
}

std::optional<std::vector<uint8_t>> SessionManager::handle_handshake_init(
    const std::vector<uint8_t>& message, const NodeId& sender_id)
{
    std::lock_guard<std::mutex> lock(mtx_);

    if (message.size() < HANDSHAKE_PAYLOAD_SIZE) {
        fprintf(stderr, "[session] handle_handshake_init: short message (%zu)\n",
                message.size());
        return std::nullopt;
    }

    uint32_t session_id;
    std::memcpy(&session_id, message.data(), 4);
    session_id = bswap32(session_id);

    X25519Key peer_eph{};
    std::memcpy(peer_eph.data(), message.data() + 4, 32);

    NodeId received_id{};
    std::memcpy(received_id.data(), message.data() + 36, 32);

    if (received_id != sender_id) {
        fprintf(stderr, "[session] handle_handshake_init: NodeID mismatch\n");
        return std::nullopt;
    }

    X25519KeyPair ephemeral = x25519_generate_keypair();

    X25519Key secret = derive_master_secret(ephemeral.private_key, peer_eph);
    if (std::all_of(secret.begin(), secret.end(), [](uint8_t b) { return b == 0; }))
        return std::nullopt;

    Session& sess = create_session(sender_id, session_id);
    derive_keys(sess, secret, session_id, false);
    sess.established = true;

    fprintf(stderr, "[session] session %08x established with ",
            session_id);
    for (auto b : sender_id) fprintf(stderr, "%02x", b);
    fprintf(stderr, "\n");

    return build_handshake_message(TYPE_HANDSHAKE_RESP, session_id, ephemeral);
}

bool SessionManager::handle_handshake_resp(
    const std::vector<uint8_t>& message, uint32_t session_id)
{
    std::lock_guard<std::mutex> lock(mtx_);

    if (message.size() < HANDSHAKE_PAYLOAD_SIZE) {
        fprintf(stderr, "[session] handle_handshake_resp: short message (%zu)\n",
                message.size());
        return false;
    }

    uint32_t resp_session_id;
    std::memcpy(&resp_session_id, message.data(), 4);
    resp_session_id = bswap32(resp_session_id);

    if (resp_session_id != session_id) {
        fprintf(stderr, "[session] handle_handshake_resp: session_id mismatch "
                "(got %08x, expected %08x)\n", resp_session_id, session_id);
        return false;
    }

    X25519Key peer_eph{};
    std::memcpy(peer_eph.data(), message.data() + 4, 32);

    NodeId peer_id{};
    std::memcpy(peer_id.data(), message.data() + 36, 32);

    auto eit = ephemerals_.find(session_id);
    if (eit == ephemerals_.end()) {
        fprintf(stderr, "[session] handle_handshake_resp: no ephemeral for "
                "session %08x\n", session_id);
        return false;
    }

    X25519Key secret = derive_master_secret(eit->second.private_key, peer_eph);
    ephemerals_.erase(eit);
    if (std::all_of(secret.begin(), secret.end(), [](uint8_t b) { return b == 0; }))
        return false;

    Session& sess = create_session(peer_id, session_id);
    derive_keys(sess, secret, session_id, true);
    sess.established = true;

    fprintf(stderr, "[session] session %08x established with ",
            session_id);
    for (auto b : peer_id) fprintf(stderr, "%02x", b);
    fprintf(stderr, "\n");

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

    uint64_t bit = (uint64_t)1 << (session.recv_last - seq);
    if (session.recv_window & bit)
        return false;

    return true;
}

void SessionManager::update_replay(Session& session, uint64_t seq) {
    if (seq > session.recv_last) {
        uint64_t shift = seq - session.recv_last;
        if (shift < REPLAY_BITS)
            session.recv_window <<= shift;
        else
            session.recv_window = 0;
        session.recv_last = seq;
    }

    uint64_t bit = (uint64_t)1 << (session.recv_last - seq);
    session.recv_window |= bit;
}

std::optional<std::vector<uint8_t>> SessionManager::encrypt_message(
    const NodeId& peer_id, uint8_t packet_type,
    const uint8_t* plaintext, size_t pt_len, uint8_t flags)
{
    auto sess_opt = get_session(peer_id);
    if (!sess_opt)
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
        fprintf(stderr, "[session] encrypt failed\n");
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
        fprintf(stderr, "[session] decrypt: packet too small (%zu)\n", len);
        return std::nullopt;
    }

    PacketHeader hdr{};
    hdr.version = data[0];
    hdr.packet_type = data[1];
    hdr.flags = data[2];
    hdr.reserved = data[3];
    hdr.session_id = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                     ((uint32_t)data[6] << 8) | (uint32_t)data[7];
    hdr.sequence_number = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
                          ((uint32_t)data[10] << 8) | (uint32_t)data[11];
    hdr.payload_length = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) |
                         ((uint32_t)data[14] << 8) | (uint32_t)data[15];

    if (hdr.version != PACKET_VERSION) {
        fprintf(stderr, "[session] decrypt: bad header\n");
        return std::nullopt;
    }

    size_t ct_len = hdr.payload_length;
    if (16 + 12 + ct_len + 16 != len) {
        fprintf(stderr, "[session] decrypt: length mismatch (hdr=%u, wire=%zu)\n",
                hdr.payload_length, len);
        return std::nullopt;
    }

    auto sess_opt = get_session_by_id(hdr.session_id);
    if (!sess_opt)
        return std::nullopt;

    Session& sess = *sess_opt.value();

    uint64_t wire_seq = ((uint64_t)hdr.sequence_number);

    if (!check_replay(sess, wire_seq)) {
        fprintf(stderr, "[session] drop: replay (seq=%llu)\n",
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
        fprintf(stderr, "[session] drop: payload too large (%zu)\n", ct_len);
        return std::nullopt;
    }
    if (!chacha20_poly1305_decrypt(
            sess.recv_key, nonce,
            ct_ptr, ct_len, tag_ptr, pt_buf,
            hdr_bytes.data(), hdr_bytes.size())) {
        fprintf(stderr, "[session] drop: decrypt/auth failure\n");
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
