#include "aegis/tunnel/tunnel.hpp"
#include "aegis/packet/packet.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <algorithm>

Tunnel::Tunnel() = default;

Tunnel::~Tunnel() { stop(); }

static uint32_t rand_session_id() {
    // Unique per call within this process (multi-peer needs distinct ids for
    // every session on a node) and time-mixed so concurrent nodes rarely
    // collide. The old srand(time()) reseed produced identical ids for all
    // handshakes started in the same second, corrupting session_to_peer_.
    static std::atomic<uint32_t> counter{0};
    uint32_t n = counter.fetch_add(1);
    uint64_t t = (uint64_t)std::chrono::high_resolution_clock::now()
                     .time_since_epoch().count();
    return (uint32_t)((t >> 16) ^ (n * 0x9E3779B1u));
}

bool Tunnel::start(const TunnelConfig& config, const std::string& adapter_name) {
    config_ = config;

    if (config_.identity)
        identity_ = *config_.identity;
    else
        identity_ = Identity::create(NetworkId{});

    fprintf(stderr, "[tunnel] node_id: ");
    for (auto b : identity_.node_id) fprintf(stderr, "%02x", b);
    fprintf(stderr, "\n");

    session_manager_ = std::make_unique<SessionManager>(identity_);
    peers_.set_session_manager(session_manager_.get());

    // Bootstrap candidates -> static peer table + direct routes. Routes are
    // Direct; relay next-hops arrive with peer propagation (step 12+).
    for (const auto& p : config_.peers) {
        peers_.upsert(p.node_id, p.public_key, p.endpoint, true);
        for (const auto& aip : p.allowed_ips) {
            Route r;
            r.prefix = aip.prefix;
            r.prefix_length = aip.prefix_length;
            r.type = NextHopType::Direct;
            r.next_hop = p.node_id;
            r.destination = p.node_id;
            if (!routing_.add_route(r))
                fprintf(stderr, "[tunnel] warning: route %08x/%u rejected\n",
                        aip.prefix, aip.prefix_length);
        }
    }

    wchar_t wname[64];
    size_t converted = 0;
    mbstowcs_s(&converted, wname, adapter_name.c_str(), _TRUNCATE);

    if (!adapter_.create(config.local_ip, config.local_prefix, wname)) {
        fprintf(stderr, "[tunnel] adapter creation failed\n");
        return false;
    }

    if (!transport_.bind(config.listen_port)) {
        fprintf(stderr, "[tunnel] bind port %u failed\n", config.listen_port);
        adapter_.close();
        return false;
    }

    fprintf(stderr, "[tunnel] listening on %u, %zu configured peer(s)\n",
            config.listen_port, config_.peers.size());

    transport_.start_receive(
        [this](const uint8_t* d, size_t l, Endpoint s) { rx_callback(d, l, s); });

    // Mesh bootstrap: start the data path immediately, then establish sessions
    // with every bootstrap candidate in background threads. Each candidate is
    // retried until it becomes available (availability-based join, no fixed
    // entry point) — an unreachable peer must not block or fail the node.
    running_ = true;
    tx_thread_ = std::thread(&Tunnel::tx_loop, this);
    for (const auto& p : config_.peers) {
        connect_threads_.emplace_back(&Tunnel::connect_loop, this, p);
    }

    fprintf(stderr, "[tunnel] up, %zu bootstrap candidate(s), joining in background\n",
            config_.peers.size());
    return true;
}

void Tunnel::stop() {
    running_ = false;
    hs_cv_.notify_all();  // wake responder connect loops blocked on the handshake
    transport_.stop_receive();
    if (tx_thread_.joinable()) tx_thread_.join();
    for (auto& t : connect_threads_)
        if (t.joinable()) t.join();
    connect_threads_.clear();
    transport_.close();
    adapter_.close();
}

bool Tunnel::session_established(const NodeId& node_id) const {
    return session_manager_->get_session(node_id).has_value();
}

void Tunnel::connect_loop(const TunnelPeer& peer) {
    fprintf(stderr, "[tunnel] connect loop for peer %02x%02x...\n",
            peer.node_id[0], peer.node_id[1]);
    while (running_) {
        if (session_established(peer.node_id))
            return;
        if (handshake_peer(peer))
            return;
        if (!running_) return;
        // Availability-based join: wait before retrying an unreachable peer so
        // the node stays up for whoever is reachable. (Backoff policy is a
        // later failure-detection concern.)
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

bool Tunnel::handshake_peer(const TunnelPeer& peer) {
    if (session_established(peer.node_id))
        return true;

    peers_.mark_connecting(peer.node_id);

    // Deterministic role: the lower NodeID initiates. Both sides of a pair
    // compute the same role, which prevents the simultaneous-init race.
    bool initiator = identity_.node_id < peer.node_id;

    fprintf(stderr, "[tunnel] handshake with peer %02x%02x... (%s)\n",
            peer.node_id[0], peer.node_id[1],
            initiator ? "initiator" : "responder");

    if (initiator) {
        uint32_t sid = rand_session_id();
        {
            std::lock_guard<std::mutex> lock(hs_mtx_);
            pending_handshakes_[peer.node_id] = {peer.node_id, sid, false};
        }

        auto init_payload = session_manager_->create_handshake_init(sid);
        PacketHeader hdr{};
        hdr.version = PACKET_VERSION;
        hdr.packet_type = TYPE_HANDSHAKE_INIT;
        hdr.session_id = sid;
        hdr.payload_length = (uint32_t)init_payload.size();
        auto hdr_bytes = SessionManager::serialize_header(hdr);
        std::vector<uint8_t> wire;
        wire.reserve(16 + init_payload.size());
        wire.insert(wire.end(), hdr_bytes.begin(), hdr_bytes.end());
        wire.insert(wire.end(), init_payload.begin(), init_payload.end());

        std::unique_lock<std::mutex> lock(hs_mtx_);
        for (int attempt = 0; attempt < 10; attempt++) {
            transport_.send(wire.data(), wire.size(), peer.endpoint);
            if (hs_cv_.wait_for(lock, std::chrono::seconds(1),
                    [&] { return !running_ ||
                             pending_handshakes_[peer.node_id].done; }))
                break;
            fprintf(stderr, "[tunnel] handshake retry %d for peer %02x%02x...\n",
                    attempt + 1, peer.node_id[0], peer.node_id[1]);
        }
        if (!running_) return false;
        if (!pending_handshakes_[peer.node_id].done &&
            !session_established(peer.node_id)) {
            fprintf(stderr, "[tunnel] handshake failed for peer %02x%02x...\n",
                    peer.node_id[0], peer.node_id[1]);
            return false;
        }
        peers_.mark_seen(peer.node_id);
        return true;
    }

    // Responder: wait for the peer's INIT; rx_callback responds and marks done.
    std::unique_lock<std::mutex> lock(hs_mtx_);
    if (!pending_handshakes_.contains(peer.node_id))
        pending_handshakes_[peer.node_id] = {peer.node_id, 0, false};
    // The INIT may already have been answered by rx before we registered, so
    // never wait on a stale flag — re-check the session right away.
    if (pending_handshakes_[peer.node_id].done ||
        session_established(peer.node_id)) {
        peers_.mark_seen(peer.node_id);
        return true;
    }
    if (!hs_cv_.wait_for(lock, std::chrono::seconds(10),
            [&] { return !running_ ||
                     pending_handshakes_[peer.node_id].done; })) {
        if (!running_) return false;
        if (session_established(peer.node_id)) {
            peers_.mark_seen(peer.node_id);
            return true;
        }
        fprintf(stderr, "[tunnel] handshake timed out for peer %02x%02x...\n",
                peer.node_id[0], peer.node_id[1]);
        return false;
    }
    peers_.mark_seen(peer.node_id);
    return true;
}

void Tunnel::tx_loop() {
    fprintf(stderr, "[tunnel] tx loop started\n");
    std::vector<uint8_t> raw;

    while (running_) {
        raw.clear();
        if (!adapter_.read_packet(raw, 100))
            continue;

        auto parsed = IPPacket::parse(raw.data(), raw.size());
        if (!parsed)
            continue;

        uint32_t dest = parsed->dest_ip;
        if ((dest & 0xF0000000u) == 0xE0000000u) continue;  // multicast
        if (dest == 0xFFFFFFFFu) continue;                  // broadcast

        // Route by destination prefix -> peer -> endpoint/session.
        auto peer_id = routing_.find_peer(dest);
        if (!peer_id) {
            if (unrouted_count_ == 0 || (unrouted_count_ % 100) == 0)
                fprintf(stderr, "[tunnel] no route for %08x, dropping (%u so far)\n",
                        dest, unrouted_count_ + 1);
            unrouted_count_++;
            continue;
        }

        Peer* peer = peers_.get_peer(*peer_id);
        if (!peer || !peer->endpoint) {
            fprintf(stderr, "[tunnel] peer %02x%02x... has no endpoint, dropping\n",
                    (*peer_id)[0], (*peer_id)[1]);
            continue;
        }

        auto enc = session_manager_->encrypt_data(*peer_id, raw.data(), raw.size());
        if (!enc) {
            fprintf(stderr, "[tunnel] encrypt failed, dropping packet\n");
            continue;
        }

        if (!transport_.send(enc->data(), enc->size(), *peer->endpoint)) {
            fprintf(stderr, "[tunnel] send failed, dropping packet\n");
        }
    }
    fprintf(stderr, "[tunnel] tx loop ended\n");
}

void Tunnel::rx_callback(const uint8_t* data, size_t len, Endpoint sender) {
    if (len < 16) return;

    uint8_t type = data[1];
    uint32_t sid = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                   ((uint32_t)data[6] << 8) | (uint32_t)data[7];

    if (type == TYPE_DATA) {
        if (!running_) return;
        auto dec = session_manager_->decrypt_data(data, len);
        if (!dec) return;
        if (auto sess = session_manager_->get_session_by_id(sid))
            peers_.mark_seen((*sess)->peer_id, sender);
        if (!adapter_.write_packet(*dec)) {
            fprintf(stderr, "[tunnel] write_packet failed\n");
        }
        return;
    }

    if (type == TYPE_HANDSHAKE_RESP) {
        std::vector<uint8_t> payload(data + 16, data + len);
        if (payload.size() < HANDSHAKE_PAYLOAD_SIZE) return;

        NodeId peer_id{};
        std::memcpy(peer_id.data(), payload.data() + 36, 32);

        std::lock_guard<std::mutex> lock(hs_mtx_);
        auto it = std::find_if(pending_handshakes_.begin(), pending_handshakes_.end(),
            [&](const auto& kv) { return kv.second.session_id == sid; });
        if (it == pending_handshakes_.end()) return;
        if (it->second.peer_id != peer_id) {
            fprintf(stderr, "[tunnel] handshake resp NodeID mismatch\n");
            return;
        }
        if (session_manager_->handle_handshake_resp(payload, sid)) {
            it->second.done = true;
            hs_cv_.notify_all();
        }
        return;
    }

    if (type == TYPE_HANDSHAKE_INIT) {
        std::vector<uint8_t> payload(data + 16, data + len);
        if (payload.size() < HANDSHAKE_PAYLOAD_SIZE) return;

        NodeId sender_id{};
        std::memcpy(sender_id.data(), payload.data() + 36, 32);

        // Static config for now: only handshake with peers we know.
        if (!peers_.has_peer(sender_id)) {
            fprintf(stderr, "[tunnel] handshake init from unknown peer, dropping\n");
            return;
        }

        auto resp_payload = session_manager_->handle_handshake_init(payload, sender_id);
        if (!resp_payload) return;

        PacketHeader hdr{};
        hdr.version = PACKET_VERSION;
        hdr.packet_type = TYPE_HANDSHAKE_RESP;
        hdr.session_id = sid;
        hdr.payload_length = (uint32_t)resp_payload->size();
        auto hdr_bytes = SessionManager::serialize_header(hdr);
        std::vector<uint8_t> out;
        out.reserve(16 + resp_payload->size());
        out.insert(out.end(), hdr_bytes.begin(), hdr_bytes.end());
        out.insert(out.end(), resp_payload->begin(), resp_payload->end());
        transport_.send(out.data(), out.size(), sender);

        // Mark done only after the response is on the wire so the responder
        // doesn't start sending data before the initiator can decrypt it.
        std::lock_guard<std::mutex> lock(hs_mtx_);
        pending_handshakes_[sender_id] = {sender_id, sid, true};
        hs_cv_.notify_all();
    }
}
