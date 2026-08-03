#include "aegis/tunnel/tunnel.hpp"
#include "aegis/packet/packet.hpp"
#include "aegis/packet/relay.hpp"
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

    // Step 15 lifecycle: keep-alive and dead-detection intervals feed the
    // maintenance loop. Tests override them; 0 means "use the default".
    peers_.set_keepalive_interval(std::chrono::milliseconds(
        config_.keepalive_interval_ms > 0 ? config_.keepalive_interval_ms
                                          : KEEPALIVE_INTERVAL_MS));
    peers_.set_dead_timeout(std::chrono::milliseconds(
        config_.dead_timeout_ms > 0 ? config_.dead_timeout_ms
                                    : DEAD_TIMEOUT_MS));

    // Bootstrap candidates -> static peer table entries. Direct routes are NOT
    // installed here: a candidate may be on a different network (step 14), in
    // which case the handshake is refused and no route toward its prefixes may
    // ever exist. Routes are installed only once the peer's session actually
    // establishes (see connect_loop), which only happens after the NetworkID
    // gate passes.
    for (const auto& p : config_.peers) {
        peers_.upsert(p.node_id, p.public_key, p.endpoint, true);
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

    // Step 14: LAN-wide presence. Announce on the shared discovery port and
    // listen for every other node's presence — same network or not (visible
    // presence, unreachable across networks). The announced endpoint is the
    // overlay address + listen port.
    Endpoint announced{};
    announced.ip = config.local_ip;
    announced.port = htons(config.listen_port);
    if (!discovery_.start(identity_, announced)) {
        fprintf(stderr, "[tunnel] warning: discovery failed to start\n");
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
    gossip_thread_ = std::thread(&Tunnel::gossip_loop, this);
    maintenance_thread_ = std::thread(&Tunnel::maintenance_loop, this);
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
    discovery_.stop();
    if (tx_thread_.joinable()) tx_thread_.join();
    if (gossip_thread_.joinable()) gossip_thread_.join();
    if (maintenance_thread_.joinable()) maintenance_thread_.join();
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
    uint32_t backoff_ms = CONNECT_BACKOFF_BASE_MS;
    while (running_) {
        if (session_established(peer.node_id)) {
            // Session is up: keep the routes installed and the mesh informed,
            // then wait quietly until the session drops (dead peer, rekey
            // teardown, stop). Re-install only on (re)establishment.
            install_configured_routes(peer);
            send_peer_table(peer.node_id);
            announce_peer_table(peer.node_id);
            backoff_ms = CONNECT_BACKOFF_BASE_MS;

            std::unique_lock<std::mutex> lock(hs_mtx_);
            hs_cv_.wait_for(lock, std::chrono::milliseconds(500),
                [&] { return !running_ || !session_established(peer.node_id); });
            continue;
        }

        // Session is down. The maintenance loop may have marked the peer dead
        // (removing its session and routes); this thread re-establishes it.
        if (handshake_peer(peer)) {
            install_configured_routes(peer);
            backoff_ms = CONNECT_BACKOFF_BASE_MS;
            continue;
        }
        if (!running_) return;
        // Availability-based join: wait before retrying an unreachable peer so
        // the node stays up for whoever is reachable. Exponential backoff caps
        // so a long-unreachable peer does not spin hot on its probe thread.
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
        if (backoff_ms < (uint32_t)CONNECT_BACKOFF_CAP_MS)
            backoff_ms = (std::min)(backoff_ms * 2, (uint32_t)CONNECT_BACKOFF_CAP_MS);
    }
}

void Tunnel::install_configured_routes(const TunnelPeer& peer) {
    for (const auto& aip : peer.allowed_ips) {
        Route r;
        r.prefix = aip.prefix;
        r.prefix_length = aip.prefix_length;
        r.type = NextHopType::Direct;
        r.next_hop = peer.node_id;
        r.destination = peer.node_id;
        r.path = {peer.node_id};
        if (!routing_.add_route(r))
            fprintf(stderr, "[tunnel] warning: route %08x/%u rejected\n",
                    aip.prefix, aip.prefix_length);
    }
}

bool Tunnel::handshake_peer(const TunnelPeer& peer, bool force) {
    if (!force && session_established(peer.node_id))
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
    else
        // done is only meaningful for the handshake that set it; a stale true
        // from an earlier handshake must not satisfy the wait below.
        pending_handshakes_[peer.node_id].done = false;
    // The INIT may already have been answered by rx before we registered, so
    // never wait on a stale flag — re-check the session right away. A session
    // is the only reliable proof the handshake completed.
    if (session_established(peer.node_id)) {
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
        auto route = routing_.find_route(dest);
        if (!route) {
            if (unrouted_count_ == 0 || (unrouted_count_ % 100) == 0)
                fprintf(stderr, "[tunnel] no route for %08x, dropping (%u so far)\n",
                        dest, unrouted_count_ + 1);
            unrouted_count_++;
            continue;
        }

        if (route->type == NextHopType::Direct) {
            Peer* peer = peers_.get_peer(route->destination);
            if (!peer || !peer->endpoint) {
                fprintf(stderr, "[tunnel] peer %02x%02x... has no endpoint, dropping\n",
                        (*route).destination[0], (*route).destination[1]);
                continue;
            }

            auto enc = session_manager_->encrypt_data(route->destination,
                                                      raw.data(), raw.size());
            if (!enc) {
                fprintf(stderr, "[tunnel] encrypt failed, dropping packet\n");
                continue;
            }

            if (!transport_.send(enc->data(), enc->size(), *peer->endpoint)) {
                fprintf(stderr, "[tunnel] send failed, dropping packet\n");
            }
            continue;
        }

        // Relay (step 13): wrap the packet in one onion layer per hop of the
        // route's path, then send the envelope to the first hop. Only the
        // source can build the onion (it owns the key to every hop); relays
        // see one layer and forward the rest, so intermediate nodes never
        // learn the full path or the payload.
        const auto& path = route->path;
        std::vector<Key> path_keys;
        path_keys.reserve(path.size());
        for (const auto& hop : path) {
            const Peer* hp = peers_.get_peer(hop);
            if (!hp) break;
            path_keys.push_back(hp->public_key);
        }
        if (path_keys.size() != path.size()) {
            fprintf(stderr, "[tunnel] relay hop unknown, dropping packet\n");
            continue;
        }

        auto onion = build_onion(identity_.keypair, path, path_keys,
                                 raw.data(), raw.size());
        if (!onion) {
            fprintf(stderr, "[tunnel] onion build failed, dropping packet\n");
            continue;
        }

        std::vector<uint8_t> payload;
        payload.reserve(NODE_ID_SIZE + onion->size());
        payload.insert(payload.end(), identity_.node_id.begin(),
                       identity_.node_id.end());
        payload.insert(payload.end(), onion->begin(), onion->end());

        auto frame = session_manager_->encrypt_message(
            route->next_hop, TYPE_RELAY, payload.data(), payload.size(),
            FLAG_RELAY);
        if (!frame) {
            fprintf(stderr, "[tunnel] relay encrypt failed, dropping packet\n");
            continue;
        }

        Peer* first = peers_.get_peer(route->next_hop);
        if (!first || !first->endpoint) {
            fprintf(stderr, "[tunnel] first hop %02x%02x... has no endpoint, dropping\n",
                    route->next_hop[0], route->next_hop[1]);
            continue;
        }
        if (!transport_.send(frame->data(), frame->size(), *first->endpoint))
            fprintf(stderr, "[tunnel] relay send failed, dropping packet\n");
    }
    fprintf(stderr, "[tunnel] tx loop ended\n");
}

void Tunnel::gossip_loop() {
    fprintf(stderr, "[tunnel] gossip loop started\n");
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(GOSSIP_INTERVAL_MS));
        if (!running_) break;
        // Full-table announce to every established peer. Periodic re-announce
        // is what carries far-end peers across a chain: the immediate
        // learn-triggered fan-out only reaches the nodes adjacent to the peer
        // we just learned from, so a node that never learns anything new
        // (e.g. B in A-B-C) would otherwise never relay C/D onward to A.
        announce_peer_table(std::nullopt);
    }
    fprintf(stderr, "[tunnel] gossip loop ended\n");
}

void Tunnel::send_keepalive(const Peer& peer) {
    auto frame = session_manager_->encrypt_message(
        peer.node_id, TYPE_KEEPALIVE, nullptr, 0);
    if (!frame) {
        fprintf(stderr, "[tunnel] keepalive encrypt failed for %02x%02x...\n",
                peer.node_id[0], peer.node_id[1]);
        return;
    }
    if (peer.endpoint)
        transport_.send(frame->data(), frame->size(), *peer.endpoint);
}

void Tunnel::rekey_peer(const NodeId& node_id) {
    Peer* p = peers_.get_peer(node_id);
    if (!p || !p->endpoint)
        return;
    TunnelPeer tp;
    tp.node_id = node_id;
    tp.public_key = p->public_key;
    tp.endpoint = *p->endpoint;
    if (handshake_peer(tp, /*force=*/true))
        fprintf(stderr, "[tunnel] rekey complete for %02x%02x...\n",
                node_id[0], node_id[1]);
    else
        fprintf(stderr, "[tunnel] rekey failed for %02x%02x...\n",
                node_id[0], node_id[1]);
}

void Tunnel::rekey_due() {
    auto interval = std::chrono::milliseconds(
        config_.rekey_interval_ms > 0 ? config_.rekey_interval_ms
                                      : REKEY_INTERVAL_MS);
    auto now = std::chrono::steady_clock::now();
    for (auto* peer : peers_.all_peers()) {
        if (peer->node_id == identity_.node_id)
            continue;
        if (peer->state != PeerState::Established)
            continue;
        // Deterministic roles: only the lower NodeID rekeys. The other side
        // auto-answers the re-INIT from its rx path, so exactly one side
        // drives each pair's rekey and the two never race.
        if (!(identity_.node_id < peer->node_id))
            continue;
        auto sess = session_manager_->get_session(peer->node_id);
        if (!sess)
            continue;
        if (now - (*sess)->established_at < interval)
            continue;
        auto attempt = rekey_attempts_.find(peer->node_id);
        if (attempt != rekey_attempts_.end() &&
            now - attempt->second < interval)
            continue;  // failed rekey already this interval; retry later
        rekey_attempts_[peer->node_id] = now;
        rekey_peer(peer->node_id);
    }
}

void Tunnel::maintenance_loop() {
    fprintf(stderr, "[tunnel] maintenance loop started\n");
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(MAINTENANCE_TICK_MS));
        if (!running_) break;

        // 1) Keep-alives: established peers silent past the interval get an
        //    empty-payload frame, so liveness is measured end-to-end (their
        //    response is any decrypted packet, which advances last_keepalive).
        for (auto* peer : peers_.peers_needing_keepalive())
            send_keepalive(*peer);

        // 2) Dead detection: a peer silent past the dead timeout loses its
        //    session and its routes. Learned peers stay listed but unroutable
        //    (step 15 policy); the connect loop re-establishes configured
        //    peers, re-installing routes only after the handshake succeeds.
        for (auto* peer : peers_.stale_peers()) {
            peers_.mark_dead(peer->node_id);
            session_manager_->remove_session(peer->node_id);
            routing_.remove_route(peer->node_id);
            fprintf(stderr, "[tunnel] peer %02x%02x... marked dead\n",
                    peer->node_id[0], peer->node_id[1]);
        }

        // 3) Garbage-collect sessions retired by a rekey.
        session_manager_->purge_retired();

        // 4) Fold same-network presence broadcasts into known peers' endpoints.
        //    Runs after keep-alives so a peer that just moved IPs has its new
        //    endpoint ready for the next connect/rekey attempt.
        refresh_endpoints_from_discovery();

        // 5) Rekey established sessions older than the interval.
        rekey_due();
    }
    fprintf(stderr, "[tunnel] maintenance loop ended\n");
}

void Tunnel::refresh_endpoints_from_discovery() {
    for (const auto& [id, presence] : discovery_.presences()) {
        if (presence.network_id != identity_.network_id)
            continue;  // cross-network: visible but never reachable
        Peer* peer = peers_.get_peer(id);
        if (!peer)
            continue;  // presence alone never creates a peer entry
        if (!peer->trusted)
            continue;  // learned peers stay endpoint-less: real IPs never propagate via gossip
        if (peer->endpoint && *peer->endpoint == presence.reachable_endpoint)
            continue;
        peers_.update_endpoint(id, presence.reachable_endpoint);
        fprintf(stderr, "[tunnel] discovery updated endpoint for %02x%02x... -> %08x:%04x\n",
                id[0], id[1], ntohl(presence.reachable_endpoint.ip),
                ntohs(presence.reachable_endpoint.port));
    }
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

    if (type == TYPE_RELAY) {
        if (!running_) return;
        handle_relay(data, len, sid);
        return;
    }

    if (type == TYPE_KEEPALIVE) {
        if (!running_) return;
        auto msg = session_manager_->decrypt_message(data, len);
        if (!msg) return;
        auto sess = session_manager_->get_session_by_id(sid);
        if (!sess) return;
        // Any decrypted packet proves liveness; mark_seen advances
        // last_keepalive so the peer drops off peers_needing_keepalive.
        peers_.mark_seen((*sess)->peer_id, sender);
        return;
    }

    if (type == TYPE_PEER_TABLE) {
        if (!running_) return;
        auto msg = session_manager_->decrypt_message(data, len);
        if (!msg) return;
        auto sess = session_manager_->get_session_by_id(sid);
        if (!sess) return;
        peers_.mark_seen((*sess)->peer_id, sender);
        handle_peer_table((*sess)->peer_id, msg->payload.data(), msg->payload.size());
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

void Tunnel::handle_relay(const uint8_t* data, size_t len, uint32_t session_id) {
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg || msg->packet_type != TYPE_RELAY) return;
    auto sess = session_manager_->get_session_by_id(session_id);
    if (!sess) return;
    peers_.mark_seen((*sess)->peer_id);

    // Payload = [32] source NodeID || onion blob. The source is who we peel
    // with — every layer was keyed to the source's static key, and a relay is
    // only ever a hop between the source and the destination.
    if (msg->payload.size() < NODE_ID_SIZE + ONION_OVERHEAD) {
        fprintf(stderr, "[tunnel] relay frame too small, dropping\n");
        return;
    }
    NodeId source{};
    std::memcpy(source.data(), msg->payload.data(), NODE_ID_SIZE);
    const uint8_t* blob = msg->payload.data() + NODE_ID_SIZE;
    size_t blob_len = msg->payload.size() - NODE_ID_SIZE;

    const Peer* sp = peers_.get_peer(source);
    if (!sp) {
        fprintf(stderr, "[tunnel] relay from unknown source %02x%02x..., dropping\n",
                source[0], source[1]);
        return;
    }

    auto peeled = peel_onion(identity_.keypair, sp->public_key, blob, blob_len);
    if (!peeled) {
        fprintf(stderr, "[tunnel] relay layer open failed (source %02x%02x...), dropping\n",
                source[0], source[1]);
        return;
    }

    // All-zero next hop => we are the final destination: deliver the packet.
    bool final = true;
    for (auto b : peeled->next_hop)
        if (b != 0) { final = false; break; }
    if (final) {
        if (!adapter_.write_packet(peeled->inner))
            fprintf(stderr, "[tunnel] relay final write_packet failed\n");
        return;
    }

    // A relay must never peel to itself — that can only come from a broken or
    // malicious path, and forwarding it would spin forever.
    if (peeled->next_hop == identity_.node_id) {
        fprintf(stderr, "[tunnel] relay loop (next hop is us), dropping\n");
        return;
    }

    const Peer* nh = peers_.get_peer(peeled->next_hop);
    if (!nh || !nh->endpoint) {
        fprintf(stderr, "[tunnel] relay next hop %02x%02x... unreachable, dropping\n",
                peeled->next_hop[0], peeled->next_hop[1]);
        return;
    }

    // Forward the inner layer to the next hop, still addressed from the
    // original source so each hop keeps peeling with the source's key.
    std::vector<uint8_t> fwd;
    fwd.reserve(NODE_ID_SIZE + peeled->inner.size());
    fwd.insert(fwd.end(), source.begin(), source.end());
    fwd.insert(fwd.end(), peeled->inner.begin(), peeled->inner.end());
    auto frame = session_manager_->encrypt_message(
        peeled->next_hop, TYPE_RELAY, fwd.data(), fwd.size(), FLAG_RELAY);
    if (!frame) {
        fprintf(stderr, "[tunnel] relay forward encrypt failed, dropping\n");
        return;
    }
    if (!transport_.send(frame->data(), frame->size(), *nh->endpoint))
        fprintf(stderr, "[tunnel] relay forward send failed, dropping\n");
}

std::vector<AdvertisedPeer> Tunnel::build_advertised_peers() const {
    std::vector<AdvertisedPeer> out;

    // Our own entry: we are always directly reachable by anyone who can reach
    // us, and only our configured prefix is advertised (never an endpoint).
    AdvertisedPeer self;
    self.node_id = identity_.node_id;
    self.public_key = identity_.keypair.public_key;
    self.prefixes.emplace_back(config_.local_ip, config_.local_prefix);
    out.push_back(std::move(self));

    auto routes = routing_.routes();
    for (const auto* peer : peers_.all_peers()) {
        if (peer->node_id == identity_.node_id)
            continue;
        AdvertisedPeer ap;
        ap.node_id = peer->node_id;
        ap.public_key = peer->public_key;
        for (const auto& r : routes) {
            if (r.destination != peer->node_id)
                continue;
            ap.prefixes.emplace_back(r.prefix, r.prefix_length);
            // Advertise our FULL hop list to this peer (first hop through the
            // destination; {peer} for direct routes). The receiver prepends
            // itself and gets a complete path without knowing anything beyond
            // the immediate sender; paths that would loop back through the
            // receiver are rejected during the merge.
            if (ap.path.empty())
                ap.path = r.path;
        }
        out.push_back(std::move(ap));
    }
    return out;
}

void Tunnel::send_peer_table(const NodeId& to_peer) {
    auto advertised = build_advertised_peers();
    auto payload = serialize_peer_table(advertised);
    auto enc = session_manager_->encrypt_message(
        to_peer, TYPE_PEER_TABLE, payload.data(), payload.size());
    if (!enc) {
        fprintf(stderr, "[tunnel] encrypt peer table failed\n");
        return;
    }
    Peer* peer = peers_.get_peer(to_peer);
    if (!peer || !peer->endpoint)
        return;
    fprintf(stderr, "[tunnel] sent peer table (%zu peer(s)) to %02x%02x...\n",
            advertised.size(), to_peer[0], to_peer[1]);
    transport_.send(enc->data(), enc->size(), *peer->endpoint);
}

void Tunnel::announce_peer_table(const std::optional<NodeId>& exclude) {
    for (auto* peer : peers_.all_peers()) {
        if (exclude && peer->node_id == *exclude)
            continue;
        if (session_established(peer->node_id))
            send_peer_table(peer->node_id);
    }
}

void Tunnel::handle_peer_table(const NodeId& sender, const uint8_t* data, size_t len) {
    auto advertised = deserialize_peer_table(data, len);
    if (!advertised) {
        fprintf(stderr, "[tunnel] peer table parse failed from %02x%02x...\n",
                sender[0], sender[1]);
        return;
    }
    size_t routes_installed = 0;
    size_t learned = merge_peer_table(peers_, routing_, *advertised, sender,
                                      identity_.node_id, &routes_installed);
    fprintf(stderr, "[tunnel] peer table from %02x%02x...: %zu peer(s), %zu new\n",
            sender[0], sender[1], advertised->size(), learned);
    // Fan out any new knowledge (peers or routes) so the mesh converges without
    // waiting for the next periodic gossip cycle.
    if (learned > 0 || routes_installed > 0)
        announce_peer_table(sender);
}
