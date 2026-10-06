#include "aegis/tunnel/tunnel.hpp"
#include "aegis/packet/packet.hpp"
#include "aegis/packet/relay.hpp"
#include "aegis/crypto/random.hpp"
#include "aegis/stun/stun.hpp"
#include "aegis/platform/logger.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <filesystem>

Tunnel::Tunnel()
    : Tunnel(system_protocol_clock(), system_random_source()) {}

Tunnel::Tunnel(ProtocolClock& clock, RandomSource& random)
    : discovery_(clock), clock_(clock), random_(random),
      relay_forward_limiter_(clock),
      handshake_rate_limiter_(clock),
      handshake_cookie_manager_(clock, random),
      peers_(PEER_MANAGER_MAX_PEERS, clock) {}

Tunnel::~Tunnel() { stop(); }

bool Tunnel::start(const TunnelConfig& config, const std::string& adapter_name) {
    const auto overlay_mtu = safe_overlay_mtu(
        config.underlay_mtu, config.max_relay_depth);
    if (!overlay_mtu) {
        aegis_log("[tunnel] invalid MTU contract: underlay=%u route-depth=%u\n",
                  config.underlay_mtu,
                  static_cast<unsigned>(config.max_relay_depth));
        return false;
    }
    config_ = config;
    network_name_ = config_.network_name;
    overlay_mtu_ = static_cast<uint32_t>(*overlay_mtu);
    oversize_outbound_drops_.store(0, std::memory_order_relaxed);
    oversize_inbound_drops_.store(0, std::memory_order_relaxed);
    invalid_inbound_drops_.store(0, std::memory_order_relaxed);
    relay_forward_limiter_.reset();
    gossip_delta_tracker_.reset();
    gossip_round_ = 0;

    const size_t datagram_budget =
        config.underlay_mtu - OUTER_IPV4_UDP_OVERHEAD;
    if (!transport_.set_max_datagram_size(datagram_budget)) {
        aegis_log("[tunnel] invalid UDP datagram budget: %zu\n",
                  datagram_budget);
        return false;
    }

    if (config_.identity)
        identity_ = *config_.identity;
    else
        identity_ = Identity::create(NetworkId{});

    aegis_log( "[tunnel] node_id: ");
    for (auto b : identity_.node_id) aegis_log( "%02x", b);
    aegis_log( "\n");

    session_manager_ = std::make_unique<SessionManager>(identity_, clock_);
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

    if (!adapter_.create(
            config.local_ip, config.local_prefix, wname,
            static_cast<uint32_t>(*overlay_mtu))) {
        aegis_log( "[tunnel] adapter creation failed\n");
        return false;
    }

    uint16_t actual_port = config.listen_port;
    bool bound = false;
    for (int retry = 0; retry < 10; retry++) {
        if (transport_.bind(actual_port)) {
            bound = true;
            break;
        }
        actual_port++;
    }
    if (!bound) {
        aegis_log( "[tunnel] bind failed starting at port %u\n", config.listen_port);
        adapter_.close();
        return false;
    }
    config_.listen_port = actual_port;

    // Optional STUN external address discovery
    stun_public_endpoint_ = std::nullopt;
    if (config_.stun_server) {
        std::string server = *config_.stun_server;
        size_t colon = server.rfind(':');
        std::string host = (colon != std::string::npos) ? server.substr(0, colon) : server;
        uint16_t port = (colon != std::string::npos) ? (uint16_t)std::atoi(server.c_str() + colon + 1) : 3478;

        auto st_ep = stun_discover(
            host, port, config.listen_port, 2000, random_);
        if (st_ep) {
            stun_public_endpoint_ = st_ep;
            uint32_t ip_h = ntohl(st_ep->ip);
            uint16_t port_h = ntohs(st_ep->port);
            aegis_log( "[tunnel] STUN public endpoint: %u.%u.%u.%u:%u\n",
                    (ip_h >> 24) & 0xFF, (ip_h >> 16) & 0xFF,
                    (ip_h >> 8) & 0xFF, ip_h & 0xFF, port_h);
        } else {
            aegis_log( "[tunnel] STUN discovery failed for %s\n", server.c_str());
        }
    }

    // Step 14: LAN-wide presence. Announce on the shared discovery port and
    // listen for every other node's presence — same network or not (visible
    // presence, unreachable across networks).
    Endpoint announced{};
    if (stun_public_endpoint_) {
        announced = *stun_public_endpoint_;
    } else {
        announced.ip = config.local_ip;
        announced.port = htons(config.listen_port);
    }
    if (!discovery_.start(identity_, announced)) {
        aegis_log( "[tunnel] warning: discovery failed to start\n");
    }


    aegis_log( "[tunnel] listening on %u, %zu configured peer(s)\n",
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

    aegis_log( "[tunnel] up, %zu bootstrap candidate(s), joining in background\n",
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
    {
        std::lock_guard<std::mutex> lock(incoming_transfers_mtx_);
        incoming_transfers_.clear();
    }
    {
        std::lock_guard<std::mutex> outgoing_lock(outgoing_transfers_mtx_);
        outgoing_transfers_.clear();
    }
    outgoing_transfers_cv_.notify_all();
}

bool Tunnel::session_established(const NodeId& node_id) const {
    return session_manager_->get_session(node_id).has_value();
}

TunnelDropStats Tunnel::drop_stats() const {
    TunnelDropStats stats;
    stats.oversize_outbound =
        oversize_outbound_drops_.load(std::memory_order_relaxed);
    stats.oversize_inbound =
        oversize_inbound_drops_.load(std::memory_order_relaxed);
    stats.invalid_inbound =
        invalid_inbound_drops_.load(std::memory_order_relaxed);
    stats.transport_oversize_send = transport_.oversize_send_drops();
    stats.transport_oversize_receive = transport_.oversize_receive_drops();
    const auto queue_drops = transport_.queue_drop_stats();
    stats.transport_data_queue_drops = queue_drops.data;
    stats.transport_control_queue_drops = queue_drops.control;
    const auto relay = relay_forward_limiter_.stats();
    stats.relay_admitted_packets = relay.admitted_packets;
    stats.relay_admitted_bytes = relay.admitted_bytes;
    stats.relay_peer_drops = relay.peer_drops;
    stats.relay_global_drops = relay.global_drops;
    stats.relay_capacity_drops = relay.capacity_drops;
    return stats;
}

bool Tunnel::packet_fits_route(size_t packet_size, size_t route_depth) {
    const auto route_mtu = safe_overlay_mtu(config_.underlay_mtu, route_depth);
    if (route_mtu && packet_size <= *route_mtu)
        return true;

    const uint64_t count =
        oversize_outbound_drops_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (count == 1 || count % 100 == 0) {
        aegis_log("[tunnel] oversize outbound packet: %zu bytes, "
                  "route depth %zu, limit %zu (%llu drop(s))\n",
                  packet_size, route_depth, route_mtu.value_or(0),
                  static_cast<unsigned long long>(count));
    }
    return false;
}

bool Tunnel::inject_inner_packet(const std::vector<uint8_t>& packet) {
    const auto status = validate_inner_ipv4_packet(
        packet.data(), packet.size(), overlay_mtu_);
    if (status != InnerPacketStatus::Valid) {
        std::atomic<uint64_t>& counter =
            status == InnerPacketStatus::Oversize
                ? oversize_inbound_drops_
                : invalid_inbound_drops_;
        const uint64_t count =
            counter.fetch_add(1, std::memory_order_relaxed) + 1;
        if (count == 1 || count % 100 == 0) {
            aegis_log("[tunnel] dropped %s inbound packet: %zu bytes, "
                      "overlay MTU %u (%llu drop(s))\n",
                      status == InnerPacketStatus::Oversize
                          ? "oversize" : "invalid",
                      packet.size(), overlay_mtu_,
                      static_cast<unsigned long long>(count));
        }
        return false;
    }
    if (!adapter_.write_packet(packet)) {
        aegis_log("[tunnel] write_packet failed\n");
        return false;
    }
    return true;
}

void Tunnel::connect_loop(const TunnelPeer& peer) {
    aegis_log( "[tunnel] connect loop for peer %02x%02x...\n",
            peer.node_id[0], peer.node_id[1]);
    uint32_t backoff_ms = CONNECT_BACKOFF_BASE_MS;
    while (running_) {
        if (session_established(peer.node_id)) {
            // Session is up: keep the routes installed and the mesh informed,
            // then wait quietly until the session drops (dead peer, rekey
            // teardown, stop). Re-install only on (re)establishment.
            install_configured_routes(peer);
            send_peer_table(peer.node_id, /*force_full=*/true);
            announce_peer_table(peer.node_id);
            backoff_ms = CONNECT_BACKOFF_BASE_MS;

            std::unique_lock<std::mutex> lock(hs_mtx_);
            hs_cv_.wait_for(lock, std::chrono::milliseconds(500),
                [&] { return !running_ || !session_established(peer.node_id); });
            continue;
        }

        // Use discovery-discovered endpoint if available
        TunnelPeer active_peer = peer;
        if (auto p = peers_.get_peer(peer.node_id)) {
            if (p->endpoint) {
                active_peer.endpoint = *p->endpoint;
            }
        }

        // Session is down. The maintenance loop may have marked the peer dead
        // (removing its session and routes); this thread re-establishes it.
        if (handshake_peer(active_peer)) {
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
            aegis_log( "[tunnel] warning: route %08x/%u rejected\n",
                    aip.prefix, aip.prefix_length);
    }
}

bool Tunnel::handshake_peer(const TunnelPeer& peer, bool force) {
    if (!force && session_established(peer.node_id))
        return true;

    peers_.mark_connecting(peer.node_id);

    // Initiate if our NodeID is lower, or if we have an explicit non-zero endpoint for the candidate.
    bool initiator = (identity_.node_id < peer.node_id) || (peer.endpoint.ip != 0);

    aegis_log( "[tunnel] handshake with peer %02x%02x... (%s)\n",
            peer.node_id[0], peer.node_id[1],
            initiator ? "initiator" : "responder");

    if (initiator) {
        std::optional<uint32_t> reserved_sid;
        for (int attempt = 0; attempt < 16 && !reserved_sid; ++attempt) {
            const auto candidate = random_.u32();
            if (!candidate) {
                aegis_log("[tunnel] secure session id generation failed\n");
                return false;
            }
            if (*candidate == 0 ||
                session_manager_->get_session_by_id(*candidate).has_value())
                continue;

            std::lock_guard<std::mutex> lock(hs_mtx_);
            const bool pending_collision = std::any_of(
                pending_handshakes_.begin(), pending_handshakes_.end(),
                [&](const auto& entry) {
                    return entry.second.session_id == *candidate;
                });
            if (!pending_collision) {
                pending_handshakes_[peer.node_id] = {
                    peer.node_id, *candidate, false, peer.endpoint};
                reserved_sid = candidate;
            }
        }
        if (!reserved_sid) {
            aegis_log("[tunnel] unable to reserve a unique session id\n");
            return false;
        }
        const uint32_t sid = *reserved_sid;

        auto init_payload = session_manager_->create_handshake_init(
            sid, peer.node_id, peer.public_key);
        if (!init_payload) {
            std::lock_guard<std::mutex> lock(hs_mtx_);
            pending_handshakes_.erase(peer.node_id);
            aegis_log("[tunnel] unable to create authenticated handshake\n");
            return false;
        }
        std::unique_lock<std::mutex> lock(hs_mtx_);
        for (int attempt = 0; attempt < 10; attempt++) {
            auto pending = pending_handshakes_.find(peer.node_id);
            if (pending == pending_handshakes_.end())
                return false;

            PacketHeader hdr{};
            hdr.version = PACKET_VERSION;
            hdr.packet_type = TYPE_HANDSHAKE_INIT;
            hdr.session_id = sid;
            hdr.payload_length = static_cast<uint32_t>(
                init_payload->size() +
                (pending->second.cookie ? HANDSHAKE_COOKIE_SIZE : 0));
            auto hdr_bytes = SessionManager::serialize_header(hdr);
            std::vector<uint8_t> wire;
            wire.reserve(PACKET_HEADER_SIZE + hdr.payload_length);
            wire.insert(wire.end(), hdr_bytes.begin(), hdr_bytes.end());
            wire.insert(wire.end(), init_payload->begin(), init_payload->end());
            if (pending->second.cookie) {
                wire.insert(
                    wire.end(), pending->second.cookie->begin(),
                    pending->second.cookie->end());
            }
            pending->second.cookie_updated = false;
            transport_.send(
                wire.data(), wire.size(), peer.endpoint,
                SendPriority::Control);
            if (hs_cv_.wait_for(lock, std::chrono::seconds(1),
                    [&] { return !running_ ||
                             pending_handshakes_[peer.node_id].done ||
                             pending_handshakes_[peer.node_id].cookie_updated; })) {
                if (!running_ || pending_handshakes_[peer.node_id].done)
                    break;
                continue;
            }
            aegis_log( "[tunnel] handshake retry %d for peer %02x%02x...\n",
                    attempt + 1, peer.node_id[0], peer.node_id[1]);
        }
        if (!running_) return false;
        if (!pending_handshakes_[peer.node_id].done &&
            !session_established(peer.node_id)) {
            aegis_log( "[tunnel] handshake failed for peer %02x%02x...\n",
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
        aegis_log( "[tunnel] handshake timed out for peer %02x%02x...\n",
                peer.node_id[0], peer.node_id[1]);
        return false;
    }
    peers_.mark_seen(peer.node_id);
    return true;
}

void Tunnel::tx_loop() {
    aegis_log( "[tunnel] tx loop started\n");
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
                aegis_log( "[tunnel] no route for %08x, dropping (%u so far)\n",
                        dest, unrouted_count_ + 1);
            unrouted_count_++;
            continue;
        }

        if (route->type == NextHopType::Direct) {
            if (!packet_fits_route(raw.size(), DIRECT_ROUTE_DEPTH))
                continue;
            auto peer = peers_.get_peer(route->destination);
            if (!peer || !peer->endpoint) {
                aegis_log( "[tunnel] peer %02x%02x... has no endpoint, dropping\n",
                        (*route).destination[0], (*route).destination[1]);
                continue;
            }

            auto enc = session_manager_->encrypt_data(route->destination,
                                                      raw.data(), raw.size());
            if (!enc) {
                aegis_log( "[tunnel] encrypt failed, dropping packet\n");
                continue;
            }

            if (!transport_.send(enc->data(), enc->size(), *peer->endpoint)) {
                aegis_log( "[tunnel] send failed, dropping packet\n");
            }
            continue;
        }

        // Relay (step 13): wrap the packet in one onion layer per hop of the
        // route's path, then send the envelope to the first hop. Only the
        // source can build the onion (it owns the key to every hop); relays
        // see one layer and forward the rest, so intermediate nodes never
        // learn the full path or the payload.
        const auto& path = route->path;
        if (path.size() > config_.max_relay_depth) {
            aegis_log("[tunnel] relay path depth %zu exceeds configured "
                      "maximum %u, dropping packet\n",
                      path.size(),
                      static_cast<unsigned>(config_.max_relay_depth));
            continue;
        }
        if (!packet_fits_route(raw.size(), path.size()))
            continue;
        std::vector<Key> path_keys;
        path_keys.reserve(path.size());
        for (const auto& hop : path) {
            auto hp = peers_.get_peer(hop);
            if (!hp) break;
            path_keys.push_back(hp->public_key);
        }
        if (path_keys.size() != path.size()) {
            aegis_log( "[tunnel] relay hop unknown, dropping packet\n");
            continue;
        }

        auto onion = build_onion(identity_.keypair, path, path_keys,
                                 raw.data(), raw.size());
        if (!onion) {
            aegis_log( "[tunnel] onion build failed, dropping packet\n");
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
            aegis_log( "[tunnel] relay encrypt failed, dropping packet\n");
            continue;
        }

        auto first = peers_.get_peer(route->next_hop);
        if (!first || !first->endpoint) {
            aegis_log( "[tunnel] first hop %02x%02x... has no endpoint, dropping\n",
                    route->next_hop[0], route->next_hop[1]);
            continue;
        }
        if (!transport_.send(frame->data(), frame->size(), *first->endpoint))
            aegis_log( "[tunnel] relay send failed, dropping packet\n");
    }
    aegis_log( "[tunnel] tx loop ended\n");
}

void Tunnel::gossip_loop() {
    aegis_log( "[tunnel] gossip loop started\n");
    while (running_) {
        const auto interval = jittered_gossip_interval(random_.u64());
        {
            std::unique_lock<std::mutex> lock(hs_mtx_);
            if (hs_cv_.wait_for(lock, interval, [this] { return !running_; }))
                break;
        }
        ++gossip_round_;
        const bool force_full =
            gossip_round_ % GOSSIP_FULL_RESYNC_ROUNDS == 0;
        // Deltas propagate changed knowledge without repeating the complete
        // table. A periodic full resync repairs a delta lost by UDP.
        announce_peer_table(std::nullopt, force_full);
    }
    aegis_log( "[tunnel] gossip loop ended\n");
}

void Tunnel::send_keepalive(const Peer& peer) {
    auto frame = session_manager_->encrypt_message(
        peer.node_id, TYPE_KEEPALIVE, nullptr, 0);
    if (!frame) {
        aegis_log( "[tunnel] keepalive encrypt failed for %02x%02x...\n",
                peer.node_id[0], peer.node_id[1]);
        return;
    }
    if (peer.endpoint) {
        transport_.send(
            frame->data(), frame->size(), *peer.endpoint,
            SendPriority::Control);
    }
}

void Tunnel::rekey_peer(const NodeId& node_id) {
    auto p = peers_.get_peer(node_id);
    if (!p || !p->endpoint)
        return;
    TunnelPeer tp;
    tp.node_id = node_id;
    tp.public_key = p->public_key;
    tp.endpoint = *p->endpoint;
    if (handshake_peer(tp, /*force=*/true))
        aegis_log( "[tunnel] rekey complete for %02x%02x...\n",
                node_id[0], node_id[1]);
    else
        aegis_log( "[tunnel] rekey failed for %02x%02x...\n",
                node_id[0], node_id[1]);
}

void Tunnel::rekey_due() {
    auto interval = std::chrono::milliseconds(
        config_.rekey_interval_ms > 0 ? config_.rekey_interval_ms
                                      : REKEY_INTERVAL_MS);
    auto now = clock_.now();
    for (const auto& peer : peers_.all_peers()) {
        if (peer.node_id == identity_.node_id)
            continue;
        if (peer.state != PeerState::Established)
            continue;
        // Deterministic roles: only the lower NodeID rekeys. The other side
        // auto-answers the re-INIT from its rx path, so exactly one side
        // drives each pair's rekey and the two never race.
        if (!(identity_.node_id < peer.node_id))
            continue;
        auto sess = session_manager_->get_session(peer.node_id);
        if (!sess)
            continue;
        if (now - sess->established_at < interval)
            continue;
        auto attempt = rekey_attempts_.find(peer.node_id);
        if (attempt != rekey_attempts_.end() &&
            now - attempt->second < interval)
            continue;  // failed rekey already this interval; retry later
        rekey_attempts_[peer.node_id] = now;
        rekey_peer(peer.node_id);
    }
}

void Tunnel::maintenance_loop() {
    aegis_log( "[tunnel] maintenance loop started\n");
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(MAINTENANCE_TICK_MS));
        if (!running_) break;

        // 1) Keep-alives: established peers silent past the interval get an
        //    empty-payload frame, so liveness is measured end-to-end (their
        //    response is any decrypted packet, which advances last_keepalive).
        for (const auto& peer : peers_.peers_needing_keepalive())
            send_keepalive(peer);

        // 2) Dead detection: a peer silent past the dead timeout loses its
        //    session and its routes. Learned peers stay listed but unroutable
        //    (step 15 policy); the connect loop re-establishes configured
        //    peers, re-installing routes only after the handshake succeeds.
        for (const auto& peer : peers_.stale_peers()) {
            peers_.mark_dead(peer.node_id);
            session_manager_->remove_session(peer.node_id);
            routing_.remove_route(peer.node_id);
            aegis_log( "[tunnel] peer %02x%02x... marked dead\n",
                    peer.node_id[0], peer.node_id[1]);
        }

        // 3) Garbage-collect sessions retired by a rekey.
        session_manager_->purge_retired();
        session_manager_->purge_incomplete_handshakes();
        session_manager_->purge_handshake_replays();

        // 4) Fold same-network presence broadcasts into known peers' endpoints.
        //    Runs after keep-alives so a peer that just moved IPs has its new
        //    endpoint ready for the next connect/rekey attempt.
        refresh_endpoints_from_discovery();

        // 5) Rekey established sessions older than the interval.
        rekey_due();

        // 6) Release abandoned partial files and tell the sender to stop.
        expire_file_transfers();
    }
    aegis_log( "[tunnel] maintenance loop ended\n");
}

void Tunnel::refresh_endpoints_from_discovery() {
    for (const auto& [id, presence] : discovery_.presences()) {
        if (presence.network_id != identity_.network_id)
            continue;  // cross-network: visible but never reachable
        auto peer = peers_.get_peer(id);
        if (!peer)
            continue;  // presence alone never creates a peer entry
        if (!peer->trusted)
            continue;  // learned peers stay endpoint-less: real IPs never propagate via gossip
        if (peer->endpoint && *peer->endpoint == presence.reachable_endpoint)
            continue;
        peers_.update_endpoint(id, presence.reachable_endpoint);
        aegis_log( "[tunnel] discovery updated endpoint for %02x%02x... -> %08x:%04x\n",
                id[0], id[1], ntohl(presence.reachable_endpoint.ip),
                ntohs(presence.reachable_endpoint.port));
    }
}

void Tunnel::rx_callback(const uint8_t* data, size_t len, Endpoint sender) {
    if (!data || len < PACKET_HEADER_SIZE) return;
    const auto header = parse_packet_header(
        std::span<const uint8_t>(data, PACKET_HEADER_SIZE));
    if (!header || header->version != PACKET_VERSION ||
        header->reserved != 0 ||
        (header->flags & static_cast<uint8_t>(~PACKET_KNOWN_FLAGS)) != 0)
        return;

    switch (header->packet_type) {
    case TYPE_DATA:
        handle_data_frame(data, len, *header, sender);
        break;
    case TYPE_RELAY:
        handle_relay_frame(data, len, *header);
        break;
    case TYPE_KEEPALIVE:
        handle_keepalive_frame(data, len, *header, sender);
        break;
    case TYPE_PEER_TABLE:
        handle_peer_table_frame(data, len, *header, sender);
        break;
    case TYPE_CHAT_MSG:
        handle_chat_frame(data, len, *header, sender);
        break;
    case TYPE_FILE_HEADER:
        handle_file_header_frame(data, len, *header, sender);
        break;
    case TYPE_FILE_CHUNK:
        handle_file_chunk_frame(data, len, *header, sender);
        break;
    case TYPE_FILE_ACK:
        handle_file_ack_frame(data, len, *header, sender);
        break;
    case TYPE_FILE_CANCEL:
        handle_file_cancel_frame(data, len, *header, sender);
        break;
    case TYPE_NETWORK_TEARDOWN:
        handle_network_teardown_frame(data, len, *header);
        break;
    case TYPE_HANDSHAKE_RESP:
        handle_handshake_response_frame(data, len, *header);
        break;
    case TYPE_HANDSHAKE_COOKIE:
        handle_handshake_cookie_frame(data, len, *header, sender);
        break;
    case TYPE_HANDSHAKE_INIT:
        handle_handshake_init_frame(data, len, *header, sender);
        break;
    default:
        break;
    }
}

void Tunnel::handle_data_frame(const uint8_t* data, size_t len,
                               const PacketHeader& header, Endpoint sender) {
    if (!running_) return;
    auto dec = session_manager_->decrypt_data(data, len);
    if (!dec) return;
    if (auto sess = session_manager_->get_session_by_id(header.session_id))
        peers_.mark_seen(sess->peer_id, sender);
    inject_inner_packet(*dec);
}

void Tunnel::handle_relay_frame(const uint8_t* data, size_t len,
                                const PacketHeader& header) {
    if (!running_) return;
    handle_relay(data, len, header.session_id);
}

void Tunnel::handle_keepalive_frame(const uint8_t* data, size_t len,
                                    const PacketHeader& header,
                                    Endpoint sender) {
    if (!running_) return;
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    // Any decrypted packet proves liveness; mark_seen advances
    // last_keepalive so the peer drops off peers_needing_keepalive.
    peers_.mark_seen(sess->peer_id, sender);
}

void Tunnel::handle_peer_table_frame(const uint8_t* data, size_t len,
                                     const PacketHeader& header,
                                     Endpoint sender) {
    if (!running_) return;
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    peers_.mark_seen(sess->peer_id, sender);
    handle_peer_table(sess->peer_id, msg->payload.data(), msg->payload.size());
}

void Tunnel::handle_chat_frame(const uint8_t* data, size_t len,
                               const PacketHeader& header, Endpoint sender) {
    if (!running_) return;
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    peers_.mark_seen(sess->peer_id, sender);

    std::string chat_text(
        reinterpret_cast<const char*>(msg->payload.data()),
        msg->payload.size());
    const NodeId peer_id = sess->peer_id;
    std::printf("\n[Peer %02x%02x...]: %s\n",
                peer_id[0], peer_id[1], chat_text.c_str());
    std::fflush(stdout);
}

void Tunnel::handle_file_header_frame(const uint8_t* data, size_t len,
                                      const PacketHeader& header,
                                      Endpoint sender) {
    if (!running_) return;
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    const auto file_header = deserialize_file_header(msg->payload);
    if (!file_header) return;
    const auto local_chunk_size =
        file_chunk_size_for_overlay_mtu(overlay_mtu_);
    if (!local_chunk_size || file_header->chunk_size > *local_chunk_size)
        return;

    auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    peers_.mark_seen(sess->peer_id, sender);

    system("mkdir downloads 2>NUL");
    const std::string out_path = "./downloads/" +
        file_transfer_part_name(sess->peer_id, file_header->transfer_id);
    const std::string final_path = "./downloads/" + file_header->filename;
    FileTransferAck ack;
    ack.transfer_id = file_header->transfer_id;
    ack.header_received = true;
    bool created = false;
    {
        std::lock_guard<std::mutex> lock(incoming_transfers_mtx_);
        const FileTransferKey key{
            sess->peer_id, file_header->transfer_id};
        auto existing = incoming_transfers_.find(key);
        if (existing != incoming_transfers_.end()) {
            if (existing->second.filename != file_header->filename ||
                existing->second.file_size != file_header->file_size ||
                existing->second.chunk_size != file_header->chunk_size ||
                existing->second.total_chunks != file_header->total_chunks ||
                existing->second.content_hash != file_header->content_hash)
                return;
            existing->second.last_activity = clock_.now();
            ack.ranges = existing->second.chunks.acknowledged_ranges();
        } else {
            size_t peer_count = 0;
            size_t global_count = 0;
            uint64_t peer_bytes = 0;
            uint64_t global_bytes = 0;
            for (const auto& [active_key, active] : incoming_transfers_) {
                if (active.completion_reported)
                    continue;
                ++global_count;
                global_bytes += active.file_size;
                if (active_key.sender == sess->peer_id) {
                    ++peer_count;
                    peer_bytes += active.file_size;
                }
            }
            if (!file_transfer_admission_allowed(
                    peer_count, peer_bytes, global_count,
                    global_bytes, file_header->file_size)) {
                send_file_cancel(sess->peer_id, sender,
                                 file_header->transfer_id,
                                 FileCancelReason::Capacity);
                return;
            }
            std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open())
                return;
            IncomingFileTransfer ft;
            ft.filename = file_header->filename;
            ft.file_size = file_header->file_size;
            ft.chunk_size = file_header->chunk_size;
            ft.total_chunks = file_header->total_chunks;
            ft.content_hash = file_header->content_hash;
            ft.output_path = out_path;
            ft.final_path = final_path;
            ft.last_activity = clock_.now();
            if (!ft.chunks.reset(file_header->total_chunks))
                return;
            incoming_transfers_.emplace(key, std::move(ft));
            created = true;
        }
    }
    send_file_ack(sess->peer_id, sender, ack);

    if (!created)
        return;

    const NodeId peer_id = sess->peer_id;
    std::printf(
        "\n[Incoming File]: '%s' (%.2f KB, %u chunks) from Peer %02x%02x...\n",
        file_header->filename.c_str(),
        static_cast<double>(file_header->file_size) / 1024.0,
        file_header->total_chunks,
        peer_id[0], peer_id[1]);
    std::fflush(stdout);
}

void Tunnel::handle_file_chunk_frame(const uint8_t* data, size_t len,
                                     const PacketHeader& header,
                                     Endpoint sender) {
    if (!running_) return;
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    const auto file_chunk = deserialize_file_chunk(msg->payload);
    if (!file_chunk) return;

    auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    peers_.mark_seen(sess->peer_id, sender);

    FileTransferAck ack;
    ack.transfer_id = file_chunk->transfer_id;
    ack.header_received = true;
    {
        std::lock_guard<std::mutex> lock(incoming_transfers_mtx_);
        const FileTransferKey key{sess->peer_id, file_chunk->transfer_id};
        auto it = incoming_transfers_.find(key);
        if (it == incoming_transfers_.end()) return;
        const FileTransferHeader expected_header{
            file_chunk->transfer_id,
            it->second.file_size,
            it->second.chunk_size,
            it->second.total_chunks,
            it->second.content_hash,
            it->second.filename
        };
        if (!is_valid_file_chunk_for_header(expected_header, *file_chunk))
            return;
        it->second.last_activity = clock_.now();

        if (!it->second.chunks.received(file_chunk->chunk_index)) {
            std::fstream fs(
                it->second.output_path,
                std::ios::binary | std::ios::in | std::ios::out);
            if (!fs.is_open()) return;
            fs.seekp(static_cast<uint64_t>(file_chunk->chunk_index) *
                         it->second.chunk_size,
                     std::ios::beg);
            fs.write(reinterpret_cast<const char*>(file_chunk->data.data()),
                     static_cast<std::streamsize>(file_chunk->data.size()));
            if (!fs) return;
            fs.close();
            if (it->second.chunks.record(file_chunk->chunk_index) !=
                FileChunkReceipt::Accepted)
                return;
        }
        if (it->second.chunks.complete() &&
            !it->second.completion_reported) {
            const auto committed = verify_and_commit_file(
                it->second.output_path, it->second.final_path,
                it->second.file_size, it->second.content_hash);
            if (committed == FileCommitResult::Committed) {
                std::printf(
                    "\n[File Received]: '%s' (%.2f KB) saved to %s\n",
                    it->second.filename.c_str(),
                    static_cast<double>(it->second.file_size) / 1024.0,
                    it->second.final_path.c_str());
                std::fflush(stdout);
                it->second.completion_reported = true;
            } else {
                (void)it->second.chunks.remove(file_chunk->chunk_index);
                aegis_log(
                    "[tunnel] completed file failed verification/rename (%d)\n",
                    static_cast<int>(committed));
            }
        }
        ack.ranges = it->second.chunks.acknowledged_ranges(
            file_chunk->chunk_index);
    }
    send_file_ack(sess->peer_id, sender, ack);
}

void Tunnel::send_file_ack(const NodeId& peer_id, Endpoint endpoint,
                           const FileTransferAck& ack) {
    const auto payload = serialize_file_ack(ack);
    if (!payload)
        return;
    const auto frame = session_manager_->encrypt_message(
        peer_id, TYPE_FILE_ACK, payload->data(), payload->size());
    if (frame)
        transport_.send(
            frame->data(), frame->size(), endpoint, SendPriority::Control);
}

void Tunnel::handle_file_ack_frame(const uint8_t* data, size_t len,
                                   const PacketHeader& header,
                                   Endpoint sender) {
    if (!running_) return;
    const auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    const auto ack = deserialize_file_ack(msg->payload);
    if (!ack) return;
    const auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    peers_.mark_seen(sess->peer_id, sender);

    const FileTransferKey key{sess->peer_id, ack->transfer_id};
    {
        std::lock_guard<std::mutex> lock(outgoing_transfers_mtx_);
        auto it = outgoing_transfers_.find(key);
        if (it == outgoing_transfers_.end())
            return;
        it->second.acknowledge(*ack, clock_.now());
    }
    outgoing_transfers_cv_.notify_all();
}

void Tunnel::send_file_cancel(const NodeId& peer_id, Endpoint endpoint,
                              uint64_t transfer_id,
                              FileCancelReason reason) {
    const auto payload = serialize_file_cancel({transfer_id, reason});
    if (!payload)
        return;
    const auto frame = session_manager_->encrypt_message(
        peer_id, TYPE_FILE_CANCEL, payload->data(), payload->size());
    if (frame)
        transport_.send(frame->data(), frame->size(), endpoint,
                        SendPriority::Control);
}

void Tunnel::handle_file_cancel_frame(const uint8_t* data, size_t len,
                                      const PacketHeader& header,
                                      Endpoint sender) {
    if (!running_) return;
    const auto msg = session_manager_->decrypt_message(data, len);
    if (!msg) return;
    const auto cancel = deserialize_file_cancel(msg->payload);
    if (!cancel) return;
    const auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    peers_.mark_seen(sess->peer_id, sender);

    const FileTransferKey key{sess->peer_id, cancel->transfer_id};
    std::string partial_path;
    {
        std::lock_guard<std::mutex> lock(incoming_transfers_mtx_);
        const auto incoming = incoming_transfers_.find(key);
        if (incoming != incoming_transfers_.end()) {
            if (!incoming->second.completion_reported)
                partial_path = incoming->second.output_path;
            incoming_transfers_.erase(incoming);
        }
    }
    if (!partial_path.empty()) {
        std::error_code error;
        std::filesystem::remove(partial_path, error);
    }
    {
        std::lock_guard<std::mutex> lock(outgoing_transfers_mtx_);
        const auto outgoing = outgoing_transfers_.find(key);
        if (outgoing != outgoing_transfers_.end())
            outgoing->second.cancel();
    }
    outgoing_transfers_cv_.notify_all();
}

void Tunnel::expire_file_transfers() {
    struct ExpiredTransfer {
        FileTransferKey key;
        std::string partial_path;
    };
    std::vector<ExpiredTransfer> expired;
    {
        std::lock_guard<std::mutex> lock(incoming_transfers_mtx_);
        const auto now = clock_.now();
        for (auto it = incoming_transfers_.begin();
             it != incoming_transfers_.end();) {
            if (!file_transfer_idle_expired(it->second.last_activity, now)) {
                ++it;
                continue;
            }
            expired.push_back({it->first,
                it->second.completion_reported
                    ? std::string{} : it->second.output_path});
            it = incoming_transfers_.erase(it);
        }
    }
    for (const auto& transfer : expired) {
        if (!transfer.partial_path.empty()) {
            std::error_code error;
            std::filesystem::remove(transfer.partial_path, error);
        }
        if (!transfer.partial_path.empty()) {
            const auto peer = peers_.get_peer(transfer.key.sender);
            if (peer && peer->endpoint)
                send_file_cancel(transfer.key.sender, *peer->endpoint,
                                 transfer.key.transfer_id,
                                 FileCancelReason::TimedOut);
        }
    }
}

void Tunnel::handle_network_teardown_frame(const uint8_t* data, size_t len,
                                           const PacketHeader& header) {
    if (!running_) return;
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg || msg->payload.size() < 32) return;

    auto sess = session_manager_->get_session_by_id(header.session_id);
    if (!sess) return;
    const NodeId requester_id = sess->peer_id;

    if (requester_id == creator_node_id_) {
        std::printf(
            "\n[Network]: Network was destroyed by creator (%02x%02x...). Disconnecting session...\n",
            requester_id[0], requester_id[1]);
        std::fflush(stdout);
        std::thread([this]() { stop(); }).detach();
    } else {
        aegis_log(
            "[tunnel] dropped teardown request from non-creator %02x%02x...\n",
            requester_id[0], requester_id[1]);
    }
}

void Tunnel::handle_handshake_response_frame(const uint8_t* data, size_t len,
                                             const PacketHeader& header) {
    std::vector<uint8_t> payload(data + PACKET_HEADER_SIZE, data + len);
    if (payload.size() != HANDSHAKE_V2_RESPONSE_FRAME_SIZE) return;

    std::lock_guard<std::mutex> lock(hs_mtx_);
    auto it = std::find_if(
        pending_handshakes_.begin(), pending_handshakes_.end(),
        [&](const auto& kv) {
            return kv.second.session_id == header.session_id;
        });
    if (it == pending_handshakes_.end()) return;
    if (session_manager_->handle_handshake_resp(payload, header.session_id)) {
        it->second.done = true;
        hs_cv_.notify_all();
    }
}

void Tunnel::handle_handshake_cookie_frame(const uint8_t* data, size_t len,
                                           const PacketHeader& header,
                                           Endpoint sender) {
    if (len != PACKET_HEADER_SIZE + HANDSHAKE_COOKIE_SIZE ||
        header.payload_length != HANDSHAKE_COOKIE_SIZE)
        return;

    std::lock_guard<std::mutex> lock(hs_mtx_);
    auto it = std::find_if(
        pending_handshakes_.begin(), pending_handshakes_.end(),
        [&](const auto& entry) {
            return entry.second.session_id == header.session_id &&
                entry.second.endpoint == sender && !entry.second.done;
        });
    if (it == pending_handshakes_.end()) return;
    HandshakeCookie cookie{};
    std::copy_n(data + PACKET_HEADER_SIZE, cookie.size(), cookie.begin());
    it->second.cookie = cookie;
    it->second.cookie_updated = true;
    hs_cv_.notify_all();
}

void Tunnel::handle_handshake_init_frame(const uint8_t* data, size_t len,
                                         const PacketHeader& header,
                                         Endpoint sender) {
    if (!handshake_rate_limiter_.allow(sender)) {
        aegis_log("[tunnel] dropped rate-limited handshake INIT\n");
        return;
    }
    const size_t bare_size =
        PACKET_HEADER_SIZE + HANDSHAKE_V2_INIT_FRAME_SIZE;
    const size_t cookie_size = bare_size + HANDSHAKE_COOKIE_SIZE;
    if ((len != bare_size && len != cookie_size) ||
        header.payload_length != len - PACKET_HEADER_SIZE)
        return;

    const std::span<const uint8_t> init_frame(
        data + PACKET_HEADER_SIZE, HANDSHAKE_V2_INIT_FRAME_SIZE);
    bool cookie_valid = false;
    if (len == cookie_size) {
        HandshakeCookie cookie{};
        std::copy_n(data + bare_size, cookie.size(), cookie.begin());
        cookie_valid = handshake_cookie_manager_.verify(
            cookie, sender, header.session_id, init_frame);
    }
    if (!cookie_valid) {
        const auto cookie = handshake_cookie_manager_.issue(
            sender, header.session_id, init_frame);
        if (!cookie) return;
        PacketHeader challenge{};
        challenge.version = PACKET_VERSION;
        challenge.packet_type = TYPE_HANDSHAKE_COOKIE;
        challenge.session_id = header.session_id;
        challenge.payload_length = HANDSHAKE_COOKIE_SIZE;
        const auto challenge_header =
            SessionManager::serialize_header(challenge);
        std::array<uint8_t, PACKET_HEADER_SIZE + HANDSHAKE_COOKIE_SIZE>
            challenge_wire{};
        std::copy(challenge_header.begin(), challenge_header.end(),
                  challenge_wire.begin());
        std::copy(cookie->begin(), cookie->end(),
                  challenge_wire.begin() + PACKET_HEADER_SIZE);
        transport_.send(
            challenge_wire.data(), challenge_wire.size(), sender,
            SendPriority::Control);
        return;
    }

    std::vector<uint8_t> payload(init_frame.begin(), init_frame.end());

    auto response = session_manager_->handle_handshake_init(
        payload, header.session_id);
    if (!response) return;
    const auto upserted = peers_.upsert(
        response->peer_id, response->peer_static_public_key, sender, false);
    if (upserted == PeerUpsertResult::IdentityConflict ||
        upserted == PeerUpsertResult::CapacityRejected) {
        session_manager_->remove_session(response->peer_id);
        return;
    }

    PacketHeader response_header{};
    response_header.version = PACKET_VERSION;
    response_header.packet_type = TYPE_HANDSHAKE_RESP;
    response_header.session_id = header.session_id;
    response_header.payload_length =
        static_cast<uint32_t>(response->message.size());
    auto header_bytes = SessionManager::serialize_header(response_header);
    std::vector<uint8_t> out;
    out.reserve(PACKET_HEADER_SIZE + response->message.size());
    out.insert(out.end(), header_bytes.begin(), header_bytes.end());
    out.insert(out.end(), response->message.begin(), response->message.end());
    if (!transport_.send(
            out.data(), out.size(), sender, SendPriority::Control)) {
        session_manager_->remove_session(response->peer_id);
        aegis_log("[tunnel] handshake response queue full, session removed\n");
        return;
    }

    // Mark done only after the response is accepted by the destination FIFO.
    // Later frames for this endpoint cannot overtake it, so the responder does
    // not enqueue data before the initiator's handshake response.
    std::lock_guard<std::mutex> lock(hs_mtx_);
    pending_handshakes_[response->peer_id] = {
        response->peer_id, header.session_id, true};
    hs_cv_.notify_all();
}

void Tunnel::handle_relay(const uint8_t* data, size_t len, uint32_t session_id) {
    auto msg = session_manager_->decrypt_message(data, len);
    if (!msg || msg->packet_type != TYPE_RELAY) return;
    auto sess = session_manager_->get_session_by_id(session_id);
    if (!sess) return;
    const NodeId authenticated_sender = sess->peer_id;
    peers_.mark_seen(authenticated_sender);

    // Payload = [32] source NodeID || onion blob. The source is who we peel
    // with — every layer was keyed to the source's static key, and a relay is
    // only ever a hop between the source and the destination.
    if (msg->payload.size() < NODE_ID_SIZE + ONION_OVERHEAD) {
        aegis_log( "[tunnel] relay frame too small, dropping\n");
        return;
    }
    NodeId source{};
    std::memcpy(source.data(), msg->payload.data(), NODE_ID_SIZE);
    const uint8_t* blob = msg->payload.data() + NODE_ID_SIZE;
    size_t blob_len = msg->payload.size() - NODE_ID_SIZE;

    const auto sp = peers_.get_peer(source);
    if (!sp) {
        aegis_log( "[tunnel] relay from unknown source %02x%02x..., dropping\n",
                source[0], source[1]);
        return;
    }

    auto peeled = peel_onion(identity_.keypair, sp->public_key, blob, blob_len);
    if (!peeled) {
        aegis_log( "[tunnel] relay layer open failed (source %02x%02x...), dropping\n",
                source[0], source[1]);
        return;
    }

    // All-zero next hop => we are the final destination: deliver the packet.
    bool final = true;
    for (auto b : peeled->next_hop)
        if (b != 0) { final = false; break; }
    if (final) {
        inject_inner_packet(peeled->inner);
        return;
    }

    // A relay must never peel to itself — that can only come from a broken or
    // malicious path, and forwarding it would spin forever.
    if (peeled->next_hop == identity_.node_id) {
        aegis_log( "[tunnel] relay loop (next hop is us), dropping\n");
        return;
    }

    const auto nh = peers_.get_peer(peeled->next_hop);
    if (!nh || !nh->endpoint) {
        aegis_log( "[tunnel] relay next hop %02x%02x... unreachable, dropping\n",
                peeled->next_hop[0], peeled->next_hop[1]);
        return;
    }

    const size_t forwarded_size =
        SESSION_FRAME_OVERHEAD + RELAY_SOURCE_OVERHEAD + peeled->inner.size();
    const auto quota = relay_forward_limiter_.allow(
        authenticated_sender, forwarded_size);
    if (quota != RelayQuotaResult::Allowed) {
        const auto quota_stats = relay_forward_limiter_.stats();
        const uint64_t drops = quota_stats.total_drops();
        if (drops == 1 || drops % 100 == 0) {
            aegis_log("[tunnel] relay quota drop from %02x%02x... "
                      "(%llu drop(s))\n",
                      authenticated_sender[0], authenticated_sender[1],
                      static_cast<unsigned long long>(drops));
        }
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
        aegis_log( "[tunnel] relay forward encrypt failed, dropping\n");
        return;
    }
    if (!transport_.send(frame->data(), frame->size(), *nh->endpoint))
        aegis_log( "[tunnel] relay forward send failed, dropping\n");
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
    for (const auto& peer : peers_.all_peers()) {
        if (peer.node_id == identity_.node_id)
            continue;
        AdvertisedPeer ap;
        ap.node_id = peer.node_id;
        ap.public_key = peer.public_key;
        for (const auto& r : routes) {
            if (r.destination != peer.node_id)
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

void Tunnel::send_peer_table(const NodeId& to_peer, bool force_full) {
    std::lock_guard<std::mutex> send_lock(gossip_send_mtx_);
    auto peer = peers_.get_peer(to_peer);
    if (!peer || !peer->endpoint)
        return;

    auto advertised = build_advertised_peers();
    const auto updates = gossip_delta_tracker_.prepare(
        to_peer, advertised, force_full);
    if (updates.empty())
        return;

    const size_t max_payload_bytes =
        transport_.max_datagram_size() > SESSION_FRAME_OVERHEAD
            ? transport_.max_datagram_size() - SESSION_FRAME_OVERHEAD
            : 0;
    const auto batches = make_gossip_batches(updates, max_payload_bytes);
    size_t sent_batches = 0;
    size_t sent_entries = 0;
    for (const auto& batch : batches) {
        const auto payload = serialize_peer_table(batch.peers);
        if (!payload)
            break;
        const auto enc = session_manager_->encrypt_message(
            to_peer, TYPE_PEER_TABLE, payload->data(), payload->size());
        if (!enc || !transport_.send(
                enc->data(), enc->size(), *peer->endpoint)) {
            break;
        }
        gossip_delta_tracker_.commit(to_peer, batch.completed_revisions);
        ++sent_batches;
        sent_entries += batch.peers.size();
    }
    if (sent_batches > 0) {
        aegis_log("[tunnel] sent %s peer table to %02x%02x...: "
                  "%zu logical update(s), %zu wire entr%s in %zu batch(es)\n",
                  force_full ? "full" : "delta", to_peer[0], to_peer[1],
                  updates.size(), sent_entries,
                  sent_entries == 1 ? "y" : "ies", sent_batches);
    }
}

void Tunnel::announce_peer_table(
    const std::optional<NodeId>& exclude, bool force_full) {
    const auto all_peers = peers_.all_peers();
    std::set<NodeId> retained;
    for (const auto& peer : all_peers)
        retained.insert(peer.node_id);
    gossip_delta_tracker_.retain_recipients(retained);

    for (const auto& peer : all_peers) {
        if (exclude && peer.node_id == *exclude)
            continue;
        if (session_established(peer.node_id))
            send_peer_table(peer.node_id, force_full);
    }
}

void Tunnel::handle_peer_table(const NodeId& sender, const uint8_t* data, size_t len) {
    auto advertised = deserialize_peer_table(data, len);
    if (!advertised) {
        aegis_log( "[tunnel] peer table parse failed from %02x%02x...\n",
                sender[0], sender[1]);
        return;
    }
    const auto stats = merge_peer_table(
        peers_, routing_, *advertised, sender, identity_.node_id);
    aegis_log(
        "[tunnel] peer table from %02x%02x...: %zu advertised, %zu accepted, "
        "%zu changed, %zu route(s), %zu malformed, %zu conflict(s), "
        "%zu capacity drop(s)\n",
        sender[0], sender[1], advertised->size(), stats.accepted,
        stats.peers_changed, stats.routes_installed, stats.malformed,
        stats.conflicting, stats.capacity_rejected);
    // Fan out any new knowledge (peers or routes) so the mesh converges without
    // waiting for the next periodic gossip cycle.
    if (stats.changed())
        announce_peer_table(sender);
}

bool Tunnel::broadcast_chat(const std::string& text) {
    if (!running_) return false;
    std::vector<Peer> established_peers;
    for (const auto& p : peers_.all_peers()) {
        if (session_established(p.node_id)) {
            established_peers.push_back(p);
        }
    }
    if (established_peers.empty()) {
        std::printf("[Aegis] No established peers connected to send message.\n");
        return false;
    }
    bool sent_any = false;
    for (const auto& peer : established_peers) {
        auto msg = session_manager_->encrypt_message(
            peer.node_id, TYPE_CHAT_MSG, (const uint8_t*)text.data(), text.size());
        if (msg && peer.endpoint) {
            transport_.send(msg->data(), msg->size(), *peer.endpoint);
            sent_any = true;
        }
    }
    return sent_any;
}

bool Tunnel::send_file(const std::string& filepath, const std::optional<NodeId>& target_peer) {
    if (!running_) {
        std::printf("[Aegis] Error: Tunnel is not running.\n");
        return false;
    }
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::printf("[Aegis] Error: Cannot open file '%s'\n", filepath.c_str());
        return false;
    }
    const std::streamoff file_end = file.tellg();
    if (file_end < 0) {
        std::printf("[Aegis] Error: Cannot determine file size for '%s'\n",
                    filepath.c_str());
        return false;
    }
    const uint64_t file_size = static_cast<uint64_t>(file_end);
    file.seekg(0, std::ios::beg);

    const auto filename = sanitize_file_name(filepath);
    if (!filename) {
        std::printf("[Aegis] Error: File name is not a safe Windows basename.\n");
        return false;
    }

    const auto chunk_size = file_chunk_size_for_overlay_mtu(overlay_mtu_);
    if (!chunk_size) {
        std::printf("[Aegis] Error: Overlay MTU is too small for file transfer.\n");
        return false;
    }
    const uint32_t total_chunks =
        file_transfer_chunk_count(file_size, *chunk_size);
    if (total_chunks == 0) {
        std::printf("[Aegis] Error: File exceeds the %llu-byte transfer limit.\n",
                    static_cast<unsigned long long>(
                        FILE_TRANSFER_MAX_FILE_SIZE));
        return false;
    }
    const auto content_hash = hash_file_sha256(filepath, file_size);
    if (!content_hash) {
        std::printf("[Aegis] Error: Cannot hash file '%s'\n", filepath.c_str());
        return false;
    }

    uint64_t transfer_id = 0;
    for (int attempt = 0; attempt < 16 && transfer_id == 0; ++attempt) {
        const auto candidate = random_.u64();
        if (!candidate) {
            aegis_log("[tunnel] secure file transfer id generation failed\n");
            return false;
        }
        transfer_id = *candidate;
    }
    if (transfer_id == 0) {
        aegis_log("[tunnel] unable to generate a non-zero file transfer id\n");
        return false;
    }

    std::vector<Peer> established_peers;
    for (const auto& p : peers_.all_peers()) {
        if (session_established(p.node_id) && p.endpoint &&
            (!target_peer || p.node_id == *target_peer)) {
            established_peers.push_back(p);
        }
    }
    if (established_peers.empty()) {
        std::printf("[Aegis] Error: No established peers connected to receive file.\n");
        return false;
    }

    std::printf("[Aegis] Sending file '%s' (%.2f KB, %u chunks) to %zu peer(s)...\n",
                filename->c_str(), (double)file_size / 1024.0, total_chunks, established_peers.size());

    const FileTransferHeader outgoing_header{
        transfer_id, file_size, *chunk_size, total_chunks,
        *content_hash, *filename};
    const auto header_payload = serialize_file_header(outgoing_header);
    if (!header_payload) {
        aegis_log("[tunnel] unable to encode file header\n");
        return false;
    }

    std::vector<FileTransferKey> transfer_keys;
    {
        std::lock_guard<std::mutex> lock(outgoing_transfers_mtx_);
        for (const auto& peer : established_peers) {
            const FileTransferKey key{peer.node_id, transfer_id};
            FileSendWindow window;
            if (!window.reset(total_chunks, clock_.now()))
                return false;
            outgoing_transfers_.insert_or_assign(key, std::move(window));
            transfer_keys.push_back(key);
        }
    }
    const std::vector<FileTransferKey> all_transfer_keys = transfer_keys;

    struct PendingFileSend {
        NodeId peer_id{};
        Endpoint endpoint{};
        FileSendAction action;
    };
    bool failed = false;
    while (running_ && !transfer_keys.empty() && !failed) {
        std::vector<PendingFileSend> sends;
        std::vector<FileTransferKey> active;
        {
            std::lock_guard<std::mutex> lock(outgoing_transfers_mtx_);
            const auto now = clock_.now();
            for (const auto& key : transfer_keys) {
                auto state = outgoing_transfers_.find(key);
                if (state == outgoing_transfers_.end()) {
                    failed = true;
                    break;
                }
                if (state->second.complete()) {
                    outgoing_transfers_.erase(state);
                    continue;
                }
                FileSendAction action = state->second.poll(now);
                if (state->second.failed()) {
                    failed = true;
                    break;
                }
                active.push_back(key);
                if (!action.send_header && action.chunks.empty())
                    continue;
                const auto peer = std::find_if(
                    established_peers.begin(), established_peers.end(),
                    [&](const Peer& candidate) {
                        return candidate.node_id == key.sender;
                    });
                if (peer == established_peers.end() || !peer->endpoint) {
                    failed = true;
                    break;
                }
                sends.push_back({key.sender, *peer->endpoint,
                                 std::move(action)});
            }
        }
        transfer_keys = std::move(active);
        if (failed || transfer_keys.empty())
            break;

        for (const auto& pending : sends) {
            if (pending.action.send_header) {
                const auto frame = session_manager_->encrypt_message(
                    pending.peer_id, TYPE_FILE_HEADER,
                    header_payload->data(), header_payload->size());
                if (frame)
                    transport_.send(frame->data(), frame->size(),
                                    pending.endpoint);
            }
            for (const uint32_t chunk_index : pending.action.chunks) {
                const uint64_t offset =
                    static_cast<uint64_t>(chunk_index) * *chunk_size;
                const size_t length = static_cast<size_t>((std::min)(
                    static_cast<uint64_t>(*chunk_size), file_size - offset));
                std::vector<uint8_t> bytes(length);
                file.clear();
                file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
                file.read(reinterpret_cast<char*>(bytes.data()),
                          static_cast<std::streamsize>(length));
                if (file.gcount() != static_cast<std::streamsize>(length)) {
                    failed = true;
                    break;
                }
                const FileTransferChunk chunk{
                    transfer_id, chunk_index, std::move(bytes)};
                const auto payload = serialize_file_chunk(chunk);
                if (!payload) {
                    failed = true;
                    break;
                }
                const auto frame = session_manager_->encrypt_message(
                    pending.peer_id, TYPE_FILE_CHUNK,
                    payload->data(), payload->size());
                if (frame)
                    transport_.send(frame->data(), frame->size(),
                                    pending.endpoint);
            }
            if (failed)
                break;
        }
        if (!failed && !transfer_keys.empty()) {
            std::unique_lock<std::mutex> lock(outgoing_transfers_mtx_);
            outgoing_transfers_cv_.wait_for(
                lock, std::chrono::milliseconds(25));
        }
    }

    if (failed || !running_) {
        for (const auto& key : transfer_keys) {
            const auto peer = std::find_if(
                established_peers.begin(), established_peers.end(),
                [&](const Peer& candidate) {
                    return candidate.node_id == key.sender;
                });
            if (peer != established_peers.end() && peer->endpoint)
                send_file_cancel(
                    key.sender, *peer->endpoint, transfer_id,
                    failed ? FileCancelReason::RetryLimit
                           : FileCancelReason::SenderCancelled);
        }
    }
    {
        std::lock_guard<std::mutex> lock(outgoing_transfers_mtx_);
        for (const auto& key : all_transfer_keys)
            outgoing_transfers_.erase(key);
    }
    if (failed || !running_) {
        std::printf("[Aegis] File '%s' transfer failed after retries.\n",
                    filename->c_str());
        return false;
    }
    std::printf("[Aegis] File '%s' transfer acknowledged by all peers.\n",
                filename->c_str());
    return true;
}

bool Tunnel::delete_network() {
    if (!running_) return false;
    if (!is_creator_) {
        std::printf("[Aegis] Error: Only the network creator has privilege to delete/destroy this network.\n");
        return false;
    }
    std::printf("[Aegis] Destroying network... Broadcasting teardown signal to all peers.\n");
    std::vector<Peer> established_peers;
    for (const auto& p : peers_.all_peers()) {
        if (session_established(p.node_id)) {
            established_peers.push_back(p);
        }
    }
    std::vector<uint8_t> payload(32);
    std::memcpy(payload.data(), identity_.node_id.data(), 32);

    for (const auto& peer : established_peers) {
        auto msg = session_manager_->encrypt_message(
            peer.node_id, TYPE_NETWORK_TEARDOWN, payload.data(), payload.size());
        if (msg && peer.endpoint) {
            transport_.send(msg->data(), msg->size(), *peer.endpoint);
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    stop();
    return true;
}

void Tunnel::leave_network() {
    if (running_) {
        std::printf("[Aegis] Disconnecting from mesh network...\n");
        stop();
    }
}
