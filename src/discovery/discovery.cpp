#include "aegis/discovery/discovery.hpp"
#include "aegis/packet/header.hpp"
#include "aegis/session/session.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>

Discovery::~Discovery() { stop(); }

std::vector<uint8_t> Discovery::build_presence(const Identity& identity,
                                               const Endpoint& endpoint)
{
    PacketHeader hdr{};
    hdr.version = PACKET_VERSION;
    hdr.packet_type = TYPE_DISCOVERY;
    hdr.flags = 0;
    hdr.reserved = 0;
    hdr.session_id = 0;
    hdr.sequence_number = 0;
    hdr.payload_length = (uint32_t)DISCOVERY_PAYLOAD_SIZE;
    auto hdr_bytes = SessionManager::serialize_header(hdr);

    std::vector<uint8_t> out;
    out.reserve(DISCOVERY_FRAME_SIZE);
    out.insert(out.end(), hdr_bytes.begin(), hdr_bytes.end());
    out.insert(out.end(), identity.node_id.begin(), identity.node_id.end());
    out.insert(out.end(), identity.network_id.begin(), identity.network_id.end());
    out.insert(out.end(), (const uint8_t*)&endpoint.ip, (const uint8_t*)&endpoint.ip + 4);
    out.insert(out.end(), (const uint8_t*)&endpoint.port, (const uint8_t*)&endpoint.port + 2);
    return out;
}

std::optional<Presence> Discovery::parse_presence(const uint8_t* data, size_t len) {
    if (len < DISCOVERY_FRAME_SIZE)
        return std::nullopt;
    if (data[0] != PACKET_VERSION || data[1] != TYPE_DISCOVERY)
        return std::nullopt;

    Presence p;
    std::memcpy(p.node_id.data(), data + 16, NODE_ID_SIZE);
    std::memcpy(p.network_id.data(), data + 48, NETWORK_ID_SIZE);
    std::memcpy(&p.endpoint.ip, data + 80, 4);
    std::memcpy(&p.endpoint.port, data + 84, 2);
    return p;
}

bool Discovery::start(const Identity& identity, const Endpoint& endpoint,
                      uint16_t discovery_port)
{
    if (running_) return true;
    identity_ = &identity;
    announced_endpoint_ = endpoint;
    discovery_port_ = discovery_port;

    SocketOptions opts;
    opts.broadcast = true;
    opts.reuseaddr = true;
    if (!socket_.bind(discovery_port_, opts)) {
        fprintf(stderr, "[discovery] bind port %u failed\n", discovery_port_);
        return false;
    }

    if (!socket_.start_receive(
            [this](const uint8_t* d, size_t l, Endpoint s) { on_presence(d, l, s); })) {
        fprintf(stderr, "[discovery] start_receive failed\n");
        return false;
    }

    running_ = true;
    announce_thread_ = std::thread(&Discovery::announce_loop, this);
    return true;
}

void Discovery::stop() {
    running_ = false;
    socket_.stop_receive();
    if (announce_thread_.joinable())
        announce_thread_.join();
    socket_.close();
}

void Discovery::announce_loop() {
    fprintf(stderr, "[discovery] announcing presence on port %u (net %02x...)\n",
            discovery_port_, identity_->network_id[0]);
    auto packet = build_presence(*identity_, announced_endpoint_);
    Endpoint bcast = Endpoint::from_parts(255, 255, 255, 255, discovery_port_);
    // Loopback broadcast too: on a single-host test every node must see every
    // other node's presence, and 255.255.255.255 may not loop back locally.
    Endpoint lbcast = Endpoint::from_parts(127, 255, 255, 255, discovery_port_);

    while (running_) {
        if (!socket_.send(packet.data(), packet.size(), bcast) ||
            !socket_.send(packet.data(), packet.size(), lbcast)) {
            fprintf(stderr, "[discovery] broadcast failed\n");
        }
        for (int i = 0; running_ && i < 10; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void Discovery::on_presence(const uint8_t* data, size_t len, Endpoint sender) {
    auto p = parse_presence(data, len);
    if (!p) {
        fprintf(stderr, "[discovery] dropped malformed presence from %08x:%04x\n",
                ntohl(sender.ip), ntohs(sender.port));
        return;
    }

    // Never record ourselves.
    if (p->node_id == identity_->node_id)
        return;

    p->last_seen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    bool same_net = (p->network_id == identity_->network_id);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        presences_[p->node_id] = *p;
    }
    fprintf(stderr, "[discovery] presence from %02x%02x... (net %02x..., %s) at %08x:%04x\n",
            p->node_id[0], p->node_id[1], p->network_id[0],
            same_net ? "same network" : "DIFFERENT network",
            ntohl(p->endpoint.ip), ntohs(p->endpoint.port));
}

std::map<NodeId, Presence> Discovery::presences() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return presences_;
}
