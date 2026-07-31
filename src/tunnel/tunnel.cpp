#include "aegis/tunnel/tunnel.hpp"
#include "aegis/packet/packet.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>

Tunnel::Tunnel()
    : identity_(Identity::create(NetworkId{})),
      session_manager_(identity_)
{
    fprintf(stderr, "[tunnel] identity: ");
    for (auto b : identity_.node_id) fprintf(stderr, "%02x", b);
    fprintf(stderr, "\n");
}

Tunnel::~Tunnel() { stop(); }

static uint32_t rand_session_id() {
    uint32_t id = 0;
#ifdef _MSC_VER
    srand((unsigned)time(nullptr));
    id = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
#else
    id = (uint32_t)rand();
#endif
    return id;
}

bool Tunnel::start(const TunnelConfig& config, const std::string& adapter_name) {
    config_ = config;

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

    fprintf(stderr, "[tunnel] listening on %u, peer endpoint %08x:%u\n",
            config.listen_port,
            ntohl(config.peer_endpoint.ip),
            ntohs(config.peer_endpoint.port));

    // ---- Handshake phase ------------------------------------------------
    // Role is resolved deterministically by listen port: the lower port
    // initiates, the higher port only responds. This avoids the deadlock
    // where both sides initiate with different session IDs and neither can
    // decrypt the other's data packets.
    bool initiator =
        config.listen_port < ntohs(config.peer_endpoint.port);

    transport_.start_receive(
        [this](const uint8_t* d, size_t l, Endpoint s) { rx_callback(d, l, s); });

    if (initiator) {
        pending_session_id_ = rand_session_id();
        auto init_payload = session_manager_.create_handshake_init(pending_session_id_);

        PacketHeader init_hdr{};
        init_hdr.version = PACKET_VERSION;
        init_hdr.packet_type = TYPE_HANDSHAKE_INIT;
        init_hdr.session_id = pending_session_id_;
        init_hdr.payload_length = (uint32_t)init_payload.size();
        auto init_hdr_bytes = SessionManager::serialize_header(init_hdr);

        std::vector<uint8_t> init_wire;
        init_wire.reserve(16 + init_payload.size());
        init_wire.insert(init_wire.end(), init_hdr_bytes.begin(), init_hdr_bytes.end());
        init_wire.insert(init_wire.end(), init_payload.begin(), init_payload.end());

        fprintf(stderr, "[tunnel] sent handshake init (session_id=%08x)\n",
                pending_session_id_);

        // Wait for handshake completion (with retries)
        std::unique_lock<std::mutex> lock(hs_mtx_);
        for (int attempt = 0; attempt < 10; attempt++) {
            transport_.send(init_wire.data(), init_wire.size(), config_.peer_endpoint);
            if (hs_cv_.wait_for(lock, std::chrono::seconds(1),
                                [this] { return hs_done_; }))
                break;
            fprintf(stderr, "[tunnel] handshake retry %d...\n", attempt + 1);
        }
    } else {
        // Responder: wait for the peer's init; rx_callback responds.
        std::unique_lock<std::mutex> lock(hs_mtx_);
        hs_cv_.wait_for(lock, std::chrono::seconds(10),
                        [this] { return hs_done_; });
    }

    if (!hs_done_) {
        fprintf(stderr, "[tunnel] handshake failed: no response\n");
        transport_.stop_receive();
        transport_.close();
        adapter_.close();
        return false;
    }

    fprintf(stderr, "[tunnel] session established (%s)\n",
            initiator ? "initiator" : "responder");
    running_ = true;
    tx_thread_ = std::thread(&Tunnel::tx_loop, this);
    return true;
}

void Tunnel::stop() {
    running_ = false;
    transport_.stop_receive();
    if (tx_thread_.joinable()) tx_thread_.join();
    transport_.close();
    adapter_.close();
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

        auto enc = session_manager_.encrypt_data(
            peer_id_, raw.data(), raw.size());
        if (!enc) {
            fprintf(stderr, "[tunnel] encrypt failed, dropping packet\n");
            continue;
        }

        if (!transport_.send(enc->data(), enc->size(), config_.peer_endpoint)) {
            fprintf(stderr, "[tunnel] send failed, dropping packet\n");
        }
    }
    fprintf(stderr, "[tunnel] tx loop ended\n");
}

void Tunnel::rx_callback(const uint8_t* data, size_t len, Endpoint) {
    if (len < 16) return;

    uint8_t type = data[1];

    if (type == TYPE_DATA) {
        if (!running_) return;
        auto dec = session_manager_.decrypt_data(data, len);
        if (!dec) return;
        if (!adapter_.write_packet(*dec)) {
            fprintf(stderr, "[tunnel] write_packet failed\n");
        }
        return;
    }

    if (type == TYPE_HANDSHAKE_RESP) {
        std::vector<uint8_t> payload(data + 16, data + len);
        if (payload.size() < 36) return;
        std::memcpy(peer_id_.data(), payload.data() + 36, 32);
        if (session_manager_.handle_handshake_resp(payload, pending_session_id_)) {
            std::lock_guard<std::mutex> lock(hs_mtx_);
            hs_done_ = true;
            hs_cv_.notify_one();
        }
        return;
    }

    if (type == TYPE_HANDSHAKE_INIT) {
        std::vector<uint8_t> payload(data + 16, data + len);
        if (payload.size() < 36) return;

        NodeId sender_id{};
        std::memcpy(sender_id.data(), payload.data() + 36, 32);
        peer_id_ = sender_id;

        auto resp_payload = session_manager_.handle_handshake_init(payload, sender_id);
        if (!resp_payload) return;

        uint32_t sid = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                       ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];

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
        transport_.send(out.data(), out.size(), config_.peer_endpoint);

        {
            std::lock_guard<std::mutex> lock(hs_mtx_);
            hs_done_ = true;
            hs_cv_.notify_one();
        }
    }
}
