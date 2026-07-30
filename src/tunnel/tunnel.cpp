#include "aegis/tunnel/tunnel.hpp"
#include <cstdio>
#include <cstring>

Tunnel::Tunnel() = default;
Tunnel::~Tunnel() { stop(); }

void increment_nonce(std::array<uint8_t, WIRE_NONCE_SIZE>& nonce) {
    for (int i = WIRE_NONCE_SIZE - 1; i >= 0; i--) {
        if (++nonce[i] != 0) break;
    }
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

    running_ = true;
    tx_thread_ = std::thread(&Tunnel::tx_loop, this);
    rx_thread_ = std::thread(&Tunnel::rx_loop, this);
    return true;
}

void Tunnel::stop() {
    running_ = false;
    transport_.stop_receive();
    if (tx_thread_.joinable()) tx_thread_.join();
    if (rx_thread_.joinable()) rx_thread_.join();
    transport_.close();
    adapter_.close();
}

void Tunnel::tx_loop() {
    fprintf(stderr, "[tunnel] tx loop started\n");
    std::vector<uint8_t> raw;
    std::vector<uint8_t> out;

    // Buffers for encrypt: max IP packet size (1500) is safe
    uint8_t ct_buf[2048];
    uint8_t tag_buf[WIRE_TAG_SIZE];

    while (running_) {
        raw.clear();
        if (!adapter_.read_packet(raw, 100))
            continue;

        auto parsed = IPPacket::parse(raw.data(), raw.size());
        if (!parsed)
            continue;

        // Encrypt IP packet with current tx_nonce
        ChaCha20Poly1305Nonce nonce_arr{};
        std::memcpy(nonce_arr.data(), tx_nonce_.data(), WIRE_NONCE_SIZE);

        if (!chacha20_poly1305_encrypt(
                config_.psk, nonce_arr,
                raw.data(), raw.size(),
                ct_buf, tag_buf)) {
            fprintf(stderr, "[tunnel] encrypt failed, dropping packet\n");
            continue;
        }

        // Build wire packet: [nonce][ciphertext][tag]
        out.clear();
        out.insert(out.end(), tx_nonce_.begin(), tx_nonce_.end());
        out.insert(out.end(), ct_buf, ct_buf + raw.size());
        out.insert(out.end(), tag_buf, tag_buf + WIRE_TAG_SIZE);

        if (!transport_.send(out.data(), out.size(), config_.peer_endpoint)) {
            fprintf(stderr, "[tunnel] send failed, dropping packet\n");
        }

        increment_nonce(tx_nonce_);
    }
    fprintf(stderr, "[tunnel] tx loop ended\n");
}

void Tunnel::rx_loop() {
    fprintf(stderr, "[tunnel] rx loop started\n");

    uint8_t pt_buf[2048];

    transport_.start_receive([this, pt_buf](const uint8_t* data, size_t len, Endpoint) mutable {
        if (!running_) return;

        if (len < WIRE_NONCE_SIZE + WIRE_TAG_SIZE) {
            fprintf(stderr, "[tunnel] drop: packet too small (%zu bytes)\n", len);
            return;
        }

        size_t ct_len = len - WIRE_NONCE_SIZE - WIRE_TAG_SIZE;

        // Parse nonce from first 12 bytes
        ChaCha20Poly1305Nonce nonce{};
        std::memcpy(nonce.data(), data, WIRE_NONCE_SIZE);

        // Tag is last 16 bytes
        const uint8_t* tag = data + WIRE_NONCE_SIZE + ct_len;

        // Ciphertext is in the middle
        const uint8_t* ct = data + WIRE_NONCE_SIZE;

        if (!chacha20_poly1305_decrypt(
                config_.psk, nonce,
                ct, ct_len, tag, pt_buf)) {
            fprintf(stderr, "[tunnel] drop: decrypt/auth failure\n");
            return;
        }

        std::vector<uint8_t> pt_vec(pt_buf, pt_buf + ct_len);
        if (!adapter_.write_packet(pt_vec)) {
            fprintf(stderr, "[tunnel] write_packet failed, dropping\n");
        }
    });
}
